// acmec
// a small (and incomplete) acme client written in rust
// implements some of https://www.rfc-editor.org/rfc/rfc8555.html

/*
	ISC License
	
	Copyright (c) 2022, aiden (aiden@citalopram.reviews)
	
	Permission to use, copy, modify, and/or distribute this software for any
	purpose with or without fee is hereby granted, provided that the above
	copyright notice and this permission notice appear in all copies.
	
	THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
	WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
	MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
	ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
	WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
	ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
	OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

// jws uses account key
// csr uses certificate's public key's corresponding private key

use std::env;
use std::fs::File;
use std::os::unix::ffi::OsStrExt;

use std::error::Error;
#[derive(std::fmt::Debug)]
struct ThrowError<'a> {
	msg: &'a str,
}
impl std::fmt::Display for ThrowError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        return write!(f, "{}", self.msg);
    }
}
impl Error for ThrowError<'_> {}
fn throw(msg: &str) -> Result<(), ThrowError> {
	return Err(ThrowError{
		msg: msg,
	});
}

use openssl::rsa::Rsa;
use openssl::sign::Signer;
use openssl::hash::MessageDigest;
use openssl::pkey;

use openssl::x509::X509Req;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::stack::Stack;

use std::io::Write;
use std::io::Seek;

use openssl::base64::{encode_block as b64e};
fn b64ue(u8s: &[u8]) -> String {
	return b64e(u8s).replace("+", "-").replace("/", "_").replace("=", "");
}

use reqwest;

use serde;
use serde_json;

#[derive(serde::Serialize, serde::Deserialize)]
struct AcmecConfig {
	// account key
	pem_kp: Vec<u8>,
	kid: String,
	
	// current pending order
	order: Option<String>,
}

struct RelevantAcmeDirectory<'a> {
	new_nonce: &'a str,
	new_account: &'a str,
	new_order: &'a str,
	terms_of_service: &'a str,
}
const ACME_DIRECTORY: RelevantAcmeDirectory = RelevantAcmeDirectory {
	new_nonce: "https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce",
	new_account: "https://acme-staging-v02.api.letsencrypt.org/acme/new-acct",
	new_order: "https://acme-staging-v02.api.letsencrypt.org/acme/new-order",
	terms_of_service: "https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf",
};

fn jws(kp: &pkey::PKey<pkey::Private>, acct: Option<&String>, nonce: String, url: &str, payload: &str) -> Result<String, Box<dyn Error>> {
	let rsa = kp.rsa()?;
	let key = match acct {
		Some(url) => {
			format!(
				r#"
					"kid": {}
				"#,
				serde_json::to_string(&(url))?
			)
		},
		None => {
			format!(
				r#"
					"jwk": {{
						"e": {},
						"n": {},
						"kty": "RSA"
					}}
				"#, 
				serde_json::to_string(&(b64ue(&(rsa.e().to_vec()))))?,
				serde_json::to_string(&(b64ue(&(rsa.n().to_vec()))))?
			)
		}
	};
	let header = b64ue(format!(
		r#"{{
			"alg": "RS256",
			{},
			"nonce": {},
			"url": {}
		}}"#,
		key,
		serde_json::to_string(&(nonce))?,
		serde_json::to_string(&(url))?
	).as_bytes());
	let body = b64ue(payload.as_bytes());
	let data_to_sign = format!("{}.{}", header, body);
	let mut signer = Signer::new(MessageDigest::sha256(), &(kp))?;
	signer.update(data_to_sign.as_bytes())?;
	let signature = b64ue(&(signer.sign_to_vec()?));
	return Ok(format!(
		r#"{{
			"protected": {},
			"payload": {},
			"signature": {}
		}}"#,
		serde_json::to_string(&(header))?,
		serde_json::to_string(&(body))?,
		serde_json::to_string(&(signature))?
	));
}

/*
 * csr (required, string):  A CSR encoding the parameters for the
 * certificate being requested [RFC2986].  The CSR is sent in the
 * base64url-encoded version of the DER format.
 */
fn b64ue_csr(csr: X509Req) -> Result<String, Box<dyn Error>> {
	return Ok(b64ue(&(csr.to_der()?)));
}
fn gen_csr(kp: &pkey::PKey<pkey::Private>, dns_names: Vec<String>) -> Result<X509Req, Box<dyn Error>> {
	let mut builder = X509Req::builder()?;
	let mut alt_names = SubjectAlternativeName::new();
	for dns_name in dns_names {
		alt_names.dns(&(dns_name));
	}
	let built_alt_names = alt_names.build(&(builder.x509v3_context(None)))?;
	let mut stack = Stack::new()?;
	stack.push(built_alt_names)?;
	builder.add_extensions(&(stack))?;
	builder.set_pubkey(&(kp))?; // yes, this really will set the public key
	builder.sign(&(kp), MessageDigest::sha256())?;
	return Ok(builder.build());
}

fn create_account(cl: &mut reqwest::blocking::Client, kp_passphrase: &[u8]) -> Result<AcmecConfig, Box<dyn Error>> {
	let kp = pkey::PKey::from_rsa(Rsa::generate(2048)?)?;
	let resp = cl.post(ACME_DIRECTORY.new_account).body(jws(
		&(kp),
		None,
		get_nonce(cl)?,
		ACME_DIRECTORY.new_account,
		"{ \"termsOfServiceAgreed\": true }",
	)?).header("content-type", "application/jose+json").send()?;
	if !resp.status().is_success() {
		throw("acme account creation was unsuccessful")?;
	}
	let headers = resp.headers();
	let location = headers.get("Location").ok_or("failed to get Location")?.to_str()?;
	return Ok(AcmecConfig {
		pem_kp: kp.private_key_to_pem_pkcs8_passphrase(openssl::symm::Cipher::aes_256_cbc(), kp_passphrase)?,
		kid: location.to_string(),
		order: None,
	});
}

fn get_nonce(cl: &mut reqwest::blocking::Client) -> Result<String, Box<dyn Error>> {
	let resp = cl.head(ACME_DIRECTORY.new_nonce).send()?;
	let headers = resp.headers();
	let replay_nonce = headers.get("Replay-Nonce").ok_or("failed to get Replay-Nonce")?;
	return Ok(replay_nonce.to_str()?.to_string());
}

fn write_cfg(file: &mut File, cfg: &AcmecConfig) -> Result<(), Box<dyn Error>> {
	file.set_len(0)?;
	file.seek(std::io::SeekFrom::Start(0))?;
	file.write_all(serde_json::to_string(&(cfg))?.as_bytes())?;
	return Ok(());
}

fn main() -> Result<(), Box<dyn Error>> {
	let mut cl = reqwest::blocking::Client::new();
	let pem_passphrase = env::var_os("ACMEC_PASSPHRASE").expect("expected environment variable AMCEC_PASSPHRASE to be valid");
	
	let mut args_iter = env::args();
	args_iter.next().expect("expected program path");
	
	let path_to_config = args_iter.next().expect("expected a config path");
	let action = args_iter.next().expect("expected an action");
	
	let mut file_options = File::options();
	file_options.read(true).write(true);
	
	if action == "create" {
		let arg = args_iter.next();
		if arg.is_none() || arg.unwrap() != "accept" {
			panic!("use `create accept` to accept the terms of service at {}", ACME_DIRECTORY.terms_of_service);
		}
		file_options.create_new(true);
		let mut file = file_options.open(&(path_to_config))?;
		let cfg = match create_account(&mut(cl), pem_passphrase.as_os_str().as_bytes()) {
			Ok(config) => config,
			Err(err) => {
				std::fs::remove_file(&(path_to_config))?;
				panic!("{}", err);
			},
		};
		match write_cfg(&mut(file), &(cfg)) {
			Ok(_) => (),
			Err(err) => {
				let kp = pkey::PKey::private_key_from_pem_passphrase(&(cfg.pem_kp), pem_passphrase.as_os_str().as_bytes())?;
				std::fs::remove_file(&(path_to_config))?;
				cl.post(&(cfg.kid)).body(jws(
					&(kp),
					Some(&(cfg.kid)),
					get_nonce(&mut(cl))?,
					&(cfg.kid),
					"{ \"status\": \"deactivated\" }",
				)?).header("content-type", "application/jose+json").send()?;
				panic!("{}", err);
			},
		};
		return Ok(());
	}
	
	let mut file = file_options.open(&(path_to_config))?;
	
	let cfg = serde_json::from_reader(&(file))?;
	write_cfg(&mut(file), &(cfg))?;
	return Ok(());
}
