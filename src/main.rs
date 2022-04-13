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
struct ThrowError<T> {
	msg: T,
}
impl <T: std::fmt::Debug + std::fmt::Display>std::fmt::Display for ThrowError<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        return write!(f, "{}", self.msg);
    }
}
impl <T: std::fmt::Debug + std::fmt::Display>Error for ThrowError<T> {}
fn throw<T>(msg: T) -> ThrowError<T> {
	return ThrowError{
		msg: msg,
	};
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

#[derive(serde::Serialize, serde::Deserialize)]
struct AcmeIdentifier {
	value: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct AcmeChallenge {
	url: String,
	r#type: String,
	status: String,
	token: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct AcmeAuthorization {
	status: String,
	identifier: AcmeIdentifier,
	challenges: Vec<AcmeChallenge>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct AcmeOrder {
	status: String,
	authorizations: Vec<String>,
	finalize: String,
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

fn ektyn(kp: &pkey::PKey<pkey::Private>) -> Result<String, Box<dyn Error>> {
	let rsa = kp.rsa()?;
	return Ok(format!(
		r#"{{"e":{},"kty":"RSA","n":{}}}"#,
		serde_json::to_string(&(b64ue(&(rsa.e().to_vec()))))?,
		serde_json::to_string(&(b64ue(&(rsa.n().to_vec()))))?
	));
}
fn token_shit(kp: &pkey::PKey<pkey::Private>, token: String) -> Result<String, Box<dyn Error>> {
	/*
	 * aight, so, the rfcs (namely 8555 and 7638) say pretty much the following (paraphrased):
	 * <shit>
	 * Thumbprint(...) {
	 * 	1. Construct a JSON object containing only the required
	 * 	members of a JWK representing the key and with no whitespace or
	 * 	line breaks before or after any syntactic elements and with the
	 * 	required members ordered lexicographically by the Unicode code
	 * 	points of the member names.
	 * 
	 * 	2. Hash the octets of the UTF-8 representation of this JSON object
	 * 	with a cryptographic hash function H.
	 * }
	 * 
	 * keyAuthorization = token || '.' || base64url(Thumbprint(accountKey))
	 * The "Thumbprint" step uses the SHA-256 digest
	 * 
	 * The client then computes the SHA-256 digest of the key authorization.
	 * The record provisioned to the DNS contains the base64url encoding of this digest.
	 * </shit>
	 * 
	 * the json shit there is such a fuck; why use json for this?
	 * anyway, the shit pretty much boils down to:
	 * 	b64ue(sha256(format!("{}.{}", token, b64ue(sha256(ektyn(kp))))))
	 */
	let mut hasher = openssl::sha::Sha256::new();
	hasher.update(ektyn(kp)?.as_bytes());
	let hash = hasher.finish();
	let b64u_hash = b64ue(&(hash));
	let mut hasher = openssl::sha::Sha256::new();
	hasher.update(format!("{}.{}", token, b64u_hash).as_bytes());
	let hash = hasher.finish();
	return Ok(b64ue(&(hash)));
}
fn jws(kp: &pkey::PKey<pkey::Private>, acct: Option<&String>, nonce: String, url: &str, payload: &str) -> Result<String, Box<dyn Error>> {
	let key = match acct {
		Some(url) => {
			format!(
				r#""kid": {}"#,
				serde_json::to_string(&(url))?
			)
		},
		None => {
			format!(r#""jwk": {}"#, ektyn(kp)?)
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
		let text = resp.text()?;
		return Err(Box::new(throw(text)));
	}
	let headers = resp.headers();
	let location = headers.get("location").ok_or("failed to get Location")?;
	return Ok(AcmecConfig {
		pem_kp: kp.private_key_to_pem_pkcs8_passphrase(openssl::symm::Cipher::aes_256_cbc(), kp_passphrase)?,
		kid: location.to_str()?.to_string(), // yippee, i am elated.
		order: None,
	});
}

fn get_nonce(cl: &mut reqwest::blocking::Client) -> Result<String, Box<dyn Error>> {
	let resp = cl.head(ACME_DIRECTORY.new_nonce).send()?;
	let headers = resp.headers();
	let replay_nonce = headers.get("replay-nonce").ok_or("failed to get Replay-Nonce")?;
	return Ok(replay_nonce.to_str()?.to_string());
}

fn write_cfg(file: &mut File, cfg: &AcmecConfig) -> Result<(), Box<dyn Error>> {
	file.set_len(0)?;
	file.seek(std::io::SeekFrom::Start(0))?;
	file.write_all(serde_json::to_string(&(cfg))?.as_bytes())?;
	return Ok(());
}

fn delete_account(path: &str, cfg: Option<(&mut reqwest::blocking::Client, &String, &pkey::PKey<pkey::Private>)>) -> Result<(), Box<dyn Error>> {
	std::fs::remove_file(&(path))?;
	if let Some(cfg_t) = cfg {
		cfg_t.0.post(cfg_t.1).body(jws(
			cfg_t.2,
			Some(cfg_t.1),
			get_nonce(cfg_t.0)?,
			cfg_t.1,
			"{ \"status\": \"deactivated\" }",
		)?).header("content-type", "application/jose+json").send()?;
	}
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
				delete_account(&(path_to_config), None)?;
				return Err(err);
			},
		};
		if let Err(err) = write_cfg(&mut(file), &(cfg)) {
			let kp = pkey::PKey::private_key_from_pem_passphrase(&(cfg.pem_kp), pem_passphrase.as_os_str().as_bytes())?;
			delete_account(&(path_to_config), Some((&mut(cl), &(cfg.kid), &(kp))))?;
			return Err(err);
		};
		return Ok(());
	}
	
	let mut file = file_options.open(&(path_to_config))?;
	
	let mut cfg: AcmecConfig = serde_json::from_reader(&(file))?;
	let kp = pkey::PKey::private_key_from_pem_passphrase(&(cfg.pem_kp), pem_passphrase.as_os_str().as_bytes())?;
	
	if action == "delete" {
		delete_account(&(path_to_config), Some((&mut(cl), &(cfg.kid), &(kp))))?;
		return Ok(());
	}
	
	if action != "order" {
		panic!("invalid action");
	}
	
	let action = args_iter.next().expect("expected an action");
	if action == "place" {
		if !cfg.order.is_none() {
			panic!("there is already a pending order");
		}
		let mut payload = String::from(r#"{"identifiers":["#);
		let mut dns_name = args_iter.next().expect("no dns names were passed");
		loop {
			payload += &(format!(r#"{{"type":"dns","value":{}}}"#, serde_json::to_string(&(dns_name))?));
			if let Some(next) = args_iter.next() {
				dns_name = next;
				payload.push(',');
			} else {
				break;
			}
		}
		payload.push_str("]}");
		let resp = cl.post(ACME_DIRECTORY.new_order).body(jws(
			&(kp),
			Some(&(cfg.kid)),
			get_nonce(&mut(cl))?,
			ACME_DIRECTORY.new_order,
			&(payload),
		)?).header("content-type", "application/jose+json").send()?;
		if !resp.status().is_success() {
			let text = resp.text()?;
			panic!("{}", text);
		}
		let headers = resp.headers();
		cfg.order = Some(headers.get("location").ok_or("failed to get Location")?.to_str()?.to_string());
	} else if action == "try-finalize" {
		let order = match cfg.order {
			Some(ref order) => order,
			None => panic!("there is no pending order"),
		};
		let pkey_passphrase = env::var_os("AMCEC_PKEY_PASSPHRASE").expect("expected environment variable ACMEC_PKEY_PASSPHRASE to be valid");
		// check pending challenges
		// generate csr
	} else if action == "cancel" {
		let order = match cfg.order {
			Some(ref order) => order,
			None => panic!("there is no pending order"),
		};
	} else {
		panic!("invalid action");
	}
	
	write_cfg(&mut(file), &(cfg))?;
	return Ok(());
}
