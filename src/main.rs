/*
	ISC License
	
	Copyright (c) 2023, aiden (aiden@cmp.bz)
	
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

// acmec
// a small (and incomplete) acme client written in rust
// implements some of https://www.rfc-editor.org/rfc/rfc8555.html

// jws uses account key
// csrs embed public keys of keypairs generated per certificate; csr representations are placed in a jws payload

use std::{env, os::unix::ffi::OsStrExt, cell::RefMut, str::from_utf8};
use openssl::{
	rsa::Rsa,
	sign::Signer,
	hash::MessageDigest,
	pkey::{self, PKey},
	symm::Cipher,
	
	x509::{X509Req, extension::SubjectAlternativeName},
	stack::Stack,

	base64::encode_block as b64e,
};
use reqwest::{self, header::HeaderValue, blocking::{Client as HttpClient, Response as HttpResponse}};
use {serde, serde_json};

mod acme;
use acme::*;

mod clean_file;
use clean_file::*;

mod config_file;
use config_file::*;

mod acmec_context;
use acmec_context::AcmecContext;

fn stringify_ser<T: serde::ser::Serialize>(s: T) -> Result<String, &'static str> {
	return serde_json::to_string(&s).map_err(|_| "failed to stringify");
}
fn stringify<T: AsRef<str>>(s: T) -> Result<String, &'static str> {
	return stringify_ser(s.as_ref());
}
fn decode_response<T: serde::de::DeserializeOwned>(resp: HttpResponse) -> Result<T, &'static str> {
	return resp.json().map_err(|_| "failed to decode response");
}

fn b64ue<T: AsRef<[u8]>>(u8s: T) -> String {
	return b64e(u8s.as_ref()).replace("+", "-").replace("/", "_").replace("=", "");
}

fn ektyn(kp: &PKey<pkey::Private>) -> Result<String, &'static str> {
	let rsa = kp
		.rsa() // why does everything have to fucking copy
		.map_err(|_| "kp.rsa() failed")?;
	let e = stringify(b64ue(rsa.e().to_vec()))?;
	let n = stringify(b64ue(rsa.n().to_vec()))?;
	return Ok(format!(r#"{{"e":{e},"kty":"RSA","n":{n}}}"#));
}

fn token_shit(kp: &PKey<pkey::Private>, token: String) -> Result<String, &'static str> {
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
	use openssl::sha::Sha256;
	let mut hasher = Sha256::new();
	hasher.update(ektyn(kp)?.as_bytes());
	let hash = hasher.finish();
	let b64u_hash = b64ue(&(hash));
	let mut hasher = Sha256::new();
	hasher.update(format!("{token}.{b64u_hash}").as_bytes());
	let hash = hasher.finish();
	return Ok(b64ue(&(hash)));
}

fn jws(context: &AcmecContext, nonce: HeaderValue, url: &str, payload: &str) -> Result<String, &'static str> {
	let key = if let Some(url) = context.key_id() {
		format!(r#""kid":{}"#, stringify(url)?)
	} else {
		format!(r#""jwk":{}"#, ektyn(context.keypair())?)
	};

	let nonce = stringify(
		nonce
			.to_str()
			.map_err(|_| "invalid Replay-Nonce HeaderValue")?
	)?;
	let url = stringify(url)?;

	let header = b64ue(format!(
		r#"{{
			"alg": "RS256",
			{key},
			"nonce": {nonce},
			"url": {url}
		}}"#,
	).as_bytes());
	let body = b64ue(payload.as_bytes());

	let data_to_sign = format!("{}.{}", header, body);
	let mut signer = Signer::new(MessageDigest::sha256(), context.keypair()).map_err(|_| "Signer::new(...) failed")?;
	signer.update(data_to_sign.as_bytes()).map_err(|_| "signer.update(...) failed")?;
	let signature = stringify(
		b64ue(
			signer.sign_to_vec().map_err(|_| "signer.sign_to_vec() failed")?
		)
	)?;

	let header = stringify(header)?;
	let body = stringify(body)?;

	return Ok(format!(
		r#"{{
			"protected": {header},
			"payload": {body},
			"signature": {signature}
		}}"#,
	));
}

fn get_nonce(cl: &RefMut<'_, HttpClient>) -> Result<HeaderValue, &'static str> {
	let mut resp = cl
		.head(relevant_directory::NEW_NONCE)
		.send()
		.map_err(|_| "get_nonce failed")?;
	let headers = resp.headers_mut();
	let replay_nonce = headers.remove("replay-nonce").ok_or("failed to get Replay-Nonce")?;
	return Ok(replay_nonce);
}

fn acme_post<T: AsRef<str>, P: AsRef<str>>(
	context: &AcmecContext,
	
	url: T,
	payload: P
) -> Result<HttpResponse, &'static str> {
	let cl = context.http_client();
	let body = jws(
		&(context),
		get_nonce(&(cl))?,
		url.as_ref(),
		payload.as_ref()
	)?;
	let resp = cl
		.post(url.as_ref())	
		.body(body)
		.header("content-type", "application/jose+json")
		.send()
		.map_err(|_| "http post request failed")?;
	return Ok(resp);
}
const NO_PAYLOAD: &'static str = "";

/*
 * csr (required, string):  A CSR encoding the parameters for the
 * certificate being requested [RFC2986].  The CSR is sent in the
 * base64url-encoded version of the DER format.
 */
fn b64ue_csr(csr: X509Req) -> Result<String, &'static str> {
	return Ok(b64ue(csr.to_der().map_err(|_| "failed to serialize X509Req")?));
}
fn gen_csr(kp: &PKey<pkey::Private>, dns_names: &Vec<String>) -> Result<X509Req, &'static str> {
	let mut builder = X509Req::builder().map_err(|_| "X509::builder() failed")?;
	let mut alt_names = SubjectAlternativeName::new();
	for dns_name in dns_names {
		alt_names.dns(&(dns_name));
	}
	let built_alt_names = alt_names.build(&(builder.x509v3_context(None))).map_err(|_| "alt_names.build(...) failed")?;
	let mut stack = Stack::new().map_err(|_| "Stack::new() failed")?;
	stack.push(built_alt_names).map_err(|_| "stack.push(...) failed")?;
	builder.add_extensions(&(stack)).map_err(|_| "builder.add_extensions(...) failed")?;
	builder.set_pubkey(&(kp)).map_err(|_| "builder.set_pubkey(...) failed")?; // yes, this really will set the public key
	builder.sign(&(kp), MessageDigest::sha256()).map_err(|_| "builder.sign(...) failed")?;
	return Ok(builder.build());
}

// account //

fn create_account(context: &AcmecContext) -> Result<HeaderValue, &'static str> {
	let mut resp = acme_post(
		context,
		relevant_directory::NEW_ACCOUNT,
		r#"{ "termsOfServiceAgreed": true }"#
	)?;
	if !resp.status().is_success() {
		if let Ok(err) = resp.text() {
			eprintln!("error: {err}");
		}
		return Err("request failed");
	}
	let headers = resp.headers_mut();
	let location = headers.remove("location").ok_or("failed to get Location")?;
	return Ok(location);
}
fn deactivate_account(context: &AcmecContext) -> Result<(), &'static str> {
	return acme_post(
		context,
		context.key_id().unwrap(),
		r#"{ "status": "deactivated" }"#
	).map(|_| ());
}

fn main() -> Result<(), &'static str> {
	let pem_passphrase = env::var_os("ACMEC_PASSPHRASE");
	
	let mut args_iter = env::args();
	args_iter.next().ok_or("expected program path")?;
	
	let path_to_config = args_iter.next().ok_or("expected a config path")?;
	let action = args_iter.next().ok_or("expected an action")?;

	let mut config_file = ConfigFile::open(path_to_config, action == "create")?;

	if action == "create" {
		if args_iter.next().as_deref() != Some("accept") {
			eprintln!("use `create accept` to accept the terms of service at {}", relevant_directory::TOS);
			return Err("terms of service not agreed to");
		}

		let kp = Rsa::generate(2048).and_then(|keypair| PKey::from_rsa(keypair)).map_err(|_| "failed to generate rsa keypair")?;
		let context = AcmecContext::new(&(kp));

		let header = create_account(&(context))?;
		let kid = header.to_str().map_err(|_| "invalid key id")?.to_owned();

		let pem_kp = if let Some(passphrase) = pem_passphrase {
			kp.private_key_to_pem_pkcs8_passphrase(
				Cipher::aes_256_cbc(),
				passphrase.as_os_str().as_bytes()
			)
		} else {
			kp.private_key_to_pem_pkcs8()
		}.map_err(|_| "failed to encode keypair as pem")?;

		config_file.set_account_details(AccountDetails {
			pem_kp, kid,
		})?;

		return Ok(());
	}

	let borrow = config_file.account_details();
	let account_details = borrow.as_ref().ok_or("invalid config file")?;
	let kp = if let Some(passphrase) = pem_passphrase {
		PKey::private_key_from_pem_passphrase(&(account_details.pem_kp), passphrase.as_os_str().as_bytes())
	} else {
		PKey::private_key_from_pem(&(account_details.pem_kp))
	}.map_err(|_| "failed to decode account keypair pem")?;
	let mut context = AcmecContext::new(&(kp));
	context.set_key_id(account_details.kid.clone());
	drop(borrow);

	match action.as_str() {
		"delete" => {
			deactivate_account(&(context))?;
			config_file.delete()?;
		}
		"order" => match args_iter.next().as_deref() {
			Some("place") => {
				config_file.order_details().as_ref().map_or(Ok(()), |_| Err("there is already an order pending"))?;

				let mut payload = String::from(r#"{"identifiers":["#);
				let dns_names: Vec<String> = args_iter.collect();
				let mut iter = dns_names.iter();
				let mut dns_name = iter.next().ok_or("no dns names were passed")?;
				loop {
					payload += &(format!(r#"{{"type":"dns","value":{}}}"#, stringify(dns_name)?));
					if let Some(next) = iter.next() {
						dns_name = &(next);
						payload.push(',');
					} else {
						break;
					}
				}
				payload.push_str("]}");
				let mut resp = acme_post(
					&(&context),
					relevant_directory::NEW_ORDER,
					payload
				)?;
				if !resp.status().is_success() {
					if let Ok(err) = resp.text() {
						eprintln!("error: {err}");
					}
					return Err("request failed");
				}
				let headers = resp.headers_mut();
				let location = headers.remove("location").ok_or("failed to get Location")?;
				let url = location.to_str().map_err(|_| "invalid header")?.to_string();
				let order: AcmeOrder = decode_response(resp)?;
				
				let mut challenge_urls = Vec::new();
				let mut output_string = String::new();
				for auth_url in &(order.authorizations) {
					let resp = acme_post(&(context), auth_url, NO_PAYLOAD)?;
					let auth: AcmeAuthorization = decode_response(resp)?;
					let challenge: AcmeChallenge = auth.challenges.into_iter().find(|challenge| &(challenge.r#type) == "dns-01").ok_or("no dns-01 challenge")?;
					challenge_urls.push(challenge.url);
					output_string += &(format!("_acme-challenge.{} {}", auth.identifier.value, token_shit(&(kp), challenge.token)?));
				}
				config_file.set_order_details(OrderDetails {
					url,
        			challenges: challenge_urls,
        			finalize: order.finalize.to_string(),
        			dns_names,
    			})?;
				println!("{}", output_string);
				return Ok(());
			},
			Some("finalize") => {
				let borrow = config_file.order_details();
				let Some(order) = borrow.as_ref() else {
					return Err("no order pending");
				};

				let cert_path = args_iter.next().ok_or("expected path to cert file")?;
				let pkey_path = args_iter.next().ok_or("expected path to pkey file")?;

				let mut cert_file = CleanFile::open(cert_path, true)?;
				let mut pkey_file = CleanFile::open(pkey_path, true)?;

				let pkey_passphrase = env::var_os("ACMEC_PKEY_PASSPHRASE");
				for url in &(order.challenges) {
					acme_post(&(context), &(url), r#"{}"#)?;
				}
				loop {
					let resp = acme_post(&(context), &(order.url), NO_PAYLOAD)?;
					let acme_order: AcmeOrder = decode_response(resp)?;
					match acme_order.status.as_str() {
						"ready" => break,
						"pending" => (),
						status => {
							eprintln!("order status: {status}");
							drop(borrow);
							config_file.discard_order()?;
							return Err("bad order status");
						}
					}
					std::thread::sleep(std::time::Duration::from_secs(3));
				}

				let mut pem_borrow = config_file.pkey_pem();
				let (cert_kp, pkey_pem) = if let Some(pkey_pem) = pem_borrow.as_ref() {
					let cert_kp = if let Some(passphrase) = &(pkey_passphrase) {
						PKey::private_key_from_pem_passphrase(&(pkey_pem), passphrase.as_os_str().as_bytes())
					} else {
						PKey::private_key_from_pem(&(pkey_pem))
					}.map_err(|_| "failed to decode certificate keypair pem")?;

					(cert_kp, pkey_pem)
				} else {
					let cert_kp = Rsa::generate(2048).and_then(|keypair| PKey::from_rsa(keypair)).map_err(|_| "failed to generate rsa keypair")?;

					drop(pem_borrow);
					config_file.set_pkey_pem(
						if let Some(passphrase) = &(pkey_passphrase) {
							cert_kp.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), passphrase.as_os_str().as_bytes())
						} else {
							cert_kp.private_key_to_pem_pkcs8()
						}.map_err(|_| "failed to serialize private key")?
					)?;

					pem_borrow = config_file.pkey_pem();
					(cert_kp, pem_borrow.as_ref().unwrap())
				};

				let pkey_pem_view = from_utf8(&(pkey_pem)).map_err(|_| "invalid utf-8 bytes in pem-encoded private key")?;

				acme_post(
					&(context), &(order.finalize),

					format!(
						r#"{{ "csr": {} }}"#,
						stringify(b64ue_csr(gen_csr(&(cert_kp), &(order.dns_names))?)?)?
					)
				)?;

				let acme_order = loop {
					let resp = acme_post(&(context), &(order.url), NO_PAYLOAD)?;
					let order: AcmeOrder = decode_response(resp)?;
					match order.status.as_str() {
						"valid" => break order,
						"processing" => (),
						status => {
							eprintln!("order status: {status}");
							// safe to discard order i think
							drop(borrow);
							drop(pem_borrow);
							config_file.discard_order()?;
							return Err("bad order status");
						} 
					}
					std::thread::sleep(std::time::Duration::from_secs(3));
				};

				let cert = acme_post(&(context), &(acme_order.certificate.ok_or("expected acme certificate")?), NO_PAYLOAD)?
					.text()
					.map_err(|_| "failed to read response")?;

				if let Err(_) = cert_file.write(&(cert)) {
					eprintln!("failed to write certificate to file, printing to stdout instead");
					println!("{}", cert);
				}
				if let Err(_) = pkey_file.write(&*(pkey_pem)) {
					eprintln!("failed to write private key to file, printing to stdout instead");
					println!("{}", pkey_pem_view);
				}

				drop(borrow);
				drop(pem_borrow);
				config_file.discard_order()?;
				return Ok(());
			},
			_ => return Err("valid subactions for order: place, finalize"),
		}
		_ => return Err("valid actions: create, delete, order"),
	}

	return Ok(());
}
