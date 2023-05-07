#[derive(Debug)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct AcmeIdentifier {
	pub value: String,
}

#[derive(Debug)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct AcmeChallenge {
	pub url: String,
	pub r#type: String,
	pub status: String,
	pub token: String,
}

#[derive(Debug)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct AcmeAuthorization {
	pub status: String,
	pub identifier: AcmeIdentifier,
	pub challenges: Vec<AcmeChallenge>,
}

#[derive(Debug)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct AcmeOrder {
	pub status: String,
	pub authorizations: Vec<String>,
	pub finalize: String,
	pub certificate: Option<String>,
}

#[cfg(debug_assertions)]
pub mod relevant_directory {
	pub static NEW_NONCE: &'static str = "https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce";
	pub static NEW_ACCOUNT: &'static str = "https://acme-staging-v02.api.letsencrypt.org/acme/new-acct";
	pub static NEW_ORDER: &'static str = "https://acme-staging-v02.api.letsencrypt.org/acme/new-order";
	pub static TOS: &'static str = "https://letsencrypt.org/documents/LE-SA-v1.3-September-21-2022.pdf";
}

#[cfg(not(debug_assertions))]
pub mod relevant_directory {
	pub static NEW_NONCE: &'static str = "https://acme-v02.api.letsencrypt.org/acme/new-nonce";
	pub static NEW_ACCOUNT: &'static str = "https://acme-v02.api.letsencrypt.org/acme/new-acct";
	pub static NEW_ORDER: &'static str = "https://acme-v02.api.letsencrypt.org/acme/new-order";
	pub static TOS: &'static str = "https://letsencrypt.org/documents/LE-SA-v1.3-September-21-2022.pdf";
}