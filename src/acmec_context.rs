use std::cell::{RefCell, RefMut};
use reqwest::blocking::Client as HttpClient;
use openssl::pkey::{self, PKey};

#[derive(Debug)]
pub struct AcmecContext<'a> {
	http_client: RefCell<HttpClient>,
	keypair: &'a pkey::PKey<pkey::Private>,
	key_id: Option<String>,
}

impl<'a> AcmecContext<'a> {
    pub fn new(keypair: &'a PKey<pkey::Private>) -> Self {
    	Self {
    		http_client: RefCell::new(HttpClient::new()), keypair, key_id: None,
    	}
    }

    pub fn http_client(&self) -> RefMut<'_, HttpClient> {
    	return self.http_client.borrow_mut();
    }

    pub fn keypair(&self) -> &pkey::PKey<pkey::Private> {
    	return self.keypair;
    }

    pub fn set_key_id(&mut self, key_id: String) {
    	self.key_id = Some(key_id);
    	return;
    }
    pub fn key_id(&self) -> Option<&String> {
    	return self.key_id.as_ref();
    }
}