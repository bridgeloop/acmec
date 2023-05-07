use std::{ffi::OsString, rc::Rc};
use reqwest::blocking::Client as HttpClient;
use openssl::pkey::{PKey, Private};

use crate::{ConfigFile, lazy_mut::LazyMut, pem_to_keypair};

#[derive(Debug)]
pub struct AcmecContext {
	http_client: LazyMut<HttpClient>,
	keypair: PKey<Private>,
	key_id: Option<Rc<String>>,
}

impl AcmecContext {
    pub fn new(keypair: PKey<Private>) -> Self {
    	Self {
    		http_client: LazyMut::default(), keypair, key_id: None,
    	}
    }
    pub fn with_config_file(config_file: &ConfigFile, pem_passphrase: Option<OsString>) -> Result<Self, &'static str> {
        let borrow = config_file.account_details();
        let account_details = borrow.as_ref().ok_or("invalid config file")?;
        let kp = pem_to_keypair(&(account_details.pem_kp), pem_passphrase)?;
        let mut context = Self::new(kp);
        context.set_key_id(account_details.kid.clone());
        drop(borrow);

        return Ok(context);
    }

    pub fn http_client(&mut self) -> &mut HttpClient {
    	return &mut(self.http_client);
    }

    pub fn keypair(&self) -> &PKey<Private> {
    	return &(self.keypair);
    }

    pub fn set_key_id(&mut self, key_id: String) {
    	self.key_id = Some(Rc::new(key_id));
    	return;
    }
    pub fn key_id(&self) -> Option<Rc<String>> {
    	return self.key_id.clone();
    }
}