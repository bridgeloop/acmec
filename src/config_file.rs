use std::cell::{RefCell, Ref};

use crate::{clean_file::CleanFile, stringify_ser};

#[derive(Debug)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct AccountDetails {
	// account key
	pub pem_kp: Vec<u8>,
	pub kid: String,
}

#[derive(Debug)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct OrderDetails {
	pub url: String,
	pub challenges: Vec<String>,
	pub finalize: String,
	pub dns_names: Vec<String>,
}

#[derive(Debug)]
#[derive(serde::Serialize, serde::Deserialize)]
struct AcmecConfig {
	// account
	account_details: RefCell<Option<AccountDetails>>,

	// current pending order
	order_details: RefCell<Option<OrderDetails>>,
	pkey_pem: RefCell<Option<Vec<u8>>>,
}
impl Default for AcmecConfig {
    fn default() -> Self {
    	return Self {
    		account_details: RefCell::new(None),

    		order_details: RefCell::new(None),
    		pkey_pem: RefCell::new(None),
    	};
    }
}

pub struct ConfigFile {
	clean_file: RefCell<CleanFile>,
	config: AcmecConfig,
}
impl ConfigFile {
	fn write(&self) -> Result<(), &'static str> {
		return self.clean_file.borrow_mut().write(stringify_ser(&(self.config))?.as_bytes());
	}
	pub fn open(path: String, create: bool) -> Result<Self, &'static str> {
		let clean_file = RefCell::new(CleanFile::open(path, create)?);
		let config: AcmecConfig = serde_json::from_reader(clean_file.borrow().file()).unwrap_or_default();
		return Ok(Self { clean_file, config });		
	}
	pub fn delete(self) -> Result<(), &'static str> {
		return self.clean_file.into_inner().delete();
	}

	pub fn account_details(&self) -> Ref<'_, Option<AccountDetails>> {
		return self.config.account_details.borrow();
	}
	pub fn set_account_details(&self, account_details: AccountDetails) -> Result<(), &'static str> {
		self.config.account_details.borrow_mut().replace(account_details);
		return self.write();
	}

	pub fn order_details(&self) -> Ref<'_, Option<OrderDetails>> {
		return self.config.order_details.borrow();
	}
	pub fn set_order_details(&self, order_details: OrderDetails) -> Result<(), &'static str> {
		self.config.order_details.borrow_mut().replace(order_details);
		return self.write();
	}

	pub fn pkey_pem(&self) -> Ref<'_, Option<Vec<u8>>> {
		return self.config.pkey_pem.borrow();
	}
	pub fn set_pkey_pem(&self, pkey_pem: Vec<u8>) -> Result<(), &'static str> {
		self.config.pkey_pem.borrow_mut().replace(pkey_pem);
		return self.write();
	}

	pub fn discard_order(&mut self) -> Result<(), &'static str> {
		self.config.order_details.borrow_mut().take();
		self.config.pkey_pem.borrow_mut().take();
		return self.write();
	}
}