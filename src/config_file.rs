use crate::{clean_file::CleanFile, stringify_ser};

#[derive(Debug, Clone)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct AccountDetails {
	// account key
	pub pem_kp: Vec<u8>,
	pub kid: String,
}

#[derive(Debug, Clone)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct OrderDetails {
	pub url: String,
	pub challenges: Vec<String>,
	pub finalize: String,
	pub dns_names: Vec<String>,
}

#[derive(Debug, Clone)]
#[derive(serde::Serialize, serde::Deserialize)]
struct AcmecConfig {
	// account
	account_details: Option<AccountDetails>,

	// current pending order
	order_details: Option<OrderDetails>,
	pkey_pem: Option<Vec<u8>>,
}
impl Default for AcmecConfig {
    fn default() -> Self {
    	return Self {
    		account_details: None,

    		order_details: None,
    		pkey_pem: None,
    	};
    }
}

pub struct ConfigFile {
	clean_file: CleanFile,
	config: AcmecConfig,
}
impl ConfigFile {
	fn write(&mut self) -> Result<(), &'static str> {
		return self.clean_file.write(stringify_ser(&(self.config))?.as_bytes());
	}
	pub fn open(path: String, create: bool) -> Result<Self, &'static str> {
		let clean_file = CleanFile::open(path, create)?;
		let config: AcmecConfig = serde_json::from_reader(clean_file.file()).unwrap_or_default();
		return Ok(Self { clean_file, config });		
	}
	pub fn delete(self) -> Result<(), &'static str> {
		return self.clean_file.delete();
	}

	pub fn account_details(&self) -> Option<AccountDetails> {
		return self.config.account_details.clone();
	}
	pub fn set_account_details(&mut self, account_details: AccountDetails) -> Result<(), &'static str> {
		self.config.account_details.replace(account_details);
		return self.write();
	}

	pub fn order_details(&self) -> Option<OrderDetails> {
		return self.config.order_details.clone();
	}
	pub fn set_order_details(&mut self, order_details: OrderDetails) -> Result<(), &'static str> {
		self.config.order_details.replace(order_details);
		return self.write();
	}

	pub fn pkey_pem(&self) -> Option<Vec<u8>> {
		return self.config.pkey_pem.clone();
	}
	pub fn set_pkey_pem(&mut self, pkey_pem: Vec<u8>) -> Result<(), &'static str> {
		self.config.pkey_pem.replace(pkey_pem);
		return self.write();
	}

	pub fn discard_order(&mut self) -> Result<(), &'static str> {
		self.config.order_details.take();
		self.config.pkey_pem.take();
		return self.write();
	}
}