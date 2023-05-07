use std::ops::{Deref, DerefMut};
use crate::{clean_file::CleanFile, stringify_ser};

mod acmec_config;
use acmec_config::AcmecConfig;

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

pub struct ConfigFile {
	clean_file: Option<CleanFile>,
	config: AcmecConfig,
}
impl ConfigFile {
	pub fn open(path: String, create: bool) -> Result<Self, &'static str> {
		let clean_file = CleanFile::open(path, create)?;
		let config: AcmecConfig = serde_json::from_reader(clean_file.file().unwrap()).unwrap_or_default();
		return Ok(Self { clean_file: Some(clean_file), config, });		
	}
	pub fn delete(mut self) -> Result<(), &'static str> {
		return self.clean_file.take().unwrap().delete();
	}
	pub fn path(&self) -> &str {
		return self.clean_file.as_ref().unwrap().path();
	}
}
impl Deref for ConfigFile {
	type Target = AcmecConfig;
	fn deref(&self) -> &Self::Target {
	    return &(self.config);
	}
}
impl DerefMut for ConfigFile {
    fn deref_mut(&mut self) -> &mut Self::Target {
    	return &mut(self.config);
    }
}
impl Drop for ConfigFile {
	fn drop(&mut self) {
		let Some(mut clean_file) = self.clean_file.take() else {
			return;
		};
		if self.changed() {
			let json_config = stringify_ser(&(self.config)).unwrap();
			clean_file.write(json_config).unwrap();
		}
	}
}