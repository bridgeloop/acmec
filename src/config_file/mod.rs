use std::{ops::{Deref, DerefMut}, path::Path};
use crate::stringify_ser;
use dropfile::DropFile;

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
	file: Option<DropFile>,
	config: AcmecConfig,
}
impl ConfigFile {
	pub fn open(path: String, create: bool) -> Result<Self, &'static str> {
		let mut file = DropFile::open(path, create)?;
		let config: AcmecConfig = serde_json::from_reader(&mut(file)).unwrap_or_default();
		return Ok(Self { file: Some(file), config, });		
	}
	pub fn delete(mut self) -> Result<(), &'static str> {
		return self.file.take().unwrap().delete();
	}
	pub fn path(&self) -> &Path {
		return self.file.as_ref().unwrap().path();
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
		let Some(mut file) = self.file.take() else {
			return;
		};
		if self.changed() {
			let json_config = stringify_ser(&(self.config)).unwrap();
			file.write_trunc(json_config.as_bytes()).unwrap();
		}
	}
}
