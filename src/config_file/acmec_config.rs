use std::cell::{RefCell, Ref};
use super::{AccountDetails, OrderDetails};

#[derive(Debug)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct AcmecConfig {
	// account
	account_details: RefCell<Option<AccountDetails>>,

	// current pending order
	order_details: RefCell<Option<OrderDetails>>,
	pkey_pem: RefCell<Option<Vec<u8>>>,

	changed: RefCell<bool>,
}
impl AcmecConfig {
	fn mutate<T>(&self, target: &RefCell<Option<T>>, new: Option<T>) {
		*self.changed.borrow_mut() = true;
		let mut borrow = target.borrow_mut();
		if let Some(new) = new {
			borrow.replace(new);
		} else {
			borrow.take();
		}
		return;
	}

	pub fn account_details(&self) -> Ref<'_, Option<AccountDetails>> {
		return self.account_details.borrow();
	}
	pub fn set_account_details(&self, account_details: AccountDetails) {
		return self.mutate(&(self.account_details), Some(account_details));
	}

	pub fn order_details(&self) -> Ref<'_, Option<OrderDetails>> {
		return self.order_details.borrow();
	}
	pub fn set_order_details(&self, order_details: OrderDetails) {
		return self.mutate(&(&self.order_details), Some(order_details));
	}

	pub fn pkey_pem(&self) -> Ref<'_, Option<Vec<u8>>> {
		return self.pkey_pem.borrow();
	}
	pub fn set_pkey_pem(&self, pkey_pem: Vec<u8>) {
		return self.mutate(&(self.pkey_pem), Some(pkey_pem));
	}

	pub fn discard_order(&mut self) {
		self.mutate(&(self.order_details), None);
		self.mutate(&(self.pkey_pem), None);

		return;
	}

	pub fn changed(&self) -> bool {
		return *self.changed.borrow();
	}
}
impl Default for AcmecConfig {
    fn default() -> Self {
    	return Self {
    		account_details: RefCell::new(None),

    		order_details: RefCell::new(None),
    		pkey_pem: RefCell::new(None),

    		changed: RefCell::new(false),
    	};
    }
}