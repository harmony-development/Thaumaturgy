use std::{sync::Arc, fmt::Debug};
use openidconnect::{core::{CoreJwsSigningAlgorithm, CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJsonWebKey, CoreJsonWebKeySet}, PrivateSigningKey, JsonWebKeySet};

pub mod rsa_key;

pub trait Key: Debug + Send + Sync + PrivateSigningKey<CoreJwsSigningAlgorithm, CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJsonWebKey> {
}

pub(crate) trait RngClone: dyn_clone::DynClone + rand::RngCore + rand::CryptoRng + Send + Sync {}
dyn_clone::clone_trait_object!(RngClone);
impl<T> RngClone for T where T: rand::RngCore + rand::CryptoRng + Clone + Send + Sync {}

#[derive(Debug, Clone)]
pub struct KeySet {
	pub keys: Arc<Vec<Box<dyn Key>>>,
}

impl Into<CoreJsonWebKeySet> for KeySet {
    fn into(self) -> CoreJsonWebKeySet {
        JsonWebKeySet::new(self.keys.iter().map(|x| x.as_verification_key()).collect())
    }
}
