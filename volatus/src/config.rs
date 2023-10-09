use std::sync::Arc;

use rsa::{pkcs1::EncodeRsaPrivateKey, BigUint};
use serde::{Serialize, Deserialize};
use pem_rfc7468::PemLabel;
use pkcs8::der::Decode;
use rand::distributions::{Alphanumeric, DistString};
use crate::keys::{self, RngClone};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Key {
	pub key_id: String,
	pub key: String,
}

impl Key {
	pub(crate) fn into_key<R: RngClone + Clone + 'static>(&self, rng: R) -> Box<dyn keys::Key> {
		let (kind, body) = pem_rfc7468::decode_vec(self.key.as_bytes()).expect("valid pem");

		if kind != pkcs1::RsaPrivateKey::PEM_LABEL {
			panic!("unsupported kind {:?}", kind);
		}

		let info = pkcs1::RsaPrivateKey::from_der(&body).expect("invalid info");

        if info.version() != pkcs1::Version::TwoPrime {
            panic!("not two prime");
        }

        let n = BigUint::from_bytes_be(info.modulus.as_bytes());
        let e = BigUint::from_bytes_be(info.public_exponent.as_bytes());
        let d = BigUint::from_bytes_be(info.private_exponent.as_bytes());
        let first_prime = BigUint::from_bytes_be(info.prime1.as_bytes());
        let second_prime = BigUint::from_bytes_be(info.prime2.as_bytes());
        let primes = vec![first_prime, second_prime];
        let key = rsa::RsaPrivateKey::from_components(n, e, d, primes).expect("from components");

		return Box::new(keys::rsa_key::Rsa {
			key_id: self.key_id.clone(),
			rng: Box::new(rng.clone()),
			key,
		});
	}
	pub(crate) fn generate<R: RngClone>(mut rng: R) -> Self {
		let rsa_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("couldn't make rsa private key");

		Self {
			key_id: Alphanumeric.sample_string(&mut rng, 10),
			key: rsa_key.to_pkcs1_pem(pem_rfc7468::LineEnding::LF).expect("to pem").to_string(),
		}
	}
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyConfig {
	pub keys: Vec<Key>,
}

impl KeyConfig {
	pub(crate) fn generate<R: RngClone>(rng: R) -> Self {
		Self {
			keys: vec![Key::generate(rng)],
		}
	}
	pub(crate) fn into_key_set<R: RngClone + Clone + 'static>(&self, rng: R) -> keys::KeySet {
		keys::KeySet {
			keys: Arc::new(self.keys.iter().map(|x| x.into_key(rng.clone())).collect())
		}
	}
}
