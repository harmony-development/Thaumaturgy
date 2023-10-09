use crate::keys::Key;
use std::fmt::{Debug, self};
use sha2::Digest;
use openidconnect::{core::{CoreJwsSigningAlgorithm, CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJsonWebKey}, PrivateSigningKey, SigningError, JsonWebKeyId};
use super::RngClone;

#[derive(Clone)]
pub(crate) struct Rsa {
	pub key_id: String,
	pub rng: Box<dyn RngClone + Send + Sync>,
	pub key: rsa::RsaPrivateKey,
}

impl Debug for Rsa {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Rsa")
			.field("key_id", &self.key_id)
			.field("rng", &"<unknown>")
			.field("key", &self.key)
			.finish()
	}
}

impl
    PrivateSigningKey<
        CoreJwsSigningAlgorithm,
        CoreJsonWebKeyType,
        CoreJsonWebKeyUse,
        CoreJsonWebKey,
    > for Rsa
{
    fn sign(
        &self,
        signature_alg: &CoreJwsSigningAlgorithm,
        msg: &[u8],
    ) -> Result<Vec<u8>, SigningError> {
        match *signature_alg {
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256 => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(msg);
                let hash = hasher.finalize().to_vec();

                self.key
                    .sign_with_rng(
                        &mut dyn_clone::clone_box(&self.rng),
                        rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
                        &hash,
                    )
                    .map_err(|_| SigningError::CryptoError)
            }
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384 => {
                let mut hasher = sha2::Sha384::new();
                hasher.update(msg);
                let hash = hasher.finalize().to_vec();

                self.key
                    .sign_with_rng(
                        &mut dyn_clone::clone_box(&self.rng),
                        rsa::Pkcs1v15Sign::new::<sha2::Sha384>(),
                        &hash,
                    )
                    .map_err(|_| SigningError::CryptoError)
            }
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha512 => {
                let mut hasher = sha2::Sha512::new();
                hasher.update(msg);
                let hash = hasher.finalize().to_vec();

                self.key
                    .sign_with_rng(
                        &mut dyn_clone::clone_box(&self.rng),
                        rsa::Pkcs1v15Sign::new::<sha2::Sha512>(),
                        &hash,
                    )
                    .map_err(|_| SigningError::CryptoError)
            }
            CoreJwsSigningAlgorithm::RsaSsaPssSha256 => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(msg);
                let hash = hasher.finalize().to_vec();

                self.key
                    .sign_with_rng(
                        &mut dyn_clone::clone_box(&self.rng),
                        rsa::Pss::new_with_salt::<sha2::Sha256>(hash.len()),
                        &hash,
                    )
                    .map_err(|_| SigningError::CryptoError)
            }
            CoreJwsSigningAlgorithm::RsaSsaPssSha384 => {
                let mut hasher = sha2::Sha384::new();
                hasher.update(msg);
                let hash = hasher.finalize().to_vec();

                self.key
                    .sign_with_rng(
                        &mut dyn_clone::clone_box(&self.rng),
                        rsa::Pss::new_with_salt::<sha2::Sha384>(hash.len()),
                        &hash,
                    )
                    .map_err(|_| SigningError::CryptoError)
            }
            CoreJwsSigningAlgorithm::RsaSsaPssSha512 => {
                let mut hasher = sha2::Sha512::new();
                hasher.update(msg);
                let hash = hasher.finalize().to_vec();

                self.key
                    .sign_with_rng(
                        &mut dyn_clone::clone_box(&self.rng),
                        rsa::Pss::new_with_salt::<sha2::Sha512>(hash.len()),
                        &hash,
                    )
                    .map_err(|_| SigningError::CryptoError)
            }
            ref other => Err(SigningError::UnsupportedAlg(
                serde_plain::to_string(other).unwrap_or_else(|err| {
                    panic!(
                        "signature alg {:?} failed to serialize to a string: {}",
                        other, err
                    )
                }),
            )),
        }
    }

    fn as_verification_key(&self) -> CoreJsonWebKey {
        use rsa::traits::PublicKeyParts;

        let public_key = self.key.to_public_key();
        return CoreJsonWebKey::new_rsa(public_key.n().to_bytes_be(), public_key.e().to_bytes_be(), Some(JsonWebKeyId::new(self.key_id.clone())));
    }
}

impl Key for Rsa {
}
