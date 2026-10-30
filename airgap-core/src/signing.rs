//! Ed25519 signing-key material the signers share: a plain 32-byte seed or a
//! BIP32-Ed25519 extended key (kL‖kR) from a converted mnemonic wallet. An
//! extended key is signed scalar-based (pallas `SecretKeyExtended`), never
//! as a 32-byte seed, and the public key derived from it is checked against
//! the one in the skey envelope when it is loaded and again every time it
//! is used.

use ed25519_dalek::{Signer, SigningKey};
use pallas_crypto::key::ed25519::SecretKeyExtended;
use zeroize::Zeroizing;

/// Why a key cannot be used. Each case means the skey file is corrupt or is
/// not what it claims to be.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MaterialError {
    #[error("extended key failed Ed25519-BIP32 structure check")]
    Structure,
    #[error("extended key public-key mismatch (corrupt skey?)")]
    PublicKeyMismatch,
    #[error("extended key public-key drift")]
    PublicKeyDrift,
}

/// Signing-key material. It deliberately has no `Debug`: it holds secret
/// key bytes.
pub enum SigningKeyMaterial {
    Plain(Zeroizing<[u8; 32]>),
    Extended {
        esk: Zeroizing<[u8; 64]>,
        /// Public key embedded in the skey envelope. [`SigningKeyMaterial::extended`]
        /// verified it equals the key derived from `esk`.
        expected_pubkey: [u8; 32],
    },
}

impl SigningKeyMaterial {
    /// Validate an extended key and wrap it: checks the Ed25519-BIP32 bit
    /// structure and that the embedded public key matches the one derived
    /// from the secret, so a corrupted or inconsistent extended skey is
    /// caught before it is ever used to sign.
    pub fn extended(esk_64: [u8; 64], pubkey_32: [u8; 32]) -> Result<Self, MaterialError> {
        let sk = SecretKeyExtended::from_bytes(esk_64).map_err(|_| MaterialError::Structure)?;
        if sk.public_key().as_ref() != pubkey_32.as_slice() {
            return Err(MaterialError::PublicKeyMismatch);
        }
        Ok(SigningKeyMaterial::Extended {
            esk: Zeroizing::new(esk_64),
            expected_pubkey: pubkey_32,
        })
    }

    /// The extended secret, re-checked against the envelope's public key so
    /// a key swapped in after loading cannot sign.
    fn extended_secret(
        esk: &[u8; 64],
        expected_pubkey: &[u8; 32],
    ) -> Result<SecretKeyExtended, MaterialError> {
        let sk = SecretKeyExtended::from_bytes(*esk).map_err(|_| MaterialError::Structure)?;
        if sk.public_key().as_ref() != expected_pubkey.as_slice() {
            return Err(MaterialError::PublicKeyDrift);
        }
        Ok(sk)
    }

    /// The 32-byte Ed25519 verification key this material signs under.
    pub fn verifying_key(&self) -> Result<[u8; 32], MaterialError> {
        match self {
            SigningKeyMaterial::Plain(seed) => {
                Ok(SigningKey::from_bytes(seed).verifying_key().to_bytes())
            }
            SigningKeyMaterial::Extended {
                esk,
                expected_pubkey,
            } => {
                let sk = Self::extended_secret(esk, expected_pubkey)?;
                let mut out = [0u8; 32];
                out.copy_from_slice(sk.public_key().as_ref());
                Ok(out)
            }
        }
    }

    /// Sign `message` (a 32-byte hash in every use), returning the
    /// verification key and the signature.
    pub fn sign(&self, message: &[u8]) -> Result<([u8; 32], [u8; 64]), MaterialError> {
        match self {
            SigningKeyMaterial::Plain(seed) => {
                let sk = SigningKey::from_bytes(seed);
                Ok((sk.verifying_key().to_bytes(), sk.sign(message).to_bytes()))
            }
            SigningKeyMaterial::Extended {
                esk,
                expected_pubkey,
            } => {
                let sk = Self::extended_secret(esk, expected_pubkey)?;
                let mut vkey = [0u8; 32];
                vkey.copy_from_slice(sk.public_key().as_ref());
                let mut sig = [0u8; 64];
                sig.copy_from_slice(sk.sign(message).as_ref());
                Ok((vkey, sig))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    /// A valid BIP32-Ed25519 extended secret: kL with the low three bits of
    /// its first byte and the top bit of its last byte cleared, bit 254 set,
    /// and bit 253 cleared.
    fn extended_secret() -> [u8; 64] {
        let mut esk = [0x42u8; 64];
        esk[0] &= 0b1111_1000;
        esk[31] &= 0b0001_1111;
        esk[31] |= 0b0100_0000;
        esk
    }

    fn public_of(esk: [u8; 64]) -> [u8; 32] {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(
            SecretKeyExtended::from_bytes(esk)
                .unwrap()
                .public_key()
                .as_ref(),
        );
        pk
    }

    #[test]
    fn a_plain_seed_signs_like_ed25519() {
        let seed = [7u8; 32];
        let m = SigningKeyMaterial::Plain(Zeroizing::new(seed));
        let (vkey, sig) = m.sign(b"hash").unwrap();
        assert_eq!(
            vkey,
            SigningKey::from_bytes(&seed).verifying_key().to_bytes()
        );
        assert_eq!(m.verifying_key().unwrap(), vkey);
        VerifyingKey::from_bytes(&vkey)
            .unwrap()
            .verify(b"hash", &Signature::from_bytes(&sig))
            .unwrap();
    }

    #[test]
    fn an_extended_key_signs_and_verifies() {
        let esk = extended_secret();
        let m = SigningKeyMaterial::extended(esk, public_of(esk)).unwrap();
        let (vkey, sig) = m.sign(b"hash").unwrap();
        assert_eq!(vkey, public_of(esk));
        assert_eq!(m.verifying_key().unwrap(), vkey);
        VerifyingKey::from_bytes(&vkey)
            .unwrap()
            .verify(b"hash", &Signature::from_bytes(&sig))
            .unwrap();
    }

    #[test]
    fn a_wrong_or_swapped_public_key_is_refused() {
        let esk = extended_secret();
        assert_eq!(
            SigningKeyMaterial::extended(esk, [0u8; 32]).err(),
            Some(MaterialError::PublicKeyMismatch)
        );
        let swapped = SigningKeyMaterial::Extended {
            esk: Zeroizing::new(esk),
            expected_pubkey: [1u8; 32],
        };
        assert_eq!(
            swapped.sign(b"hash").err(),
            Some(MaterialError::PublicKeyDrift)
        );
        assert_eq!(
            swapped.verifying_key().err(),
            Some(MaterialError::PublicKeyDrift)
        );
    }
}
