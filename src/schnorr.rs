#![allow(non_snake_case)]

use crate::keys::KeyPair;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};

/// Struct to represent a Schnorr signature
#[derive(Debug, PartialEq, Clone)]
pub struct SchnorrSignature {
    pub R: RistrettoPoint, // Commitment point
    pub s: Scalar,         // Response scalar
}

impl SchnorrSignature {
    /// Generates a new KeyPair for signing
    pub fn keygen() -> KeyPair {
        KeyPair::generate()
    }

    /// Sign a message with a private key
    pub fn sign(message: &[u8], signing_key: &Scalar) -> SchnorrSignature {
        // choose random r from Zp
        let r = Scalar::random(&mut OsRng);

        // calculate R = r * G
        let R = r * &RISTRETTO_BASEPOINT_POINT;

        let public_key = signing_key * &RISTRETTO_BASEPOINT_POINT;

        // hash R and message
        let mut hasher = Sha512::new();
        hasher.update(&public_key.compress().to_bytes());
        hasher.update(&R.compress().to_bytes());
        hasher.update(message);

        // calculate signature
        let s = r + signing_key * Scalar::from_hash(hasher);

        SchnorrSignature { R, s }
    }

    /// Verify a Schnorr signature
    pub fn verify(
        signature: &SchnorrSignature,
        message: &[u8],
        public_key: &RistrettoPoint,
    ) -> bool {
        // hash R and message
        let mut hasher = Sha512::new();
        hasher.update(&public_key.compress().to_bytes());
        hasher.update(&signature.R.compress().to_bytes());
        hasher.update(message);

        // Calculate h
        let h = Scalar::from_hash(hasher);

        // Verify the signature
        let lhs = signature.s * RISTRETTO_BASEPOINT_POINT;
        let rhs = signature.R + h * public_key;

        lhs == rhs
    }

    // Converts RistrettoPoint to a byte array
    pub fn point_to_bytes(point: &RistrettoPoint) -> Vec<u8> {
        point.compress().as_bytes().to_vec()
    }

    // Converts Scalar to a byte array
    pub fn scalar_to_bytes(scalar: &Scalar) -> Vec<u8> {
        scalar.to_bytes().to_vec()
    }

    // Converts byte array back to RistrettoPoint
    pub fn bytes_to_point(bytes: &[u8]) -> Result<RistrettoPoint, &'static str> {
        if bytes.len() != 32 {
            return Err("Invalid byte length for RistrettoPoint");
        }

        let mut array = [0u8; 32];
        array.copy_from_slice(bytes); // Convert &[u8] to [u8; 32]

        let R_compressed = CompressedRistretto(array); // Compressed form
        let R = R_compressed
            .decompress()
            .ok_or("Failed to decompress RistrettoPoint")?; // Handle decompression failure

        Ok(R)
    }

    pub fn emty_signature() -> SchnorrSignature {
        SchnorrSignature {
            R: RISTRETTO_BASEPOINT_POINT,
            s: Scalar::ZERO,
        }
    }

    // Converts byte array back to Scalar
    pub fn bytes_to_scalar(bytes: &[u8]) -> Result<Scalar, &'static str> {
        if bytes.len() != 32 {
            return Err("Invalid byte length for Scalar");
        }

        let array: [u8; 32] = bytes.try_into().map_err(|_| "Invalid length")?;
        let scalar = Scalar::from_canonical_bytes(array);

        // Handle CtOption<Scalar>
        if scalar.is_some().into() {
            Ok(scalar.unwrap())
        } else {
            Err("Invalid scalar")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_signature() {
        // Generate keypair
        let keypair: KeyPair = SchnorrSignature::keygen();

        // Sign a message
        let message = b"Test message for Schnorr signature";
        let signature = SchnorrSignature::sign(message, &keypair.private_key);

        // Verify the signature
        let is_valid = SchnorrSignature::verify(&signature, message, &keypair.public_key);
        assert!(
            is_valid,
            "The signature should be valid for the original message"
        );
    }

    #[test]
    fn test_invalid_signature_message() {
        // Generate keypair
        let keypair: KeyPair = SchnorrSignature::keygen();
        // Sign a message
        let message = b"Test message for Schnorr signature";
        let signature = SchnorrSignature::sign(message, &keypair.private_key);

        // Modify the message
        let modified_message = b"Modified test message";

        // Verify the signature with the modified message
        let is_valid = SchnorrSignature::verify(&signature, modified_message, &keypair.public_key);
        assert!(
            !is_valid,
            "The signature should be invalid for the modified message"
        );
    }

    #[test]
    fn test_invalid_signature_signature() {
        // Generate keypair
        let keypair: KeyPair = SchnorrSignature::keygen();
        // Sign a message
        let message = b"Test message for Schnorr signature";
        let signature = SchnorrSignature::sign(message, &keypair.private_key);

        // Alter the signature by modifying the `s` scalar
        let altered_signature = SchnorrSignature {
            R: signature.R,
            s: signature.s + Scalar::ONE, // Change the response scalar `s`
        };

        // Verify the altered signature
        let is_valid = SchnorrSignature::verify(&altered_signature, message, &keypair.public_key);
        assert!(!is_valid, "The altered signature should be invalid");
    }

    #[test]
    fn test_edge_case_empty_message() {
        // Generate keypair
        let keypair: KeyPair = SchnorrSignature::keygen();
        // Sign an empty message
        let empty_message = b"";
        let signature = SchnorrSignature::sign(empty_message, &keypair.private_key);

        // Verify the signature for the empty message
        let is_valid = SchnorrSignature::verify(&signature, empty_message, &keypair.public_key);
        assert!(
            is_valid,
            "The signature should be valid for an empty message"
        );
    }

    #[test]
    fn test_invalid_public_key() {
        // Generate keypairs
        let keypair1: KeyPair = SchnorrSignature::keygen();
        let keypair2: KeyPair = SchnorrSignature::keygen();

        // Sign a message with the first keypair
        let message = b"Test message for Schnorr signature";
        let signature = SchnorrSignature::sign(message, &keypair1.private_key);

        // Try to verify with a different public key
        let is_valid = SchnorrSignature::verify(&signature, message, &keypair2.public_key);
        assert!(
            !is_valid,
            "The signature should be invalid for a different public key"
        );
    }

    #[test]
    fn test_repeated_signing_different_signatures() {
        // Generate keypair
        let keypair: KeyPair = SchnorrSignature::keygen();

        // Sign the same message twice
        let message = b"Test message for Schnorr signature";
        let signature1 = SchnorrSignature::sign(message, &keypair.private_key);
        let signature2 = SchnorrSignature::sign(message, &keypair.private_key);

        // The signatures should be different due to different random nonces
        assert_ne!(
            signature1.R, signature2.R,
            "Signatures should be different due to randomness"
        );
        assert_ne!(
            signature1.s, signature2.s,
            "Response scalars should be different due to randomness"
        );
    }
}
