extern crate curve25519_dalek;
extern crate rand;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};

use crate::keys::KeyPair;

/// Struct to hold the ElGamal ciphertext
pub struct ElGamalCiphertext {
    pub c1: RistrettoPoint, // C1 = r * G
    pub c2: Scalar, // C2 = M + Hash(r * public_key) as a Scalar: we want to encrypt AES keys as scalars
}

impl ElGamalCiphertext {
    /// Generates a new KeyPair for encryption
    pub fn keygen() -> KeyPair {}

    /// Encrypts a message (represented as a scalar) using the recipient's public key
    /// Returns an `ElGamalCiphertext` struct containing the encrypted message
    pub fn encrypt(message: &Scalar, public_key: &RistrettoPoint) -> ElGamalCiphertext {}

    /// Decrypts an ElGamal ciphertext using the recipient's private key
    /// Returns the decrypted scalar (original message)
    pub fn decrypt(&self, private_key: &Scalar) -> Scalar {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar; // Ensure KeyPair is imported for testing

    #[test]
    fn test_elgamal_correctness() {
        // Generate key pair for encryption and decryption
        let keypair = ElGamalCiphertext::keygen();

        // Message to encrypt (as a scalar)
        let message = Scalar::random(&mut OsRng);

        // Encrypt the message
        let ciphertext = ElGamalCiphertext::encrypt(&message, &keypair.public_key);

        // Decrypt the message
        let decrypted_message = ciphertext.decrypt(&keypair.private_key);

        // Ensure the decrypted message matches the original message
        assert_eq!(
            decrypted_message, message,
            "Decrypted message should match the original message"
        );
    }

    #[test]
    fn test_elgamal_different_keys() {
        // Generate two different key pairs
        let keypair1 = ElGamalCiphertext::keygen();
        let keypair2 = ElGamalCiphertext::keygen();

        // Message to encrypt
        let message = Scalar::random(&mut OsRng);

        // Encrypt with the first keypair
        let ciphertext = ElGamalCiphertext::encrypt(&message, &keypair1.public_key);

        // Attempt to decrypt with the wrong keypair
        let decrypted_message_wrong_key = ciphertext.decrypt(&keypair2.private_key);

        // Ensure the decrypted message with the wrong key does not match the original message
        assert_ne!(
            decrypted_message_wrong_key, message,
            "Decryption with the wrong key should not match the original message"
        );
    }

    #[test]
    fn test_elgamal_repeated_encryption_produces_different_ciphertexts() {
        // Generate key pair
        let keypair = ElGamalCiphertext::keygen();

        // Message to encrypt
        let message = Scalar::random(&mut OsRng);

        // Encrypt the same message twice
        let ciphertext1 = ElGamalCiphertext::encrypt(&message, &keypair.public_key);
        let ciphertext2 = ElGamalCiphertext::encrypt(&message, &keypair.public_key);

        // Ensure that the two ciphertexts are different due to randomness in encryption
        assert_ne!(
            ciphertext1.c1, ciphertext2.c1,
            "Ciphertexts should have different C1 values due to random nonce"
        );
        assert_ne!(
            ciphertext1.c2, ciphertext2.c2,
            "Ciphertexts should have different C2 values due to different shared secrets"
        );
    }

    #[test]
    fn test_elgamal_encrypt_small_scalar() {
        // Generate key pair
        let keypair = ElGamalCiphertext::keygen();

        // Small message to encrypt (scalar of 1)
        let small_message = Scalar::ONE;

        // Encrypt the small scalar
        let ciphertext = ElGamalCiphertext::encrypt(&small_message, &keypair.public_key);

        // Decrypt the message
        let decrypted_message = ciphertext.decrypt(&keypair.private_key);

        // Ensure the decrypted message matches the original small message
        assert_eq!(
            decrypted_message, small_message,
            "Decrypted small scalar message should match the original small scalar"
        );
    }

    #[test]
    fn test_elgamal_encrypt_zero_scalar() {
        // Generate key pair
        let keypair = ElGamalCiphertext::keygen();

        // Message to encrypt (scalar of 0)
        let zero_message = Scalar::ZERO;

        // Encrypt the zero scalar
        let ciphertext = ElGamalCiphertext::encrypt(&zero_message, &keypair.public_key);

        // Decrypt the message
        let decrypted_message = ciphertext.decrypt(&keypair.private_key);

        // Ensure the decrypted message matches the original zero scalar
        assert_eq!(
            decrypted_message, zero_message,
            "Decrypted zero scalar message should match the original zero scalar"
        );
    }
}
