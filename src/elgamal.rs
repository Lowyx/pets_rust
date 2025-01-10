extern crate curve25519_dalek;
extern crate rand;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::{random, rngs::OsRng};
use sha2::{Digest, Sha512};

use crate::keys::KeyPair;

/// Struct to hold the ElGamal ciphertext
pub struct ElGamalCiphertext {
    pub c1: RistrettoPoint, // C1 = r * G
    pub c2: Scalar, // C2 = M + Hash(r * public_key) as a Scalar: we want to encrypt AES keys as scalars
}

impl ElGamalCiphertext {
    /// Generates a new KeyPair for encryption
    pub fn keygen() -> KeyPair {
        KeyPair::generate()
    }

    /// Encrypts a message (represented as a scalar) using the recipient's public key
    /// Returns an `ElGamalCiphertext` struct containing the encrypted message
    pub fn encrypt(message: &Scalar, public_key: &RistrettoPoint) -> ElGamalCiphertext {
        //generate random r from Zp
        let r = Scalar::random(&mut OsRng); 
        //calculate c1 from g^r
        let c1 = r * RISTRETTO_BASEPOINT_POINT;
        //calculate the shared secret pk^r
        let secret = r * public_key;
        //prepare new hash
        let mut hasher = Sha512::new();
        //converting shared secret (RistrettoPoint) in bytes
        hasher.update(secret.compress().to_bytes());
        //hashing of converted shared secret
        let hashed_secret = hasher.finalize();
        //convert the first 32 bytes into an [u8; 32] array
        let mut hashed_bytes = [0u8; 32];
        hashed_bytes.copy_from_slice(&hashed_secret[..32]);
        //treat hashed shared secret as Scalar
        let hashed_scalar = Scalar::from_bytes_mod_order(hashed_bytes);
        //calculate c2 from H(pk^r)+m
        let c2 = hashed_scalar + message;
        //return ElGamal Ciphertext
        ElGamalCiphertext{c1,c2}
    }

    /// Decrypts an ElGamal ciphertext using the recipient's private key
    /// Returns the decrypted scalar (original message)
    pub fn decrypt(&self, private_key: &Scalar) -> Scalar {
        //prepare new hash
        let mut hasher = Sha512::new();
        //calculate c1^sk
        let secret = self.c1 * private_key;
        //converting secret (RistrettoPoint) in bytes
        hasher.update(secret.compress().to_bytes());
        //hashing
        let hashed_secret = hasher.finalize();
        //convert the first 32 bytes into an [u8; 32] array
        let mut hashed_bytes = [0u8; 32];
        hashed_bytes.copy_from_slice(&hashed_secret[..32]);
        //treat hashed shared secret as Scalar
        let hashed_scalar = Scalar::from_bytes_mod_order(hashed_bytes);
        //calculate and return message m
        let m = self.c2 - hashed_scalar;
        m
    }
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
