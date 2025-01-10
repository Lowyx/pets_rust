use crate::aes::{AESCiphertext, AES_NONCE_SIZE};
use crate::elgamal::ElGamalCiphertext;
use crate::keys::KeyPair;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::{self, Scalar};

pub struct HybridCiphertext {
    pub elgamal_ciphertext: ElGamalCiphertext,
    pub aes_ciphertext: AESCiphertext,
}

impl HybridCiphertext {
    pub fn keygen() -> KeyPair {
        ElGamalCiphertext::keygen()
    }

    pub fn encrypt(message: &[u8],public_key: &RistrettoPoint) -> Result<HybridCiphertext, String> {
        let aes_key = AESCiphertext::keygen();
        let aes_result = AESCiphertext::encrypt(&aes_key, message)?;

        let elgamal_ciphertext = ElGamalCiphertext::encrypt(&aes_key, public_key);
       
       
        Ok(HybridCiphertext {
            elgamal_ciphertext,
            aes_ciphertext: aes_result,
            })

    }

    /// Hybrid decryption: Decrypts the AES key using the ElGamal private key, then decrypts the AES ciphertext
    pub fn decrypt(&self, private_key: &Scalar) -> Result<Vec<u8>, String> {
        let aes_key = ElGamalCiphertext::decrypt(&self.elgamal_ciphertext, private_key);    
        let plaintext = AESCiphertext::decrypt(&aes_key, &self.aes_ciphertext);
        plaintext
    }

    /// Serializes the HybridCiphertext into a Vec<u8>
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();

        // Serialize ElGamalCiphertext (RistrettoPoint and Scalar)
        let c1_bytes = self.elgamal_ciphertext.c1.compress().to_bytes(); // 32 bytes
        let c2_bytes = self.elgamal_ciphertext.c2.to_bytes(); // 32 bytes

        // Append ElGamalCiphertext to the buffer
        buffer.extend_from_slice(&c1_bytes);
        buffer.extend_from_slice(&c2_bytes);

        // Serialize AESCiphertext (Nonce and Ciphertext)
        buffer.extend_from_slice(&self.aes_ciphertext.nonce); // AES_NONCE_SIZE bytes
        buffer.extend_from_slice(&self.aes_ciphertext.ciphertext); // Ciphertext (variable size)

        buffer
    }

    /// Deserializes a &[u8] back into a HybridCiphertext
    pub fn deserialize(bytes: &[u8]) -> Result<HybridCiphertext, String> {
        let mut offset = 0;

        // Deserialize ElGamalCiphertext
        if bytes.len() < 64 {
            return Err("Not enough bytes to deserialize ElGamalCiphertext".to_string());
        }

        // Deserialize c1 (RistrettoPoint)
        let c1_bytes: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| "Invalid byte slice for c1".to_string())?;
        offset += 32;

        // Correctly handle the result from `CompressedRistretto::from_slice`
        let c1_compressed = CompressedRistretto(c1_bytes);
        let c1 = c1_compressed
            .decompress()
            .ok_or("Failed to decompress c1 RistrettoPoint")?;

        // Deserialize c2 (Scalar)
        let c2_bytes: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| "Invalid byte slice for c2".to_string())?;
        offset += 32;
        let c2 = Scalar::from_bytes_mod_order(c2_bytes);

        let elgamal_ciphertext = ElGamalCiphertext { c1, c2 };

        // Deserialize AESCiphertext
        if bytes.len() < offset + AES_NONCE_SIZE {
            return Err("Not enough bytes to deserialize AESCiphertext".to_string());
        }

        let nonce: [u8; AES_NONCE_SIZE] = bytes[offset..offset + AES_NONCE_SIZE]
            .try_into()
            .map_err(|_| "Invalid byte slice for nonce".to_string())?;
        offset += AES_NONCE_SIZE;

        let ciphertext = bytes[offset..].to_vec(); // The rest of the bytes are the ciphertext

        let aes_ciphertext = AESCiphertext { nonce, ciphertext };

        Ok(HybridCiphertext {
            elgamal_ciphertext,
            aes_ciphertext,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_encryption_decryption() {
        // Sample message to encrypt
        let message = b"Hello, hybrid encryption!";

        // Generate ElGamal keypair
        let keypair = HybridCiphertext::keygen();

        // Perform hybrid encryption
        let hybrid_ciphertext = HybridCiphertext::encrypt(message, &keypair.public_key)
            .expect("Hybrid encryption failed");

        // Perform hybrid decryption
        let decrypted_message = hybrid_ciphertext
            .decrypt(&keypair.private_key)
            .expect("Hybrid decryption failed");

        // Ensure the decrypted message matches the original
        assert_eq!(decrypted_message, message);
    }

    #[test]
    fn test_serialization_deserialization() {
        // Generate sample data for testing
        let message = b"Hello, hybrid encryption!";

        // Generate ElGamal keypair
        let keypair = HybridCiphertext::keygen();

        // Perform hybrid encryption
        let hybrid_ciphertext = HybridCiphertext::encrypt(message, &keypair.public_key)
            .expect("Hybrid encryption failed");

        // Serialize the hybrid ciphertext
        let serialized = hybrid_ciphertext.serialize();

        println!("{:?}", serialized);

        // Deserialize it back into a HybridCiphertext
        let deserialized = HybridCiphertext::deserialize(&serialized).unwrap();
        let decrypted_message = deserialized
            .decrypt(&keypair.private_key)
            .expect("Hybrid decryption failed");

        // Ensure the decrypted message matches the original
        assert_eq!(decrypted_message, message);
    }
}
