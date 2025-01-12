use crate::hybrid_enc::HybridCiphertext;
use crate::keys::KeyPair;
use crate::schnorr::SchnorrSignature;
use crate::serializers::*;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT; // addition
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs::File;
use std::io::Read;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub version: u8, // The version number of the message (1 byte)
    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub payload: Vec<u8>, // The message content (or payload) stored as a Base64-encoded string in JSON.
    #[serde(
        serialize_with = "serialize_fixed_base64",
        deserialize_with = "deserialize_fixed_base64"
    )]
    pub recipient: [u8; 32], // The recipient's identifier (stored as Vec<u8> to serialize easily)
    #[serde(
        serialize_with = "serialize_fixed_base64",
        deserialize_with = "deserialize_fixed_base64"
    )]
    pub sender: [u8; 32], // The recipient's identifier (stored as Vec<u8> to serialize easily)
    #[serde(
        serialize_with = "serialize_schnorr_signature",
        deserialize_with = "deserialize_schnorr_signature"
    )]
    pub signature: SchnorrSignature,
}

impl Message {
    /// Creates a new message with a version, payload, and recipient (CompressedRistretto converted to Vec<u8>)
    pub fn new(
        version: u8,
        payload: Vec<u8>,
        recipient: CompressedRistretto, // inconsistent with line 25 "pub recipient: [u8; 32]"
        sender: CompressedRistretto, // inconsistent with line 30 "pub sender: [u8; 32]"
        signature: SchnorrSignature,
    ) -> Self {
        Message {
            version,
            payload,
            recipient: recipient.to_bytes(),
            sender: sender.to_bytes(),
            signature,
        }
    }

    pub fn display(&self) {
        println!("Version: {}", self.version);
        println!("Payload: {:?}", self.payload);
        println!("Recipient: {:?}", self.recipient);
        println!("Sender: {:?}", self.sender);
        println!("Signature: {:?}", self.signature);
    }

    /// Writes the message to a JSON file
    pub fn to_file(&self, filepath: &str) -> std::io::Result<()> {
        let file = File::create(filepath)?;
        serde_json::to_writer_pretty(file, &self)?; // Write JSON in a human-readable format

        Ok(())
    }

    /// Encrypts the whole message using hybrid encryption
    pub fn encrypt(&mut self, elgamal_public_key: &RistrettoPoint) -> Result<(), String> {
        // Serialize the current message to bytes
        let serialized_message = serialize_message_to_bytes(self)?;

        // Encrypt the serialized message using the provided public key
        let hybrid_ciphertext = HybridCiphertext::encrypt(&serialized_message, elgamal_public_key)?;

        // Update the message fields with the encrypted data
        // The payload contains the serialized hybrid ciphertext
        self.payload = hybrid_ciphertext.serialize();
        self.version = self.version + 1;
        self.sender = CompressedRistretto::default().to_bytes();
        self.recipient = elgamal_public_key.compress().to_bytes();
        self.signature = SchnorrSignature::emty_signature();

        Ok(())
    }

    /// Decrypts the payload using hybrid decryption
    pub fn decrypt(&mut self, elgamal_private_key: &Scalar) -> Result<(), String> {
        // Decode the Base64 payload to bytes
        let hybrid_ciphertext = HybridCiphertext::deserialize(&self.payload)?;

        // Decrypt the hybrid ciphertext
        let decrypted_bytes = hybrid_ciphertext.decrypt(elgamal_private_key)?;

        // Deserialize the decrypted bytes back into a Message
        let decrypted_message = deserialize_message_from_bytes(&decrypted_bytes)?;

        // Restore the fields of the message
        self.version = decrypted_message.version;
        self.payload = decrypted_message.payload;
        self.sender = decrypted_message.sender;
        self.recipient = decrypted_message.recipient;
        self.signature = decrypted_message.signature;

        Ok(())
    }

    /// signs the payload using Schnorr signatures, sets the signing public key as sender
    pub fn sign(&mut self, signing_key: &Scalar) {
        let verification_key = signing_key * RISTRETTO_BASEPOINT_POINT;

        let sig = SchnorrSignature::sign(&self.payload, signing_key);

        self.signature = sig;
        self.sender = verification_key.compress().to_bytes();
    }

    /// Verifies the Schnorr signature of the message
    pub fn verify(&self) -> bool {
        let verification_key = CompressedRistretto::from_slice(&self.sender)
            .expect("Error converting sender to CompressedRistretto")
            .decompress()
            .expect("Error decompressing sender to RistrettoPoint");
        
        return SchnorrSignature::verify(&self.signature, &self.payload, &verification_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use rand::rngs::OsRng;
    use std::fs;

    #[test]
    fn test_message_creation() {
        // Create a sample payload and recipient
        let payload = b"Hello, this is a message!".to_vec();
        let mut csprng = OsRng;
        let recipient = RistrettoPoint::random(&mut csprng).compress();

        // Create a new message
        let version: u8 = 1;
        let message = Message::new(
            version,
            payload.clone(),
            recipient,
            recipient,
            SchnorrSignature::emty_signature(),
        );

        // Check if the fields match
        assert_eq!(message.version, version);
        assert_eq!(message.payload, payload);
        assert_eq!(message.recipient, recipient.to_bytes());

        // Display the message
        message.display();
    }

    #[test]
    fn test_message_encryption_and_decryption() {
        // Sample message to encrypt
        let payload = b"Hello, hybrid encryption!".to_vec();

        // Generate ElGamal keypair
        let keypair = KeyPair::generate();

        // Create a new message with version 0
        let mut message = Message::new(
            0,
            payload.clone(),
            keypair.public_key.compress(),
            keypair.public_key.compress(),
            SchnorrSignature::emty_signature(),
        );

        // Encrypt the message
        message
            .encrypt(&keypair.public_key)
            .expect("Encryption failed");

        // Ensure the message version is 1 after encryption
        assert_eq!(message.version, 1, "Version should be 1 after encryption");

        // Ensure the payload is not the same as the original (it should be encrypted)
        assert_ne!(
            message.payload, payload,
            "Encrypted payload should not match the original payload"
        );

        // Decrypt the message
        message
            .decrypt(&keypair.private_key)
            .expect("Decryption failed");

        // Ensure the message version is back to 0 after decryption
        assert_eq!(message.version, 0, "Version should be 0 after decryption");

        // Ensure the decrypted message matches the original payload
        assert_eq!(
            message.payload, payload,
            "Decrypted payload should match the original payload"
        );
    }
}
