#![allow(non_snake_case)]
use crate::schnorr::SchnorrSignature;
use crate::Message;
use base64::prelude::*;

use serde::de::Error;
use serde::{ser::SerializeMap, Serializer};
use serde::{Deserialize, Deserializer};

/// Serialize Vec<u8> as a Base64 string
pub fn serialize_base64<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let base64_str = BASE64_STANDARD.encode(bytes); // Convert bytes to Base64 string
    serializer.serialize_str(&base64_str)
}
// Base64 serialize function for [u8; 32]
pub fn serialize_fixed_base64<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let base64_str = BASE64_STANDARD.encode(bytes); // Convert to base64 string
    serializer.serialize_str(&base64_str) // Serialize as string
}

/// Deserialize Base64 string back into Vec<u8>
pub fn deserialize_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let base64_str = String::deserialize(deserializer)?; // Deserialize as string
    BASE64_STANDARD
        .decode(&base64_str)
        .map_err(serde::de::Error::custom) // Convert Base64 string back to bytes
}

/// Deserialize Base64 string back into [08;32]
pub fn deserialize_fixed_base64<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
    D: Deserializer<'de>,
{
    let base64_str = String::deserialize(deserializer)?; // Deserialize as string
    let bytes = BASE64_STANDARD
        .decode(&base64_str)
        .map_err(serde::de::Error::custom)?; // Convert Base64 string back to bytes

    // Ensure the length is exactly 32 bytes
    if bytes.len() == 32 {
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(array)
    } else {
        Err(serde::de::Error::custom("Invalid length for byte array"))
    }
}

// Serializer for `SchnorrSignature`
pub fn serialize_schnorr_signature<S>(
    signature: &SchnorrSignature,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let r_bytes = SchnorrSignature::point_to_bytes(&signature.R);
    let s_bytes = SchnorrSignature::scalar_to_bytes(&signature.s);

    let mut map = serializer.serialize_map(Some(2))?;
    map.serialize_entry("R", &BASE64_STANDARD.encode(&r_bytes))?;
    map.serialize_entry("s", &BASE64_STANDARD.encode(&s_bytes))?;
    map.end()
}

// Deserializer for `SchnorrSignature`
pub fn deserialize_schnorr_signature<'de, D>(deserializer: D) -> Result<SchnorrSignature, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct SchnorrSignatureHelper {
        R: String,
        s: String,
    }

    let helper = SchnorrSignatureHelper::deserialize(deserializer)?;

    let r_bytes = BASE64_STANDARD
        .decode(&helper.R)
        .map_err(D::Error::custom)?;
    let s_bytes = BASE64_STANDARD
        .decode(&helper.s)
        .map_err(D::Error::custom)?;

    let R = SchnorrSignature::bytes_to_point(&r_bytes).map_err(D::Error::custom)?;
    let s = SchnorrSignature::bytes_to_scalar(&s_bytes).map_err(D::Error::custom)?;

    Ok(SchnorrSignature { R, s })
}

/// Serializes the Message struct into a Vec<u8> (binary format).
pub fn serialize_message_to_bytes(message: &Message) -> Result<Vec<u8>, String> {
    // Serialize the Message struct into a JSON string.
    let json_string = serde_json::to_string(message)
        .map_err(|e| format!("Failed to serialize message: {}", e))?;

    // Convert the JSON string into a Vec<u8>.
    Ok(json_string.into_bytes())
}

/// Deserializes the Message from a Vec<u8> back into the Message struct.
pub fn deserialize_message_from_bytes(bytes: &[u8]) -> Result<Message, String> {
    // Convert the Vec<u8> back into a JSON string.
    let json_string =
        String::from_utf8(bytes.to_vec()).map_err(|e| format!("Invalid UTF-8 sequence: {}", e))?;

    // Deserialize the JSON string back into a Message struct.
    serde_json::from_str(&json_string).map_err(|e| format!("Failed to deserialize message: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schnorr::SchnorrSignature;
    use curve25519_dalek::ristretto::CompressedRistretto;

    #[test]
    fn test_serialize_and_deserialize_message() {
        // Create a sample message
        let payload = b"Test message".to_vec();
        let recipient = CompressedRistretto::default(); // Use default recipient for test
        let sender = CompressedRistretto::default(); // Use default sender for test
        let signature = SchnorrSignature::emty_signature(); // Use empty signature for test

        let message = Message::new(1, payload.clone(), sender, recipient, signature);

        // Serialize the message to bytes
        let serialized_bytes =
            serialize_message_to_bytes(&message).expect("Failed to serialize message to bytes");

        // Ensure the serialized bytes are not empty
        assert!(
            !serialized_bytes.is_empty(),
            "Serialized bytes should not be empty"
        );

        // Deserialize the bytes back into a Message struct
        let deserialized_message = deserialize_message_from_bytes(&serialized_bytes)
            .expect("Failed to deserialize bytes into message");

        // Verify that the original and deserialized messages match
        assert_eq!(message.version, deserialized_message.version);
        assert_eq!(message.payload, deserialized_message.payload);
        assert_eq!(message.recipient, deserialized_message.recipient);
        assert_eq!(message.sender, deserialized_message.sender);
        assert_eq!(message.signature, deserialized_message.signature);

        // Display the deserialized message for visual verification
        deserialized_message.display();
    }
}
