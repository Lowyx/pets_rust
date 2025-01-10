use base64::prelude::*;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use std::fs::{self,File};
use std::io::Write;
use std::io::{self, Read};
use std::path::Path;

/// Struct to hold public and private key pair
#[derive(Debug)]
pub struct KeyPair {
    pub private_key: Scalar,
    pub public_key: RistrettoPoint,
}

impl KeyPair {
    /// Generate a Schnorr signature key pair
    pub fn generate() -> KeyPair {
        let private_key = Scalar::random(&mut OsRng);
        let public_key = private_key * RISTRETTO_BASEPOINT_POINT;
        KeyPair {
            private_key,
            public_key,
        }
    }

    /// Write the keypair to a file
    pub fn write_to_file(&self, keypair_path: &str) -> Result<(),io::Error> {
        let path = Path::new(keypair_path);
        let private_key_encoded = BASE64_STANDARD.encode(self.private_key.to_bytes());
        let public_key_encoded =
            BASE64_STANDARD.encode(self.public_key.compress().to_bytes());

        let mut file = File::create(path)?;
        writeln!(file, "{}\n{}", private_key_encoded, public_key_encoded)?;
        Ok(())
    }

    /// Write the private key to a file
    pub fn write_sk_to_file(&self, sk_path: &str) -> Result<(),io::Error> {
        let path = Path::new(sk_path);
        let private_key_encoded = BASE64_STANDARD.encode(self.private_key.to_bytes());
        let mut file = File::create(path)?;
        writeln!(file, "{}", private_key_encoded)?;
        Ok(())
    }

    /// Write the public key to a file
    pub fn write_pk_to_file(&self, pk_path: &str) -> Result<(),io::Error> {
        let path = Path::new(pk_path);
        let public_key_encoded =
            BASE64_STANDARD.encode(self.public_key.compress().to_bytes());
        let mut file = File::create(path)?;
        writeln!(file, "{}", public_key_encoded)?;
        Ok(())
    }

    /// Read a keypair from a file
    pub fn from_file(keypair_path: &str) -> Result<KeyPair,io::Error> {
        let path = Path::new(keypair_path);
        let content = fs::read_to_string(path)?;
        let mut lines = content.lines();
        
        let private_key_encoded = lines.next().ok_or(io::Error::new(
            io::ErrorKind::InvalidData,
            "File does not contain a private key",
        ))?;
        // let public_key_encoded = lines.next().ok_or(io::Error::new(
        //     io::ErrorKind::InvalidData,
        //     "File does not contain a public key",
        // ))?;

        let private_key_bytes = BASE64_STANDARD
            .decode(private_key_encoded)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid private key"))?;
        // let public_key_bytes = BASE64_STANDARD
        //     .decode(public_key_encoded)
        //     .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid public key"))?;

        let private_key = Scalar::from_canonical_bytes(private_key_bytes.as_slice().try_into().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid private key size"))?)
            .unwrap();
        let public_key = private_key * RISTRETTO_BASEPOINT_POINT;

        // let public_key_compressed =
        //     CompressedRistretto::from_slice(&public_key_bytes);
        // let public_key = public_key_compressed
        //     .unwrap()
        //     .decompress()
        //     .ok_or(io::Error::new(io::ErrorKind::InvalidData, "Invalid public key"))?;

        Ok(KeyPair {
            private_key,
            public_key,
        })
    }

    /// Read a public key from a file
    pub fn pk_from_file(pk_path: &str) -> Result<RistrettoPoint,io::Error> {
        let path = Path::new(pk_path);
        let content = fs::read_to_string(path)?;
        let public_key_encoded = content.trim();

        let public_key_bytes = BASE64_STANDARD
            .decode(public_key_encoded)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid public key"))?;

        let public_key_compressed =
            CompressedRistretto::from_slice(&public_key_bytes);
        
        Ok(public_key_compressed
            .unwrap()
            .decompress()
            .ok_or(io::Error::new(io::ErrorKind::InvalidData, "Invalid public key"))?)
    }

    /// Read a private key from a file
    pub fn sk_from_file(sk_path: &str) -> Result<Scalar,io::Error> {
        let path = Path::new(sk_path);
        let content = fs::read_to_string(path)?;
        let private_key_encoded = content.trim();

        let private_key_bytes = BASE64_STANDARD
            .decode(private_key_encoded)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid private key"))?;

        Ok(Scalar::from_canonical_bytes(private_key_bytes.as_slice().try_into().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid private key size"))?)
            .unwrap())
    }

}

// Unit tests for keys module
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_generate_keypair() {
        let keypair = KeyPair::generate();
        assert!(
            keypair.public_key != RistrettoPoint::default(),
            "Public key should not be default"
        );
        assert!(
            keypair.private_key != Scalar::default(),
            "Private key should not be default"
        );
        assert!(
            keypair.private_key * &RISTRETTO_BASEPOINT_POINT == keypair.public_key,
            "Public key should be g^private_key"
        )
    }

    #[test]
    fn test_write_and_read_keypair() {
        let keypair = KeyPair::generate();
        let pk_filepath = "pk_test.txt";
        let sk_filepath = "sk_test.txt";

        // Write the keypair to a file
        keypair
            .write_sk_to_file(&sk_filepath)
            .expect("Failed to write sk to file");
        keypair
            .write_pk_to_file(&pk_filepath)
            .expect("Failed to write pk to file");

        // Read the keypair back from the file
        let read_keypair =
            KeyPair::from_file(&sk_filepath).expect("Failed to read keypair from file");

        let read_pk = KeyPair::pk_from_file(&pk_filepath).expect("Failed to read pk from file");

        // Check if the written and read key pairs are equal
        assert_eq!(
            keypair.private_key, read_keypair.private_key,
            "Private keys should match"
        );
        assert_eq!(
            keypair.public_key, read_keypair.public_key,
            "Public keys should match"
        );
        assert_eq!(keypair.public_key, read_pk, "Public keys should match");

        // Clean up the test file
        fs::remove_file(&sk_filepath).expect("Failed to remove sk test file");
        fs::remove_file(&pk_filepath).expect("Failed to remove pk test file");
    }
}
