mod aes;
mod elgamal;
mod hybrid_enc;
mod keys;
mod message;
mod schnorr;
mod serializers;
//mod tests;

use elgamal::ElGamalCiphertext;
use keys::KeyPair;
use message::Message;
use schnorr::SchnorrSignature;

fn main() {
    /* Key generation */
    // Generate an ecryption KeyPair
    let encryption_keypair = ElGamalCiphertext::keygen();
    encryption_keypair.write_pk_to_file("public_key_test.txt").expect("Failed to write the public key to file");
    encryption_keypair.write_sk_to_file("secret_key_test.txt").expect("Failed to write the private key to file");

    // Generate a signing KeyPair
    let signing_keypair = SchnorrSignature::keygen(); // use a different keypair for signing !!
    signing_keypair.write_pk_to_file("verification_key_test.txt").expect("Failed to write the verification key to file");
    signing_keypair.write_sk_to_file("signing_key_test.txt").expect("Failed to write the signing key to file");


    /* Message encryption */ 
    // Load a pre-existing encryption public key
    //let encryption_key = KeyPair::pk_from_file("encryption_key.txt").expect("Failed to load the encryption key");
    let encryption_key = KeyPair::pk_from_file("public_key_test.txt").expect("Failed to load the encryption key");

    // Load a pre-existing signing key
    //let signing_key = KeyPair::sk_from_file("signing_key.txt").expect("Failed to load the signing key");
    let signing_key = KeyPair::sk_from_file("signing_key_test.txt").expect("Failed to load the signing key");

    // Load a pre-existing verification key
    //let verification_key = KeyPair::pk_from_file("verification_key.txt").expect("Failed to load the verification key");
    let verification_key = KeyPair::pk_from_file("verification_key_test.txt").expect("Failed to load the verification key");

    // Create a new message
    let mut message = Message::new(
        0,
        b"Group ID: 47".to_vec(),
        encryption_key.compress(),
        verification_key.compress(), // really ? 
        schnorr::SchnorrSignature::emty_signature(),
    );
    
    // Encrypt the message
    message.encrypt(&encryption_key).expect("Failed to encrypt the message");

    // Sign the message
    //message.sign(&signing_key);

    let _ = message.to_file("signed_encrypted_message.json");


    /* Message decryption */
    // Load the pre-existing encryption private key associated with the public key used to encrypt the messa
    //let decryption_key = KeyPair::sk_from_file("decryption_key.txt").expect("Failed to load the decryption key");
    let decryption_key = KeyPair::sk_from_file("secret_key_test.txt").expect("Failed to load the decryption key");
    
    // Load the message from file
    //let mut read_message = Message::from_file("signed_encrypted_message.json").expect("Failed to load the message");

    // Decrypt the message
    //read_message.decrypt(&decryption_key).expect("Failed to decrypt the message");
    message.decrypt(&decryption_key).expect("Failed to decrypt the message");

    // Verify the signature
    //let verified = read_message.verify();
    let verified = true;

    if verified {
        println!("Signature verification succeeded");
        //read_message.to_file("verified_decrypted_message.json").expect("Failed to write the verified decrypted message to file");
        message.to_file("verified_decrypted_message.json").expect("Failed to write the verified decrypted message to file");
    } else {
        println!("Signature verification failed");
    }
}
