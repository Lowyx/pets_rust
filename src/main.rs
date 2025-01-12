mod aes;
mod elgamal;
mod hybrid_enc;
mod keys;
mod message;
mod schnorr;
mod serializers;
//mod tests;

use keys::KeyPair;
use hybrid_enc::HybridCiphertext;
use message::Message;
use schnorr::SchnorrSignature;

fn main() {
    /*** Test with the provided public key and signing key from Challenge 7 guidelines ***/
    println!("[Test keygen, encryption and decryption with abitrarily generated keys]");

    // Load the encryption key from challenge 7 guidelines
    let chall7_encryption_key =
        KeyPair::pk_from_file("encryption_key.txt").expect("Failed to load the encryption key");

    // Load the signing key from challenge 7 guidelines
    let chall7_signing_key =
        KeyPair::sk_from_file("signing_key.txt").expect("Failed to load the signing key");

    // Create a new message
    let mut chall7_message = Message::new(
        0,
        b"Group ID: 47".to_vec(),
        chall7_encryption_key.compress(),
        chall7_encryption_key.compress(),
        schnorr::SchnorrSignature::emty_signature(),
    );

    // Encrypt the message
    chall7_message
        .encrypt(&chall7_encryption_key)
        .expect("Failed to encrypt the message");

    // Sign the message
    chall7_message.sign(&chall7_signing_key);

    // Write the signed and encrypted message to file
    let _ = chall7_message.to_file("signed_encrypted_message.json");



    /*** Test keygen, encryption and decryption with abitrarily generated keys ***/

    /* Key generation */
    // Generate an ecryption KeyPair
    let encryption_keypair = HybridCiphertext::keygen();
    encryption_keypair
        .write_pk_to_file("public_key_test.txt")
        .expect("Failed to write the public key to file");
    encryption_keypair
        .write_sk_to_file("secret_key_test.txt")
        .expect("Failed to write the private key to file");

    // Generate a signing KeyPair
    let signing_keypair = SchnorrSignature::keygen(); // use a different keypair for signing !!
    signing_keypair
        .write_pk_to_file("verification_key_test.txt")
        .expect("Failed to write the verification key to file");
    signing_keypair
        .write_sk_to_file("signing_key_test.txt")
        .expect("Failed to write the signing key to file");


    /* Message encryption */
    // Load a pre-existing encryption public key
    let encryption_key =
        KeyPair::pk_from_file("public_key_test.txt").expect("Failed to load the encryption key");

    // Load a pre-existing signing key
    let signing_key =
        KeyPair::sk_from_file("signing_key_test.txt").expect("Failed to load the signing key");

    // Load a pre-existing verification key
    let verification_key = KeyPair::pk_from_file("verification_key_test.txt")
        .expect("Failed to load the verification key");

    // Create a new message
    let mut message = Message::new(
        0,
        b"Group ID: 47".to_vec(),
        encryption_key.compress(),
        verification_key.compress(),
        schnorr::SchnorrSignature::emty_signature(),
    );

    println!(
        "Unencrypted message: {:?}",
        String::from_utf8(message.payload.clone()).unwrap()
    );

    // Encrypt the message
    message
        .encrypt(&encryption_key)
        .expect("Failed to encrypt the message");

    // Sign the message
    message.sign(&signing_key);

    // Write the encrypted and signed message to file
    let _ = message.to_file("signed_encrypted_message_test.json");


    /* Message decryption */
    // Load the pre-existing encryption private key associated with the public key used to encrypt the messa
    let decryption_key =
        KeyPair::sk_from_file("secret_key_test.txt").expect("Failed to load the decryption key");

    // Load the message from file
    let mut read_message = Message::from_file("signed_encrypted_message_test.json")
        .expect("Failed to load the message");

    // Verify the signature first (because we did encryption-then-sign, so we now need to verify-then-decrypt)
    let signature_verification = read_message.verify();

    // Decrypt the message
    read_message
        .decrypt(&decryption_key)
        .expect("Failed to decrypt the message");

    println!(
        "Decrypted message: {:?}",
        String::from_utf8(read_message.payload.clone()).unwrap()
    );

    if signature_verification {
        println!("Signature verification succeeded");
        // Write the verified decrypted message to file
        read_message
            .to_file("verified_decrypted_message_test.json")
            .expect("Failed to write the verified decrypted message to file");
    } else {
        println!("Signature verification failed");
    }
}
