use ursa::cl::{
    *,
    issuer::Issuer,
    prover::Prover,
    verifier::Verifier,
};
use ursa::bn::BigNumber;
use ursa::signatures::{
    SignatureScheme,
    ed25519::Ed25519Sha512,
    secp256k1::EcdsaSecp256k1Sha256
};
use ursa::bls::*;

use sha2::Digest;

fn main() {
    //Example of using the Camenisch-Lysyanskaya signature and ZKPs

    let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    credential_schema_builder.add_attr("name").unwrap();
    credential_schema_builder.add_attr("gender").unwrap();
    credential_schema_builder.add_attr("age").unwrap();
    credential_schema_builder.add_attr("height").unwrap();
    let credential_schema = credential_schema_builder.finalize().unwrap();

    let mut non_credential_schema_builder = NonCredentialSchemaBuilder::new().unwrap();
    non_credential_schema_builder.add_attr("link_secret").unwrap();
    let non_credential_schema = non_credential_schema_builder.finalize().unwrap();

    println!("Creating Issuer keys");
    let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) =
            Issuer::new_credential_def(&credential_schema, &non_credential_schema, true).unwrap();

    let master_secret = Prover::new_master_secret().unwrap();
    let credential_nonce = new_nonce().unwrap();

    let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
    let name_att = BigNumber::from_bytes(sha2::Sha256::digest(b"example_name").to_vec().as_slice()).unwrap();
    let gender_att = BigNumber::from_bytes(sha2::Sha256::digest(b"unknown").to_vec().as_slice()).unwrap();


    credential_values_builder.add_value_hidden("link_secret", &master_secret.value().unwrap()).unwrap();
    credential_values_builder.add_value_known("name", &name_att).unwrap();
    credential_values_builder.add_value_known("gender", &gender_att).unwrap();
    credential_values_builder.add_dec_known("age", "28").unwrap();
    credential_values_builder.add_dec_known("height", "175").unwrap();
    let cred_values = credential_values_builder.finalize().unwrap();

    println!("Blinding link secret");
    let (blinded_credential_secrets,
         credential_secrets_blinding_factors,
         blinded_credential_secrets_correctness_proof,
        ) = Prover::blind_credential_secrets(
            &cred_pub_key,
            &cred_key_correctness_proof,
            &cred_values,
            &credential_nonce,
        ).unwrap();

    let cred_issuance_nonce = new_nonce().unwrap();

    println!("Signing the credential");
    let (mut cred_signature, signature_correctness_proof) = Issuer::sign_credential(
        "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
        &blinded_credential_secrets,
        &blinded_credential_secrets_correctness_proof,
        &credential_nonce,
        &cred_issuance_nonce,
        &cred_values,
        &cred_pub_key,
        &cred_priv_key,
    ).unwrap();

    println!("Unblinding the signature");
    Prover::process_credential_signature(
            &mut cred_signature,
            &cred_values,
            &signature_correctness_proof,
            &credential_secrets_blinding_factors,
            &cred_pub_key,
            &cred_issuance_nonce,
            None,
            None,
            None,
        ).unwrap();

    println!("Create a proof that example_name is over 18");
    let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        sub_proof_request_builder.add_revealed_attr("name").unwrap();
        sub_proof_request_builder
            .add_predicate("age", "GE", 18)
            .unwrap();
    let sub_proof_request = sub_proof_request_builder.finalize().unwrap();
    let mut proof_builder = Prover::new_proof_builder().unwrap();
    proof_builder.add_common_attribute("master_secret").unwrap();
    proof_builder
        .add_sub_proof_request(
            &sub_proof_request,
            &credential_schema,
            &non_credential_schema,
            &cred_signature,
            &cred_values,
            &cred_pub_key,
            None,
            None,
        ).unwrap();

    let proof_request_nonce = new_nonce().unwrap();
    let proof = proof_builder.finalize(&proof_request_nonce).unwrap();

    let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
    proof_verifier
        .add_sub_proof_request(
            &sub_proof_request,
            &credential_schema,
            &non_credential_schema,
            &cred_pub_key,
            None,
            None,
        ).unwrap();
    let is_valid = proof_verifier.verify(&proof, &proof_request_nonce).unwrap();
    println!("example_name >= 18: {}", is_valid);

    //Example of BLS Signature

    println!("Demoing BLS signature");
    let generator = Generator::new().unwrap();
    let sign_key = SignKey::new(None).unwrap();
    let ver_key  = VerKey::new(&generator, &sign_key).unwrap();

    println!("generator = {:?}", generator);
    println!("sign_key  = {:?}", sign_key);
    println!("ver_key   = {:?}", ver_key);
    let message = sha2::Sha256::digest(b"This is a test").to_vec();
    let signature = Bls::sign(message.as_slice(), &sign_key).unwrap();

    println!("signature = {:?}", signature);
    println!("valid_sig = {}", Bls::verify(&signature, message.as_slice(), &ver_key, &generator).unwrap());

    println!("Demoing Ed25519 signature");
    let scheme = Ed25519Sha512::new();
    let (public, private) = scheme.keypair(None).unwrap();
    let signature = scheme.sign(message.as_slice(), &private).unwrap();
    let res = scheme.verify(message.as_slice(), signature.as_slice(), &public).unwrap();
    println!("verify = {}", res);

    println!("Demoing BitCoin Curve signature");
    let scheme = EcdsaSecp256k1Sha256::new();
    let (public, private) = scheme.keypair(None).unwrap();
    let signature = scheme.sign(message.as_slice(), &private).unwrap();
    let res = scheme.verify(message.as_slice(), signature.as_slice(), &public).unwrap();
    println!("verify = {}", res);
}
