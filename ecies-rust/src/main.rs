extern crate bitcoin_hashes;
extern crate secp256k1;

use bitcoin_hashes::{sha256, Hash};
use secp256k1::{Error, Message, PublicKey, Secp256k1, SecretKey, Signature, Signing, Verification};
use ecies::{decrypt, encrypt, utils::generate_keypair};

fn verify<C: Verification>(secp: &Secp256k1<C>, msg: &[u8], sig: [u8; 64], pubkey: [u8; 33]) -> Result<bool, Error> {
    let msg = sha256::Hash::hash(msg);
    let msg = Message::from_slice(&msg)?;
    let sig = Signature::from_compact(&sig)?;
    let pubkey = PublicKey::from_slice(&pubkey)?;

    Ok(secp.verify(&msg, &sig, &pubkey).is_ok())
}

fn sign<C: Signing>(secp: &Secp256k1<C>, msg: &[u8], seckey: [u8; 32]) -> Result<Signature, Error> {
    let msg = sha256::Hash::hash(msg);
    let msg = Message::from_slice(&msg)?;
    let seckey = SecretKey::from_slice(&seckey)?;
    Ok(secp.sign(&msg, &seckey))
}

fn main() {
    const MSG: &str = "helloworld";
    let msg = MSG.as_bytes();

    // gen key pair
    let (sk, pk) = generate_keypair();
    let (sk, pk) = (&sk.serialize(), &pk.serialize_compressed());

    // ecies
    assert_eq!(
        msg,
        decrypt(sk, &encrypt(pk, msg).unwrap()).unwrap().as_slice()
    );

    // ecdsa
    let secp = Secp256k1::new();
    let signature = sign(&secp, msg, *sk).unwrap();
    let serialize_sig = signature.serialize_compact();
    assert!(verify(&secp, msg, serialize_sig, *pk).unwrap());

    println!("Hello, world!");
}
