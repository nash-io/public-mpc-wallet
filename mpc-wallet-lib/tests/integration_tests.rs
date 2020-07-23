use bigints::traits::Converter;
use bigints::BigInt;
use mpc_wallet_lib::client::{
    compute_presig, fill_rpool_secp256k1, fill_rpool_secp256r1, APIchildkeyCreator,
};
use mpc_wallet_lib::common::{
    dh_init_secp256k1, dh_init_secp256r1, publickey_from_secretkey, verify, Curve,
};
use mpc_wallet_lib::curves::traits::ECScalar;
use mpc_wallet_lib::server::{
    complete_sig, compute_rpool_secp256k1, compute_rpool_secp256r1, generate_paillier_keypair,
    generate_paillier_proof,
};

#[test]
fn test_integration_k1() {
    let secret_key =
        BigInt::from_hex("4794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1")
            .unwrap();
    let mut api_childkey_creator = APIchildkeyCreator::init(&secret_key);
    let (paillier_pk, paillier_sk) = generate_paillier_keypair();
    let correct_key_proof = generate_paillier_proof(&paillier_sk);
    api_childkey_creator = api_childkey_creator
        .verify_paillier(&paillier_pk, &correct_key_proof)
        .unwrap();
    let api_childkey = api_childkey_creator
        .create_api_childkey(Curve::Secp256k1)
        .unwrap();
    let msg_hash =
        BigInt::from_hex("000000000000000fffffffffffffffffff00000000000000ffffffffff000000")
            .unwrap();
    let (client_dh_secrets, client_dh_publics) = dh_init_secp256k1(1).unwrap();
    let (server_dh_secrets, server_dh_publics) = dh_init_secp256k1(1).unwrap();
    fill_rpool_secp256k1(client_dh_secrets, &server_dh_publics, &paillier_pk).unwrap();
    let rpool = compute_rpool_secp256k1(&server_dh_secrets, &client_dh_publics).unwrap();
    let (presig, r) = compute_presig(&api_childkey, &msg_hash, Curve::Secp256k1).unwrap();
    let k = rpool
        .get(&format!("{:0>66}", r.to_hex()))
        .unwrap()
        .to_big_int();
    let (_, s, _) = complete_sig(&paillier_sk, &presig, &r, &k, Curve::Secp256k1).unwrap();
    verify(
        &r,
        &s,
        &publickey_from_secretkey(&secret_key, Curve::Secp256k1).unwrap(),
        &msg_hash,
        Curve::Secp256k1,
    )
    .unwrap();
}

#[test]
fn test_integration_r1() {
    let secret_key =
        BigInt::from_hex("4794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1")
            .unwrap();
    let mut api_childkey_creator = APIchildkeyCreator::init(&secret_key);
    let (paillier_pk, paillier_sk) = generate_paillier_keypair();
    let correct_key_proof = generate_paillier_proof(&paillier_sk);
    api_childkey_creator = api_childkey_creator
        .verify_paillier(&paillier_pk, &correct_key_proof)
        .unwrap();
    let api_childkey = api_childkey_creator
        .create_api_childkey(Curve::Secp256r1)
        .unwrap();
    let msg_hash =
        BigInt::from_hex("000000000000000fffffffffffffffffff00000000000000ffffffffff000000")
            .unwrap();
    let (client_dh_secrets, client_dh_publics) = dh_init_secp256r1(1).unwrap();
    let (server_dh_secrets, server_dh_publics) = dh_init_secp256r1(1).unwrap();
    fill_rpool_secp256r1(client_dh_secrets, &server_dh_publics, &paillier_pk).unwrap();
    let rpool = compute_rpool_secp256r1(&server_dh_secrets, &client_dh_publics).unwrap();
    let (presig, r) = compute_presig(&api_childkey, &msg_hash, Curve::Secp256r1).unwrap();
    let k = rpool
        .get(&format!("{:0>66}", r.to_hex()))
        .unwrap()
        .to_big_int();
    let (_, s, _) = complete_sig(&paillier_sk, &presig, &r, &k, Curve::Secp256r1).unwrap();
    verify(
        &r,
        &s,
        &publickey_from_secretkey(&secret_key, Curve::Secp256r1).unwrap(),
        &msg_hash,
        Curve::Secp256r1,
    )
    .unwrap();
}
