#[macro_use]
extern crate criterion;

use bigints::traits::Converter;
use bigints::BigInt;
use criterion::{black_box, Criterion};
use mpc_wallet_lib::common::{
    dh_init_secp256k1, dh_init_secp256r1, publickey_from_secretkey, verify, Curve,
};

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("dh_init_secp256k1", |b| {
        b.iter(|| {
            dh_init_secp256k1(black_box(10)).unwrap();
        })
    });

    c.bench_function("dh_init_secp256r1", |b| {
        b.iter(|| {
            dh_init_secp256r1(black_box(10)).unwrap();
        })
    });

    let secret_key =
        BigInt::from_hex("4794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1")
            .unwrap();
    c.bench_function("publickey_from_secretkey_k1", |b| {
        b.iter(|| {
            publickey_from_secretkey(black_box(&secret_key), black_box(Curve::Secp256k1)).unwrap();
        })
    });
    c.bench_function("publickey_from_secretkey_r1", |b| {
        b.iter(|| {
            publickey_from_secretkey(black_box(&secret_key), black_box(Curve::Secp256r1)).unwrap();
        })
    });

    let r_k1 = BigInt::from_hex("cd5645ad8d2c0a1e3107210b98b7b4ad8b293375fd82c1c8dc2d4e761ae434e4")
        .unwrap();
    let s_k1 = BigInt::from_hex("1ae625af09f673a9e0596801c63a1d9a553b2e3557798da3882505f380edad13")
        .unwrap();
    let pk_k1 = publickey_from_secretkey(&secret_key, Curve::Secp256k1).unwrap();
    let msg_hash =
        BigInt::from_hex("000000000000000fffffffffffffffffff00000000000000ffffffffff000000")
            .unwrap();
    c.bench_function("verify_k1", |b| {
        b.iter(|| {
            verify(
                black_box(&r_k1),
                black_box(&s_k1),
                black_box(&pk_k1),
                black_box(&msg_hash),
                black_box(Curve::Secp256k1),
            )
            .unwrap();
        })
    });

    let r_r1 = BigInt::from_hex("fbbd391e96101516dcb893e9c35a208e1f9028ebb43398aaa3669c96f9f97d69")
        .unwrap();
    let s_r1 = BigInt::from_hex("251104f967580ac98c890ffbaa718366f5a2df39255cd5bf31ee3367f475b5d7")
        .unwrap();
    let pk_r1 = publickey_from_secretkey(&secret_key, Curve::Secp256r1).unwrap();
    c.bench_function("verify_r1", |b| {
        b.iter(|| {
            verify(
                black_box(&r_r1),
                black_box(&s_r1),
                black_box(&pk_r1),
                black_box(&msg_hash),
                black_box(Curve::Secp256r1),
            )
            .unwrap();
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = criterion_benchmark
}

criterion_main!(benches);
