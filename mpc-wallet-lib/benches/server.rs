#[macro_use]
extern crate criterion;

use bigints::traits::Converter;
use bigints::BigInt;
use criterion::{black_box, Criterion};
use mpc_wallet_lib::common::{dh_init_secp256k1, dh_init_secp256r1, Curve};
use mpc_wallet_lib::server::{
    complete_sig, compute_rpool_secp256k1, compute_rpool_secp256r1, generate_paillier_proof,
};
use paillier::{DecryptionKey, MinimalDecryptionKey};

fn criterion_benchmark(c: &mut Criterion) {
    let paillier_sk = DecryptionKey::from(MinimalDecryptionKey{p: BigInt::from_hex("d3542d07cda6034cf8568b68d69f07b716c98dcc466d7fb89d2a40db4addfe1402ac6007b609734c80fa4dd24f005cc2d404651f724561391fd2c714c054c5ecb98c0d367d5d99cddbd788489151daa247feef546ba173db02576793f2386c89a78e1cf0b1b5e3882efb709663c8fb50f3b973e87447bc0a473b792eeb9720ef").unwrap(), q: BigInt::from_hex("bf9f1abdcfd5f3e30a609ad469637eeadf068f67735c319cd0bfe3cb7ed915d93c33c77078762c3deab68fd66a46903a3241f84ccf827ac27faa339d12f4cf818732220b2a899660765a8554d8bc6490bc7490b7874fe1651dccd25b74bcdb5481e1d09bfe3ec6143c2f9bb2cf3658d514fc8c1e48a8e095b8a0f9fe94891f67").unwrap()});
    c.bench_function("generate_paillier_proof", |b| {
        b.iter(|| {
            generate_paillier_proof(black_box(&paillier_sk));
        })
    });

    let (dh_secrets_k1, dh_publics_k1) = dh_init_secp256k1(10).unwrap();
    c.bench_function("compute_rpool_secp256k1", |b| {
        b.iter(|| {
            compute_rpool_secp256k1(black_box(&dh_secrets_k1), black_box(&dh_publics_k1)).unwrap();
        })
    });

    let (dh_secrets_r1, dh_publics_r1) = dh_init_secp256r1(10).unwrap();
    c.bench_function("compute_rpool_secp256r1", |b| {
        b.iter(|| {
            compute_rpool_secp256r1(black_box(&dh_secrets_r1), black_box(&dh_publics_r1)).unwrap();
        })
    });

    let presig_k1 = BigInt::from_hex("5a955a53b4598601890b70d1c0cba4e4bcf446623cfe529e7e52451932125f880b4139683434ff25f589e7f09441499e97a29227d8fbb484f2be4e9c602f92d411193c7b1c016290524cdbdf94f260959c1d9aacba3955d66ee759335738099902f68201a3a919358f4a2a99b1e61d63a839ad75d681e62b5258f18a4415f40709c8faac80082340cd2b96a8210eb5b1a31f9b0e498a01d985131923ce0b3ac2e874ba1089782db6c667a90c4fb1f5d1b98e133196e533efe8ad2d025806498921d1f89007e6cf013d1ed7683c41d4b07f6b3ff293b9a783043051ef1eaa0d195e706321c2ea6349d61dbf8e053dbe76e8f65d44c96c8b8ede0e69d0bba00def739123e5e5e2adb640d603defd1aa8204df00d0db82155e687e8127e9fcdbfabd2449fb48e11f85903ac9d08b32296085d114e024e677b6ec507fbaad262f4646248e0222588627fda9e20087eec30b1d94cffe9a254678821f7515afd89f5db7801886355cd3bb07493fff73bbf2256dab6b4f79dcbb4ed14adc0a731e2ce781b77728356e62277ce21fe1f4f4190a4b56499738f02bb65df7c71ed9e47fc81e2a23ee8686e921d47e11f3dc3f26eb35faffc41a9e870ab43474d4dfe0a0c1db1ec65837ee7babad54bbbb05b6648aa336f7749a8e0677415d3491431ed58ad922c71cb18c3683a0480eca1e39414ce200d6799d4f17332d647dd7f69c53637").unwrap();
    let r_k1 =
        BigInt::from_hex("02ec71e402771be8e826da22beb05f4eb0a3fb9eefcd06ebd0cb03010c942845ed")
            .unwrap();
    let k_k1 = BigInt::from_hex("b95d4e79d09b35bdfc863cdeb8bbfd85d557546e75fe2582961fbe0497525f6e")
        .unwrap();
    c.bench_function("complete_sig_k1", |b| {
        b.iter(|| {
            complete_sig(
                black_box(&paillier_sk),
                black_box(&presig_k1),
                black_box(&r_k1),
                black_box(&k_k1),
                black_box(Curve::Secp256k1),
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
