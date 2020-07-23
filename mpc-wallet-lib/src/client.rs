/*
 * Client functions for MPC-based API keys
 */

use crate::common::{
    correct_key_proof_rho, publickey_from_secretkey, CorrectKeyProof, Curve, CORRECT_KEY_M,
};
use crate::curves::secp256_k1::{Secp256k1Point, Secp256k1Scalar};
use crate::curves::secp256_r1::{Secp256r1Point, Secp256r1Scalar};
use crate::curves::traits::{ECPoint, ECScalar};
use bigints::traits::{Converter, Modulo, Samplable, ZeroizeBN};
use bigints::BigInt;
use chrono::prelude::{DateTime, Utc};
use chrono::Duration;
use indexmap::{IndexMap, IndexSet};
use lazy_static::__Deref;
#[cfg(feature = "num_bigint")]
use num_integer::Integer;
#[cfg(feature = "num_bigint")]
use num_traits::identities::{One, Zero};
use paillier::traits::{EncryptWithChosenRandomness, PrecomputeRandomness};
use paillier::{
    Add, EncryptionKey, Mul, Paillier, PrecomputedRandomness, Randomness, RawCiphertext,
    RawPlaintext,
};
#[cfg(not(feature = "wasm"))]
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use zeroize::Zeroize;
use zeroize::Zeroizing;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct APIchildkeyCreator {
    #[serde(with = "bigints::serialize::bigint")]
    secret_key: BigInt,
    paillier_pk: Option<EncryptionKey>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct APIchildkey {
    pub paillier_pk: EncryptionKey,
    pub public_key: String,
    #[serde(with = "bigints::serialize::bigint")]
    pub client_secret_share: BigInt,
    #[serde(with = "bigints::serialize::bigint")]
    pub server_secret_share_encrypted: BigInt,
}

impl APIchildkeyCreator {
    /// initialize api key creation by setting the full secret key
    pub fn init(secret_key: &BigInt) -> APIchildkeyCreator {
        APIchildkeyCreator {
            secret_key: secret_key.clone(),
            paillier_pk: None,
        }
    }
    /// initialize api key creation by setting the full secret key and the paillier public key.
    /// paillier public key must have been verified for correctness by the client!
    pub fn init_with_verified_paillier(
        secret_key: &BigInt,
        paillier_pk: &EncryptionKey,
    ) -> APIchildkeyCreator {
        APIchildkeyCreator {
            secret_key: secret_key.clone(),
            paillier_pk: Some(paillier_pk.clone()),
        }
    }
    /// verify that the paillier public key was generated correctly
    pub fn verify_paillier(
        self,
        paillier_pk: &EncryptionKey,
        correct_key_proof: &CorrectKeyProof,
    ) -> Result<APIchildkeyCreator, ()> {
        verify_correct_key_proof(correct_key_proof, &paillier_pk.n)?;
        Ok(APIchildkeyCreator {
            secret_key: self.secret_key,
            paillier_pk: Some(paillier_pk.clone()),
        })
    }
    /// create api childkey, i.e., both secret shares, paillier pk, and public key
    /// client can do this iff:
    ///        - the client knows the full secret key, and
    ///        - the client is trusted, and
    ///        - we don't allow rekeying.
    /// we do this to facilitate fast api childkey creation (as we can skip the range proof entirely).
    pub fn create_api_childkey(self, curve: Curve) -> Result<APIchildkey, ()> {
        match self.paillier_pk.clone() {
            Some(val) => val,
            None => return Err(()),
        };
        if curve == Curve::Secp256k1 {
            let random = Zeroizing::<Secp256k1Scalar>::new(Secp256k1Scalar::new_random());
            // client's secret share is set to the full secret key
            let secret_key = Zeroizing::<Secp256k1Scalar>::new(ECScalar::from(&self.secret_key));
            let client_secret_share =
                Zeroizing::<Secp256k1Scalar>::new(random.invert() * secret_key.deref());
            // server's secret share is set to random * 1
            let mut server_secret_share = random.to_big_int();
            let public_key =
                publickey_from_secretkey(&self.secret_key, curve).expect("Invalid curve");
            let server_secret_share_encrypted =
                encrypt_secret_share(&self.paillier_pk.clone().unwrap(), &server_secret_share);
            server_secret_share.zeroize_bn();
            Ok(APIchildkey {
                paillier_pk: self.paillier_pk.unwrap(),
                public_key,
                client_secret_share: client_secret_share.to_big_int(),
                server_secret_share_encrypted,
            })
        } else if curve == Curve::Secp256r1 {
            let random = Zeroizing::<Secp256r1Scalar>::new(Secp256r1Scalar::new_random());
            // client's secret share is set to the full secret key
            let secret_key = Zeroizing::<Secp256r1Scalar>::new(ECScalar::from(&self.secret_key));
            let client_secret_share =
                Zeroizing::<Secp256r1Scalar>::new(random.invert() * secret_key.deref());
            // server's secret share is set to random * 1
            let mut server_secret_share = random.to_big_int();
            let public_key =
                publickey_from_secretkey(&self.secret_key, curve).expect("Invalid curve");
            let server_secret_share_encrypted =
                encrypt_secret_share(&self.paillier_pk.clone().unwrap(), &server_secret_share);
            server_secret_share.zeroize_bn();
            Ok(APIchildkey {
                paillier_pk: self.paillier_pk.unwrap(),
                public_key,
                client_secret_share: client_secret_share.to_big_int(),
                server_secret_share_encrypted,
            })
        } else {
            Err(())
        }
    }
}

/// compute presignature
pub fn compute_presig(
    api_childkey: &APIchildkey,
    msg_hash: &BigInt,
    curve: Curve,
) -> Result<(BigInt, BigInt), ()> {
    let rx: BigInt;
    let q: BigInt;
    let mut k: BigInt;
    let r: BigInt;
    if curve == Curve::Secp256k1 {
        // get and remove random value r and k from rpool
        let mut pool_entry = match RPOOL_SECP256K1.lock().unwrap().pop() {
            Option::Some(val) => val,
            Option::None => return Err(()),
        };
        k = (pool_entry.1).1.clone();
        (pool_entry.1).1.zeroize_bn();
        r = pool_entry.0;
        let r_point = match Secp256k1Point::from_bigint(&r) {
            Ok(v) => v,
            Err(_) => return Err(()),
        };
        q = Secp256k1Scalar::q();
        rx = r_point.x_coor().unwrap().mod_floor(&q);
    } else if curve == Curve::Secp256r1 {
        // get and remove random value r and k from rpool
        let mut pool_entry = match RPOOL_SECP256R1.lock().unwrap().pop() {
            Option::Some(val) => val,
            Option::None => return Err(()),
        };
        k = (pool_entry.1).1.clone();
        (pool_entry.1).1.zeroize_bn();
        r = pool_entry.0;
        let r_point = match Secp256r1Point::from_bigint(&r) {
            Ok(v) => v,
            Err(_) => return Err(()),
        };
        q = Secp256r1Scalar::q();
        rx = r_point.x_coor().unwrap().mod_floor(&q);
    } else {
        return Err(());
    }
    // get and remove random value for Paillier from pool
    let mut rn = match POOL_PAILLIER.lock().unwrap().pop() {
        Option::Some(val) => val,
        Option::None => return Err(()),
    };
    let c3 = compute_presig_curveindependent(api_childkey, msg_hash, &rx, &q, &k, &rn);
    k.zeroize_bn();
    rn.zeroize_bn();
    Ok((c3, r))
}

fn compute_presig_curveindependent(
    api_childkey: &APIchildkey,
    msg_hash: &BigInt,
    rx: &BigInt,
    q: &BigInt,
    k: &BigInt,
    rn: &BigInt,
) -> BigInt {
    let rho = BigInt::sample_below(&q.pow(2u32));
    let mut k_inv = BigInt::mod_inv(k, q);
    let partial_sig = rho * q + BigInt::mod_mul(&k_inv, msg_hash, q);
    let mut rn_ = PrecomputedRandomness(rn.clone());
    let c1 = Paillier::encrypt_with_chosen_randomness(
        &api_childkey.paillier_pk,
        RawPlaintext::from(partial_sig),
        &rn_,
    );
    rn_.0.zeroize_bn();
    let v = BigInt::mod_mul(
        &k_inv,
        &BigInt::mod_mul(&rx, &api_childkey.client_secret_share, &q),
        &q,
    );
    k_inv.zeroize_bn();
    let c2 = Paillier::mul(
        &api_childkey.paillier_pk,
        RawCiphertext::from(&api_childkey.server_secret_share_encrypted),
        RawPlaintext::from(v),
    );
    Paillier::add(&api_childkey.paillier_pk, c2, c1)
        .0
        .into_owned()
}

// two pools of r-values (one for each curve) and one pool of random values for Paillier.
// mutex is essential for security (helps us ensuring that no value is used twice).
lazy_static! {
    static ref RPOOL_SECP256R1: Mutex<IndexMap<BigInt, (DateTime<Utc>, BigInt)>> =
        Mutex::new(IndexMap::new());
    static ref RPOOL_SECP256K1: Mutex<IndexMap<BigInt, (DateTime<Utc>, BigInt)>> =
        Mutex::new(IndexMap::new());
    static ref POOL_PAILLIER: Mutex<IndexSet<BigInt>> = Mutex::new(IndexSet::new());
}

/// fill pool of random values for Paillier
fn fill_pool_paillier(n: usize, paillier_pk: &EncryptionKey) {
    // sequentially for wasm, else parallel
    #[cfg(feature = "wasm")]
    for _ in 0..n {
        let mut randomness =
            Paillier::precompute(paillier_pk, &Randomness::sample(paillier_pk).0).0;
        POOL_PAILLIER.lock().unwrap().insert(randomness.clone());
        randomness.zeroize_bn();
    }
    #[cfg(not(feature = "wasm"))]
    (0..n).into_par_iter().for_each(|_| {
        let mut randomness =
            Paillier::precompute(paillier_pk, &Randomness::sample(paillier_pk).0).0;
        POOL_PAILLIER.lock().unwrap().insert(randomness.clone());
        randomness.zeroize_bn();
    });
}

/// fill pool of random and nonce values for secp256r1 as well as random values for Paillier
pub fn fill_rpool_secp256r1(
    mut own_dh_secrets: Vec<Secp256r1Scalar>,
    other_dh_publics: &[Secp256r1Point],
    paillier_pk: &EncryptionKey,
) -> Result<(), ()> {
    if own_dh_secrets.len() != other_dh_publics.len() {
        return Err(());
    }
    // sequentially for wasm, else parallel
    #[cfg(feature = "wasm")]
    for i in 0..own_dh_secrets.len() {
        let r = other_dh_publics[i]
            .scalar_mul(&own_dh_secrets[i].get_element())
            .bytes_compressed_to_big_int();
        RPOOL_SECP256R1
            .lock()
            .unwrap()
            .insert(r, (Utc::now(), own_dh_secrets[i].to_big_int()));
    }
    #[cfg(not(feature = "wasm"))]
    (0..own_dh_secrets.len()).into_par_iter().for_each(|i| {
        let r = other_dh_publics[i]
            .scalar_mul(&own_dh_secrets[i].get_element())
            .bytes_compressed_to_big_int();
        RPOOL_SECP256R1
            .lock()
            .unwrap()
            .insert(r, (Utc::now(), own_dh_secrets[i].to_big_int()));
    });
    for i in &mut own_dh_secrets {
        i.zeroize();
    }
    fill_pool_paillier(own_dh_secrets.len(), paillier_pk);
    Ok(())
}

/// fill pool of random and nonce values for secp256k1 as well as random values for Paillier
pub fn fill_rpool_secp256k1(
    mut own_dh_secrets: Vec<Secp256k1Scalar>,
    other_dh_publics: &[Secp256k1Point],
    paillier_pk: &EncryptionKey,
) -> Result<(), ()> {
    if own_dh_secrets.len() != other_dh_publics.len() {
        return Err(());
    }
    // sequentially for wasm, else parallel
    #[cfg(feature = "wasm")]
    for i in 0..own_dh_secrets.len() {
        let r = other_dh_publics[i]
            .scalar_mul(&own_dh_secrets[i].get_element())
            .bytes_compressed_to_big_int();
        RPOOL_SECP256K1
            .lock()
            .unwrap()
            .insert(r, (Utc::now(), own_dh_secrets[i].to_big_int()));
    }
    #[cfg(not(feature = "wasm"))]
    (0..own_dh_secrets.len()).into_par_iter().for_each(|i| {
        let r = other_dh_publics[i]
            .scalar_mul(&own_dh_secrets[i].get_element())
            .bytes_compressed_to_big_int();
        RPOOL_SECP256K1
            .lock()
            .unwrap()
            .insert(r, (Utc::now(), own_dh_secrets[i].to_big_int()));
    });
    for i in &mut own_dh_secrets {
        i.zeroize();
    }
    fill_pool_paillier(own_dh_secrets.len(), paillier_pk);
    Ok(())
}

/// get number of r-values in pool
pub fn get_rpool_size(curve: Curve) -> Result<usize, ()> {
    if curve == Curve::Secp256k1 {
        // remove all entries that are older than 48 hours. The server expires values after 72 hours, so 24 hours safety margin should be fine.
        RPOOL_SECP256K1
            .lock()
            .unwrap()
            .retain(|_, v| Utc::now() - v.0 < Duration::hours(48));
        Ok(RPOOL_SECP256K1.lock().unwrap().len())
    } else if curve == Curve::Secp256r1 {
        // remove all entries that are older than 48 hours. The server expires values after 72 hours, so 24 hours safety margin should be fine.
        RPOOL_SECP256R1
            .lock()
            .unwrap()
            .retain(|_, v| Utc::now() - v.0 < Duration::hours(48));
        Ok(RPOOL_SECP256R1.lock().unwrap().len())
    } else {
        Err(())
    }
}

/// encrypt server secret share under paillier public key
pub fn encrypt_secret_share(paillier_pk: &EncryptionKey, server_secret_share: &BigInt) -> BigInt {
    let mut paillier_randomness = Randomness::sample(paillier_pk);
    let server_encrypted_secret_share = Paillier::encrypt_with_chosen_randomness(
        paillier_pk,
        RawPlaintext::from(server_secret_share),
        &paillier_randomness,
    )
    .0
    .into_owned();
    paillier_randomness.0.zeroize_bn();
    server_encrypted_secret_share
}

/// sign() is not needed for MPC but used as a faster replacement for the JS implementation
pub fn sign(secret_key: &Secp256k1Scalar, msg_hash: &BigInt) -> (BigInt, BigInt) {
    secret_key.clone().sign(&msg_hash)
}

/// verify proof of correct paillier key generation
/// see paper "Efficient Noninteractive Certification of RSA Moduli and Beyond" by Goldberg et al. 2019 Section 3.2 and Appendix C.4
fn verify_correct_key_proof(correct_key_proof: &CorrectKeyProof, n: &BigInt) -> Result<(), ()> {
    let sigma = &correct_key_proof.sigma_vec;
    // product of all primes < 6370 (alpha)
    let primorial = BigInt::from_hex("4ddec772c2ee9fb11e7b9ed0e5f6b7de5b83a0f20cfad9f37ec2ad151341ebbe75cb190441855d0d9014efd683716ac93e5e5369e8f72854979e198ba184ad4e7a4ff76b9eff3cd6533e8c5b2c2a5d8bb62ed86d280d2f0fa1666a5454d0e10b5e67c96e809fd3daddab1f77ba6d5dace62a1939d3c729e9f131f84190aa3407d5f02cf23a90a6c50acefbd123c66c5cc78c935883c0cee1435437811496b10a13900f4f59794d67b494c52279e3159330f1d076d623a8b0b59322559d16c68dc6f3d1d377a1668b7f80f945e7407cee358e9a02bb6b983a56e3199156eb40214b098bf3d301bdd132487f1354db3771885772f49fe86f8890668dfb5e5f9b1b677431081875f91cc019461b9cae2825226ae7ffe870658e573401005f331db99eb66ca6c7fa31b6e2838f1a7da59fb7935a619ffab6d0586431993b6a4c32861141d3139015562ea824550e1a26dfcc53085ebd0885742832c4542fc6436591b3f973d6f9cd7235094738734d082ef51af29824940809d660c8d322d4a44fcf43071b8b473d12d36019fee110aa59aaee6ab7426889bfd07073d9ce03476fdbd04cc6479f73500676f2832c6a0a00ad6c832f5309e9803598e41ffb325e6c403f35730887ef0f6e5a91fdc147ce022ef9ab1851550f9ff93115a626b4f9af82c4eabebafe3b52380d0f9f28f2f5961689807934b9e58d1956314334dc71088a6bd907712a38104fd5ad523efcb10d02c76fdb846594e094b3200b3c3956b17d2d555b6375c1c65c3b19fee9f1e8726f9f6f0c4128f2dd4d5fdd7be1261371bc538b2015e4d3d0ce147bcdc0cd561d5fe21a9f0bf91b5804fca0e41d17f5e5bc6d53e94220ebec6816b020306b7dbd9c6320859de0771f89e76c5af81f45aa29086e82148cbbbc6fbe69929288daa640bbb8d01d995e0218b12d70f83b556f0584fb17740a21f12bbd7894790b7d4bbc58f01844c40cb887e6d1817e8254243884a82443fcb9d9c95e3422e2a8b9810c1309d743e8ff2d82de816fea1e13744a40b54da01035e426405cecb4ba960d60ccb2529ae6627f1fe98ce9307eadae3b74f90c57a6a6b0779be0a1fd953a780c46ba19a09a6bdfbb659d42cb7ec1e9917dfbe7da508db6924a0c99acc7b3b40763d7207ebb07f25f21c410726ed1d0a1244346687bbb310a14a6a68edb3843069a987699f9f20a6da72576fa14fbe8f4ed35a6cd8475bed9c70b51a5fd99bbbe1a2ab43df1e51fda1c701e7823db06544545752b927f16fef58b1109ff0c945dfce0a3e7111896eb49b470f37a3326f3a985b00b747bdce7fb5f38812c2973bac4d75218e0fcb1bb8be4ecdf099fb09741e3171ef4ef3ac9f5a05e4fa2baa6b440c99b433ca98afca73b58d9e4088aafc4f95c2277605d172471fd3f745315ef1ab8a17b52b48bad7d28b08081560a6d06fc558c96f3f70694ce26f81a41786b12cfbd79c5e3f99a879ada2d4e79480de14e8b15924777246ef90d210bfec6941a430827d05a0a66b3d6ef95521f114ad7054f369724de2ac44976136285b6f99348cfe802ca6e70470e2d21b3f6645eb6a23b0b98a177201fa3fb87b89312247e").unwrap();
    // check that N is > 0 and not divisable by all the primes < alpha
    if n <= &BigInt::zero() || primorial.gcd(n) != BigInt::one() {
        return Err(());
    }
    // check that sigma indeed consists of m elements
    if sigma.len() != CORRECT_KEY_M {
        return Err(());
    }
    // check that each sigma element is > 0 and that rho_i == sigma_i ^ N mod N
    let rho = correct_key_proof_rho(n);
    for i in 0..sigma.len() {
        if sigma[i] <= BigInt::zero() {
            return Err(());
        }
        if rho[i] != BigInt::mod_pow(&sigma[i], n, n) {
            return Err(());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::client::POOL_PAILLIER;
    use crate::client::{
        compute_presig, encrypt_secret_share, fill_rpool_secp256k1, fill_rpool_secp256r1,
        get_rpool_size, sign, verify_correct_key_proof, APIchildkeyCreator,
    };
    use crate::common::{publickey_from_secretkey, verify, CorrectKeyProof, Curve};
    use crate::curves::secp256_k1::{Secp256k1Point, Secp256k1Scalar};
    use crate::curves::secp256_r1::{Secp256r1Point, Secp256r1Scalar};
    use crate::curves::traits::ECScalar;
    use bigints::traits::Converter;
    use bigints::BigInt;
    use paillier::{EncryptionKey, MinimalEncryptionKey};
    use std::sync::Mutex;

    lazy_static! {
        // mutex is needed to properly test paillier pool
        static ref PAILLIER_POOL_LOCK: Mutex<()> = Mutex::new(());
    }

    #[test]
    fn test_verify_correct_key_proof_ok() {
        let paillier_pk = EncryptionKey::from(MinimalEncryptionKey{n: BigInt::from_hex("9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129").unwrap()});
        let correct_key_proof: CorrectKeyProof = serde_json::from_str(&"{\"sigma_vec\":[\"14f21d17357e5d0d8d2cb3cf6d0b9439323473be7e1f68db541b77450f87a20941640bf8a317d4ea6272b12923449e73ea5598a6197219fb6c7ca416a3552301c9cc5b47580ce35e4c9e37a97ec0bdbe2b48c2db21cde5bcef9fc04c6e767c59c0500929b76f87901e5a4d8adb38097c44ed790a0ae2e9f6985823f1789aa47a8298d02763751b73942bbee79c4544f9bd2b82e405f15d801cb41d4831012f99172ef49fee6ea33599caadcdb89c1eb768e30b11878f37e12d232b624cbe589a7767af46d958632574535893c0337858399aed65638b97bcaddee45e40fe79a5014fcd1e398b19807439f58236373197653a8ea82ab3a84173d5a8d45bcae823\",\"32beda264c7fde6cb41d48ce44e6e93af5ed0e1cb5c7cd29f7fa3cbf72b78b9bc3e5267c4f9a75de40eb95a4bdc73dd1d8a435799daf2365f9377aed3c4524016d2ea58002c66fd0a8bcb8e74bac9923b723bc9f8752f82d9cba8bec4f414f314a40842031427b0bb8cdc514bfb61a5f85a51d8b7a290ccbd1000af937a6a7fd7a6070ba40a6801a2909e11d71a773958195d82f72995e69b989ab91207b68ac891e6585848f7aea80e1a0693427a0a512c0cbfbfe5d9ffe02462856ca918af9ebd2ad2f9b44a84b628ec7a7ed4d7232e72c52f2af5ef8988e3c09715fbe1a0af871109028335fb95370ae3e7ecf646063c1914ceeff8cf22ca06d250f02904c\",\"27236e62e810849d58c24b57d2061be4223a175224a89b94ce1261ae9f7a61ec058a43589c83aa3029e61c488fa33b0ea8fb72c36f4b3f962f858f4b0dd822a2810124cba42c8c2a42046b324a3c0712799979be7da1e6dff82c466149484246769f43683231ba8a89185587086cef1de589a4d59b74ac20fcbe0310403f9347417a4c8a8b90b78671d265471fe5ca839e509d4b6f5c2ec33ae255abf54aa12700772a174074048bc4edecc142c268b765f8bf4c0ab7b253882f77c1cb0e410e8e21a23ba364ec37adee59e0395920ab403ab77f095ed8bda39fad9b00886c9e2682a8314bd71fc2db9d2b2a8476ac295c262ba16d4657c62af9bb6a4729c214\",\"974e6e3a63e90275733cbf0b1516d940f0b0c8bd6140f16abb22988289b88b327c5a3e2a1de6d00f03e6f78ee934da02590ee45c6b4c0c8f53ccf6adc35cd0e9ee73f5ad88c8b8bc5b2a489c6e2b900cdc5c2b8ef0aaeb4a99dae6bac9a4bbeb12ceacbafc181a43f9176e503d71100b39b71e5f3975daffd3735b8d26c0b3ae43a92737373730bb22bdc3c06b8b281da79a6994c4c21dda8b89e2a0c9767efa559c895da05e127935b4d33eb1e2acab29cd096e5ed73a4812f86f8839aff7ab8e0baff3535098f1cdddb4ae14e1e7eb702674b4bd8253fefe3bd4245afd6dcb365de617df815ff0cc761415f7001a4149825c50626ebbd0aeeb92172be401e2\",\"43e75be1f60bc68a05aaceea143aa14498880ce8ab1417621f7041d8dd76a80e16484e07580060033bb6eeb67a516215f2bdbdcf2bbbe327ae22000b342a51cafe49ea50ce0b459d5e8334b84de284227a3d504d5fcde913b08b27c6997a27b9a307d132379e0688ce6c38f418b1e94ad87b85e86ab48374d736a7c2f402016255b728c258d945591760a314ebc0e98411fdf3c73e6ed8fd7e23cb1cab8a0517d79a33c27de6548be0ab506db1c2b4b573faf7bcb817cbf0d489da9c168a8c8e6bb4ba0edbfcd1fd01f5eddb89ac84d7a218d83635e354e77619725be00426aaaae90221b65c063ef479184599036182098f3e623a57567ff52172fcd0463e23\",\"70ab52b4bde2f26ba9603b1d211ab94ce95d84a8f09fbb1817700897bc1beb4b3bfe24850f61751204cec784ddd182e5a4432a8d6f48ff475a58d4e63ddc70de5b68a4ee392384031d2b3f352a74c5b8b9fe6f8113a046dcab29b6a168203031d783a4321a7d3f2e971761164454af67367c51a4d46218f817034705c3b013162b83b609647944dd7173e37d02f04b0aef42d1ad2f53902b3e88ccf2523c8526b50b3e47a9d51673992d69ed1f0ac39849b473c1ca0fdb5c34c9b344cf820a3b6566d3db80fb0d6646646080e19bf1448f8859ac1c0275c863950779cd22d248a358a3edb4e60676b4ec353d62c25f7b8c836293108be03a353ea8815c3dba9c\",\"84fb3dcc1348efc024c59df79e69c33d0d67d3f7af328cf0af6048d0080862f0ad0eae3bb676851b58b22db6e7c46474cb6aed94a73b35caf65e0c9f36743f55853bbc1d895649435edfeff25977e8130133078577d547c67c8d31236e1dbcac18252f71fac884078e229f97a7b451391f501b85266252137674f898ab9afb505d4f1ca7455e2339ee992395afd3c9a5cb8724733bdb40ed625932106b47dfe890bdea045178a46dffa1608a1ef01b4dda7a7381ee24f4c10fd63b84b1ece8c425435992f567c709d21324aa50a751042fc4cd2afc283ddb8b2867a694945337fe985a2090e45a8df28c68c828a0e6bae3d18f9a8251dbf46e4e7898feb23ca6\",\"23346102965ad3e6d474ac60f0fb4154dff2bf4250204390db22560f1ffcf47047489c38f02708c9776ed349078bcf7822c2bf50e0af9999a610d69e6f14e3d2ff138e706fbad8359bf496d2519ee900a04ac69eaa7e26bb11e4f302288221889bc58ce20608829db11fbc0a64ad066d7cd1704ae730d954dd84a1a35fb03dfab608b8e483d05ad71c2f6e2e38f59afe3005b60d508383ef160f23aed233bf76e108e3d0e3e6a87032b5b6b7b14f50c5b40aeefde5811ea5fa8a601124370b3d58ebca0906fa0ce72e90a23d713d3d74f2d59256d043011c6b350ebb664ba0a96ae7a5611d71f03d60b60d75e328f6a086aa1932f58026a20c3c3ac4f797587e\",\"12786ce1db47ed46d0bd326d844d3c611f9816b59817fb32a0729d4eb7c3975442410b86f5054d3de4be3f9ba442f0750aa0f284269c57e73ad7c644d3182a3ed26f46462ac687287260117abca70255461dc728adced54b9da10206a88fd213dc423ecc7db4842c3b4ff031ee8eb16304178f4e8eaed9db3e2f6c150dca1532a0a6d8e455cf13e7b4beed736ac8525b84b213ba96fced8ab8a9f47d5cdc8fe02e7eede3f417d2dc07ea10eea71486d3b1f9a0b9d6612efc83908702e6b77499a4861d770d136440962c0b35148b4a1af55989b94509a0ca765bdf1fee850eb175be5676581be779c94192a0326513a768c326fa67a202e66d0eaa70a91932d6\",\"354fd63ff01cf79fd2c90928231e364195a4b6c1d7874011ab6440b583f7027990c37eb4a9bd0125c31a61c31bbed0e36850261df09d5395a1885e5faf9f7bbdff0e545495f7e4761894493ace3de65ca7135a2a751aa2f40d21907bdcf65cec2fa896e457eb02889b0e3e8a5bcfdf133847ccec39c886823aef9f7f2ef9650345324efd55d0fc2e349cebffd6b7a542d4b9db9a4353e30da8f4e9aacd35ff5023180d34488261ba80413fd0cb56257db3e543f72e6d2bd82776e24d2db62107f83d6169fbf63eecfb1b33e58058bff6c0a04a6605d14f3ea77c4959293a19c3309e55d86d1ce1d308967bd2b550fbe2df0219444801d842fab7f6b0f26436e4\",\"61186ef51490cf59e822d5e3f84561ffb4f0b921c205581540ac13d8f978765791ab43942dcf470eac454dc13ce375df68bee5e152ee048fd14c5b6edfc053c2d548008e29a50fcf392069e9fe851fcc58c0f3f4ecd14d2885b9940b2a7bc7cc2818910fef3800a7dcf7e7f5a58905fcaedbf7fcd0dbff40293a403148cffedf1a5730554a10a1eed001cfbad38c4051b2a640a79271e43aae09e7733fe3b881fdba14cd397af91a1499f40069f47f65a0bc167d4c66ab5d8c0fcde37383911f75b4d3207a8a5c4dfa6ecf610c6ac20da6e96c0cd691c0642c8bb7a6be2837785774f4bbaac2529bf5291c94ab49961373e8991eb2018aa9d93529f66dd7695a\"]}".to_string()).unwrap();
        verify_correct_key_proof(&correct_key_proof, &paillier_pk.n).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_verify_correct_key_proof_wrong_pk() {
        let paillier_pk = EncryptionKey::from(MinimalEncryptionKey{n: BigInt::from_hex("ae2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129").unwrap()});
        let correct_key_proof: CorrectKeyProof = serde_json::from_str(&"{\"sigma_vec\":[\"14f21d17357e5d0d8d2cb3cf6d0b9439323473be7e1f68db541b77450f87a20941640bf8a317d4ea6272b12923449e73ea5598a6197219fb6c7ca416a3552301c9cc5b47580ce35e4c9e37a97ec0bdbe2b48c2db21cde5bcef9fc04c6e767c59c0500929b76f87901e5a4d8adb38097c44ed790a0ae2e9f6985823f1789aa47a8298d02763751b73942bbee79c4544f9bd2b82e405f15d801cb41d4831012f99172ef49fee6ea33599caadcdb89c1eb768e30b11878f37e12d232b624cbe589a7767af46d958632574535893c0337858399aed65638b97bcaddee45e40fe79a5014fcd1e398b19807439f58236373197653a8ea82ab3a84173d5a8d45bcae823\",\"32beda264c7fde6cb41d48ce44e6e93af5ed0e1cb5c7cd29f7fa3cbf72b78b9bc3e5267c4f9a75de40eb95a4bdc73dd1d8a435799daf2365f9377aed3c4524016d2ea58002c66fd0a8bcb8e74bac9923b723bc9f8752f82d9cba8bec4f414f314a40842031427b0bb8cdc514bfb61a5f85a51d8b7a290ccbd1000af937a6a7fd7a6070ba40a6801a2909e11d71a773958195d82f72995e69b989ab91207b68ac891e6585848f7aea80e1a0693427a0a512c0cbfbfe5d9ffe02462856ca918af9ebd2ad2f9b44a84b628ec7a7ed4d7232e72c52f2af5ef8988e3c09715fbe1a0af871109028335fb95370ae3e7ecf646063c1914ceeff8cf22ca06d250f02904c\",\"27236e62e810849d58c24b57d2061be4223a175224a89b94ce1261ae9f7a61ec058a43589c83aa3029e61c488fa33b0ea8fb72c36f4b3f962f858f4b0dd822a2810124cba42c8c2a42046b324a3c0712799979be7da1e6dff82c466149484246769f43683231ba8a89185587086cef1de589a4d59b74ac20fcbe0310403f9347417a4c8a8b90b78671d265471fe5ca839e509d4b6f5c2ec33ae255abf54aa12700772a174074048bc4edecc142c268b765f8bf4c0ab7b253882f77c1cb0e410e8e21a23ba364ec37adee59e0395920ab403ab77f095ed8bda39fad9b00886c9e2682a8314bd71fc2db9d2b2a8476ac295c262ba16d4657c62af9bb6a4729c214\",\"974e6e3a63e90275733cbf0b1516d940f0b0c8bd6140f16abb22988289b88b327c5a3e2a1de6d00f03e6f78ee934da02590ee45c6b4c0c8f53ccf6adc35cd0e9ee73f5ad88c8b8bc5b2a489c6e2b900cdc5c2b8ef0aaeb4a99dae6bac9a4bbeb12ceacbafc181a43f9176e503d71100b39b71e5f3975daffd3735b8d26c0b3ae43a92737373730bb22bdc3c06b8b281da79a6994c4c21dda8b89e2a0c9767efa559c895da05e127935b4d33eb1e2acab29cd096e5ed73a4812f86f8839aff7ab8e0baff3535098f1cdddb4ae14e1e7eb702674b4bd8253fefe3bd4245afd6dcb365de617df815ff0cc761415f7001a4149825c50626ebbd0aeeb92172be401e2\",\"43e75be1f60bc68a05aaceea143aa14498880ce8ab1417621f7041d8dd76a80e16484e07580060033bb6eeb67a516215f2bdbdcf2bbbe327ae22000b342a51cafe49ea50ce0b459d5e8334b84de284227a3d504d5fcde913b08b27c6997a27b9a307d132379e0688ce6c38f418b1e94ad87b85e86ab48374d736a7c2f402016255b728c258d945591760a314ebc0e98411fdf3c73e6ed8fd7e23cb1cab8a0517d79a33c27de6548be0ab506db1c2b4b573faf7bcb817cbf0d489da9c168a8c8e6bb4ba0edbfcd1fd01f5eddb89ac84d7a218d83635e354e77619725be00426aaaae90221b65c063ef479184599036182098f3e623a57567ff52172fcd0463e23\",\"70ab52b4bde2f26ba9603b1d211ab94ce95d84a8f09fbb1817700897bc1beb4b3bfe24850f61751204cec784ddd182e5a4432a8d6f48ff475a58d4e63ddc70de5b68a4ee392384031d2b3f352a74c5b8b9fe6f8113a046dcab29b6a168203031d783a4321a7d3f2e971761164454af67367c51a4d46218f817034705c3b013162b83b609647944dd7173e37d02f04b0aef42d1ad2f53902b3e88ccf2523c8526b50b3e47a9d51673992d69ed1f0ac39849b473c1ca0fdb5c34c9b344cf820a3b6566d3db80fb0d6646646080e19bf1448f8859ac1c0275c863950779cd22d248a358a3edb4e60676b4ec353d62c25f7b8c836293108be03a353ea8815c3dba9c\",\"84fb3dcc1348efc024c59df79e69c33d0d67d3f7af328cf0af6048d0080862f0ad0eae3bb676851b58b22db6e7c46474cb6aed94a73b35caf65e0c9f36743f55853bbc1d895649435edfeff25977e8130133078577d547c67c8d31236e1dbcac18252f71fac884078e229f97a7b451391f501b85266252137674f898ab9afb505d4f1ca7455e2339ee992395afd3c9a5cb8724733bdb40ed625932106b47dfe890bdea045178a46dffa1608a1ef01b4dda7a7381ee24f4c10fd63b84b1ece8c425435992f567c709d21324aa50a751042fc4cd2afc283ddb8b2867a694945337fe985a2090e45a8df28c68c828a0e6bae3d18f9a8251dbf46e4e7898feb23ca6\",\"23346102965ad3e6d474ac60f0fb4154dff2bf4250204390db22560f1ffcf47047489c38f02708c9776ed349078bcf7822c2bf50e0af9999a610d69e6f14e3d2ff138e706fbad8359bf496d2519ee900a04ac69eaa7e26bb11e4f302288221889bc58ce20608829db11fbc0a64ad066d7cd1704ae730d954dd84a1a35fb03dfab608b8e483d05ad71c2f6e2e38f59afe3005b60d508383ef160f23aed233bf76e108e3d0e3e6a87032b5b6b7b14f50c5b40aeefde5811ea5fa8a601124370b3d58ebca0906fa0ce72e90a23d713d3d74f2d59256d043011c6b350ebb664ba0a96ae7a5611d71f03d60b60d75e328f6a086aa1932f58026a20c3c3ac4f797587e\",\"12786ce1db47ed46d0bd326d844d3c611f9816b59817fb32a0729d4eb7c3975442410b86f5054d3de4be3f9ba442f0750aa0f284269c57e73ad7c644d3182a3ed26f46462ac687287260117abca70255461dc728adced54b9da10206a88fd213dc423ecc7db4842c3b4ff031ee8eb16304178f4e8eaed9db3e2f6c150dca1532a0a6d8e455cf13e7b4beed736ac8525b84b213ba96fced8ab8a9f47d5cdc8fe02e7eede3f417d2dc07ea10eea71486d3b1f9a0b9d6612efc83908702e6b77499a4861d770d136440962c0b35148b4a1af55989b94509a0ca765bdf1fee850eb175be5676581be779c94192a0326513a768c326fa67a202e66d0eaa70a91932d6\",\"354fd63ff01cf79fd2c90928231e364195a4b6c1d7874011ab6440b583f7027990c37eb4a9bd0125c31a61c31bbed0e36850261df09d5395a1885e5faf9f7bbdff0e545495f7e4761894493ace3de65ca7135a2a751aa2f40d21907bdcf65cec2fa896e457eb02889b0e3e8a5bcfdf133847ccec39c886823aef9f7f2ef9650345324efd55d0fc2e349cebffd6b7a542d4b9db9a4353e30da8f4e9aacd35ff5023180d34488261ba80413fd0cb56257db3e543f72e6d2bd82776e24d2db62107f83d6169fbf63eecfb1b33e58058bff6c0a04a6605d14f3ea77c4959293a19c3309e55d86d1ce1d308967bd2b550fbe2df0219444801d842fab7f6b0f26436e4\",\"61186ef51490cf59e822d5e3f84561ffb4f0b921c205581540ac13d8f978765791ab43942dcf470eac454dc13ce375df68bee5e152ee048fd14c5b6edfc053c2d548008e29a50fcf392069e9fe851fcc58c0f3f4ecd14d2885b9940b2a7bc7cc2818910fef3800a7dcf7e7f5a58905fcaedbf7fcd0dbff40293a403148cffedf1a5730554a10a1eed001cfbad38c4051b2a640a79271e43aae09e7733fe3b881fdba14cd397af91a1499f40069f47f65a0bc167d4c66ab5d8c0fcde37383911f75b4d3207a8a5c4dfa6ecf610c6ac20da6e96c0cd691c0642c8bb7a6be2837785774f4bbaac2529bf5291c94ab49961373e8991eb2018aa9d93529f66dd7695a\"]}".to_string()).unwrap();
        verify_correct_key_proof(&correct_key_proof, &paillier_pk.n).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_verify_correct_key_proof_wrong_sigma_len() {
        let paillier_pk = EncryptionKey::from(MinimalEncryptionKey{n: BigInt::from_hex("9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129").unwrap()});
        let correct_key_proof: CorrectKeyProof = serde_json::from_str(&"{\"sigma_vec\":[\"32beda264c7fde6cb41d48ce44e6e93af5ed0e1cb5c7cd29f7fa3cbf72b78b9bc3e5267c4f9a75de40eb95a4bdc73dd1d8a435799daf2365f9377aed3c4524016d2ea58002c66fd0a8bcb8e74bac9923b723bc9f8752f82d9cba8bec4f414f314a40842031427b0bb8cdc514bfb61a5f85a51d8b7a290ccbd1000af937a6a7fd7a6070ba40a6801a2909e11d71a773958195d82f72995e69b989ab91207b68ac891e6585848f7aea80e1a0693427a0a512c0cbfbfe5d9ffe02462856ca918af9ebd2ad2f9b44a84b628ec7a7ed4d7232e72c52f2af5ef8988e3c09715fbe1a0af871109028335fb95370ae3e7ecf646063c1914ceeff8cf22ca06d250f02904c\",\"27236e62e810849d58c24b57d2061be4223a175224a89b94ce1261ae9f7a61ec058a43589c83aa3029e61c488fa33b0ea8fb72c36f4b3f962f858f4b0dd822a2810124cba42c8c2a42046b324a3c0712799979be7da1e6dff82c466149484246769f43683231ba8a89185587086cef1de589a4d59b74ac20fcbe0310403f9347417a4c8a8b90b78671d265471fe5ca839e509d4b6f5c2ec33ae255abf54aa12700772a174074048bc4edecc142c268b765f8bf4c0ab7b253882f77c1cb0e410e8e21a23ba364ec37adee59e0395920ab403ab77f095ed8bda39fad9b00886c9e2682a8314bd71fc2db9d2b2a8476ac295c262ba16d4657c62af9bb6a4729c214\",\"974e6e3a63e90275733cbf0b1516d940f0b0c8bd6140f16abb22988289b88b327c5a3e2a1de6d00f03e6f78ee934da02590ee45c6b4c0c8f53ccf6adc35cd0e9ee73f5ad88c8b8bc5b2a489c6e2b900cdc5c2b8ef0aaeb4a99dae6bac9a4bbeb12ceacbafc181a43f9176e503d71100b39b71e5f3975daffd3735b8d26c0b3ae43a92737373730bb22bdc3c06b8b281da79a6994c4c21dda8b89e2a0c9767efa559c895da05e127935b4d33eb1e2acab29cd096e5ed73a4812f86f8839aff7ab8e0baff3535098f1cdddb4ae14e1e7eb702674b4bd8253fefe3bd4245afd6dcb365de617df815ff0cc761415f7001a4149825c50626ebbd0aeeb92172be401e2\",\"43e75be1f60bc68a05aaceea143aa14498880ce8ab1417621f7041d8dd76a80e16484e07580060033bb6eeb67a516215f2bdbdcf2bbbe327ae22000b342a51cafe49ea50ce0b459d5e8334b84de284227a3d504d5fcde913b08b27c6997a27b9a307d132379e0688ce6c38f418b1e94ad87b85e86ab48374d736a7c2f402016255b728c258d945591760a314ebc0e98411fdf3c73e6ed8fd7e23cb1cab8a0517d79a33c27de6548be0ab506db1c2b4b573faf7bcb817cbf0d489da9c168a8c8e6bb4ba0edbfcd1fd01f5eddb89ac84d7a218d83635e354e77619725be00426aaaae90221b65c063ef479184599036182098f3e623a57567ff52172fcd0463e23\",\"70ab52b4bde2f26ba9603b1d211ab94ce95d84a8f09fbb1817700897bc1beb4b3bfe24850f61751204cec784ddd182e5a4432a8d6f48ff475a58d4e63ddc70de5b68a4ee392384031d2b3f352a74c5b8b9fe6f8113a046dcab29b6a168203031d783a4321a7d3f2e971761164454af67367c51a4d46218f817034705c3b013162b83b609647944dd7173e37d02f04b0aef42d1ad2f53902b3e88ccf2523c8526b50b3e47a9d51673992d69ed1f0ac39849b473c1ca0fdb5c34c9b344cf820a3b6566d3db80fb0d6646646080e19bf1448f8859ac1c0275c863950779cd22d248a358a3edb4e60676b4ec353d62c25f7b8c836293108be03a353ea8815c3dba9c\",\"84fb3dcc1348efc024c59df79e69c33d0d67d3f7af328cf0af6048d0080862f0ad0eae3bb676851b58b22db6e7c46474cb6aed94a73b35caf65e0c9f36743f55853bbc1d895649435edfeff25977e8130133078577d547c67c8d31236e1dbcac18252f71fac884078e229f97a7b451391f501b85266252137674f898ab9afb505d4f1ca7455e2339ee992395afd3c9a5cb8724733bdb40ed625932106b47dfe890bdea045178a46dffa1608a1ef01b4dda7a7381ee24f4c10fd63b84b1ece8c425435992f567c709d21324aa50a751042fc4cd2afc283ddb8b2867a694945337fe985a2090e45a8df28c68c828a0e6bae3d18f9a8251dbf46e4e7898feb23ca6\",\"23346102965ad3e6d474ac60f0fb4154dff2bf4250204390db22560f1ffcf47047489c38f02708c9776ed349078bcf7822c2bf50e0af9999a610d69e6f14e3d2ff138e706fbad8359bf496d2519ee900a04ac69eaa7e26bb11e4f302288221889bc58ce20608829db11fbc0a64ad066d7cd1704ae730d954dd84a1a35fb03dfab608b8e483d05ad71c2f6e2e38f59afe3005b60d508383ef160f23aed233bf76e108e3d0e3e6a87032b5b6b7b14f50c5b40aeefde5811ea5fa8a601124370b3d58ebca0906fa0ce72e90a23d713d3d74f2d59256d043011c6b350ebb664ba0a96ae7a5611d71f03d60b60d75e328f6a086aa1932f58026a20c3c3ac4f797587e\",\"12786ce1db47ed46d0bd326d844d3c611f9816b59817fb32a0729d4eb7c3975442410b86f5054d3de4be3f9ba442f0750aa0f284269c57e73ad7c644d3182a3ed26f46462ac687287260117abca70255461dc728adced54b9da10206a88fd213dc423ecc7db4842c3b4ff031ee8eb16304178f4e8eaed9db3e2f6c150dca1532a0a6d8e455cf13e7b4beed736ac8525b84b213ba96fced8ab8a9f47d5cdc8fe02e7eede3f417d2dc07ea10eea71486d3b1f9a0b9d6612efc83908702e6b77499a4861d770d136440962c0b35148b4a1af55989b94509a0ca765bdf1fee850eb175be5676581be779c94192a0326513a768c326fa67a202e66d0eaa70a91932d6\",\"354fd63ff01cf79fd2c90928231e364195a4b6c1d7874011ab6440b583f7027990c37eb4a9bd0125c31a61c31bbed0e36850261df09d5395a1885e5faf9f7bbdff0e545495f7e4761894493ace3de65ca7135a2a751aa2f40d21907bdcf65cec2fa896e457eb02889b0e3e8a5bcfdf133847ccec39c886823aef9f7f2ef9650345324efd55d0fc2e349cebffd6b7a542d4b9db9a4353e30da8f4e9aacd35ff5023180d34488261ba80413fd0cb56257db3e543f72e6d2bd82776e24d2db62107f83d6169fbf63eecfb1b33e58058bff6c0a04a6605d14f3ea77c4959293a19c3309e55d86d1ce1d308967bd2b550fbe2df0219444801d842fab7f6b0f26436e4\",\"61186ef51490cf59e822d5e3f84561ffb4f0b921c205581540ac13d8f978765791ab43942dcf470eac454dc13ce375df68bee5e152ee048fd14c5b6edfc053c2d548008e29a50fcf392069e9fe851fcc58c0f3f4ecd14d2885b9940b2a7bc7cc2818910fef3800a7dcf7e7f5a58905fcaedbf7fcd0dbff40293a403148cffedf1a5730554a10a1eed001cfbad38c4051b2a640a79271e43aae09e7733fe3b881fdba14cd397af91a1499f40069f47f65a0bc167d4c66ab5d8c0fcde37383911f75b4d3207a8a5c4dfa6ecf610c6ac20da6e96c0cd691c0642c8bb7a6be2837785774f4bbaac2529bf5291c94ab49961373e8991eb2018aa9d93529f66dd7695a\"]}".to_string()).unwrap();
        verify_correct_key_proof(&correct_key_proof, &paillier_pk.n).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_verify_correct_key_proof_wrong_sigma() {
        let paillier_pk = EncryptionKey::from(MinimalEncryptionKey{n: BigInt::from_hex("9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129").unwrap()});
        let correct_key_proof: CorrectKeyProof = serde_json::from_str(&"{\"sigma_vec\":[\"24f21d17357e5d0d8d2cb3cf6d0b9439323473be7e1f68db541b77450f87a20941640bf8a317d4ea6272b12923449e73ea5598a6197219fb6c7ca416a3552301c9cc5b47580ce35e4c9e37a97ec0bdbe2b48c2db21cde5bcef9fc04c6e767c59c0500929b76f87901e5a4d8adb38097c44ed790a0ae2e9f6985823f1789aa47a8298d02763751b73942bbee79c4544f9bd2b82e405f15d801cb41d4831012f99172ef49fee6ea33599caadcdb89c1eb768e30b11878f37e12d232b624cbe589a7767af46d958632574535893c0337858399aed65638b97bcaddee45e40fe79a5014fcd1e398b19807439f58236373197653a8ea82ab3a84173d5a8d45bcae823\",\"32beda264c7fde6cb41d48ce44e6e93af5ed0e1cb5c7cd29f7fa3cbf72b78b9bc3e5267c4f9a75de40eb95a4bdc73dd1d8a435799daf2365f9377aed3c4524016d2ea58002c66fd0a8bcb8e74bac9923b723bc9f8752f82d9cba8bec4f414f314a40842031427b0bb8cdc514bfb61a5f85a51d8b7a290ccbd1000af937a6a7fd7a6070ba40a6801a2909e11d71a773958195d82f72995e69b989ab91207b68ac891e6585848f7aea80e1a0693427a0a512c0cbfbfe5d9ffe02462856ca918af9ebd2ad2f9b44a84b628ec7a7ed4d7232e72c52f2af5ef8988e3c09715fbe1a0af871109028335fb95370ae3e7ecf646063c1914ceeff8cf22ca06d250f02904c\",\"27236e62e810849d58c24b57d2061be4223a175224a89b94ce1261ae9f7a61ec058a43589c83aa3029e61c488fa33b0ea8fb72c36f4b3f962f858f4b0dd822a2810124cba42c8c2a42046b324a3c0712799979be7da1e6dff82c466149484246769f43683231ba8a89185587086cef1de589a4d59b74ac20fcbe0310403f9347417a4c8a8b90b78671d265471fe5ca839e509d4b6f5c2ec33ae255abf54aa12700772a174074048bc4edecc142c268b765f8bf4c0ab7b253882f77c1cb0e410e8e21a23ba364ec37adee59e0395920ab403ab77f095ed8bda39fad9b00886c9e2682a8314bd71fc2db9d2b2a8476ac295c262ba16d4657c62af9bb6a4729c214\",\"974e6e3a63e90275733cbf0b1516d940f0b0c8bd6140f16abb22988289b88b327c5a3e2a1de6d00f03e6f78ee934da02590ee45c6b4c0c8f53ccf6adc35cd0e9ee73f5ad88c8b8bc5b2a489c6e2b900cdc5c2b8ef0aaeb4a99dae6bac9a4bbeb12ceacbafc181a43f9176e503d71100b39b71e5f3975daffd3735b8d26c0b3ae43a92737373730bb22bdc3c06b8b281da79a6994c4c21dda8b89e2a0c9767efa559c895da05e127935b4d33eb1e2acab29cd096e5ed73a4812f86f8839aff7ab8e0baff3535098f1cdddb4ae14e1e7eb702674b4bd8253fefe3bd4245afd6dcb365de617df815ff0cc761415f7001a4149825c50626ebbd0aeeb92172be401e2\",\"43e75be1f60bc68a05aaceea143aa14498880ce8ab1417621f7041d8dd76a80e16484e07580060033bb6eeb67a516215f2bdbdcf2bbbe327ae22000b342a51cafe49ea50ce0b459d5e8334b84de284227a3d504d5fcde913b08b27c6997a27b9a307d132379e0688ce6c38f418b1e94ad87b85e86ab48374d736a7c2f402016255b728c258d945591760a314ebc0e98411fdf3c73e6ed8fd7e23cb1cab8a0517d79a33c27de6548be0ab506db1c2b4b573faf7bcb817cbf0d489da9c168a8c8e6bb4ba0edbfcd1fd01f5eddb89ac84d7a218d83635e354e77619725be00426aaaae90221b65c063ef479184599036182098f3e623a57567ff52172fcd0463e23\",\"70ab52b4bde2f26ba9603b1d211ab94ce95d84a8f09fbb1817700897bc1beb4b3bfe24850f61751204cec784ddd182e5a4432a8d6f48ff475a58d4e63ddc70de5b68a4ee392384031d2b3f352a74c5b8b9fe6f8113a046dcab29b6a168203031d783a4321a7d3f2e971761164454af67367c51a4d46218f817034705c3b013162b83b609647944dd7173e37d02f04b0aef42d1ad2f53902b3e88ccf2523c8526b50b3e47a9d51673992d69ed1f0ac39849b473c1ca0fdb5c34c9b344cf820a3b6566d3db80fb0d6646646080e19bf1448f8859ac1c0275c863950779cd22d248a358a3edb4e60676b4ec353d62c25f7b8c836293108be03a353ea8815c3dba9c\",\"84fb3dcc1348efc024c59df79e69c33d0d67d3f7af328cf0af6048d0080862f0ad0eae3bb676851b58b22db6e7c46474cb6aed94a73b35caf65e0c9f36743f55853bbc1d895649435edfeff25977e8130133078577d547c67c8d31236e1dbcac18252f71fac884078e229f97a7b451391f501b85266252137674f898ab9afb505d4f1ca7455e2339ee992395afd3c9a5cb8724733bdb40ed625932106b47dfe890bdea045178a46dffa1608a1ef01b4dda7a7381ee24f4c10fd63b84b1ece8c425435992f567c709d21324aa50a751042fc4cd2afc283ddb8b2867a694945337fe985a2090e45a8df28c68c828a0e6bae3d18f9a8251dbf46e4e7898feb23ca6\",\"23346102965ad3e6d474ac60f0fb4154dff2bf4250204390db22560f1ffcf47047489c38f02708c9776ed349078bcf7822c2bf50e0af9999a610d69e6f14e3d2ff138e706fbad8359bf496d2519ee900a04ac69eaa7e26bb11e4f302288221889bc58ce20608829db11fbc0a64ad066d7cd1704ae730d954dd84a1a35fb03dfab608b8e483d05ad71c2f6e2e38f59afe3005b60d508383ef160f23aed233bf76e108e3d0e3e6a87032b5b6b7b14f50c5b40aeefde5811ea5fa8a601124370b3d58ebca0906fa0ce72e90a23d713d3d74f2d59256d043011c6b350ebb664ba0a96ae7a5611d71f03d60b60d75e328f6a086aa1932f58026a20c3c3ac4f797587e\",\"12786ce1db47ed46d0bd326d844d3c611f9816b59817fb32a0729d4eb7c3975442410b86f5054d3de4be3f9ba442f0750aa0f284269c57e73ad7c644d3182a3ed26f46462ac687287260117abca70255461dc728adced54b9da10206a88fd213dc423ecc7db4842c3b4ff031ee8eb16304178f4e8eaed9db3e2f6c150dca1532a0a6d8e455cf13e7b4beed736ac8525b84b213ba96fced8ab8a9f47d5cdc8fe02e7eede3f417d2dc07ea10eea71486d3b1f9a0b9d6612efc83908702e6b77499a4861d770d136440962c0b35148b4a1af55989b94509a0ca765bdf1fee850eb175be5676581be779c94192a0326513a768c326fa67a202e66d0eaa70a91932d6\",\"354fd63ff01cf79fd2c90928231e364195a4b6c1d7874011ab6440b583f7027990c37eb4a9bd0125c31a61c31bbed0e36850261df09d5395a1885e5faf9f7bbdff0e545495f7e4761894493ace3de65ca7135a2a751aa2f40d21907bdcf65cec2fa896e457eb02889b0e3e8a5bcfdf133847ccec39c886823aef9f7f2ef9650345324efd55d0fc2e349cebffd6b7a542d4b9db9a4353e30da8f4e9aacd35ff5023180d34488261ba80413fd0cb56257db3e543f72e6d2bd82776e24d2db62107f83d6169fbf63eecfb1b33e58058bff6c0a04a6605d14f3ea77c4959293a19c3309e55d86d1ce1d308967bd2b550fbe2df0219444801d842fab7f6b0f26436e4\",\"61186ef51490cf59e822d5e3f84561ffb4f0b921c205581540ac13d8f978765791ab43942dcf470eac454dc13ce375df68bee5e152ee048fd14c5b6edfc053c2d548008e29a50fcf392069e9fe851fcc58c0f3f4ecd14d2885b9940b2a7bc7cc2818910fef3800a7dcf7e7f5a58905fcaedbf7fcd0dbff40293a403148cffedf1a5730554a10a1eed001cfbad38c4051b2a640a79271e43aae09e7733fe3b881fdba14cd397af91a1499f40069f47f65a0bc167d4c66ab5d8c0fcde37383911f75b4d3207a8a5c4dfa6ecf610c6ac20da6e96c0cd691c0642c8bb7a6be2837785774f4bbaac2529bf5291c94ab49961373e8991eb2018aa9d93529f66dd7695a\"]}".to_string()).unwrap();
        verify_correct_key_proof(&correct_key_proof, &paillier_pk.n).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_api_childkey_creator_wrong_paillier_pk() {
        let api_childkey_creator = APIchildkeyCreator::init(
            &BigInt::from_hex("4794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1")
                .unwrap(),
        );
        let paillier_pk = EncryptionKey::from(MinimalEncryptionKey{n: BigInt::from_hex("ae2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129").unwrap()});
        let correct_key_proof: CorrectKeyProof = serde_json::from_str(&"{\"sigma_vec\":[\"86ba927cc5974e2f9357e4041e097ede786aa519cf2d8499402b60bf0fb1ae9adc529b8fe72ca51baa940cc93eb292eee7f0334f1f7ee16d320b4d8989f8c444109b1745ecb5efc5c7d1d3a796115cb0e04fcb9e98c3b7316b5e23cf331ac599734d51d565a58e9167103eb9e3af74a15f4bfa4120ff311f192dfb852ac1c8f8a572067bbfa7c7ff5513a29936c6a304d142820f930ccdc48abe43b36b23b8010125aa6cb59cafb9e57976bc0bda14d5cb61e9810e06ebcab54182451c8d1c4e06856a99d67cd942f4a5e60564a602215f59e67dc403bfb3edfe16437dbee6cf41de4f0d5b21aa053b10c3669ad38c75bf27692586792963e99fae66df24facb\",\"7381a547eed881e757a55fd6bcaaf2f218fd29e82833527eed79a42203120140dfbceaeb45a23785b3860fcc064d29845795168fc16588ba020d215d973a27c921b9524377da575b271b55e9cceefd281f09af00abf27ad45df938a29caa66af6fc0ab81a0010c2d4ca49a680b2f42aca5dd3647e6852c5e3097803b242bbb272932cd95595dfa47267413a6148f5223bf8adbd2b88628914398ccd1f2d24b0be85de7c810981cb3a5caf845e2f81ebc177da079987286a9d0c4d0bf8cf7f542892cfbf9164c7ae20bb0b57e3508269d43b93c7172048da3306a7d60aef17845157e43d5bf8eeddd2aed1da564bbe971d071d359525b5b3704d4e2e077dcfade\",\"8405adf1195421347ea8043824aca5952875ebcba66d82a2af3f31af42bbb7e038f6547c2b40b45a064be9f8064610116e2f5740e16649e233989d2058a109b2ae10d651c64bce97634596aeee781ddc634305c326c3be6df49cba4557d532a40f911a67826d81865a24c32688cee8f81786ee76511c66ba25fce9d2503978d777fe773b9a2a0357a797adbc77ac0e9bc0cbab37b3a8f6a42227bebf181004f9a55b6a557783c9150d9408792bd73b1c0071b31c23f3c8ec18d5749d46ea0c431e73fcc8c64a57426402cce9917d7809d94687318a39ee27b01ef9041001401f889e436d3d48fbdde1072b7533b0d00f6a13d0bb0bb94020ca9b77c93d42d5f3\",\"570861a8c14df0b19f6b8159131bef4259338ef6faeab481b6c14e1fc7e57ede571e3698f89c9a08ee9d91c58d594fbc2cd98fff4a483d360c1ecc703820361854061b8a516ce86ca82e8a2e1653f3b25b9d710f6f4e84b8e991450126171f0baa1ac2bfd87653b31f7c30619b6ad9684b48b2dde399c229bed057984415ba552a606eb1ab2b4324adf3826b9c9844f1ecc5634d197877f29626fe59399e739e5f73e502d2fb6a0a016862008583125ec0cfd9c18a3f183ed493d1f5bf236f6a3f7ce345998afae9f963bfee2f705a8df3c253407708fa92091d34d6da6f487d8e7df7b38fbf4e919fa093f64b8782e5e96372080006b9b982013aaffa9c0c58\",\"282184ad00cbc48211eb828e33462bd6c87c53f05c98395e2a0b58924732f25a947c8524c2b09dfcab1d6f70730c4684e11a6b0911199d9562be52872463d51091455b792398e56521d90387077f8948c894707d5cfb42ce3b155f65fb7b80575906a5af2e1b663455d8cd898d743bc727a06c3febdf5f55489d9372da4fbfb516e09faa15a9da0008037f6afb90531a34f08a0ff1b843fd3e0b2c20a8458f767ae85925de160facad7014c96f3f3dd39b2511475fde6ae09476def71fb7ba6c072dc33d2e468f31b55ecbc08c50ddbafe710748cc7d72f509260cceee5171f6b8b0c257ffe5bfa2d09c76265bb54672792c22a137111b9b5e1835ecf8decdde\",\"8813fd4a00617a1ed4ab79662a155535bee18bda39897bef30a0273c5e9e880560b6020b272c23e966fcd03ecebf51bb725c8bbae1ff13762a3bf2e6388e0e3d818a47db0e38fb92bc8e1736804349399ad0ab2d057ee577d6206f69df914868c337c68030a77a0dce18d2793fa971eb4c2a9d56980e77ad5ff52679cfdd69972579402d9a1078060f2a760c7a6363d85c6652049cda386612b0362559f691e95c2ce9a4ce279f977dc9b9fa51d58e42f3bba5c95b07256f86453dd745acfef156f5369c8b1c8b3f240982e0ac52ebe5bd3d1aeeb8cb9daeac84aaaa1fd789d06c4644d4d6adf8ac088d65ca401cb58f489d7a31c9b8f00ffd53671901718736\",\"45109996a12ccb5a4af7a33872bd4526266acb2b6fb62de70d1ffa6ee9f642e32dca886d4d178c1b41e10c8a919d1eabe525835e66488d402215e7906d9c853a4a410f85121cfdcc5673e0487c40442d18649cbee8f032134431344c4a94622ab8e374644efac7e188dc3ebfa5ba7d76af30acb2e7465aae40454594f9313ff845c109eb00deca6cf949f3d612eee279e3a3ccd393901043dea0eb07b6568741adce54fc268becb522824a0acc2861c123bc21d70392e037fdbfe46c35b4e85581ffb231e8a3ecf46fe8cea69759113345beb1a5aaf22121b4c5de5ced09e7037467461c6a3f6f4e821a8ee43da3b6bbd3d9bc07f3f854c82a80ab9721dd6830\",\"62ba72d6c9a6403e14a5f49f8dcdd003fa7c01feefbdc17fbc7a40b4c562eb2f2e6f068e05a8e7e5120de1ea350d244c2fe7ec0f2149797d61232cad298859b59ecdf3a6fa270190f25346c04a99ea285ecc4666c6e58f29f6b9e5d2c0929f75a4bdea81641d8d001cd44a5382a1c79856c19b19a8d1e13f5a3230f0e928e5b93e5fdebefde559c29f02f153dfb0ca911102b1d03bf094d799e5e39cc58abd186053f050c7db2646517016763ab185b8d9316ddfc15ae71063159e57d6bc9f548700c7f01c62d2e9b49671ba54d79d9b8b901978056bc13627e17d44fce53c004c6df4e8e225da1f75d2f385b16d8ee2687cfe56934644dad5abc8e3cdcce64d\",\"9a47120575204c8f76a980b4733ffc69dbc34959ca8f565ac277b55985b8b4d9cd3f4887d59ef0f5d2d0b8bb1f10d8fdcd167935380367592a895d134928931dd85f66e4253ec4d3e4a2c1b5ba5b2af4ef0d20c394c8b1526c6010458cd3023f32ce32b917322cee3315d633bfb2f8e16b69cfe362c6df3963bc95b6bfb60661e613e76e0b3a6c3c06c49f26de09343ac38a66a4d1cae8496d4b82a78b9b7f2f2097182812b5d5ab4bf8950f49f1f553584b7aa993cfe1c96d8fd78a2d9201f42af6f56c2ed6373925e2b5cc8ff4dc1e238ccce1754c792ac82a61d45fba4898b3bb6372e7827616b06353535457f6366eaa2d42b7a167e2be4ee086699a1b41\",\"31ad95d0e1ef37d078f0ef74fb6fe8f9ea47db0aa31e78a37420e7ad9bd1b2bca058efb395885d2fea08106ef8ffa898e19be1f562665b2514c4b7cea39fc678449c7c103cd2dc8d8f980dd3b926a6532e113d25d1a9a891e374a33ae0dc21691fc4a4db7c638585158f516d5fb592c540ae2b6266a81905909c3b1fbdc22e248ea3d0e5f0895112769581509581d749486137f057c6b0fc77fd4784da9904250e7f5fe088fe4ced7451bae6829a2b9c8286cbac4e4171caf4e2089edc754912392b906062e101344fe51841c391e4bb7f2d672be01ddb3fae68b44f0c02000ad3cb0be7af954fcca4ed3f19ebcdca8acccaa60e03c035b196eec87ece42f50\",\"3054c555c41509b39eccc86bbf80bade7eb18e8a694947ca4f7ebf0ef309dc4a35690fe2e3fc8a76db33fb5e6554a52f73d32da987d768a220bdff621a54c83aa382092658f6657c95c767456682d5da2aff4a53a0958ce4a7dae61262c1f47e365d52d7981541ea0ed3a00a0c30bad31a6738bc19a254bf78dac870f604aeca1766b9ea5dc1e239819b8b07f02d5d176065bfa087ce000a581b1f92011309d0bb0f0e10d98877a4279e7d56460b40ad9c2909226c510b3938f92459b11a33c3e6c8637b66d8ce6bd81e04e0cfc166cb9fa90622df20482a7d8ac3c3d8877b0477ba41152500c88bf554fa81ac4f1c44a04b814f42104c012dd6b75e10f13271\"]}".to_string()).unwrap();
        api_childkey_creator
            .verify_paillier(&paillier_pk, &correct_key_proof)
            .unwrap();
    }

    #[test]
    #[should_panic]
    fn test_api_childkey_creator_wrong_proof() {
        let api_childkey_creator = APIchildkeyCreator::init(
            &BigInt::from_hex("4794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1")
                .unwrap(),
        );
        let paillier_pk = EncryptionKey::from(MinimalEncryptionKey{n: BigInt::from_hex("9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129").unwrap()});
        let correct_key_proof: CorrectKeyProof = serde_json::from_str(&"{\"sigma_vec\":[\"96ba927cc5974e2f9357e4041e097ede786aa519cf2d8499402b60bf0fb1ae9adc529b8fe72ca51baa940cc93eb292eee7f0334f1f7ee16d320b4d8989f8c444109b1745ecb5efc5c7d1d3a796115cb0e04fcb9e98c3b7316b5e23cf331ac599734d51d565a58e9167103eb9e3af74a15f4bfa4120ff311f192dfb852ac1c8f8a572067bbfa7c7ff5513a29936c6a304d142820f930ccdc48abe43b36b23b8010125aa6cb59cafb9e57976bc0bda14d5cb61e9810e06ebcab54182451c8d1c4e06856a99d67cd942f4a5e60564a602215f59e67dc403bfb3edfe16437dbee6cf41de4f0d5b21aa053b10c3669ad38c75bf27692586792963e99fae66df24facb\",\"7381a547eed881e757a55fd6bcaaf2f218fd29e82833527eed79a42203120140dfbceaeb45a23785b3860fcc064d29845795168fc16588ba020d215d973a27c921b9524377da575b271b55e9cceefd281f09af00abf27ad45df938a29caa66af6fc0ab81a0010c2d4ca49a680b2f42aca5dd3647e6852c5e3097803b242bbb272932cd95595dfa47267413a6148f5223bf8adbd2b88628914398ccd1f2d24b0be85de7c810981cb3a5caf845e2f81ebc177da079987286a9d0c4d0bf8cf7f542892cfbf9164c7ae20bb0b57e3508269d43b93c7172048da3306a7d60aef17845157e43d5bf8eeddd2aed1da564bbe971d071d359525b5b3704d4e2e077dcfade\",\"8405adf1195421347ea8043824aca5952875ebcba66d82a2af3f31af42bbb7e038f6547c2b40b45a064be9f8064610116e2f5740e16649e233989d2058a109b2ae10d651c64bce97634596aeee781ddc634305c326c3be6df49cba4557d532a40f911a67826d81865a24c32688cee8f81786ee76511c66ba25fce9d2503978d777fe773b9a2a0357a797adbc77ac0e9bc0cbab37b3a8f6a42227bebf181004f9a55b6a557783c9150d9408792bd73b1c0071b31c23f3c8ec18d5749d46ea0c431e73fcc8c64a57426402cce9917d7809d94687318a39ee27b01ef9041001401f889e436d3d48fbdde1072b7533b0d00f6a13d0bb0bb94020ca9b77c93d42d5f3\",\"570861a8c14df0b19f6b8159131bef4259338ef6faeab481b6c14e1fc7e57ede571e3698f89c9a08ee9d91c58d594fbc2cd98fff4a483d360c1ecc703820361854061b8a516ce86ca82e8a2e1653f3b25b9d710f6f4e84b8e991450126171f0baa1ac2bfd87653b31f7c30619b6ad9684b48b2dde399c229bed057984415ba552a606eb1ab2b4324adf3826b9c9844f1ecc5634d197877f29626fe59399e739e5f73e502d2fb6a0a016862008583125ec0cfd9c18a3f183ed493d1f5bf236f6a3f7ce345998afae9f963bfee2f705a8df3c253407708fa92091d34d6da6f487d8e7df7b38fbf4e919fa093f64b8782e5e96372080006b9b982013aaffa9c0c58\",\"282184ad00cbc48211eb828e33462bd6c87c53f05c98395e2a0b58924732f25a947c8524c2b09dfcab1d6f70730c4684e11a6b0911199d9562be52872463d51091455b792398e56521d90387077f8948c894707d5cfb42ce3b155f65fb7b80575906a5af2e1b663455d8cd898d743bc727a06c3febdf5f55489d9372da4fbfb516e09faa15a9da0008037f6afb90531a34f08a0ff1b843fd3e0b2c20a8458f767ae85925de160facad7014c96f3f3dd39b2511475fde6ae09476def71fb7ba6c072dc33d2e468f31b55ecbc08c50ddbafe710748cc7d72f509260cceee5171f6b8b0c257ffe5bfa2d09c76265bb54672792c22a137111b9b5e1835ecf8decdde\",\"8813fd4a00617a1ed4ab79662a155535bee18bda39897bef30a0273c5e9e880560b6020b272c23e966fcd03ecebf51bb725c8bbae1ff13762a3bf2e6388e0e3d818a47db0e38fb92bc8e1736804349399ad0ab2d057ee577d6206f69df914868c337c68030a77a0dce18d2793fa971eb4c2a9d56980e77ad5ff52679cfdd69972579402d9a1078060f2a760c7a6363d85c6652049cda386612b0362559f691e95c2ce9a4ce279f977dc9b9fa51d58e42f3bba5c95b07256f86453dd745acfef156f5369c8b1c8b3f240982e0ac52ebe5bd3d1aeeb8cb9daeac84aaaa1fd789d06c4644d4d6adf8ac088d65ca401cb58f489d7a31c9b8f00ffd53671901718736\",\"45109996a12ccb5a4af7a33872bd4526266acb2b6fb62de70d1ffa6ee9f642e32dca886d4d178c1b41e10c8a919d1eabe525835e66488d402215e7906d9c853a4a410f85121cfdcc5673e0487c40442d18649cbee8f032134431344c4a94622ab8e374644efac7e188dc3ebfa5ba7d76af30acb2e7465aae40454594f9313ff845c109eb00deca6cf949f3d612eee279e3a3ccd393901043dea0eb07b6568741adce54fc268becb522824a0acc2861c123bc21d70392e037fdbfe46c35b4e85581ffb231e8a3ecf46fe8cea69759113345beb1a5aaf22121b4c5de5ced09e7037467461c6a3f6f4e821a8ee43da3b6bbd3d9bc07f3f854c82a80ab9721dd6830\",\"62ba72d6c9a6403e14a5f49f8dcdd003fa7c01feefbdc17fbc7a40b4c562eb2f2e6f068e05a8e7e5120de1ea350d244c2fe7ec0f2149797d61232cad298859b59ecdf3a6fa270190f25346c04a99ea285ecc4666c6e58f29f6b9e5d2c0929f75a4bdea81641d8d001cd44a5382a1c79856c19b19a8d1e13f5a3230f0e928e5b93e5fdebefde559c29f02f153dfb0ca911102b1d03bf094d799e5e39cc58abd186053f050c7db2646517016763ab185b8d9316ddfc15ae71063159e57d6bc9f548700c7f01c62d2e9b49671ba54d79d9b8b901978056bc13627e17d44fce53c004c6df4e8e225da1f75d2f385b16d8ee2687cfe56934644dad5abc8e3cdcce64d\",\"9a47120575204c8f76a980b4733ffc69dbc34959ca8f565ac277b55985b8b4d9cd3f4887d59ef0f5d2d0b8bb1f10d8fdcd167935380367592a895d134928931dd85f66e4253ec4d3e4a2c1b5ba5b2af4ef0d20c394c8b1526c6010458cd3023f32ce32b917322cee3315d633bfb2f8e16b69cfe362c6df3963bc95b6bfb60661e613e76e0b3a6c3c06c49f26de09343ac38a66a4d1cae8496d4b82a78b9b7f2f2097182812b5d5ab4bf8950f49f1f553584b7aa993cfe1c96d8fd78a2d9201f42af6f56c2ed6373925e2b5cc8ff4dc1e238ccce1754c792ac82a61d45fba4898b3bb6372e7827616b06353535457f6366eaa2d42b7a167e2be4ee086699a1b41\",\"31ad95d0e1ef37d078f0ef74fb6fe8f9ea47db0aa31e78a37420e7ad9bd1b2bca058efb395885d2fea08106ef8ffa898e19be1f562665b2514c4b7cea39fc678449c7c103cd2dc8d8f980dd3b926a6532e113d25d1a9a891e374a33ae0dc21691fc4a4db7c638585158f516d5fb592c540ae2b6266a81905909c3b1fbdc22e248ea3d0e5f0895112769581509581d749486137f057c6b0fc77fd4784da9904250e7f5fe088fe4ced7451bae6829a2b9c8286cbac4e4171caf4e2089edc754912392b906062e101344fe51841c391e4bb7f2d672be01ddb3fae68b44f0c02000ad3cb0be7af954fcca4ed3f19ebcdca8acccaa60e03c035b196eec87ece42f50\",\"3054c555c41509b39eccc86bbf80bade7eb18e8a694947ca4f7ebf0ef309dc4a35690fe2e3fc8a76db33fb5e6554a52f73d32da987d768a220bdff621a54c83aa382092658f6657c95c767456682d5da2aff4a53a0958ce4a7dae61262c1f47e365d52d7981541ea0ed3a00a0c30bad31a6738bc19a254bf78dac870f604aeca1766b9ea5dc1e239819b8b07f02d5d176065bfa087ce000a581b1f92011309d0bb0f0e10d98877a4279e7d56460b40ad9c2909226c510b3938f92459b11a33c3e6c8637b66d8ce6bd81e04e0cfc166cb9fa90622df20482a7d8ac3c3d8877b0477ba41152500c88bf554fa81ac4f1c44a04b814f42104c012dd6b75e10f13271\"]}".to_string()).unwrap();
        api_childkey_creator
            .verify_paillier(&paillier_pk, &correct_key_proof)
            .unwrap();
    }

    #[test]
    fn test_api_childkey_creation_k1_ok() {
        let secret_key =
            BigInt::from_hex("4794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1")
                .unwrap();
        let mut api_childkey_creator = APIchildkeyCreator::init(&secret_key);
        let paillier_pk = EncryptionKey::from(MinimalEncryptionKey{n: BigInt::from_hex("9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129").unwrap()});
        let correct_key_proof: CorrectKeyProof = serde_json::from_str(&"{\"sigma_vec\":[\"14f21d17357e5d0d8d2cb3cf6d0b9439323473be7e1f68db541b77450f87a20941640bf8a317d4ea6272b12923449e73ea5598a6197219fb6c7ca416a3552301c9cc5b47580ce35e4c9e37a97ec0bdbe2b48c2db21cde5bcef9fc04c6e767c59c0500929b76f87901e5a4d8adb38097c44ed790a0ae2e9f6985823f1789aa47a8298d02763751b73942bbee79c4544f9bd2b82e405f15d801cb41d4831012f99172ef49fee6ea33599caadcdb89c1eb768e30b11878f37e12d232b624cbe589a7767af46d958632574535893c0337858399aed65638b97bcaddee45e40fe79a5014fcd1e398b19807439f58236373197653a8ea82ab3a84173d5a8d45bcae823\",\"32beda264c7fde6cb41d48ce44e6e93af5ed0e1cb5c7cd29f7fa3cbf72b78b9bc3e5267c4f9a75de40eb95a4bdc73dd1d8a435799daf2365f9377aed3c4524016d2ea58002c66fd0a8bcb8e74bac9923b723bc9f8752f82d9cba8bec4f414f314a40842031427b0bb8cdc514bfb61a5f85a51d8b7a290ccbd1000af937a6a7fd7a6070ba40a6801a2909e11d71a773958195d82f72995e69b989ab91207b68ac891e6585848f7aea80e1a0693427a0a512c0cbfbfe5d9ffe02462856ca918af9ebd2ad2f9b44a84b628ec7a7ed4d7232e72c52f2af5ef8988e3c09715fbe1a0af871109028335fb95370ae3e7ecf646063c1914ceeff8cf22ca06d250f02904c\",\"27236e62e810849d58c24b57d2061be4223a175224a89b94ce1261ae9f7a61ec058a43589c83aa3029e61c488fa33b0ea8fb72c36f4b3f962f858f4b0dd822a2810124cba42c8c2a42046b324a3c0712799979be7da1e6dff82c466149484246769f43683231ba8a89185587086cef1de589a4d59b74ac20fcbe0310403f9347417a4c8a8b90b78671d265471fe5ca839e509d4b6f5c2ec33ae255abf54aa12700772a174074048bc4edecc142c268b765f8bf4c0ab7b253882f77c1cb0e410e8e21a23ba364ec37adee59e0395920ab403ab77f095ed8bda39fad9b00886c9e2682a8314bd71fc2db9d2b2a8476ac295c262ba16d4657c62af9bb6a4729c214\",\"974e6e3a63e90275733cbf0b1516d940f0b0c8bd6140f16abb22988289b88b327c5a3e2a1de6d00f03e6f78ee934da02590ee45c6b4c0c8f53ccf6adc35cd0e9ee73f5ad88c8b8bc5b2a489c6e2b900cdc5c2b8ef0aaeb4a99dae6bac9a4bbeb12ceacbafc181a43f9176e503d71100b39b71e5f3975daffd3735b8d26c0b3ae43a92737373730bb22bdc3c06b8b281da79a6994c4c21dda8b89e2a0c9767efa559c895da05e127935b4d33eb1e2acab29cd096e5ed73a4812f86f8839aff7ab8e0baff3535098f1cdddb4ae14e1e7eb702674b4bd8253fefe3bd4245afd6dcb365de617df815ff0cc761415f7001a4149825c50626ebbd0aeeb92172be401e2\",\"43e75be1f60bc68a05aaceea143aa14498880ce8ab1417621f7041d8dd76a80e16484e07580060033bb6eeb67a516215f2bdbdcf2bbbe327ae22000b342a51cafe49ea50ce0b459d5e8334b84de284227a3d504d5fcde913b08b27c6997a27b9a307d132379e0688ce6c38f418b1e94ad87b85e86ab48374d736a7c2f402016255b728c258d945591760a314ebc0e98411fdf3c73e6ed8fd7e23cb1cab8a0517d79a33c27de6548be0ab506db1c2b4b573faf7bcb817cbf0d489da9c168a8c8e6bb4ba0edbfcd1fd01f5eddb89ac84d7a218d83635e354e77619725be00426aaaae90221b65c063ef479184599036182098f3e623a57567ff52172fcd0463e23\",\"70ab52b4bde2f26ba9603b1d211ab94ce95d84a8f09fbb1817700897bc1beb4b3bfe24850f61751204cec784ddd182e5a4432a8d6f48ff475a58d4e63ddc70de5b68a4ee392384031d2b3f352a74c5b8b9fe6f8113a046dcab29b6a168203031d783a4321a7d3f2e971761164454af67367c51a4d46218f817034705c3b013162b83b609647944dd7173e37d02f04b0aef42d1ad2f53902b3e88ccf2523c8526b50b3e47a9d51673992d69ed1f0ac39849b473c1ca0fdb5c34c9b344cf820a3b6566d3db80fb0d6646646080e19bf1448f8859ac1c0275c863950779cd22d248a358a3edb4e60676b4ec353d62c25f7b8c836293108be03a353ea8815c3dba9c\",\"84fb3dcc1348efc024c59df79e69c33d0d67d3f7af328cf0af6048d0080862f0ad0eae3bb676851b58b22db6e7c46474cb6aed94a73b35caf65e0c9f36743f55853bbc1d895649435edfeff25977e8130133078577d547c67c8d31236e1dbcac18252f71fac884078e229f97a7b451391f501b85266252137674f898ab9afb505d4f1ca7455e2339ee992395afd3c9a5cb8724733bdb40ed625932106b47dfe890bdea045178a46dffa1608a1ef01b4dda7a7381ee24f4c10fd63b84b1ece8c425435992f567c709d21324aa50a751042fc4cd2afc283ddb8b2867a694945337fe985a2090e45a8df28c68c828a0e6bae3d18f9a8251dbf46e4e7898feb23ca6\",\"23346102965ad3e6d474ac60f0fb4154dff2bf4250204390db22560f1ffcf47047489c38f02708c9776ed349078bcf7822c2bf50e0af9999a610d69e6f14e3d2ff138e706fbad8359bf496d2519ee900a04ac69eaa7e26bb11e4f302288221889bc58ce20608829db11fbc0a64ad066d7cd1704ae730d954dd84a1a35fb03dfab608b8e483d05ad71c2f6e2e38f59afe3005b60d508383ef160f23aed233bf76e108e3d0e3e6a87032b5b6b7b14f50c5b40aeefde5811ea5fa8a601124370b3d58ebca0906fa0ce72e90a23d713d3d74f2d59256d043011c6b350ebb664ba0a96ae7a5611d71f03d60b60d75e328f6a086aa1932f58026a20c3c3ac4f797587e\",\"12786ce1db47ed46d0bd326d844d3c611f9816b59817fb32a0729d4eb7c3975442410b86f5054d3de4be3f9ba442f0750aa0f284269c57e73ad7c644d3182a3ed26f46462ac687287260117abca70255461dc728adced54b9da10206a88fd213dc423ecc7db4842c3b4ff031ee8eb16304178f4e8eaed9db3e2f6c150dca1532a0a6d8e455cf13e7b4beed736ac8525b84b213ba96fced8ab8a9f47d5cdc8fe02e7eede3f417d2dc07ea10eea71486d3b1f9a0b9d6612efc83908702e6b77499a4861d770d136440962c0b35148b4a1af55989b94509a0ca765bdf1fee850eb175be5676581be779c94192a0326513a768c326fa67a202e66d0eaa70a91932d6\",\"354fd63ff01cf79fd2c90928231e364195a4b6c1d7874011ab6440b583f7027990c37eb4a9bd0125c31a61c31bbed0e36850261df09d5395a1885e5faf9f7bbdff0e545495f7e4761894493ace3de65ca7135a2a751aa2f40d21907bdcf65cec2fa896e457eb02889b0e3e8a5bcfdf133847ccec39c886823aef9f7f2ef9650345324efd55d0fc2e349cebffd6b7a542d4b9db9a4353e30da8f4e9aacd35ff5023180d34488261ba80413fd0cb56257db3e543f72e6d2bd82776e24d2db62107f83d6169fbf63eecfb1b33e58058bff6c0a04a6605d14f3ea77c4959293a19c3309e55d86d1ce1d308967bd2b550fbe2df0219444801d842fab7f6b0f26436e4\",\"61186ef51490cf59e822d5e3f84561ffb4f0b921c205581540ac13d8f978765791ab43942dcf470eac454dc13ce375df68bee5e152ee048fd14c5b6edfc053c2d548008e29a50fcf392069e9fe851fcc58c0f3f4ecd14d2885b9940b2a7bc7cc2818910fef3800a7dcf7e7f5a58905fcaedbf7fcd0dbff40293a403148cffedf1a5730554a10a1eed001cfbad38c4051b2a640a79271e43aae09e7733fe3b881fdba14cd397af91a1499f40069f47f65a0bc167d4c66ab5d8c0fcde37383911f75b4d3207a8a5c4dfa6ecf610c6ac20da6e96c0cd691c0642c8bb7a6be2837785774f4bbaac2529bf5291c94ab49961373e8991eb2018aa9d93529f66dd7695a\"]}".to_string()).unwrap();
        api_childkey_creator = api_childkey_creator
            .verify_paillier(&paillier_pk, &correct_key_proof)
            .unwrap();
        let api_childkey_creator_verified =
            APIchildkeyCreator::init_with_verified_paillier(&secret_key, &paillier_pk);
        assert_eq!(api_childkey_creator, api_childkey_creator_verified);
        assert_ne!(
            api_childkey_creator
                .create_api_childkey(Curve::Secp256k1)
                .unwrap(),
            api_childkey_creator_verified
                .create_api_childkey(Curve::Secp256k1)
                .unwrap()
        );
    }

    #[test]
    fn test_api_childkey_creation_r1_ok() {
        let secret_key =
            BigInt::from_hex("4794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1")
                .unwrap();
        let mut api_childkey_creator = APIchildkeyCreator::init(&secret_key);
        let paillier_pk = EncryptionKey::from(MinimalEncryptionKey{n: BigInt::from_hex("9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129").unwrap()});
        let correct_key_proof: CorrectKeyProof = serde_json::from_str(&"{\"sigma_vec\":[\"14f21d17357e5d0d8d2cb3cf6d0b9439323473be7e1f68db541b77450f87a20941640bf8a317d4ea6272b12923449e73ea5598a6197219fb6c7ca416a3552301c9cc5b47580ce35e4c9e37a97ec0bdbe2b48c2db21cde5bcef9fc04c6e767c59c0500929b76f87901e5a4d8adb38097c44ed790a0ae2e9f6985823f1789aa47a8298d02763751b73942bbee79c4544f9bd2b82e405f15d801cb41d4831012f99172ef49fee6ea33599caadcdb89c1eb768e30b11878f37e12d232b624cbe589a7767af46d958632574535893c0337858399aed65638b97bcaddee45e40fe79a5014fcd1e398b19807439f58236373197653a8ea82ab3a84173d5a8d45bcae823\",\"32beda264c7fde6cb41d48ce44e6e93af5ed0e1cb5c7cd29f7fa3cbf72b78b9bc3e5267c4f9a75de40eb95a4bdc73dd1d8a435799daf2365f9377aed3c4524016d2ea58002c66fd0a8bcb8e74bac9923b723bc9f8752f82d9cba8bec4f414f314a40842031427b0bb8cdc514bfb61a5f85a51d8b7a290ccbd1000af937a6a7fd7a6070ba40a6801a2909e11d71a773958195d82f72995e69b989ab91207b68ac891e6585848f7aea80e1a0693427a0a512c0cbfbfe5d9ffe02462856ca918af9ebd2ad2f9b44a84b628ec7a7ed4d7232e72c52f2af5ef8988e3c09715fbe1a0af871109028335fb95370ae3e7ecf646063c1914ceeff8cf22ca06d250f02904c\",\"27236e62e810849d58c24b57d2061be4223a175224a89b94ce1261ae9f7a61ec058a43589c83aa3029e61c488fa33b0ea8fb72c36f4b3f962f858f4b0dd822a2810124cba42c8c2a42046b324a3c0712799979be7da1e6dff82c466149484246769f43683231ba8a89185587086cef1de589a4d59b74ac20fcbe0310403f9347417a4c8a8b90b78671d265471fe5ca839e509d4b6f5c2ec33ae255abf54aa12700772a174074048bc4edecc142c268b765f8bf4c0ab7b253882f77c1cb0e410e8e21a23ba364ec37adee59e0395920ab403ab77f095ed8bda39fad9b00886c9e2682a8314bd71fc2db9d2b2a8476ac295c262ba16d4657c62af9bb6a4729c214\",\"974e6e3a63e90275733cbf0b1516d940f0b0c8bd6140f16abb22988289b88b327c5a3e2a1de6d00f03e6f78ee934da02590ee45c6b4c0c8f53ccf6adc35cd0e9ee73f5ad88c8b8bc5b2a489c6e2b900cdc5c2b8ef0aaeb4a99dae6bac9a4bbeb12ceacbafc181a43f9176e503d71100b39b71e5f3975daffd3735b8d26c0b3ae43a92737373730bb22bdc3c06b8b281da79a6994c4c21dda8b89e2a0c9767efa559c895da05e127935b4d33eb1e2acab29cd096e5ed73a4812f86f8839aff7ab8e0baff3535098f1cdddb4ae14e1e7eb702674b4bd8253fefe3bd4245afd6dcb365de617df815ff0cc761415f7001a4149825c50626ebbd0aeeb92172be401e2\",\"43e75be1f60bc68a05aaceea143aa14498880ce8ab1417621f7041d8dd76a80e16484e07580060033bb6eeb67a516215f2bdbdcf2bbbe327ae22000b342a51cafe49ea50ce0b459d5e8334b84de284227a3d504d5fcde913b08b27c6997a27b9a307d132379e0688ce6c38f418b1e94ad87b85e86ab48374d736a7c2f402016255b728c258d945591760a314ebc0e98411fdf3c73e6ed8fd7e23cb1cab8a0517d79a33c27de6548be0ab506db1c2b4b573faf7bcb817cbf0d489da9c168a8c8e6bb4ba0edbfcd1fd01f5eddb89ac84d7a218d83635e354e77619725be00426aaaae90221b65c063ef479184599036182098f3e623a57567ff52172fcd0463e23\",\"70ab52b4bde2f26ba9603b1d211ab94ce95d84a8f09fbb1817700897bc1beb4b3bfe24850f61751204cec784ddd182e5a4432a8d6f48ff475a58d4e63ddc70de5b68a4ee392384031d2b3f352a74c5b8b9fe6f8113a046dcab29b6a168203031d783a4321a7d3f2e971761164454af67367c51a4d46218f817034705c3b013162b83b609647944dd7173e37d02f04b0aef42d1ad2f53902b3e88ccf2523c8526b50b3e47a9d51673992d69ed1f0ac39849b473c1ca0fdb5c34c9b344cf820a3b6566d3db80fb0d6646646080e19bf1448f8859ac1c0275c863950779cd22d248a358a3edb4e60676b4ec353d62c25f7b8c836293108be03a353ea8815c3dba9c\",\"84fb3dcc1348efc024c59df79e69c33d0d67d3f7af328cf0af6048d0080862f0ad0eae3bb676851b58b22db6e7c46474cb6aed94a73b35caf65e0c9f36743f55853bbc1d895649435edfeff25977e8130133078577d547c67c8d31236e1dbcac18252f71fac884078e229f97a7b451391f501b85266252137674f898ab9afb505d4f1ca7455e2339ee992395afd3c9a5cb8724733bdb40ed625932106b47dfe890bdea045178a46dffa1608a1ef01b4dda7a7381ee24f4c10fd63b84b1ece8c425435992f567c709d21324aa50a751042fc4cd2afc283ddb8b2867a694945337fe985a2090e45a8df28c68c828a0e6bae3d18f9a8251dbf46e4e7898feb23ca6\",\"23346102965ad3e6d474ac60f0fb4154dff2bf4250204390db22560f1ffcf47047489c38f02708c9776ed349078bcf7822c2bf50e0af9999a610d69e6f14e3d2ff138e706fbad8359bf496d2519ee900a04ac69eaa7e26bb11e4f302288221889bc58ce20608829db11fbc0a64ad066d7cd1704ae730d954dd84a1a35fb03dfab608b8e483d05ad71c2f6e2e38f59afe3005b60d508383ef160f23aed233bf76e108e3d0e3e6a87032b5b6b7b14f50c5b40aeefde5811ea5fa8a601124370b3d58ebca0906fa0ce72e90a23d713d3d74f2d59256d043011c6b350ebb664ba0a96ae7a5611d71f03d60b60d75e328f6a086aa1932f58026a20c3c3ac4f797587e\",\"12786ce1db47ed46d0bd326d844d3c611f9816b59817fb32a0729d4eb7c3975442410b86f5054d3de4be3f9ba442f0750aa0f284269c57e73ad7c644d3182a3ed26f46462ac687287260117abca70255461dc728adced54b9da10206a88fd213dc423ecc7db4842c3b4ff031ee8eb16304178f4e8eaed9db3e2f6c150dca1532a0a6d8e455cf13e7b4beed736ac8525b84b213ba96fced8ab8a9f47d5cdc8fe02e7eede3f417d2dc07ea10eea71486d3b1f9a0b9d6612efc83908702e6b77499a4861d770d136440962c0b35148b4a1af55989b94509a0ca765bdf1fee850eb175be5676581be779c94192a0326513a768c326fa67a202e66d0eaa70a91932d6\",\"354fd63ff01cf79fd2c90928231e364195a4b6c1d7874011ab6440b583f7027990c37eb4a9bd0125c31a61c31bbed0e36850261df09d5395a1885e5faf9f7bbdff0e545495f7e4761894493ace3de65ca7135a2a751aa2f40d21907bdcf65cec2fa896e457eb02889b0e3e8a5bcfdf133847ccec39c886823aef9f7f2ef9650345324efd55d0fc2e349cebffd6b7a542d4b9db9a4353e30da8f4e9aacd35ff5023180d34488261ba80413fd0cb56257db3e543f72e6d2bd82776e24d2db62107f83d6169fbf63eecfb1b33e58058bff6c0a04a6605d14f3ea77c4959293a19c3309e55d86d1ce1d308967bd2b550fbe2df0219444801d842fab7f6b0f26436e4\",\"61186ef51490cf59e822d5e3f84561ffb4f0b921c205581540ac13d8f978765791ab43942dcf470eac454dc13ce375df68bee5e152ee048fd14c5b6edfc053c2d548008e29a50fcf392069e9fe851fcc58c0f3f4ecd14d2885b9940b2a7bc7cc2818910fef3800a7dcf7e7f5a58905fcaedbf7fcd0dbff40293a403148cffedf1a5730554a10a1eed001cfbad38c4051b2a640a79271e43aae09e7733fe3b881fdba14cd397af91a1499f40069f47f65a0bc167d4c66ab5d8c0fcde37383911f75b4d3207a8a5c4dfa6ecf610c6ac20da6e96c0cd691c0642c8bb7a6be2837785774f4bbaac2529bf5291c94ab49961373e8991eb2018aa9d93529f66dd7695a\"]}".to_string()).unwrap();
        api_childkey_creator = api_childkey_creator
            .verify_paillier(&paillier_pk, &correct_key_proof)
            .unwrap();
        let api_childkey_creator_verified =
            APIchildkeyCreator::init_with_verified_paillier(&secret_key, &paillier_pk);
        assert_eq!(api_childkey_creator, api_childkey_creator_verified);
        assert_ne!(
            api_childkey_creator
                .create_api_childkey(Curve::Secp256r1)
                .unwrap(),
            api_childkey_creator_verified
                .create_api_childkey(Curve::Secp256r1)
                .unwrap()
        );
    }

    #[test]
    fn test_compute_presig_k1() {
        // need a mutex around the paillier pool to allow our assertions to hold
        let _shared = PAILLIER_POOL_LOCK.lock();
        let paillier_pk = EncryptionKey::from(MinimalEncryptionKey{n: BigInt::from_hex("9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129").unwrap()});
        assert_eq!(get_rpool_size(Curve::Secp256k1).unwrap(), 0);
        assert_eq!(POOL_PAILLIER.lock().unwrap().len(), 0);
        let dh_secret: Secp256k1Scalar = ECScalar::from(
            &BigInt::from_hex("8ea92bf3aa6f4ec4939b0888cd71dc6dc113f9cafe571c0bb501c8c9004bb47c")
                .unwrap(),
        );
        let dh_public = Secp256k1Point::from_bigint(
            &BigInt::from_hex("34bfa8dd79ff0777e32b89f22a19623ff4fe6fe63aaeb3e2d165fc12cbb2471db")
                .unwrap(),
        )
        .unwrap();
        let dh_public_vec = vec![dh_public];
        fill_rpool_secp256k1(vec![dh_secret.clone()], &dh_public_vec, &paillier_pk).unwrap();
        assert_eq!(get_rpool_size(Curve::Secp256k1).unwrap(), 1);
        assert_eq!(POOL_PAILLIER.lock().unwrap().len(), 1);
        let msg_hash =
            BigInt::from_hex("000000000000000fffffffffffffffffff00000000000000ffffffffff000000")
                .unwrap();
        let secret_key =
            BigInt::from_hex("4794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1")
                .unwrap();
        let api_childkey_creator =
            APIchildkeyCreator::init_with_verified_paillier(&secret_key, &paillier_pk);
        let api_childkey = api_childkey_creator
            .create_api_childkey(Curve::Secp256k1)
            .unwrap();
        let (presig1, r) = compute_presig(&api_childkey, &msg_hash, Curve::Secp256k1).unwrap();
        assert_eq!(
            r,
            BigInt::from_hex("3703d86c98836a6ef32371e1b91ed2ca64bd6d7a0774631f47ffebc49406c94ac")
                .unwrap()
        );
        assert_eq!(POOL_PAILLIER.lock().unwrap().len(), 0);
        fill_rpool_secp256k1(vec![dh_secret], &dh_public_vec, &paillier_pk).unwrap();
        assert_eq!(POOL_PAILLIER.lock().unwrap().len(), 1);
        let (presig2, _) = compute_presig(&api_childkey, &msg_hash, Curve::Secp256k1).unwrap();
        assert_ne!(presig1, presig2);
        assert_eq!(POOL_PAILLIER.lock().unwrap().len(), 0);
    }

    #[test]
    fn test_compute_presig_r1() {
        // need a mutex around the paillier pool to allow our assertions to hold
        let _shared = PAILLIER_POOL_LOCK.lock();
        let paillier_pk = EncryptionKey::from(MinimalEncryptionKey{n: BigInt::from_hex("9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129").unwrap()});
        assert_eq!(get_rpool_size(Curve::Secp256r1).unwrap(), 0);
        //assert_eq!(POOL_PAILLIER.lock().unwrap().len(), 0);
        let dh_secret: Secp256r1Scalar = ECScalar::from(
            &BigInt::from_hex("EAB592977DF1A8E7D77DB58F4DAE73C860920D28B763A0737217D3793563D53E")
                .unwrap(),
        );
        let dh_public = Secp256r1Point::from_bigint(
            &BigInt::from_hex("2366a21b029c2e4d627ac5f7e94769ed1b28727f2403b54c8deb076661cd685ae")
                .unwrap(),
        )
        .unwrap();
        let dh_secret_vec = vec![dh_secret];
        let dh_public_vec = vec![dh_public];
        fill_rpool_secp256r1(dh_secret_vec.clone(), &dh_public_vec, &paillier_pk).unwrap();
        assert_eq!(get_rpool_size(Curve::Secp256r1).unwrap(), 1);
        //assert_eq!(POOL_PAILLIER.lock().unwrap().len(), 1);
        let msg_hash =
            BigInt::from_hex("000000000000000fffffffffffffffffff00000000000000ffffffffff000000")
                .unwrap();
        let secret_key =
            BigInt::from_hex("4794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1")
                .unwrap();
        let api_childkey_creator =
            APIchildkeyCreator::init_with_verified_paillier(&secret_key, &paillier_pk);
        let api_childkey = api_childkey_creator
            .create_api_childkey(Curve::Secp256r1)
            .unwrap();
        let (presig1, r) = compute_presig(&api_childkey, &msg_hash, Curve::Secp256r1).unwrap();
        assert_eq!(
            r,
            BigInt::from_hex("306978b9dd8d1438387f3e1e58ecec203c61ac0c848834ed094ebef5547b74fda")
                .unwrap()
        );
        //assert_eq!(POOL_PAILLIER.lock().unwrap().len(), 0);
        fill_rpool_secp256r1(dh_secret_vec.clone(), &dh_public_vec, &paillier_pk).unwrap();
        //assert_eq!(POOL_PAILLIER.lock().unwrap().len(), 1);
        let (presig2, _) = compute_presig(&api_childkey, &msg_hash, Curve::Secp256r1).unwrap();
        assert_ne!(presig1, presig2);
        //assert_eq!(POOL_PAILLIER.lock().unwrap().len(), 0);
    }

    #[test]
    fn test_encrypt_secrate_share() {
        let secret_key =
            BigInt::from_hex("4794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1")
                .unwrap();
        let paillier_pk = EncryptionKey::from(MinimalEncryptionKey{n: BigInt::from_hex("9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129").unwrap()});
        let secret_share_encrypted1 = encrypt_secret_share(&paillier_pk, &secret_key);
        let secret_share_encrypted2 = encrypt_secret_share(&paillier_pk, &secret_key);
        assert_ne!(secret_share_encrypted1, secret_share_encrypted2);
    }

    #[test]
    fn test_sign() {
        let sk: Secp256k1Scalar = ECScalar::from(
            &BigInt::from_hex("4794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1")
                .unwrap(),
        );
        let msg_hash =
            BigInt::from_hex("100000000000000fffffffffffffffffff00000000000000ffffffffff000000")
                .unwrap();
        let signature = sign(&sk, &msg_hash);
        assert!(verify(
            &signature.0,
            &signature.1,
            &publickey_from_secretkey(&sk.to_big_int(), Curve::Secp256k1).unwrap(),
            &msg_hash,
            Curve::Secp256k1
        )
        .unwrap());
    }
}
