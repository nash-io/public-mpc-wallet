/*
 * Server functions for MPC-based API keys
 */

use crate::common::{correct_key_proof_rho, CorrectKeyProof, Curve, PAILLIER_KEY_SIZE};
use crate::curves::secp256_k1::{Secp256k1Point, Secp256k1Scalar};
use crate::curves::secp256_r1::{Secp256r1Point, Secp256r1Scalar};
use crate::curves::traits::{ECPoint, ECScalar};
use bigints::traits::{BitManipulation, Converter, Modulo, ZeroizeBN};
use bigints::BigInt;
#[cfg(feature = "num_bigint")]
use num_integer::Integer;
use paillier::{
    extract_nroot, Decrypt, DecryptionKey, EncryptionKey, KeyGeneration, Paillier, RawCiphertext,
};
use rayon::iter::{IntoParallelRefMutIterator, ParallelIterator};
use std::cmp;
use std::collections::HashMap;

/// generate paillier keypair
pub fn generate_paillier_keypair() -> (EncryptionKey, DecryptionKey) {
    Paillier::keypair_safe_primes_with_modulus_size(PAILLIER_KEY_SIZE).keys()
}

/// generate proof that paillier key was generated correctly
pub fn generate_paillier_proof(paillier_sk: &DecryptionKey) -> CorrectKeyProof {
    let n = &paillier_sk.p * &paillier_sk.q;
    let rho = correct_key_proof_rho(&n);
    let sigma_vec = correct_key_proof_sigma(&paillier_sk, &rho);
    CorrectKeyProof { sigma_vec }
}

/// compute r_pool-values for secp256r1
pub fn compute_rpool_secp256r1(
    server_dh_secrets: &[Secp256r1Scalar],
    client_dh_publics: &[Secp256r1Point],
) -> Result<HashMap<String, Secp256r1Scalar>, ()> {
    if server_dh_secrets.len() != client_dh_publics.len() {
        return Err(());
    }
    let mut rpool_new = HashMap::new();
    let mut tmp = vec!["0".to_string(); server_dh_secrets.len()];
    for (i, item) in tmp.iter_mut().enumerate().take(server_dh_secrets.len()) {
        *item = i.to_string();
    }
    // execute scalar multiplication in parallel
    tmp.par_iter_mut().for_each(|i| {
        *i = format!(
            // use strings with leading zeros for ME
            "{:0>66}",
            client_dh_publics[i.parse::<usize>().unwrap()]
                .scalar_mul(&server_dh_secrets[i.parse::<usize>().unwrap()].get_element())
                .bytes_compressed_to_big_int()
                .to_hex()
        )
    });
    for i in 0..server_dh_secrets.len() {
        rpool_new.insert(tmp[i].clone(), server_dh_secrets[i].clone());
    }
    Ok(rpool_new)
}

/// compute r_pool-values for secp256k1
pub fn compute_rpool_secp256k1(
    server_dh_secrets: &[Secp256k1Scalar],
    client_dh_publics: &[Secp256k1Point],
) -> Result<HashMap<String, Secp256k1Scalar>, ()> {
    if server_dh_secrets.len() != client_dh_publics.len() {
        return Err(());
    }
    let mut rpool_new = HashMap::new();
    let mut tmp = vec!["0".to_string(); server_dh_secrets.len()];
    for (i, item) in tmp.iter_mut().enumerate().take(server_dh_secrets.len()) {
        *item = i.to_string();
    }
    // execute scalar multiplication in parallel
    tmp.par_iter_mut().for_each(|i| {
        *i = format!(
            // use strings with leading zeros for ME
            "{:0>66}",
            client_dh_publics[i.parse::<usize>().unwrap()]
                .scalar_mul(&server_dh_secrets[i.parse::<usize>().unwrap()].get_element())
                .bytes_compressed_to_big_int()
                .to_hex()
        )
    });
    for i in 0..server_dh_secrets.len() {
        let to_insert = server_dh_secrets[i].clone();
        rpool_new.insert(tmp[i].clone(), to_insert);
    }
    Ok(rpool_new)
}

/// complete presignature to conventional ECDSA signature
pub fn complete_sig(
    paillier_sk: &DecryptionKey,
    presig: &BigInt,
    r: &BigInt,
    k: &BigInt,
    curve: Curve,
) -> Result<(BigInt, BigInt, u8), ()> {
    let q: BigInt;
    let rx: BigInt;
    let ry: BigInt;
    if curve == Curve::Secp256k1 {
        let r_point = match Secp256k1Point::from_bigint(&r) {
            Ok(v) => v,
            Err(_) => return Err(()),
        };
        q = Secp256k1Scalar::q();
        rx = r_point.x_coor().unwrap().mod_floor(&q);
        ry = r_point.y_coor().unwrap().mod_floor(&q);
    } else if curve == Curve::Secp256r1 {
        let r_point = match Secp256r1Point::from_bigint(&r) {
            Ok(v) => v,
            Err(_) => return Err(()),
        };
        q = Secp256r1Scalar::q();
        rx = r_point.x_coor().unwrap().mod_floor(&q);
        ry = r_point.y_coor().unwrap().mod_floor(&q);
    } else {
        return Err(());
    }
    let (s, recid) = complete_sig_curveindependent(&paillier_sk, &presig, &k, &rx, &ry, &q);
    Ok((rx, s, recid))
}

fn complete_sig_curveindependent(
    paillier_sk: &DecryptionKey,
    presig: &BigInt,
    k: &BigInt,
    rx: &BigInt,
    ry: &BigInt,
    q: &BigInt,
) -> (BigInt, u8) {
    let mut s_tag = Paillier::decrypt(paillier_sk, &RawCiphertext::from(presig))
        .0
        .into_owned();
    let mut k_inv = BigInt::mod_inv(&k, &q);
    let s_tag_tag = BigInt::mod_mul(&k_inv, &s_tag, &q);
    k_inv.zeroize_bn();
    s_tag.zeroize_bn();
    let s = cmp::min(s_tag_tag.clone(), q.clone() - s_tag_tag.clone());
    // compute recovery id that allows to uniquely derive the public key from the signature
    let mut recid = if rx > q { 2 } else { 0 } | if ry.test_bit(0) { 1 } else { 0 };
    if s_tag_tag > q / 2 {
        recid ^= 1;
    }
    // recovery id starts at 27 (or at 31 for compressed public keys) - for whatever reason..
    recid += 27;
    (s, recid)
}

/// compute sigma values for correct key proof
/// see paper "Efficient Noninteractive Certification of RSA Moduli and Beyond" by Goldberg et al. 2019 Section 3.2 and Appendix C.4
fn correct_key_proof_sigma(paillier_sk: &DecryptionKey, rho: &[BigInt]) -> Vec<BigInt> {
    let mut sigma_vec: Vec<BigInt> = Vec::new();
    for i in rho.iter() {
        sigma_vec.push(extract_nroot(&paillier_sk, &i));
    }
    sigma_vec
}

#[cfg(test)]
mod tests {
    use crate::common::{CorrectKeyProof, Curve, PAILLIER_KEY_SIZE};
    use crate::curves::secp256_k1::{Secp256k1Point, Secp256k1Scalar};
    use crate::curves::secp256_r1::{Secp256r1Point, Secp256r1Scalar};
    use crate::curves::traits::ECScalar;
    use crate::server::{
        complete_sig, compute_rpool_secp256k1, compute_rpool_secp256r1, correct_key_proof_sigma,
        generate_paillier_keypair, generate_paillier_proof,
    };
    use bigints::traits::{Converter, NumberTests};
    use bigints::BigInt;
    use paillier::{DecryptionKey, MinimalDecryptionKey};
    use std::collections::HashMap;

    #[test]
    fn test_correct_key_proof_sigma() {
        let paillier_sk = DecryptionKey::from(MinimalDecryptionKey{p: BigInt::from_hex("d3542d07cda6034cf8568b68d69f07b716c98dcc466d7fb89d2a40db4addfe1402ac6007b609734c80fa4dd24f005cc2d404651f724561391fd2c714c054c5ecb98c0d367d5d99cddbd788489151daa247feef546ba173db02576793f2386c89a78e1cf0b1b5e3882efb709663c8fb50f3b973e87447bc0a473b792eeb9720ef").unwrap(), q: BigInt::from_hex("bf9f1abdcfd5f3e30a609ad469637eeadf068f67735c319cd0bfe3cb7ed915d93c33c77078762c3deab68fd66a46903a3241f84ccf827ac27faa339d12f4cf818732220b2a899660765a8554d8bc6490bc7490b7874fe1651dccd25b74bcdb5481e1d09bfe3ec6143c2f9bb2cf3658d514fc8c1e48a8e095b8a0f9fe94891f67").unwrap()});
        let rho = BigInt::from_hex("14f21d17357e5d0d8d2cb3cf6d0b9439323473be7e1f68db541b77450f87a20941640bf8a317d4ea6272b12923449e73ea5598a6197219fb6c7ca416a3552301c9cc5b47580ce35e4c9e37a97ec0bdbe2b48c2db21cde5bcef9fc04c6e767c59c0500929b76f87901e5a4d8adb38097c44ed790a0ae2e9f6985823f1789aa47a8298d02763751b73942bbee79c4544f9bd2b82e405f15d801cb41d4831012f99172ef49fee6ea33599caadcdb89c1eb768e30b11878f37e12d232b624cbe589a7767af46d958632574535893c0337858399aed65638b97bcaddee45e40fe79a5014fcd1e398b19807439f58236373197653a8ea82ab3a84173d5a8d45bcae823").unwrap();
        assert_eq!(correct_key_proof_sigma(&paillier_sk, &[rho]), [BigInt::from_hex("14aeae9cdf9522da01b69c4795400e78b2a943c0f2089573359f6a69fafd2b8d7d4cbb119a5445fdd84eb3381e492a3b843e01379bc7a9098b1abc312f65dfe5093125e871b1fc1d1b5ec517290f11ad191267dc109cf954c7ecf61176a232d54dae7d2215961e30e2a2ac475ebefabaf727799cbfdb15ffe0aeff50b1b42536289e9f3d5e926d9a422bf4ef1f2e89e2eb78e509e05d54eea6b3809be75b2eb6e20c0e04bb2861a9d0d7ad72f9800151384b9d98fc2cee20bd2a6bde43324ccfabb786d65ff1c04de62a4c685bdfdf897f9e6cbbff86e3c5efa3a3157487f3b3d5918f8aca74ffe739f93d20e243d1cfdb02f6453934e27bb5372fc7d53e152a").unwrap()]);
    }

    #[test]
    fn test_correct_key_proof_sigma_wrong_pk() {
        let paillier_sk = DecryptionKey::from(MinimalDecryptionKey{p: BigInt::from_hex("e3542d07cda6034cf8568b68d69f07b716c98dcc466d7fb89d2a40db4addfe1402ac6007b609734c80fa4dd24f005cc2d404651f724561391fd2c714c054c5ecb98c0d367d5d99cddbd788489151daa247feef546ba173db02576793f2386c89a78e1cf0b1b5e3882efb709663c8fb50f3b973e87447bc0a473b792eeb9720ef").unwrap(), q: BigInt::from_hex("bf9f1abdcfd5f3e30a609ad469637eeadf068f67735c319cd0bfe3cb7ed915d93c33c77078762c3deab68fd66a46903a3241f84ccf827ac27faa339d12f4cf818732220b2a899660765a8554d8bc6490bc7490b7874fe1651dccd25b74bcdb5481e1d09bfe3ec6143c2f9bb2cf3658d514fc8c1e48a8e095b8a0f9fe94891f67").unwrap()});
        let rho = BigInt::from_hex("14f21d17357e5d0d8d2cb3cf6d0b9439323473be7e1f68db541b77450f87a20941640bf8a317d4ea6272b12923449e73ea5598a6197219fb6c7ca416a3552301c9cc5b47580ce35e4c9e37a97ec0bdbe2b48c2db21cde5bcef9fc04c6e767c59c0500929b76f87901e5a4d8adb38097c44ed790a0ae2e9f6985823f1789aa47a8298d02763751b73942bbee79c4544f9bd2b82e405f15d801cb41d4831012f99172ef49fee6ea33599caadcdb89c1eb768e30b11878f37e12d232b624cbe589a7767af46d958632574535893c0337858399aed65638b97bcaddee45e40fe79a5014fcd1e398b19807439f58236373197653a8ea82ab3a84173d5a8d45bcae823").unwrap();
        assert_ne!(correct_key_proof_sigma(&paillier_sk, &[rho]), [BigInt::from_hex("14aeae9cdf9522da01b69c4795400e78b2a943c0f2089573359f6a69fafd2b8d7d4cbb119a5445fdd84eb3381e492a3b843e01379bc7a9098b1abc312f65dfe5093125e871b1fc1d1b5ec517290f11ad191267dc109cf954c7ecf61176a232d54dae7d2215961e30e2a2ac475ebefabaf727799cbfdb15ffe0aeff50b1b42536289e9f3d5e926d9a422bf4ef1f2e89e2eb78e509e05d54eea6b3809be75b2eb6e20c0e04bb2861a9d0d7ad72f9800151384b9d98fc2cee20bd2a6bde43324ccfabb786d65ff1c04de62a4c685bdfdf897f9e6cbbff86e3c5efa3a3157487f3b3d5918f8aca74ffe739f93d20e243d1cfdb02f6453934e27bb5372fc7d53e152a").unwrap()]);
    }

    #[test]
    fn test_generate_paillier_keypair() {
        let (paillier_pk, _) = generate_paillier_keypair();
        assert!(NumberTests::bits(&paillier_pk.n) >= PAILLIER_KEY_SIZE - 1);
    }

    #[test]
    fn test_correct_key_proof_ok() {
        let paillier_sk = DecryptionKey::from(MinimalDecryptionKey{p: BigInt::from_hex("d3542d07cda6034cf8568b68d69f07b716c98dcc466d7fb89d2a40db4addfe1402ac6007b609734c80fa4dd24f005cc2d404651f724561391fd2c714c054c5ecb98c0d367d5d99cddbd788489151daa247feef546ba173db02576793f2386c89a78e1cf0b1b5e3882efb709663c8fb50f3b973e87447bc0a473b792eeb9720ef").unwrap(), q: BigInt::from_hex("bf9f1abdcfd5f3e30a609ad469637eeadf068f67735c319cd0bfe3cb7ed915d93c33c77078762c3deab68fd66a46903a3241f84ccf827ac27faa339d12f4cf818732220b2a899660765a8554d8bc6490bc7490b7874fe1651dccd25b74bcdb5481e1d09bfe3ec6143c2f9bb2cf3658d514fc8c1e48a8e095b8a0f9fe94891f67").unwrap()});
        let correct_key_proof_generated = generate_paillier_proof(&paillier_sk);
        let correct_key_proof_expected: CorrectKeyProof = serde_json::from_str(&"{\"sigma_vec\":[\"14f21d17357e5d0d8d2cb3cf6d0b9439323473be7e1f68db541b77450f87a20941640bf8a317d4ea6272b12923449e73ea5598a6197219fb6c7ca416a3552301c9cc5b47580ce35e4c9e37a97ec0bdbe2b48c2db21cde5bcef9fc04c6e767c59c0500929b76f87901e5a4d8adb38097c44ed790a0ae2e9f6985823f1789aa47a8298d02763751b73942bbee79c4544f9bd2b82e405f15d801cb41d4831012f99172ef49fee6ea33599caadcdb89c1eb768e30b11878f37e12d232b624cbe589a7767af46d958632574535893c0337858399aed65638b97bcaddee45e40fe79a5014fcd1e398b19807439f58236373197653a8ea82ab3a84173d5a8d45bcae823\",\"32beda264c7fde6cb41d48ce44e6e93af5ed0e1cb5c7cd29f7fa3cbf72b78b9bc3e5267c4f9a75de40eb95a4bdc73dd1d8a435799daf2365f9377aed3c4524016d2ea58002c66fd0a8bcb8e74bac9923b723bc9f8752f82d9cba8bec4f414f314a40842031427b0bb8cdc514bfb61a5f85a51d8b7a290ccbd1000af937a6a7fd7a6070ba40a6801a2909e11d71a773958195d82f72995e69b989ab91207b68ac891e6585848f7aea80e1a0693427a0a512c0cbfbfe5d9ffe02462856ca918af9ebd2ad2f9b44a84b628ec7a7ed4d7232e72c52f2af5ef8988e3c09715fbe1a0af871109028335fb95370ae3e7ecf646063c1914ceeff8cf22ca06d250f02904c\",\"27236e62e810849d58c24b57d2061be4223a175224a89b94ce1261ae9f7a61ec058a43589c83aa3029e61c488fa33b0ea8fb72c36f4b3f962f858f4b0dd822a2810124cba42c8c2a42046b324a3c0712799979be7da1e6dff82c466149484246769f43683231ba8a89185587086cef1de589a4d59b74ac20fcbe0310403f9347417a4c8a8b90b78671d265471fe5ca839e509d4b6f5c2ec33ae255abf54aa12700772a174074048bc4edecc142c268b765f8bf4c0ab7b253882f77c1cb0e410e8e21a23ba364ec37adee59e0395920ab403ab77f095ed8bda39fad9b00886c9e2682a8314bd71fc2db9d2b2a8476ac295c262ba16d4657c62af9bb6a4729c214\",\"974e6e3a63e90275733cbf0b1516d940f0b0c8bd6140f16abb22988289b88b327c5a3e2a1de6d00f03e6f78ee934da02590ee45c6b4c0c8f53ccf6adc35cd0e9ee73f5ad88c8b8bc5b2a489c6e2b900cdc5c2b8ef0aaeb4a99dae6bac9a4bbeb12ceacbafc181a43f9176e503d71100b39b71e5f3975daffd3735b8d26c0b3ae43a92737373730bb22bdc3c06b8b281da79a6994c4c21dda8b89e2a0c9767efa559c895da05e127935b4d33eb1e2acab29cd096e5ed73a4812f86f8839aff7ab8e0baff3535098f1cdddb4ae14e1e7eb702674b4bd8253fefe3bd4245afd6dcb365de617df815ff0cc761415f7001a4149825c50626ebbd0aeeb92172be401e2\",\"43e75be1f60bc68a05aaceea143aa14498880ce8ab1417621f7041d8dd76a80e16484e07580060033bb6eeb67a516215f2bdbdcf2bbbe327ae22000b342a51cafe49ea50ce0b459d5e8334b84de284227a3d504d5fcde913b08b27c6997a27b9a307d132379e0688ce6c38f418b1e94ad87b85e86ab48374d736a7c2f402016255b728c258d945591760a314ebc0e98411fdf3c73e6ed8fd7e23cb1cab8a0517d79a33c27de6548be0ab506db1c2b4b573faf7bcb817cbf0d489da9c168a8c8e6bb4ba0edbfcd1fd01f5eddb89ac84d7a218d83635e354e77619725be00426aaaae90221b65c063ef479184599036182098f3e623a57567ff52172fcd0463e23\",\"70ab52b4bde2f26ba9603b1d211ab94ce95d84a8f09fbb1817700897bc1beb4b3bfe24850f61751204cec784ddd182e5a4432a8d6f48ff475a58d4e63ddc70de5b68a4ee392384031d2b3f352a74c5b8b9fe6f8113a046dcab29b6a168203031d783a4321a7d3f2e971761164454af67367c51a4d46218f817034705c3b013162b83b609647944dd7173e37d02f04b0aef42d1ad2f53902b3e88ccf2523c8526b50b3e47a9d51673992d69ed1f0ac39849b473c1ca0fdb5c34c9b344cf820a3b6566d3db80fb0d6646646080e19bf1448f8859ac1c0275c863950779cd22d248a358a3edb4e60676b4ec353d62c25f7b8c836293108be03a353ea8815c3dba9c\",\"84fb3dcc1348efc024c59df79e69c33d0d67d3f7af328cf0af6048d0080862f0ad0eae3bb676851b58b22db6e7c46474cb6aed94a73b35caf65e0c9f36743f55853bbc1d895649435edfeff25977e8130133078577d547c67c8d31236e1dbcac18252f71fac884078e229f97a7b451391f501b85266252137674f898ab9afb505d4f1ca7455e2339ee992395afd3c9a5cb8724733bdb40ed625932106b47dfe890bdea045178a46dffa1608a1ef01b4dda7a7381ee24f4c10fd63b84b1ece8c425435992f567c709d21324aa50a751042fc4cd2afc283ddb8b2867a694945337fe985a2090e45a8df28c68c828a0e6bae3d18f9a8251dbf46e4e7898feb23ca6\",\"23346102965ad3e6d474ac60f0fb4154dff2bf4250204390db22560f1ffcf47047489c38f02708c9776ed349078bcf7822c2bf50e0af9999a610d69e6f14e3d2ff138e706fbad8359bf496d2519ee900a04ac69eaa7e26bb11e4f302288221889bc58ce20608829db11fbc0a64ad066d7cd1704ae730d954dd84a1a35fb03dfab608b8e483d05ad71c2f6e2e38f59afe3005b60d508383ef160f23aed233bf76e108e3d0e3e6a87032b5b6b7b14f50c5b40aeefde5811ea5fa8a601124370b3d58ebca0906fa0ce72e90a23d713d3d74f2d59256d043011c6b350ebb664ba0a96ae7a5611d71f03d60b60d75e328f6a086aa1932f58026a20c3c3ac4f797587e\",\"12786ce1db47ed46d0bd326d844d3c611f9816b59817fb32a0729d4eb7c3975442410b86f5054d3de4be3f9ba442f0750aa0f284269c57e73ad7c644d3182a3ed26f46462ac687287260117abca70255461dc728adced54b9da10206a88fd213dc423ecc7db4842c3b4ff031ee8eb16304178f4e8eaed9db3e2f6c150dca1532a0a6d8e455cf13e7b4beed736ac8525b84b213ba96fced8ab8a9f47d5cdc8fe02e7eede3f417d2dc07ea10eea71486d3b1f9a0b9d6612efc83908702e6b77499a4861d770d136440962c0b35148b4a1af55989b94509a0ca765bdf1fee850eb175be5676581be779c94192a0326513a768c326fa67a202e66d0eaa70a91932d6\",\"354fd63ff01cf79fd2c90928231e364195a4b6c1d7874011ab6440b583f7027990c37eb4a9bd0125c31a61c31bbed0e36850261df09d5395a1885e5faf9f7bbdff0e545495f7e4761894493ace3de65ca7135a2a751aa2f40d21907bdcf65cec2fa896e457eb02889b0e3e8a5bcfdf133847ccec39c886823aef9f7f2ef9650345324efd55d0fc2e349cebffd6b7a542d4b9db9a4353e30da8f4e9aacd35ff5023180d34488261ba80413fd0cb56257db3e543f72e6d2bd82776e24d2db62107f83d6169fbf63eecfb1b33e58058bff6c0a04a6605d14f3ea77c4959293a19c3309e55d86d1ce1d308967bd2b550fbe2df0219444801d842fab7f6b0f26436e4\",\"61186ef51490cf59e822d5e3f84561ffb4f0b921c205581540ac13d8f978765791ab43942dcf470eac454dc13ce375df68bee5e152ee048fd14c5b6edfc053c2d548008e29a50fcf392069e9fe851fcc58c0f3f4ecd14d2885b9940b2a7bc7cc2818910fef3800a7dcf7e7f5a58905fcaedbf7fcd0dbff40293a403148cffedf1a5730554a10a1eed001cfbad38c4051b2a640a79271e43aae09e7733fe3b881fdba14cd397af91a1499f40069f47f65a0bc167d4c66ab5d8c0fcde37383911f75b4d3207a8a5c4dfa6ecf610c6ac20da6e96c0cd691c0642c8bb7a6be2837785774f4bbaac2529bf5291c94ab49961373e8991eb2018aa9d93529f66dd7695a\"]}".to_string()).unwrap();
        assert_eq!(correct_key_proof_generated, correct_key_proof_expected);
    }

    #[test]
    fn test_correct_key_proof_wrong() {
        let paillier_sk = DecryptionKey::from(MinimalDecryptionKey{p: BigInt::from_hex("e3542d07cda6034cf8568b68d69f07b716c98dcc466d7fb89d2a40db4addfe1402ac6007b609734c80fa4dd24f005cc2d404651f724561391fd2c714c054c5ecb98c0d367d5d99cddbd788489151daa247feef546ba173db02576793f2386c89a78e1cf0b1b5e3882efb709663c8fb50f3b973e87447bc0a473b792eeb9720ef").unwrap(), q: BigInt::from_hex("bf9f1abdcfd5f3e30a609ad469637eeadf068f67735c319cd0bfe3cb7ed915d93c33c77078762c3deab68fd66a46903a3241f84ccf827ac27faa339d12f4cf818732220b2a899660765a8554d8bc6490bc7490b7874fe1651dccd25b74bcdb5481e1d09bfe3ec6143c2f9bb2cf3658d514fc8c1e48a8e095b8a0f9fe94891f67").unwrap()});
        let correct_key_proof_generated = generate_paillier_proof(&paillier_sk);
        let correct_key_proof_expected: CorrectKeyProof = serde_json::from_str(&"{\"sigma_vec\":[\"86ba927cc5974e2f9357e4041e097ede786aa519cf2d8499402b60bf0fb1ae9adc529b8fe72ca51baa940cc93eb292eee7f0334f1f7ee16d320b4d8989f8c444109b1745ecb5efc5c7d1d3a796115cb0e04fcb9e98c3b7316b5e23cf331ac599734d51d565a58e9167103eb9e3af74a15f4bfa4120ff311f192dfb852ac1c8f8a572067bbfa7c7ff5513a29936c6a304d142820f930ccdc48abe43b36b23b8010125aa6cb59cafb9e57976bc0bda14d5cb61e9810e06ebcab54182451c8d1c4e06856a99d67cd942f4a5e60564a602215f59e67dc403bfb3edfe16437dbee6cf41de4f0d5b21aa053b10c3669ad38c75bf27692586792963e99fae66df24facb\",\"7381a547eed881e757a55fd6bcaaf2f218fd29e82833527eed79a42203120140dfbceaeb45a23785b3860fcc064d29845795168fc16588ba020d215d973a27c921b9524377da575b271b55e9cceefd281f09af00abf27ad45df938a29caa66af6fc0ab81a0010c2d4ca49a680b2f42aca5dd3647e6852c5e3097803b242bbb272932cd95595dfa47267413a6148f5223bf8adbd2b88628914398ccd1f2d24b0be85de7c810981cb3a5caf845e2f81ebc177da079987286a9d0c4d0bf8cf7f542892cfbf9164c7ae20bb0b57e3508269d43b93c7172048da3306a7d60aef17845157e43d5bf8eeddd2aed1da564bbe971d071d359525b5b3704d4e2e077dcfade\",\"8405adf1195421347ea8043824aca5952875ebcba66d82a2af3f31af42bbb7e038f6547c2b40b45a064be9f8064610116e2f5740e16649e233989d2058a109b2ae10d651c64bce97634596aeee781ddc634305c326c3be6df49cba4557d532a40f911a67826d81865a24c32688cee8f81786ee76511c66ba25fce9d2503978d777fe773b9a2a0357a797adbc77ac0e9bc0cbab37b3a8f6a42227bebf181004f9a55b6a557783c9150d9408792bd73b1c0071b31c23f3c8ec18d5749d46ea0c431e73fcc8c64a57426402cce9917d7809d94687318a39ee27b01ef9041001401f889e436d3d48fbdde1072b7533b0d00f6a13d0bb0bb94020ca9b77c93d42d5f3\",\"570861a8c14df0b19f6b8159131bef4259338ef6faeab481b6c14e1fc7e57ede571e3698f89c9a08ee9d91c58d594fbc2cd98fff4a483d360c1ecc703820361854061b8a516ce86ca82e8a2e1653f3b25b9d710f6f4e84b8e991450126171f0baa1ac2bfd87653b31f7c30619b6ad9684b48b2dde399c229bed057984415ba552a606eb1ab2b4324adf3826b9c9844f1ecc5634d197877f29626fe59399e739e5f73e502d2fb6a0a016862008583125ec0cfd9c18a3f183ed493d1f5bf236f6a3f7ce345998afae9f963bfee2f705a8df3c253407708fa92091d34d6da6f487d8e7df7b38fbf4e919fa093f64b8782e5e96372080006b9b982013aaffa9c0c58\",\"282184ad00cbc48211eb828e33462bd6c87c53f05c98395e2a0b58924732f25a947c8524c2b09dfcab1d6f70730c4684e11a6b0911199d9562be52872463d51091455b792398e56521d90387077f8948c894707d5cfb42ce3b155f65fb7b80575906a5af2e1b663455d8cd898d743bc727a06c3febdf5f55489d9372da4fbfb516e09faa15a9da0008037f6afb90531a34f08a0ff1b843fd3e0b2c20a8458f767ae85925de160facad7014c96f3f3dd39b2511475fde6ae09476def71fb7ba6c072dc33d2e468f31b55ecbc08c50ddbafe710748cc7d72f509260cceee5171f6b8b0c257ffe5bfa2d09c76265bb54672792c22a137111b9b5e1835ecf8decdde\",\"8813fd4a00617a1ed4ab79662a155535bee18bda39897bef30a0273c5e9e880560b6020b272c23e966fcd03ecebf51bb725c8bbae1ff13762a3bf2e6388e0e3d818a47db0e38fb92bc8e1736804349399ad0ab2d057ee577d6206f69df914868c337c68030a77a0dce18d2793fa971eb4c2a9d56980e77ad5ff52679cfdd69972579402d9a1078060f2a760c7a6363d85c6652049cda386612b0362559f691e95c2ce9a4ce279f977dc9b9fa51d58e42f3bba5c95b07256f86453dd745acfef156f5369c8b1c8b3f240982e0ac52ebe5bd3d1aeeb8cb9daeac84aaaa1fd789d06c4644d4d6adf8ac088d65ca401cb58f489d7a31c9b8f00ffd53671901718736\",\"45109996a12ccb5a4af7a33872bd4526266acb2b6fb62de70d1ffa6ee9f642e32dca886d4d178c1b41e10c8a919d1eabe525835e66488d402215e7906d9c853a4a410f85121cfdcc5673e0487c40442d18649cbee8f032134431344c4a94622ab8e374644efac7e188dc3ebfa5ba7d76af30acb2e7465aae40454594f9313ff845c109eb00deca6cf949f3d612eee279e3a3ccd393901043dea0eb07b6568741adce54fc268becb522824a0acc2861c123bc21d70392e037fdbfe46c35b4e85581ffb231e8a3ecf46fe8cea69759113345beb1a5aaf22121b4c5de5ced09e7037467461c6a3f6f4e821a8ee43da3b6bbd3d9bc07f3f854c82a80ab9721dd6830\",\"62ba72d6c9a6403e14a5f49f8dcdd003fa7c01feefbdc17fbc7a40b4c562eb2f2e6f068e05a8e7e5120de1ea350d244c2fe7ec0f2149797d61232cad298859b59ecdf3a6fa270190f25346c04a99ea285ecc4666c6e58f29f6b9e5d2c0929f75a4bdea81641d8d001cd44a5382a1c79856c19b19a8d1e13f5a3230f0e928e5b93e5fdebefde559c29f02f153dfb0ca911102b1d03bf094d799e5e39cc58abd186053f050c7db2646517016763ab185b8d9316ddfc15ae71063159e57d6bc9f548700c7f01c62d2e9b49671ba54d79d9b8b901978056bc13627e17d44fce53c004c6df4e8e225da1f75d2f385b16d8ee2687cfe56934644dad5abc8e3cdcce64d\",\"9a47120575204c8f76a980b4733ffc69dbc34959ca8f565ac277b55985b8b4d9cd3f4887d59ef0f5d2d0b8bb1f10d8fdcd167935380367592a895d134928931dd85f66e4253ec4d3e4a2c1b5ba5b2af4ef0d20c394c8b1526c6010458cd3023f32ce32b917322cee3315d633bfb2f8e16b69cfe362c6df3963bc95b6bfb60661e613e76e0b3a6c3c06c49f26de09343ac38a66a4d1cae8496d4b82a78b9b7f2f2097182812b5d5ab4bf8950f49f1f553584b7aa993cfe1c96d8fd78a2d9201f42af6f56c2ed6373925e2b5cc8ff4dc1e238ccce1754c792ac82a61d45fba4898b3bb6372e7827616b06353535457f6366eaa2d42b7a167e2be4ee086699a1b41\",\"31ad95d0e1ef37d078f0ef74fb6fe8f9ea47db0aa31e78a37420e7ad9bd1b2bca058efb395885d2fea08106ef8ffa898e19be1f562665b2514c4b7cea39fc678449c7c103cd2dc8d8f980dd3b926a6532e113d25d1a9a891e374a33ae0dc21691fc4a4db7c638585158f516d5fb592c540ae2b6266a81905909c3b1fbdc22e248ea3d0e5f0895112769581509581d749486137f057c6b0fc77fd4784da9904250e7f5fe088fe4ced7451bae6829a2b9c8286cbac4e4171caf4e2089edc754912392b906062e101344fe51841c391e4bb7f2d672be01ddb3fae68b44f0c02000ad3cb0be7af954fcca4ed3f19ebcdca8acccaa60e03c035b196eec87ece42f50\",\"3054c555c41509b39eccc86bbf80bade7eb18e8a694947ca4f7ebf0ef309dc4a35690fe2e3fc8a76db33fb5e6554a52f73d32da987d768a220bdff621a54c83aa382092658f6657c95c767456682d5da2aff4a53a0958ce4a7dae61262c1f47e365d52d7981541ea0ed3a00a0c30bad31a6738bc19a254bf78dac870f604aeca1766b9ea5dc1e239819b8b07f02d5d176065bfa087ce000a581b1f92011309d0bb0f0e10d98877a4279e7d56460b40ad9c2909226c510b3938f92459b11a33c3e6c8637b66d8ce6bd81e04e0cfc166cb9fa90622df20482a7d8ac3c3d8877b0477ba41152500c88bf554fa81ac4f1c44a04b814f42104c012dd6b75e10f13271\"]}".to_string()).unwrap();
        assert_ne!(correct_key_proof_generated, correct_key_proof_expected);
    }

    #[test]
    fn test_rpool_r1_ok() {
        let dh_secret: Secp256r1Scalar = ECScalar::from(
            &BigInt::from_hex("ffa8b1420c958881923ba9f7fcaf1c5bd994499d31da5d677ca9fa79c5762a28")
                .unwrap(),
        );
        let dh_public = Secp256r1Point::from_bigint(
            &BigInt::from_hex("2ba1b94b7ab036e2597081e3127d762e02f9967cc7badedfe1cc7ee142a75aba0")
                .unwrap(),
        )
        .unwrap();
        let dh_secret_vec = vec![dh_secret.clone()];
        let dh_public_vec = vec![dh_public];
        let computed = compute_rpool_secp256r1(&dh_secret_vec, &dh_public_vec).unwrap();
        let mut expected = HashMap::new();
        expected.insert(
            "03195834f65ee4df0d11d2c4a6dc1fbc205692539b613f1cfdb6177ee1c11300dd".to_string(),
            dh_secret,
        );
        assert_eq!(computed, expected);
    }

    #[test]
    fn test_rpool_r1_wrong_secret() {
        let dh_secret: Secp256r1Scalar = ECScalar::from(
            &BigInt::from_hex("efa8b1420c958881923ba9f7fcaf1c5bd994499d31da5d677ca9fa79c5762a28")
                .unwrap(),
        );
        let dh_public = Secp256r1Point::from_bigint(
            &BigInt::from_hex("2ba1b94b7ab036e2597081e3127d762e02f9967cc7badedfe1cc7ee142a75aba0")
                .unwrap(),
        )
        .unwrap();
        let dh_secret_vec = vec![dh_secret.clone()];
        let dh_public_vec = vec![dh_public];
        let computed = compute_rpool_secp256r1(&dh_secret_vec, &dh_public_vec).unwrap();
        let mut expected = HashMap::new();
        expected.insert(
            "03195834f65ee4df0d11d2c4a6dc1fbc205692539b613f1cfdb6177ee1c11300dd".to_string(),
            dh_secret,
        );
        assert_ne!(computed, expected);
    }

    #[test]
    fn test_rpool_r1_wrong_public() {
        let dh_secret: Secp256r1Scalar = ECScalar::from(
            &BigInt::from_hex("ffa8b1420c958881923ba9f7fcaf1c5bd994499d31da5d677ca9fa79c5762a28")
                .unwrap(),
        );
        let dh_public = Secp256r1Point::from_bigint(
            &BigInt::from_hex("3ba1b94b7ab036e2597081e3127d762e02f9967cc7badedfe1cc7ee142a75aba0")
                .unwrap(),
        )
        .unwrap();
        let dh_secret_vec = vec![dh_secret.clone()];
        let dh_public_vec = vec![dh_public];
        let computed = compute_rpool_secp256r1(&dh_secret_vec, &dh_public_vec).unwrap();
        let mut expected = HashMap::new();
        expected.insert(
            "03195834f65ee4df0d11d2c4a6dc1fbc205692539b613f1cfdb6177ee1c11300dd".to_string(),
            dh_secret,
        );
        assert_ne!(computed, expected);
    }

    #[test]
    fn test_rpool_k1_ok() {
        let dh_secret: Secp256k1Scalar = ECScalar::from(
            &BigInt::from_hex("953fe5d3d0f74c98dc78fec8482f4d5245727e21109177851a338e92a0b717c2")
                .unwrap(),
        );
        let dh_public = Secp256k1Point::from_bigint(
            &BigInt::from_hex("2dc0573e3f91dc0915f50f053c1f361772a916b927dc782068dedb44c02d54eee")
                .unwrap(),
        )
        .unwrap();
        let dh_secret_vec = vec![dh_secret.clone()];
        let dh_public_vec = vec![dh_public];
        let computed = compute_rpool_secp256k1(&dh_secret_vec, &dh_public_vec).unwrap();
        let mut expected = HashMap::new();
        expected.insert(
            "03388cb4cecb898818ff8fa00fc28b7c1a8d9cbb4aedcec83b7a86434900141aae".to_string(),
            dh_secret,
        );
        assert_eq!(computed, expected);
    }

    #[test]
    fn test_rpool_k1_wrong_secret() {
        let dh_secret: Secp256k1Scalar = ECScalar::from(
            &BigInt::from_hex("a53fe5d3d0f74c98dc78fec8482f4d5245727e21109177851a338e92a0b717c2")
                .unwrap(),
        );
        let dh_public = Secp256k1Point::from_bigint(
            &BigInt::from_hex("2dc0573e3f91dc0915f50f053c1f361772a916b927dc782068dedb44c02d54eee")
                .unwrap(),
        )
        .unwrap();
        let dh_secret_vec = vec![dh_secret.clone()];
        let dh_public_vec = vec![dh_public];
        let computed = compute_rpool_secp256k1(&dh_secret_vec, &dh_public_vec).unwrap();
        let mut expected = HashMap::new();
        expected.insert(
            "03388cb4cecb898818ff8fa00fc28b7c1a8d9cbb4aedcec83b7a86434900141aae".to_string(),
            dh_secret,
        );
        assert_ne!(computed, expected);
    }

    #[test]
    fn test_rpool_k1_wrong_public() {
        let dh_secret: Secp256k1Scalar = ECScalar::from(
            &BigInt::from_hex("953fe5d3d0f74c98dc78fec8482f4d5245727e21109177851a338e92a0b717c2")
                .unwrap(),
        );
        let dh_public = Secp256k1Point::from_bigint(
            &BigInt::from_hex("3dc0573e3f91dc0915f50f053c1f361772a916b927dc782068dedb44c02d54eee")
                .unwrap(),
        )
        .unwrap();
        let dh_secret_vec = vec![dh_secret.clone()];
        let dh_public_vec = vec![dh_public];
        let computed = compute_rpool_secp256k1(&dh_secret_vec, &dh_public_vec).unwrap();
        let mut expected = HashMap::new();
        expected.insert(
            "03388cb4cecb898818ff8fa00fc28b7c1a8d9cbb4aedcec83b7a86434900141aae".to_string(),
            dh_secret,
        );
        assert_ne!(computed, expected);
    }

    #[test]
    fn test_complete_sig_k1_ok() {
        let paillier_sk = DecryptionKey::from(MinimalDecryptionKey{p: BigInt::from_hex("d3542d07cda6034cf8568b68d69f07b716c98dcc466d7fb89d2a40db4addfe1402ac6007b609734c80fa4dd24f005cc2d404651f724561391fd2c714c054c5ecb98c0d367d5d99cddbd788489151daa247feef546ba173db02576793f2386c89a78e1cf0b1b5e3882efb709663c8fb50f3b973e87447bc0a473b792eeb9720ef").unwrap(), q: BigInt::from_hex("bf9f1abdcfd5f3e30a609ad469637eeadf068f67735c319cd0bfe3cb7ed915d93c33c77078762c3deab68fd66a46903a3241f84ccf827ac27faa339d12f4cf818732220b2a899660765a8554d8bc6490bc7490b7874fe1651dccd25b74bcdb5481e1d09bfe3ec6143c2f9bb2cf3658d514fc8c1e48a8e095b8a0f9fe94891f67").unwrap()});
        let presig = BigInt::from_hex("4eef881b16b678841b4688be1609cf3eb4b9d31b00e74d9f2c0a7c6e827a43eb099099802893d7568655db7ceb590092a09f2d3154e4c25527091c50e8b956104e03f6ec04bd13158341d1728f7f0e9aa9e9664e0fbfcca06a2fbb97a48ddbf6e86d39b58cd8581b494b084f6b2d1d70f66994da6b7c73a034f0580b77658aed33517b7cf6b6cfb6e23a67001ab4caa49ed8445890a74d60ecac4140cc0ae9817a7d974deb1111784c0ad400ae30c74e421d0f5f31b42364c44b577be00ef13deb2a2d9c90b913abfad7056fb2e9d86f1ad521441f7a58b264c56b5da86e1d07a84d50ef28c711d023ca5f7c8759d4aa9d6fc83db5be69c05d8a6804a344c169e3dc7ab542283f1f03151bade022ce18685f0142523fb27154e29104efb10757e5be11c669c4a16d1de7d294d019c0a742cf64f0b91953ff36da960ac55aa023ff10fd9410bfb0fe5f68210d93a7c67d4e743aaae7aef6659b90a0b23e7ad267514ec359624581b8d6a1fd839db0ab05c1ab82192214c3e3d26b337d4937fd9a4d1c78d843c511e6de4f4f44fe7784a7edc33fdabd222be0c6600d38c55f48967847f17f6f049fe4b0ac485010226c16eece202a34b357d5acee6109d5bccfa3a61a79c80ddebb8c2cef192afa0440452739bbe55fc94b6a0af2d98328196b6041e584215a399ce615cfd697c6cca8ea30bac926de61b636d4029a226955854d").unwrap();
        let r =
            BigInt::from_hex("027c1adefb68c11af735850d77e24bd0c4dbc256cf100d441d4542d853a81508f3")
                .unwrap();
        let k =
            BigInt::from_hex("88779a4565cc853f6a46475963515a6e50330d4e83c4235dbb160e1164d9a730")
                .unwrap();
        let curve = Curve::Secp256k1;
        let (r_, s, recid) = complete_sig(&paillier_sk, &presig, &r, &k, curve).unwrap();
        assert_eq!(
            r_,
            BigInt::from_hex("7c1adefb68c11af735850d77e24bd0c4dbc256cf100d441d4542d853a81508f3")
                .unwrap()
        );
        assert_eq!(
            s,
            BigInt::from_hex("4b4b24ef84023a5a37bc9b3524060a6339bd71ca7520b4c0972a80e79995843e")
                .unwrap()
        );
        assert_eq!(recid, 28);
    }

    #[test]
    fn test_complete_sig_k1_wrong_paillier() {
        let paillier_sk = DecryptionKey::from(MinimalDecryptionKey{p: BigInt::from_hex("f3542d07cda6034cf8568b68d69f07b716c98dcc466d7fb89d2a40db4addfe1402ac6007b609734c80fa4dd24f005cc2d404651f724561391fd2c714c054c5ecb98c0d367d5d99cddbd788489151daa247feef546ba173db02576793f2386c89a78e1cf0b1b5e3882efb709663c8fb50f3b973e87447bc0a473b792eeb9720ef").unwrap(), q: BigInt::from_hex("bf9f1abdcfd5f3e30a609ad469637eeadf068f67735c319cd0bfe3cb7ed915d93c33c77078762c3deab68fd66a46903a3241f84ccf827ac27faa339d12f4cf818732220b2a899660765a8554d8bc6490bc7490b7874fe1651dccd25b74bcdb5481e1d09bfe3ec6143c2f9bb2cf3658d514fc8c1e48a8e095b8a0f9fe94891f67").unwrap()});
        let presig = BigInt::from_hex("4eef881b16b678841b4688be1609cf3eb4b9d31b00e74d9f2c0a7c6e827a43eb099099802893d7568655db7ceb590092a09f2d3154e4c25527091c50e8b956104e03f6ec04bd13158341d1728f7f0e9aa9e9664e0fbfcca06a2fbb97a48ddbf6e86d39b58cd8581b494b084f6b2d1d70f66994da6b7c73a034f0580b77658aed33517b7cf6b6cfb6e23a67001ab4caa49ed8445890a74d60ecac4140cc0ae9817a7d974deb1111784c0ad400ae30c74e421d0f5f31b42364c44b577be00ef13deb2a2d9c90b913abfad7056fb2e9d86f1ad521441f7a58b264c56b5da86e1d07a84d50ef28c711d023ca5f7c8759d4aa9d6fc83db5be69c05d8a6804a344c169e3dc7ab542283f1f03151bade022ce18685f0142523fb27154e29104efb10757e5be11c669c4a16d1de7d294d019c0a742cf64f0b91953ff36da960ac55aa023ff10fd9410bfb0fe5f68210d93a7c67d4e743aaae7aef6659b90a0b23e7ad267514ec359624581b8d6a1fd839db0ab05c1ab82192214c3e3d26b337d4937fd9a4d1c78d843c511e6de4f4f44fe7784a7edc33fdabd222be0c6600d38c55f48967847f17f6f049fe4b0ac485010226c16eece202a34b357d5acee6109d5bccfa3a61a79c80ddebb8c2cef192afa0440452739bbe55fc94b6a0af2d98328196b6041e584215a399ce615cfd697c6cca8ea30bac926de61b636d4029a226955854d").unwrap();
        let r =
            BigInt::from_hex("027c1adefb68c11af735850d77e24bd0c4dbc256cf100d441d4542d853a81508f3")
                .unwrap();
        let k =
            BigInt::from_hex("88779a4565cc853f6a46475963515a6e50330d4e83c4235dbb160e1164d9a730")
                .unwrap();
        let curve = Curve::Secp256k1;
        let (r_, s, recid) = complete_sig(&paillier_sk, &presig, &r, &k, curve).unwrap();
        assert_eq!(
            r_,
            BigInt::from_hex("7c1adefb68c11af735850d77e24bd0c4dbc256cf100d441d4542d853a81508f3")
                .unwrap()
        );
        assert_ne!(
            s,
            BigInt::from_hex("4b4b24ef84023a5a37bc9b3524060a6339bd71ca7520b4c0972a80e79995843e")
                .unwrap()
        );
        assert_ne!(recid, 28);
    }

    #[test]
    fn test_complete_sig_k1_wrong_presig() {
        let paillier_sk = DecryptionKey::from(MinimalDecryptionKey{p: BigInt::from_hex("d3542d07cda6034cf8568b68d69f07b716c98dcc466d7fb89d2a40db4addfe1402ac6007b609734c80fa4dd24f005cc2d404651f724561391fd2c714c054c5ecb98c0d367d5d99cddbd788489151daa247feef546ba173db02576793f2386c89a78e1cf0b1b5e3882efb709663c8fb50f3b973e87447bc0a473b792eeb9720ef").unwrap(), q: BigInt::from_hex("bf9f1abdcfd5f3e30a609ad469637eeadf068f67735c319cd0bfe3cb7ed915d93c33c77078762c3deab68fd66a46903a3241f84ccf827ac27faa339d12f4cf818732220b2a899660765a8554d8bc6490bc7490b7874fe1651dccd25b74bcdb5481e1d09bfe3ec6143c2f9bb2cf3658d514fc8c1e48a8e095b8a0f9fe94891f67").unwrap()});
        let presig = BigInt::from_hex("5eef881b16b678841b4688be1609cf3eb4b9d31b00e74d9f2c0a7c6e827a43eb099099802893d7568655db7ceb590092a09f2d3154e4c25527091c50e8b956104e03f6ec04bd13158341d1728f7f0e9aa9e9664e0fbfcca06a2fbb97a48ddbf6e86d39b58cd8581b494b084f6b2d1d70f66994da6b7c73a034f0580b77658aed33517b7cf6b6cfb6e23a67001ab4caa49ed8445890a74d60ecac4140cc0ae9817a7d974deb1111784c0ad400ae30c74e421d0f5f31b42364c44b577be00ef13deb2a2d9c90b913abfad7056fb2e9d86f1ad521441f7a58b264c56b5da86e1d07a84d50ef28c711d023ca5f7c8759d4aa9d6fc83db5be69c05d8a6804a344c169e3dc7ab542283f1f03151bade022ce18685f0142523fb27154e29104efb10757e5be11c669c4a16d1de7d294d019c0a742cf64f0b91953ff36da960ac55aa023ff10fd9410bfb0fe5f68210d93a7c67d4e743aaae7aef6659b90a0b23e7ad267514ec359624581b8d6a1fd839db0ab05c1ab82192214c3e3d26b337d4937fd9a4d1c78d843c511e6de4f4f44fe7784a7edc33fdabd222be0c6600d38c55f48967847f17f6f049fe4b0ac485010226c16eece202a34b357d5acee6109d5bccfa3a61a79c80ddebb8c2cef192afa0440452739bbe55fc94b6a0af2d98328196b6041e584215a399ce615cfd697c6cca8ea30bac926de61b636d4029a226955854d").unwrap();
        let r =
            BigInt::from_hex("027c1adefb68c11af735850d77e24bd0c4dbc256cf100d441d4542d853a81508f3")
                .unwrap();
        let k =
            BigInt::from_hex("88779a4565cc853f6a46475963515a6e50330d4e83c4235dbb160e1164d9a730")
                .unwrap();
        let curve = Curve::Secp256k1;
        let (r_, s, recid) = complete_sig(&paillier_sk, &presig, &r, &k, curve).unwrap();
        assert_eq!(
            r_,
            BigInt::from_hex("7c1adefb68c11af735850d77e24bd0c4dbc256cf100d441d4542d853a81508f3")
                .unwrap()
        );
        assert_ne!(
            s,
            BigInt::from_hex("4b4b24ef84023a5a37bc9b3524060a6339bd71ca7520b4c0972a80e79995843e")
                .unwrap()
        );
        assert_ne!(recid, 28);
    }

    #[test]
    fn test_complete_sig_k1_wrong_r() {
        let paillier_sk = DecryptionKey::from(MinimalDecryptionKey{p: BigInt::from_hex("d3542d07cda6034cf8568b68d69f07b716c98dcc466d7fb89d2a40db4addfe1402ac6007b609734c80fa4dd24f005cc2d404651f724561391fd2c714c054c5ecb98c0d367d5d99cddbd788489151daa247feef546ba173db02576793f2386c89a78e1cf0b1b5e3882efb709663c8fb50f3b973e87447bc0a473b792eeb9720ef").unwrap(), q: BigInt::from_hex("bf9f1abdcfd5f3e30a609ad469637eeadf068f67735c319cd0bfe3cb7ed915d93c33c77078762c3deab68fd66a46903a3241f84ccf827ac27faa339d12f4cf818732220b2a899660765a8554d8bc6490bc7490b7874fe1651dccd25b74bcdb5481e1d09bfe3ec6143c2f9bb2cf3658d514fc8c1e48a8e095b8a0f9fe94891f67").unwrap()});
        let presig = BigInt::from_hex("4eef881b16b678841b4688be1609cf3eb4b9d31b00e74d9f2c0a7c6e827a43eb099099802893d7568655db7ceb590092a09f2d3154e4c25527091c50e8b956104e03f6ec04bd13158341d1728f7f0e9aa9e9664e0fbfcca06a2fbb97a48ddbf6e86d39b58cd8581b494b084f6b2d1d70f66994da6b7c73a034f0580b77658aed33517b7cf6b6cfb6e23a67001ab4caa49ed8445890a74d60ecac4140cc0ae9817a7d974deb1111784c0ad400ae30c74e421d0f5f31b42364c44b577be00ef13deb2a2d9c90b913abfad7056fb2e9d86f1ad521441f7a58b264c56b5da86e1d07a84d50ef28c711d023ca5f7c8759d4aa9d6fc83db5be69c05d8a6804a344c169e3dc7ab542283f1f03151bade022ce18685f0142523fb27154e29104efb10757e5be11c669c4a16d1de7d294d019c0a742cf64f0b91953ff36da960ac55aa023ff10fd9410bfb0fe5f68210d93a7c67d4e743aaae7aef6659b90a0b23e7ad267514ec359624581b8d6a1fd839db0ab05c1ab82192214c3e3d26b337d4937fd9a4d1c78d843c511e6de4f4f44fe7784a7edc33fdabd222be0c6600d38c55f48967847f17f6f049fe4b0ac485010226c16eece202a34b357d5acee6109d5bccfa3a61a79c80ddebb8c2cef192afa0440452739bbe55fc94b6a0af2d98328196b6041e584215a399ce615cfd697c6cca8ea30bac926de61b636d4029a226955854d").unwrap();
        let r =
            BigInt::from_hex("0371202794e5d09b308ef0db6fad6da7bb9386dda2dfb25aa43c9dc61e16cb5b88")
                .unwrap();
        let k =
            BigInt::from_hex("88779a4565cc853f6a46475963515a6e50330d4e83c4235dbb160e1164d9a730")
                .unwrap();
        let curve = Curve::Secp256k1;
        let (r_, s, recid) = complete_sig(&paillier_sk, &presig, &r, &k, curve).unwrap();
        assert_ne!(
            r_,
            BigInt::from_hex("7c1adefb68c11af735850d77e24bd0c4dbc256cf100d441d4542d853a81508f3")
                .unwrap()
        );
        assert_eq!(
            s,
            BigInt::from_hex("4b4b24ef84023a5a37bc9b3524060a6339bd71ca7520b4c0972a80e79995843e")
                .unwrap()
        );
        assert_ne!(recid, 28);
    }

    #[test]
    fn test_complete_sig_k1_wrong_k() {
        let paillier_sk = DecryptionKey::from(MinimalDecryptionKey{p: BigInt::from_hex("d3542d07cda6034cf8568b68d69f07b716c98dcc466d7fb89d2a40db4addfe1402ac6007b609734c80fa4dd24f005cc2d404651f724561391fd2c714c054c5ecb98c0d367d5d99cddbd788489151daa247feef546ba173db02576793f2386c89a78e1cf0b1b5e3882efb709663c8fb50f3b973e87447bc0a473b792eeb9720ef").unwrap(), q: BigInt::from_hex("bf9f1abdcfd5f3e30a609ad469637eeadf068f67735c319cd0bfe3cb7ed915d93c33c77078762c3deab68fd66a46903a3241f84ccf827ac27faa339d12f4cf818732220b2a899660765a8554d8bc6490bc7490b7874fe1651dccd25b74bcdb5481e1d09bfe3ec6143c2f9bb2cf3658d514fc8c1e48a8e095b8a0f9fe94891f67").unwrap()});
        let presig = BigInt::from_hex("4eef881b16b678841b4688be1609cf3eb4b9d31b00e74d9f2c0a7c6e827a43eb099099802893d7568655db7ceb590092a09f2d3154e4c25527091c50e8b956104e03f6ec04bd13158341d1728f7f0e9aa9e9664e0fbfcca06a2fbb97a48ddbf6e86d39b58cd8581b494b084f6b2d1d70f66994da6b7c73a034f0580b77658aed33517b7cf6b6cfb6e23a67001ab4caa49ed8445890a74d60ecac4140cc0ae9817a7d974deb1111784c0ad400ae30c74e421d0f5f31b42364c44b577be00ef13deb2a2d9c90b913abfad7056fb2e9d86f1ad521441f7a58b264c56b5da86e1d07a84d50ef28c711d023ca5f7c8759d4aa9d6fc83db5be69c05d8a6804a344c169e3dc7ab542283f1f03151bade022ce18685f0142523fb27154e29104efb10757e5be11c669c4a16d1de7d294d019c0a742cf64f0b91953ff36da960ac55aa023ff10fd9410bfb0fe5f68210d93a7c67d4e743aaae7aef6659b90a0b23e7ad267514ec359624581b8d6a1fd839db0ab05c1ab82192214c3e3d26b337d4937fd9a4d1c78d843c511e6de4f4f44fe7784a7edc33fdabd222be0c6600d38c55f48967847f17f6f049fe4b0ac485010226c16eece202a34b357d5acee6109d5bccfa3a61a79c80ddebb8c2cef192afa0440452739bbe55fc94b6a0af2d98328196b6041e584215a399ce615cfd697c6cca8ea30bac926de61b636d4029a226955854d").unwrap();
        let r =
            BigInt::from_hex("027c1adefb68c11af735850d77e24bd0c4dbc256cf100d441d4542d853a81508f3")
                .unwrap();
        let k =
            BigInt::from_hex("a8779a4565cc853f6a46475963515a6e50330d4e83c4235dbb160e1164d9a730")
                .unwrap();
        let curve = Curve::Secp256k1;
        let (r_, s, recid) = complete_sig(&paillier_sk, &presig, &r, &k, curve).unwrap();
        assert_eq!(
            r_,
            BigInt::from_hex("7c1adefb68c11af735850d77e24bd0c4dbc256cf100d441d4542d853a81508f3")
                .unwrap()
        );
        assert_ne!(
            s,
            BigInt::from_hex("4b4b24ef84023a5a37bc9b3524060a6339bd71ca7520b4c0972a80e79995843e")
                .unwrap()
        );
        assert_ne!(recid, 28);
    }

    #[test]
    #[should_panic]
    fn test_complete_sig_k1_wrong_curve() {
        let paillier_sk = DecryptionKey::from(MinimalDecryptionKey{p: BigInt::from_hex("d3542d07cda6034cf8568b68d69f07b716c98dcc466d7fb89d2a40db4addfe1402ac6007b609734c80fa4dd24f005cc2d404651f724561391fd2c714c054c5ecb98c0d367d5d99cddbd788489151daa247feef546ba173db02576793f2386c89a78e1cf0b1b5e3882efb709663c8fb50f3b973e87447bc0a473b792eeb9720ef").unwrap(), q: BigInt::from_hex("bf9f1abdcfd5f3e30a609ad469637eeadf068f67735c319cd0bfe3cb7ed915d93c33c77078762c3deab68fd66a46903a3241f84ccf827ac27faa339d12f4cf818732220b2a899660765a8554d8bc6490bc7490b7874fe1651dccd25b74bcdb5481e1d09bfe3ec6143c2f9bb2cf3658d514fc8c1e48a8e095b8a0f9fe94891f67").unwrap()});
        let presig = BigInt::from_hex("4eef881b16b678841b4688be1609cf3eb4b9d31b00e74d9f2c0a7c6e827a43eb099099802893d7568655db7ceb590092a09f2d3154e4c25527091c50e8b956104e03f6ec04bd13158341d1728f7f0e9aa9e9664e0fbfcca06a2fbb97a48ddbf6e86d39b58cd8581b494b084f6b2d1d70f66994da6b7c73a034f0580b77658aed33517b7cf6b6cfb6e23a67001ab4caa49ed8445890a74d60ecac4140cc0ae9817a7d974deb1111784c0ad400ae30c74e421d0f5f31b42364c44b577be00ef13deb2a2d9c90b913abfad7056fb2e9d86f1ad521441f7a58b264c56b5da86e1d07a84d50ef28c711d023ca5f7c8759d4aa9d6fc83db5be69c05d8a6804a344c169e3dc7ab542283f1f03151bade022ce18685f0142523fb27154e29104efb10757e5be11c669c4a16d1de7d294d019c0a742cf64f0b91953ff36da960ac55aa023ff10fd9410bfb0fe5f68210d93a7c67d4e743aaae7aef6659b90a0b23e7ad267514ec359624581b8d6a1fd839db0ab05c1ab82192214c3e3d26b337d4937fd9a4d1c78d843c511e6de4f4f44fe7784a7edc33fdabd222be0c6600d38c55f48967847f17f6f049fe4b0ac485010226c16eece202a34b357d5acee6109d5bccfa3a61a79c80ddebb8c2cef192afa0440452739bbe55fc94b6a0af2d98328196b6041e584215a399ce615cfd697c6cca8ea30bac926de61b636d4029a226955854d").unwrap();
        let r =
            BigInt::from_hex("027c1adefb68c11af735850d77e24bd0c4dbc256cf100d441d4542d853a81508f3")
                .unwrap();
        let k =
            BigInt::from_hex("88779a4565cc853f6a46475963515a6e50330d4e83c4235dbb160e1164d9a730")
                .unwrap();
        let curve = Curve::Secp256r1;
        complete_sig(&paillier_sk, &presig, &r, &k, curve).unwrap();
    }

    #[test]
    fn test_complete_sig_r1_ok() {
        let paillier_sk = DecryptionKey::from(MinimalDecryptionKey{p: BigInt::from_hex("d3542d07cda6034cf8568b68d69f07b716c98dcc466d7fb89d2a40db4addfe1402ac6007b609734c80fa4dd24f005cc2d404651f724561391fd2c714c054c5ecb98c0d367d5d99cddbd788489151daa247feef546ba173db02576793f2386c89a78e1cf0b1b5e3882efb709663c8fb50f3b973e87447bc0a473b792eeb9720ef").unwrap(), q: BigInt::from_hex("bf9f1abdcfd5f3e30a609ad469637eeadf068f67735c319cd0bfe3cb7ed915d93c33c77078762c3deab68fd66a46903a3241f84ccf827ac27faa339d12f4cf818732220b2a899660765a8554d8bc6490bc7490b7874fe1651dccd25b74bcdb5481e1d09bfe3ec6143c2f9bb2cf3658d514fc8c1e48a8e095b8a0f9fe94891f67").unwrap()});
        let presig = BigInt::from_hex("3a4f82ec76b17ddfc10b15878713cc31fe914674a36b834da70215670d19997a56db6fa8b38fbdb2672a73aafcb4ba7162f35b1ccc0474622f2d2a50406fcd8cfbbca0ad6adaf3bd6c8d574393a8cca548e88f93383d426bb634a390f21014562ca45c2b739b270e65760ef43fc28fa207bfe6e7e159f8f943e66606037814586d512057c0036e98e6b9e2432723c9b86eb6ecc43def1fd8d608ba8334872be86659690bb10e7da72dcc18df5f316b2e6fc0ff37b351cca3510f48b50053c7de638ebbded1a2bc34ff130ad8df98e7353fb6c9be6893bd6d6fa1b07eb79a0bf815fe6e611ec7c99564b7acca2d7266d7de64b3e7fb4911638c0cda8b5c7896f261971e7a6bb04bca5ff6bb80153aed189d62d899d88727778b12e6d9b6d49b0af2dd5bbcc57a8950cd02a5f993bebcf85eeb3ca36179166b52a188870777dcb6d67d707c07f013c035e33c49e76b91389dabc681d04928bfc27be1acea29c61087caf6f8675c1ef572275d5e724e8ed7dea616d2058ba07a7f261622a7479c2bb63bea79956f7b84202e740a1ff0ddaff3500dfa6ab2dfafd2aa0a3a20629f71ebdeb1328d71ecb4301a95f98ee3b82c87eb286138f30f947ccaa9a1bf042ed829b89550455e2fae3fbc8d7803dc53e6565dc3999d2c739c568e80175e15e4d7e5679cce42fd86f44c7b5c87cccceb7a4f8cbda1ce87f3e3f38beb516f2cf737").unwrap();
        let r =
            BigInt::from_hex("030a3ec2711ae5dc9e71711dc4d6bf2beb755be5639a9ce1854e258c4c44921fff")
                .unwrap();
        let k =
            BigInt::from_hex("e1d1318d8b96ed598ce80f8fb9197327bca23f7db51021a6c5cfb8b01851b2ff")
                .unwrap();
        let curve = Curve::Secp256r1;
        let (r_, s, recid) = complete_sig(&paillier_sk, &presig, &r, &k, curve).unwrap();
        assert_eq!(
            r_,
            BigInt::from_hex("0a3ec2711ae5dc9e71711dc4d6bf2beb755be5639a9ce1854e258c4c44921fff")
                .unwrap()
        );
        assert_eq!(
            s,
            BigInt::from_hex("271f3513c9ac42e82ba602b76a40a1510902a6671221f77ba881e8d847c82b22")
                .unwrap()
        );
        assert_eq!(recid, 28);
    }

    #[test]
    fn test_complete_sig_r1_wrong_paillier() {
        let paillier_sk = DecryptionKey::from(MinimalDecryptionKey{p: BigInt::from_hex("d3542d07cda6034cf8568b68d69f07b716c98dcc466d7fb89d2a40db4addfe1402ac6007b609734c80fa4dd24f005cc2d404651f724561391fd2c714c054c5ecb98c0d367d5d99cddbd788489151daa247feef546ba173db02576793f2386c89a78e1cf0b1b5e3882efb709663c8fb50f3b973e87447bc0a473b792eeb9720ef").unwrap(), q: BigInt::from_hex("bf9f1abdcfd5f3e30a609ad469637eeadf068f67735c319cd0bfe3cb7ed915d93c33c77078762c3deab68fd66a46903a3241f84ccf827ac27faa339d12f4cf818732220b2a899660765a8554d8bc6490bc7490b7874fe1651dccd25b74bcdb5481e1d09bfe3ec6143c2f9bb2cf3658d514fc8c1e48a8e095b8a0f9fe94891f67").unwrap()});
        let presig = BigInt::from_hex("4a4f82ec76b17ddfc10b15878713cc31fe914674a36b834da70215670d19997a56db6fa8b38fbdb2672a73aafcb4ba7162f35b1ccc0474622f2d2a50406fcd8cfbbca0ad6adaf3bd6c8d574393a8cca548e88f93383d426bb634a390f21014562ca45c2b739b270e65760ef43fc28fa207bfe6e7e159f8f943e66606037814586d512057c0036e98e6b9e2432723c9b86eb6ecc43def1fd8d608ba8334872be86659690bb10e7da72dcc18df5f316b2e6fc0ff37b351cca3510f48b50053c7de638ebbded1a2bc34ff130ad8df98e7353fb6c9be6893bd6d6fa1b07eb79a0bf815fe6e611ec7c99564b7acca2d7266d7de64b3e7fb4911638c0cda8b5c7896f261971e7a6bb04bca5ff6bb80153aed189d62d899d88727778b12e6d9b6d49b0af2dd5bbcc57a8950cd02a5f993bebcf85eeb3ca36179166b52a188870777dcb6d67d707c07f013c035e33c49e76b91389dabc681d04928bfc27be1acea29c61087caf6f8675c1ef572275d5e724e8ed7dea616d2058ba07a7f261622a7479c2bb63bea79956f7b84202e740a1ff0ddaff3500dfa6ab2dfafd2aa0a3a20629f71ebdeb1328d71ecb4301a95f98ee3b82c87eb286138f30f947ccaa9a1bf042ed829b89550455e2fae3fbc8d7803dc53e6565dc3999d2c739c568e80175e15e4d7e5679cce42fd86f44c7b5c87cccceb7a4f8cbda1ce87f3e3f38beb516f2cf737").unwrap();
        let r =
            BigInt::from_hex("030a3ec2711ae5dc9e71711dc4d6bf2beb755be5639a9ce1854e258c4c44921fff")
                .unwrap();
        let k =
            BigInt::from_hex("e1d1318d8b96ed598ce80f8fb9197327bca23f7db51021a6c5cfb8b01851b2ff")
                .unwrap();
        let curve = Curve::Secp256r1;
        let (r_, s, recid) = complete_sig(&paillier_sk, &presig, &r, &k, curve).unwrap();
        assert_eq!(
            r_,
            BigInt::from_hex("0a3ec2711ae5dc9e71711dc4d6bf2beb755be5639a9ce1854e258c4c44921fff")
                .unwrap()
        );
        assert_ne!(
            s,
            BigInt::from_hex("271f3513c9ac42e82ba602b76a40a1510902a6671221f77ba881e8d847c82b22")
                .unwrap()
        );
        assert_eq!(recid, 28);
    }

    #[test]
    fn test_complete_sig_r1_wrong_presig() {
        let paillier_sk = DecryptionKey::from(MinimalDecryptionKey{p: BigInt::from_hex("d3542d07cda6034cf8568b68d69f07b716c98dcc466d7fb89d2a40db4addfe1402ac6007b609734c80fa4dd24f005cc2d404651f724561391fd2c714c054c5ecb98c0d367d5d99cddbd788489151daa247feef546ba173db02576793f2386c89a78e1cf0b1b5e3882efb709663c8fb50f3b973e87447bc0a473b792eeb9720ef").unwrap(), q: BigInt::from_hex("bf9f1abdcfd5f3e30a609ad469637eeadf068f67735c319cd0bfe3cb7ed915d93c33c77078762c3deab68fd66a46903a3241f84ccf827ac27faa339d12f4cf818732220b2a899660765a8554d8bc6490bc7490b7874fe1651dccd25b74bcdb5481e1d09bfe3ec6143c2f9bb2cf3658d514fc8c1e48a8e095b8a0f9fe94891f67").unwrap()});
        let presig = BigInt::from_hex("3a5f82ec76b17ddfc10b15878713cc31fe914674a36b834da70215670d19997a56db6fa8b38fbdb2672a73aafcb4ba7162f35b1ccc0474622f2d2a50406fcd8cfbbca0ad6adaf3bd6c8d574393a8cca548e88f93383d426bb634a390f21014562ca45c2b739b270e65760ef43fc28fa207bfe6e7e159f8f943e66606037814586d512057c0036e98e6b9e2432723c9b86eb6ecc43def1fd8d608ba8334872be86659690bb10e7da72dcc18df5f316b2e6fc0ff37b351cca3510f48b50053c7de638ebbded1a2bc34ff130ad8df98e7353fb6c9be6893bd6d6fa1b07eb79a0bf815fe6e611ec7c99564b7acca2d7266d7de64b3e7fb4911638c0cda8b5c7896f261971e7a6bb04bca5ff6bb80153aed189d62d899d88727778b12e6d9b6d49b0af2dd5bbcc57a8950cd02a5f993bebcf85eeb3ca36179166b52a188870777dcb6d67d707c07f013c035e33c49e76b91389dabc681d04928bfc27be1acea29c61087caf6f8675c1ef572275d5e724e8ed7dea616d2058ba07a7f261622a7479c2bb63bea79956f7b84202e740a1ff0ddaff3500dfa6ab2dfafd2aa0a3a20629f71ebdeb1328d71ecb4301a95f98ee3b82c87eb286138f30f947ccaa9a1bf042ed829b89550455e2fae3fbc8d7803dc53e6565dc3999d2c739c568e80175e15e4d7e5679cce42fd86f44c7b5c87cccceb7a4f8cbda1ce87f3e3f38beb516f2cf737").unwrap();
        let r =
            BigInt::from_hex("030a3ec2711ae5dc9e71711dc4d6bf2beb755be5639a9ce1854e258c4c44921fff")
                .unwrap();
        let k =
            BigInt::from_hex("e1d1318d8b96ed598ce80f8fb9197327bca23f7db51021a6c5cfb8b01851b2ff")
                .unwrap();
        let curve = Curve::Secp256r1;
        let (r_, s, recid) = complete_sig(&paillier_sk, &presig, &r, &k, curve).unwrap();
        assert_eq!(
            r_,
            BigInt::from_hex("0a3ec2711ae5dc9e71711dc4d6bf2beb755be5639a9ce1854e258c4c44921fff")
                .unwrap()
        );
        assert_ne!(
            s,
            BigInt::from_hex("271f3513c9ac42e82ba602b76a40a1510902a6671221f77ba881e8d847c82b22")
                .unwrap()
        );
        assert_eq!(recid, 28);
    }

    #[test]
    fn test_complete_sig_r1_wrong_r() {
        let paillier_sk = DecryptionKey::from(MinimalDecryptionKey{p: BigInt::from_hex("d3542d07cda6034cf8568b68d69f07b716c98dcc466d7fb89d2a40db4addfe1402ac6007b609734c80fa4dd24f005cc2d404651f724561391fd2c714c054c5ecb98c0d367d5d99cddbd788489151daa247feef546ba173db02576793f2386c89a78e1cf0b1b5e3882efb709663c8fb50f3b973e87447bc0a473b792eeb9720ef").unwrap(), q: BigInt::from_hex("bf9f1abdcfd5f3e30a609ad469637eeadf068f67735c319cd0bfe3cb7ed915d93c33c77078762c3deab68fd66a46903a3241f84ccf827ac27faa339d12f4cf818732220b2a899660765a8554d8bc6490bc7490b7874fe1651dccd25b74bcdb5481e1d09bfe3ec6143c2f9bb2cf3658d514fc8c1e48a8e095b8a0f9fe94891f67").unwrap()});
        let presig = BigInt::from_hex("3a4f82ec76b17ddfc10b15878713cc31fe914674a36b834da70215670d19997a56db6fa8b38fbdb2672a73aafcb4ba7162f35b1ccc0474622f2d2a50406fcd8cfbbca0ad6adaf3bd6c8d574393a8cca548e88f93383d426bb634a390f21014562ca45c2b739b270e65760ef43fc28fa207bfe6e7e159f8f943e66606037814586d512057c0036e98e6b9e2432723c9b86eb6ecc43def1fd8d608ba8334872be86659690bb10e7da72dcc18df5f316b2e6fc0ff37b351cca3510f48b50053c7de638ebbded1a2bc34ff130ad8df98e7353fb6c9be6893bd6d6fa1b07eb79a0bf815fe6e611ec7c99564b7acca2d7266d7de64b3e7fb4911638c0cda8b5c7896f261971e7a6bb04bca5ff6bb80153aed189d62d899d88727778b12e6d9b6d49b0af2dd5bbcc57a8950cd02a5f993bebcf85eeb3ca36179166b52a188870777dcb6d67d707c07f013c035e33c49e76b91389dabc681d04928bfc27be1acea29c61087caf6f8675c1ef572275d5e724e8ed7dea616d2058ba07a7f261622a7479c2bb63bea79956f7b84202e740a1ff0ddaff3500dfa6ab2dfafd2aa0a3a20629f71ebdeb1328d71ecb4301a95f98ee3b82c87eb286138f30f947ccaa9a1bf042ed829b89550455e2fae3fbc8d7803dc53e6565dc3999d2c739c568e80175e15e4d7e5679cce42fd86f44c7b5c87cccceb7a4f8cbda1ce87f3e3f38beb516f2cf737").unwrap();
        let r =
            BigInt::from_hex("031a3ec2711ae5dc9e71711dc4d6bf2beb755be5639a9ce1854e258c4c44921fff")
                .unwrap();
        let k =
            BigInt::from_hex("e1d1318d8b96ed598ce80f8fb9197327bca23f7db51021a6c5cfb8b01851b2ff")
                .unwrap();
        let curve = Curve::Secp256r1;
        let (r_, s, recid) = complete_sig(&paillier_sk, &presig, &r, &k, curve).unwrap();
        assert_ne!(
            r_,
            BigInt::from_hex("0a3ec2711ae5dc9e71711dc4d6bf2beb755be5639a9ce1854e258c4c44921fff")
                .unwrap()
        );
        assert_eq!(
            s,
            BigInt::from_hex("271f3513c9ac42e82ba602b76a40a1510902a6671221f77ba881e8d847c82b22")
                .unwrap()
        );
        assert_eq!(recid, 28);
    }

    #[test]
    fn test_complete_sig_r1_wrong_k() {
        let paillier_sk = DecryptionKey::from(MinimalDecryptionKey{p: BigInt::from_hex("d3542d07cda6034cf8568b68d69f07b716c98dcc466d7fb89d2a40db4addfe1402ac6007b609734c80fa4dd24f005cc2d404651f724561391fd2c714c054c5ecb98c0d367d5d99cddbd788489151daa247feef546ba173db02576793f2386c89a78e1cf0b1b5e3882efb709663c8fb50f3b973e87447bc0a473b792eeb9720ef").unwrap(), q: BigInt::from_hex("bf9f1abdcfd5f3e30a609ad469637eeadf068f67735c319cd0bfe3cb7ed915d93c33c77078762c3deab68fd66a46903a3241f84ccf827ac27faa339d12f4cf818732220b2a899660765a8554d8bc6490bc7490b7874fe1651dccd25b74bcdb5481e1d09bfe3ec6143c2f9bb2cf3658d514fc8c1e48a8e095b8a0f9fe94891f67").unwrap()});
        let presig = BigInt::from_hex("3a4f82ec76b17ddfc10b15878713cc31fe914674a36b834da70215670d19997a56db6fa8b38fbdb2672a73aafcb4ba7162f35b1ccc0474622f2d2a50406fcd8cfbbca0ad6adaf3bd6c8d574393a8cca548e88f93383d426bb634a390f21014562ca45c2b739b270e65760ef43fc28fa207bfe6e7e159f8f943e66606037814586d512057c0036e98e6b9e2432723c9b86eb6ecc43def1fd8d608ba8334872be86659690bb10e7da72dcc18df5f316b2e6fc0ff37b351cca3510f48b50053c7de638ebbded1a2bc34ff130ad8df98e7353fb6c9be6893bd6d6fa1b07eb79a0bf815fe6e611ec7c99564b7acca2d7266d7de64b3e7fb4911638c0cda8b5c7896f261971e7a6bb04bca5ff6bb80153aed189d62d899d88727778b12e6d9b6d49b0af2dd5bbcc57a8950cd02a5f993bebcf85eeb3ca36179166b52a188870777dcb6d67d707c07f013c035e33c49e76b91389dabc681d04928bfc27be1acea29c61087caf6f8675c1ef572275d5e724e8ed7dea616d2058ba07a7f261622a7479c2bb63bea79956f7b84202e740a1ff0ddaff3500dfa6ab2dfafd2aa0a3a20629f71ebdeb1328d71ecb4301a95f98ee3b82c87eb286138f30f947ccaa9a1bf042ed829b89550455e2fae3fbc8d7803dc53e6565dc3999d2c739c568e80175e15e4d7e5679cce42fd86f44c7b5c87cccceb7a4f8cbda1ce87f3e3f38beb516f2cf737").unwrap();
        let r =
            BigInt::from_hex("030a3ec2711ae5dc9e71711dc4d6bf2beb755be5639a9ce1854e258c4c44921fff")
                .unwrap();
        let k =
            BigInt::from_hex("f1d1318d8b96ed598ce80f8fb9197327bca23f7db51021a6c5cfb8b01851b2ff")
                .unwrap();
        let curve = Curve::Secp256r1;
        let (r_, s, recid) = complete_sig(&paillier_sk, &presig, &r, &k, curve).unwrap();
        assert_eq!(
            r_,
            BigInt::from_hex("0a3ec2711ae5dc9e71711dc4d6bf2beb755be5639a9ce1854e258c4c44921fff")
                .unwrap()
        );
        assert_ne!(
            s,
            BigInt::from_hex("271f3513c9ac42e82ba602b76a40a1510902a6671221f77ba881e8d847c82b22")
                .unwrap()
        );
        assert_ne!(recid, 28);
    }

    #[test]
    #[should_panic]
    fn test_complete_sig_r1_wrong_curve() {
        let paillier_sk = DecryptionKey::from(MinimalDecryptionKey{p: BigInt::from_hex("d3542d07cda6034cf8568b68d69f07b716c98dcc466d7fb89d2a40db4addfe1402ac6007b609734c80fa4dd24f005cc2d404651f724561391fd2c714c054c5ecb98c0d367d5d99cddbd788489151daa247feef546ba173db02576793f2386c89a78e1cf0b1b5e3882efb709663c8fb50f3b973e87447bc0a473b792eeb9720ef").unwrap(), q: BigInt::from_hex("bf9f1abdcfd5f3e30a609ad469637eeadf068f67735c319cd0bfe3cb7ed915d93c33c77078762c3deab68fd66a46903a3241f84ccf827ac27faa339d12f4cf818732220b2a899660765a8554d8bc6490bc7490b7874fe1651dccd25b74bcdb5481e1d09bfe3ec6143c2f9bb2cf3658d514fc8c1e48a8e095b8a0f9fe94891f67").unwrap()});
        let presig = BigInt::from_hex("3a4f82ec76b17ddfc10b15878713cc31fe914674a36b834da70215670d19997a56db6fa8b38fbdb2672a73aafcb4ba7162f35b1ccc0474622f2d2a50406fcd8cfbbca0ad6adaf3bd6c8d574393a8cca548e88f93383d426bb634a390f21014562ca45c2b739b270e65760ef43fc28fa207bfe6e7e159f8f943e66606037814586d512057c0036e98e6b9e2432723c9b86eb6ecc43def1fd8d608ba8334872be86659690bb10e7da72dcc18df5f316b2e6fc0ff37b351cca3510f48b50053c7de638ebbded1a2bc34ff130ad8df98e7353fb6c9be6893bd6d6fa1b07eb79a0bf815fe6e611ec7c99564b7acca2d7266d7de64b3e7fb4911638c0cda8b5c7896f261971e7a6bb04bca5ff6bb80153aed189d62d899d88727778b12e6d9b6d49b0af2dd5bbcc57a8950cd02a5f993bebcf85eeb3ca36179166b52a188870777dcb6d67d707c07f013c035e33c49e76b91389dabc681d04928bfc27be1acea29c61087caf6f8675c1ef572275d5e724e8ed7dea616d2058ba07a7f261622a7479c2bb63bea79956f7b84202e740a1ff0ddaff3500dfa6ab2dfafd2aa0a3a20629f71ebdeb1328d71ecb4301a95f98ee3b82c87eb286138f30f947ccaa9a1bf042ed829b89550455e2fae3fbc8d7803dc53e6565dc3999d2c739c568e80175e15e4d7e5679cce42fd86f44c7b5c87cccceb7a4f8cbda1ce87f3e3f38beb516f2cf737").unwrap();
        let r =
            BigInt::from_hex("030a3ec2711ae5dc9e71711dc4d6bf2beb755be5639a9ce1854e258c4c44921fff")
                .unwrap();
        let k =
            BigInt::from_hex("e1d1318d8b96ed598ce80f8fb9197327bca23f7db51021a6c5cfb8b01851b2ff")
                .unwrap();
        let curve = Curve::Secp256k1;
        complete_sig(&paillier_sk, &presig, &r, &k, curve).unwrap();
    }
}
