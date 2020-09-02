/*
 * Node.js client interface to MPC-based API keys
 */

use mpc_wallet_lib::bigints::traits::Converter;
use mpc_wallet_lib::bigints::BigInt;
use mpc_wallet_lib::curves::secp256_k1::{Secp256k1Point, Secp256k1Scalar};
use mpc_wallet_lib::curves::secp256_r1::{Secp256r1Point, Secp256r1Scalar};
use mpc_wallet_lib::curves::traits::ECScalar;
use mpc_wallet_lib::paillier::EncryptionKey;
use mpc_wallet_lib::{client, common};
use neon::prelude::register_module;
use neon_serde::export;

export! {
    /// Generate shared random values using Diffie-Hellman
    /// Input: n: number of values to generate, curve: Secp256r1 or Secp256k1
    /// Output: dh_secrets: list of (n) DH secret values, dh_publics: list of (n) DH public values
    fn dh_init(n: usize, curve: common::Curve) -> String {
        if curve == common::Curve::Secp256k1 {
            let (dh_secrets, dh_publics) = match common::dh_init_secp256k1(n) {
                Ok(v) => v,
                Err(_) => return serde_json::to_string(&(false, &"error: n is too big.")).unwrap(),
            };
            serde_json::to_string(&(true, &dh_secrets, &dh_publics)).unwrap()
        } else if curve == common::Curve::Secp256r1 {
            let (dh_secrets, dh_publics) = match common::dh_init_secp256r1(n) {
                Ok(v) => v,
                Err(_) => return serde_json::to_string(&(false, &"error: n is too big.")).unwrap(),
            };
            serde_json::to_string(&(true, &dh_secrets, &dh_publics)).unwrap()
        } else {
            serde_json::to_string(&(false, &"error: invalid curve")).unwrap()
        }
    }

    /// Fill pool of random and nonce values to facilitate signature generation with a single message.
    /// Input: client_dh_secrets: list of client DH secret values, server_dh_publics: list of server DH public values, curve: Secp256k1 or Secp256r1, paillier_pk: Paillier public key
    /// Output: none
    fn fill_rpool(client_dh_secrets_str: String, server_dh_publics_str: String, curve: common::Curve, paillier_pk_str: String) -> String {
        let paillier_pk: EncryptionKey = match serde_json::from_str(&paillier_pk_str) {
            Ok(v) => v,
            Err(_) => {
                return serde_json::to_string(&(false, &"error deserializing paillier_pk")).unwrap()
            }
        };
        if curve == common::Curve::Secp256k1 {
            let client_dh_secrets: Vec<Secp256k1Scalar> =
            match serde_json::from_str(&client_dh_secrets_str) {
                Ok(v) => v,
                Err(_) => {
                    return serde_json::to_string(&(false, &"error deserializing client_dh_secrets"))
                        .unwrap()
                }
            };
            let server_dh_publics: Vec<Secp256k1Point> =
                match serde_json::from_str(&server_dh_publics_str) {
                    Ok(v) => v,
                    Err(_) => {
                        return serde_json::to_string(&(
                            false,
                            &"error deserializing server_dh_publics",
                        ))
                        .unwrap()
                    }
                };
            match client::fill_rpool_secp256k1(client_dh_secrets, &server_dh_publics, &paillier_pk) {
                Ok(v) => v,
                Err(_) => return serde_json::to_string(&(false, &"error filling rpool")).unwrap(),
            };
        } else if curve == common::Curve::Secp256r1 {
            let client_dh_secrets: Vec<Secp256r1Scalar> =
            match serde_json::from_str(&client_dh_secrets_str) {
                Ok(v) => v,
                Err(_) => {
                    return serde_json::to_string(&(false, &"error deserializing client_dh_secrets"))
                        .unwrap()
                }
            };
            let server_dh_publics: Vec<Secp256r1Point> =
                match serde_json::from_str(&server_dh_publics_str) {
                    Ok(v) => v,
                    Err(_) => {
                        return serde_json::to_string(&(
                            false,
                            &"error deserializing server_dh_publics",
                        ))
                        .unwrap()
                    }
                };
            match client::fill_rpool_secp256r1(client_dh_secrets, &server_dh_publics, &paillier_pk) {
                Ok(v) => v,
                Err(_) => return serde_json::to_string(&(false, &"error filling rpool")).unwrap(),
            };
        } else {
            return serde_json::to_string(&(false, &"error: invalid curve")).unwrap();
        }
        serde_json::to_string(&(&true, &"rpool filled successfully")).unwrap()
    }

    /// Get current size of pool of r-values.
    /// Input: curve: Secp256k1 or Secp256r1
    /// Output: size of pool
    fn get_rpool_size(curve: common::Curve) -> String {
        let size = match client::get_rpool_size(curve) {
            Ok(v) => v,
            Err(_) => return serde_json::to_string(&(false, &"error: invalid curve")).unwrap(),
        };
        serde_json::to_string(&(&true, size)).unwrap()
    }

    /// Compute presignature.
    /// Input: api_childkey: API childkey struct, msg_hash: message hash, curve: Secp256k1 or Secp256r1 curve
    /// Output: presig: presignature, r: message-independent part of the signature used
    fn compute_presig(api_childkey_str: String, msg_hash_str: String, curve: common::Curve) -> String {
        let api_childkey: client::APIchildkey = match serde_json::from_str(&api_childkey_str) {
            Ok(v) => v,
            Err(_) => {
                return serde_json::to_string(&(false, &"error deserializing api_childkey")).unwrap()
            }
        };
        let msg_hash = match BigInt::from_hex(&msg_hash_str) {
            Ok(v) => v,
            Err(_) => return serde_json::to_string(&(false, &"error deserializing msg_hash")).unwrap(),
        };
        let (presig, r) = match client::compute_presig(&api_childkey, &msg_hash, curve) {
            Ok(v) => v,
            Err(_) => {
                return serde_json::to_string(&(
                    false,
                    &"error: rpool empty, invalid r value, or invalid curve.",
                ))
                .unwrap()
            }
        };
        // add leading zeros if necessary
        serde_json::to_string(&(
            &true,
            &format!("{:0>1024}", presig.to_hex()),
            &format!("{:0>66}", r.to_hex()),
        ))
        .unwrap()
    }

    /// Generate signature for given message hash under given secret key
    /// Input: secret_key: full secret key, msg_hash: message hash
    /// Output: (r, s): ECDSA signature
    fn sign(secret_key_str: String, msg_hash_str: String) -> String {
        let secret_key_int = match BigInt::from_hex(&secret_key_str) {
            Ok(v) => v,
            Err(_) => {
                return serde_json::to_string(&(false, &"error deserializing secret_key")).unwrap()
            }
        };
        let secret_key: Secp256k1Scalar = ECScalar::from(&secret_key_int);
        let msg_hash = match BigInt::from_hex(&msg_hash_str) {
            Ok(v) => v,
            Err(_) => return serde_json::to_string(&(false, &"error deserializing msg_hash")).unwrap(),
        };
        let (r, s) = client::sign(&secret_key, &msg_hash);
        serde_json::to_string(&(&true, &format!("{:0>64}", r.to_hex()), &format!("{:0>64}", s.to_hex()))).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::{compute_presig, dh_init, fill_rpool, get_rpool_size, sign};
    use mpc_wallet_lib::common::Curve;

    #[test]
    fn test_dh_init_ok() {
        let result = dh_init(1, Curve::Secp256k1);
        let (success, _, _): (bool, Vec<String>, Vec<String>) =
            serde_json::from_str(&result).unwrap();
        assert!(success);
    }

    #[test]
    fn test_get_rpool_size_ok() {
        let result = get_rpool_size(Curve::Secp256k1);
        let (success, _): (bool, usize) = serde_json::from_str(&result).unwrap();
        assert!(success);
    }

    #[test]
    fn test_fill_rpool_k1_ok() {
        let result = fill_rpool(
            "[\"aa75ca8a2fd3f8af94976bfaa7aa476dc31f5d78d9fef8fb86a97a775f611ae5\"]".to_string(),
            "[\"031241ac15c9c9c070e1cba1dbdb3992018f9c66f0e50a8d9afbebc510aaf355e7\"]".to_string(),
            Curve::Secp256k1,
            "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}".to_string(),
        );
        let (success, _): (bool, String) = serde_json::from_str(&result).unwrap();
        assert!(success);
    }

    #[test]
    fn test_fill_rpool_k1_wrong_dh_secrets() {
        let result = fill_rpool(
            "[a\"aa75ca8a2fd3f8af94976bfaa7aa476dc31f5d78d9fef8fb86a97a775f611ae5\"]".to_string(),
            "[\"031241ac15c9c9c070e1cba1dbdb3992018f9c66f0e50a8d9afbebc510aaf355e7\"]".to_string(),
            Curve::Secp256k1,
            "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}".to_string(),
        );
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing client_dh_secrets");
        assert!(!success);
    }

    #[test]
    fn test_fill_rpool_k1_wrong_dh_publics() {
        let result = fill_rpool(
            "[\"aa75ca8a2fd3f8af94976bfaa7aa476dc31f5d78d9fef8fb86a97a775f611ae5\"]".to_string(),
            "\"031241ac15c9c9c070e1cba1dbdb3992018f9c66f0e50a8d9afbebc510aaf355e7\"]".to_string(),
            Curve::Secp256k1,
            "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}".to_string(),
        );
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        println!("{:?}", msg);
        assert_eq!(msg, "error deserializing server_dh_publics");
        assert!(!success);
    }

    #[test]
    fn test_fill_rpool_r1_ok() {
        let result = fill_rpool(
            "[\"312a8e55996f72a708929e68c7c0f4dcdcdcddb35d512f9ded388bcd7dce8633\"]".to_string(),
            "[\"0260b63daf0f1576b1275f4713c2393dd0de89abbc14e70c7b1e209f5a9fbb69f0\"]".to_string(),
            Curve::Secp256r1,
            "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}".to_string(),
        );
        let (success, _): (bool, String) = serde_json::from_str(&result).unwrap();
        assert!(success);
    }

    #[test]
    fn test_fill_rpool_r1_wrong_dh_secrets() {
        let result = fill_rpool(
            "\"312a8e55996f72a708929e68c7c0f4dcdcdcddb35d512f9ded388bcd7dce8633\"]".to_string(),
            "[\"0260b63daf0f1576b1275f4713c2393dd0de89abbc14e70c7b1e209f5a9fbb69f0\"]".to_string(),
            Curve::Secp256r1,
            "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}".to_string(),
        );
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing client_dh_secrets");
        assert!(!success);
    }

    #[test]
    fn test_fill_rpool_r1_wrong_dh_publics() {
        let result = fill_rpool(
            "[\"312a8e55996f72a708929e68c7c0f4dcdcdcddb35d512f9ded388bcd7dce8633\"]".to_string(),
            "[\"\"]".to_string(),
            Curve::Secp256r1,
            "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}".to_string(),
        );
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing server_dh_publics");
        assert!(!success);
    }

    #[test]
    fn test_compute_presig_k1_ok() {
        fill_rpool(
            "[\"aa75ca8a2fd3f8af94976bfaa7aa476dc31f5d78d9fef8fb86a97a775f611ae5\"]".to_string(),
            "[\"031241ac15c9c9c070e1cba1dbdb3992018f9c66f0e50a8d9afbebc510aaf355e7\"]".to_string(),
            Curve::Secp256k1,
            "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}".to_string(),
        );
        let result = compute_presig(
        "{\"paillier_pk\":{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"},\"public_key\":\"042f1fa347032efc9cece1e1c5edcbdda64aaff92911949fe0adbb165e8d82c13025485b8c218e56a5dd932cc9ab6efaff611dc42cc3aa3acd0b0ea5ba7f1a8de3\",\"client_secret_share\":\"bc45e8d856be2e179e015dc2429d84a628cb7f4755f63e030784e1ee3ee9f43d\",\"server_secret_share_encrypted\":\"4996ad9776bf178dc7155f4b7994b94a5c85b0c3579b9ecca3c3903c9569845e1f51368ba3cb764819fb739047ccfcffe57a47a0fe640c8ef67d416b8888d4b0235de56418c944a8a38bec9bcde913ff5109d68055b7c843dd4c5e77d4d654305a74493ddc1353eb7261dcf4a8c8545604b48d96e272887aa06c80fa58532e8c3a4f7e44869ea42a73084a7b48d02503b8e8489230660b05a08ace5e4517c1a8f51bca8d50952e99f3c0e84a71dc3831ea4b2ff9cbd9a37ce057320c14b71b2daf0fb66edc7d3a02547b6518f557ceabe7981e3958f8ffa7befc71191bfcfa08d382e7fa60d2bd7f76a59ce33a35c829d89f7326c17142d89e660ab328714e2e3087dff5e0950a2c11c3320257a90d679b7a3bc5cd9c7ab5c03d39d7416f6530dda75e9582fddffb558f637272d26c18c23a54a5f292badd0cb69f758a7bc6cacc38b5bd7e4b1021b62d85af345d5e42bda7e47144e8646d37e999686d479ad91f117fb0b2656026d271f1a56bc8cbeba409e9ccc45ff1f393141dde2e1c4ed1ad1ceb63ea1725a601c050a5789c901b155b180cef078b2c16adf7956640df8c185cf8e973acdb6c1bda1ab408a03849a6cf41a12ae69e5886c087686048c21b0fcc9dff020af065809b8ad9165354669fb77df11cfcb502042da9acc1f7cccbcee5b5ff458130e12bbbc1cec3b26acfad6373cb4b4ea8cc5597af6299836b70\"}".to_string(),
        "000000000000000fffffffffffffffffff00000000000000ffffffffff000000".to_string(),
        Curve::Secp256k1);
        let (success, _, _): (bool, String, String) = serde_json::from_str(&result).unwrap();
        assert!(success);
    }

    #[test]
    fn test_compute_presig_k1_wrong_childkey() {
        fill_rpool(
            "[\"aa75ca8a2fd3f8af94976bfaa7aa476dc31f5d78d9fef8fb86a97a775f611ae5\"]".to_string(),
            "[\"031241ac15c9c9c070e1cba1dbdb3992018f9c66f0e50a8d9afbebc510aaf355e7\"]".to_string(),
            Curve::Secp256k1,
            "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}".to_string(),
        );
        let result = compute_presig(
        "a{\"paillier_pk\":{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"},\"public_key\":\"042f1fa347032efc9cece1e1c5edcbdda64aaff92911949fe0adbb165e8d82c13025485b8c218e56a5dd932cc9ab6efaff611dc42cc3aa3acd0b0ea5ba7f1a8de3\",\"client_secret_share\":\"bc45e8d856be2e179e015dc2429d84a628cb7f4755f63e030784e1ee3ee9f43d\",\"server_secret_share_encrypted\":\"4996ad9776bf178dc7155f4b7994b94a5c85b0c3579b9ecca3c3903c9569845e1f51368ba3cb764819fb739047ccfcffe57a47a0fe640c8ef67d416b8888d4b0235de56418c944a8a38bec9bcde913ff5109d68055b7c843dd4c5e77d4d654305a74493ddc1353eb7261dcf4a8c8545604b48d96e272887aa06c80fa58532e8c3a4f7e44869ea42a73084a7b48d02503b8e8489230660b05a08ace5e4517c1a8f51bca8d50952e99f3c0e84a71dc3831ea4b2ff9cbd9a37ce057320c14b71b2daf0fb66edc7d3a02547b6518f557ceabe7981e3958f8ffa7befc71191bfcfa08d382e7fa60d2bd7f76a59ce33a35c829d89f7326c17142d89e660ab328714e2e3087dff5e0950a2c11c3320257a90d679b7a3bc5cd9c7ab5c03d39d7416f6530dda75e9582fddffb558f637272d26c18c23a54a5f292badd0cb69f758a7bc6cacc38b5bd7e4b1021b62d85af345d5e42bda7e47144e8646d37e999686d479ad91f117fb0b2656026d271f1a56bc8cbeba409e9ccc45ff1f393141dde2e1c4ed1ad1ceb63ea1725a601c050a5789c901b155b180cef078b2c16adf7956640df8c185cf8e973acdb6c1bda1ab408a03849a6cf41a12ae69e5886c087686048c21b0fcc9dff020af065809b8ad9165354669fb77df11cfcb502042da9acc1f7cccbcee5b5ff458130e12bbbc1cec3b26acfad6373cb4b4ea8cc5597af6299836b70\"}".to_string(),
        "000000000000000fffffffffffffffffff00000000000000ffffffffff000000".to_string(),
        Curve::Secp256k1);
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing api_childkey");
        assert!(!success);
    }

    #[test]
    fn test_compute_presig_k1_wrong_hash() {
        fill_rpool(
            "[\"aa75ca8a2fd3f8af94976bfaa7aa476dc31f5d78d9fef8fb86a97a775f611ae5\"]".to_string(),
            "[\"031241ac15c9c9c070e1cba1dbdb3992018f9c66f0e50a8d9afbebc510aaf355e7\"]".to_string(),
            Curve::Secp256k1,
            "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}".to_string(),
        );
        let result = compute_presig(
        "{\"paillier_pk\":{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"},\"public_key\":\"042f1fa347032efc9cece1e1c5edcbdda64aaff92911949fe0adbb165e8d82c13025485b8c218e56a5dd932cc9ab6efaff611dc42cc3aa3acd0b0ea5ba7f1a8de3\",\"client_secret_share\":\"bc45e8d856be2e179e015dc2429d84a628cb7f4755f63e030784e1ee3ee9f43d\",\"server_secret_share_encrypted\":\"4996ad9776bf178dc7155f4b7994b94a5c85b0c3579b9ecca3c3903c9569845e1f51368ba3cb764819fb739047ccfcffe57a47a0fe640c8ef67d416b8888d4b0235de56418c944a8a38bec9bcde913ff5109d68055b7c843dd4c5e77d4d654305a74493ddc1353eb7261dcf4a8c8545604b48d96e272887aa06c80fa58532e8c3a4f7e44869ea42a73084a7b48d02503b8e8489230660b05a08ace5e4517c1a8f51bca8d50952e99f3c0e84a71dc3831ea4b2ff9cbd9a37ce057320c14b71b2daf0fb66edc7d3a02547b6518f557ceabe7981e3958f8ffa7befc71191bfcfa08d382e7fa60d2bd7f76a59ce33a35c829d89f7326c17142d89e660ab328714e2e3087dff5e0950a2c11c3320257a90d679b7a3bc5cd9c7ab5c03d39d7416f6530dda75e9582fddffb558f637272d26c18c23a54a5f292badd0cb69f758a7bc6cacc38b5bd7e4b1021b62d85af345d5e42bda7e47144e8646d37e999686d479ad91f117fb0b2656026d271f1a56bc8cbeba409e9ccc45ff1f393141dde2e1c4ed1ad1ceb63ea1725a601c050a5789c901b155b180cef078b2c16adf7956640df8c185cf8e973acdb6c1bda1ab408a03849a6cf41a12ae69e5886c087686048c21b0fcc9dff020af065809b8ad9165354669fb77df11cfcb502042da9acc1f7cccbcee5b5ff458130e12bbbc1cec3b26acfad6373cb4b4ea8cc5597af6299836b70\"}".to_string(),
        "z000000000000000fffffffffffffffffff00000000000000ffffffffff000000".to_string(),
        Curve::Secp256k1);
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing msg_hash");
        assert!(!success);
    }

    #[test]
    fn test_compute_presig_r1_ok() {
        fill_rpool(
            "[\"312a8e55996f72a708929e68c7c0f4dcdcdcddb35d512f9ded388bcd7dce8633\"]".to_string(),
            "[\"0260b63daf0f1576b1275f4713c2393dd0de89abbc14e70c7b1e209f5a9fbb69f0\"]".to_string(),
            Curve::Secp256r1,
            "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}".to_string(),
        );
        let result = compute_presig(
        "{\"paillier_pk\":{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"},\"public_key\":\"04edb74abcc30629455eccbe8d3a61a8694999656de8b8f0615ad50c4c3ef238e5dcf1956f7877ffb5c927e5d3e479fe913e10a0caa7a34866fe44f8bddf4b0a04\",\"client_secret_share\":\"50dae30585846dd84c7cbf8fc6343937c562ae6e0cc4658b712a6ac3478c12d6\",\"server_secret_share_encrypted\":\"52de7f3c637d3d62853394a388fe092fcc125bbcf23a9507f641771073bdf690a64529eaee5979f411cc9972c12cbbfa13b3c55f5201ad335f382b26ed90d46913d5367a3144553c32e90609416505e60e374adba08c944c375d3c20d3fc3b31c2c2766c4b2572dc8a4434bdab56ea49e4b815d515df6269db07b35f21af1e45b2cef6d1b2acd0777ba0c80c184404c36cfe35ea4b809262dd9217f58c461857ed948874b20c74eb419a0e7c62842edbd500c619e0e390d8807ca3938d6d9229993ef89574212c7581b5abfc4c293d607187d85fdedc8a9a21156c59ad3189d08d61414bfffcba45f91cdfe9c479147fdf5fce2b22bebaa07dae62b0e728176b7787cceba5d1c8b66c4dd2e4197f9ba1911917adc94f149820391ebdc1d031a12f58f4eb3422071b9f236140be1c98010adafb6cf867f52f0d0b1dafa9f08bf42f1c19062e7eb65e441dc38b1fdcb047b2ce879ee3e3c59f22bb29f1d8b7788ef26512ee735987d3ae30fd8eb4308d1f8758dc713e0716564cfdfecaed7244961e90450d761e524a4f538e9b20bd779c7ae6bf81f47226215bb2b20a425ff333cec1cf849d34eeb2f250672ca88ff7400f6d3864bf6e4de701c07a13d0d4d40459c0663a95159fb3112f6375ddcc26c785e10e9956998c848c7cfcb9d8f5692ad544c5109fc9a113cc66950b557e9be737d61a1d05694f0eb90ee918f07ec3a8\"}".to_string(),
        "000000000000000fffffffffffffffffff00000000000000ffffffffff000000".to_string(),
        Curve::Secp256r1);
        let (success, _, _): (bool, String, String) = serde_json::from_str(&result).unwrap();
        assert!(success);
    }

    #[test]
    fn test_compute_presig_r1_wrong_childkey() {
        fill_rpool(
            "[\"312a8e55996f72a708929e68c7c0f4dcdcdcddb35d512f9ded388bcd7dce8633\"]".to_string(),
            "[\"0260b63daf0f1576b1275f4713c2393dd0de89abbc14e70c7b1e209f5a9fbb69f0\"]".to_string(),
            Curve::Secp256r1,
            "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}".to_string(),
        );
        let result = compute_presig(
        "{\"\":{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"},\"public_key\":\"04edb74abcc30629455eccbe8d3a61a8694999656de8b8f0615ad50c4c3ef238e5dcf1956f7877ffb5c927e5d3e479fe913e10a0caa7a34866fe44f8bddf4b0a04\",\"client_secret_share\":\"50dae30585846dd84c7cbf8fc6343937c562ae6e0cc4658b712a6ac3478c12d6\",\"server_secret_share_encrypted\":\"52de7f3c637d3d62853394a388fe092fcc125bbcf23a9507f641771073bdf690a64529eaee5979f411cc9972c12cbbfa13b3c55f5201ad335f382b26ed90d46913d5367a3144553c32e90609416505e60e374adba08c944c375d3c20d3fc3b31c2c2766c4b2572dc8a4434bdab56ea49e4b815d515df6269db07b35f21af1e45b2cef6d1b2acd0777ba0c80c184404c36cfe35ea4b809262dd9217f58c461857ed948874b20c74eb419a0e7c62842edbd500c619e0e390d8807ca3938d6d9229993ef89574212c7581b5abfc4c293d607187d85fdedc8a9a21156c59ad3189d08d61414bfffcba45f91cdfe9c479147fdf5fce2b22bebaa07dae62b0e728176b7787cceba5d1c8b66c4dd2e4197f9ba1911917adc94f149820391ebdc1d031a12f58f4eb3422071b9f236140be1c98010adafb6cf867f52f0d0b1dafa9f08bf42f1c19062e7eb65e441dc38b1fdcb047b2ce879ee3e3c59f22bb29f1d8b7788ef26512ee735987d3ae30fd8eb4308d1f8758dc713e0716564cfdfecaed7244961e90450d761e524a4f538e9b20bd779c7ae6bf81f47226215bb2b20a425ff333cec1cf849d34eeb2f250672ca88ff7400f6d3864bf6e4de701c07a13d0d4d40459c0663a95159fb3112f6375ddcc26c785e10e9956998c848c7cfcb9d8f5692ad544c5109fc9a113cc66950b557e9be737d61a1d05694f0eb90ee918f07ec3a8\"}".to_string(),
        "000000000000000fffffffffffffffffff00000000000000ffffffffff000000".to_string(),
        Curve::Secp256r1);
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing api_childkey");
        assert!(!success);
    }

    #[test]
    fn test_compute_presig_r1_wrong_hash() {
        fill_rpool(
            "[\"312a8e55996f72a708929e68c7c0f4dcdcdcddb35d512f9ded388bcd7dce8633\"]".to_string(),
            "[\"0260b63daf0f1576b1275f4713c2393dd0de89abbc14e70c7b1e209f5a9fbb69f0\"]".to_string(),
            Curve::Secp256r1,
            "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}".to_string(),
        );
        let result = compute_presig(
        "{\"paillier_pk\":{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"},\"public_key\":\"04edb74abcc30629455eccbe8d3a61a8694999656de8b8f0615ad50c4c3ef238e5dcf1956f7877ffb5c927e5d3e479fe913e10a0caa7a34866fe44f8bddf4b0a04\",\"client_secret_share\":\"50dae30585846dd84c7cbf8fc6343937c562ae6e0cc4658b712a6ac3478c12d6\",\"server_secret_share_encrypted\":\"52de7f3c637d3d62853394a388fe092fcc125bbcf23a9507f641771073bdf690a64529eaee5979f411cc9972c12cbbfa13b3c55f5201ad335f382b26ed90d46913d5367a3144553c32e90609416505e60e374adba08c944c375d3c20d3fc3b31c2c2766c4b2572dc8a4434bdab56ea49e4b815d515df6269db07b35f21af1e45b2cef6d1b2acd0777ba0c80c184404c36cfe35ea4b809262dd9217f58c461857ed948874b20c74eb419a0e7c62842edbd500c619e0e390d8807ca3938d6d9229993ef89574212c7581b5abfc4c293d607187d85fdedc8a9a21156c59ad3189d08d61414bfffcba45f91cdfe9c479147fdf5fce2b22bebaa07dae62b0e728176b7787cceba5d1c8b66c4dd2e4197f9ba1911917adc94f149820391ebdc1d031a12f58f4eb3422071b9f236140be1c98010adafb6cf867f52f0d0b1dafa9f08bf42f1c19062e7eb65e441dc38b1fdcb047b2ce879ee3e3c59f22bb29f1d8b7788ef26512ee735987d3ae30fd8eb4308d1f8758dc713e0716564cfdfecaed7244961e90450d761e524a4f538e9b20bd779c7ae6bf81f47226215bb2b20a425ff333cec1cf849d34eeb2f250672ca88ff7400f6d3864bf6e4de701c07a13d0d4d40459c0663a95159fb3112f6375ddcc26c785e10e9956998c848c7cfcb9d8f5692ad544c5109fc9a113cc66950b557e9be737d61a1d05694f0eb90ee918f07ec3a8\"}".to_string(),
        "000000000000000fffffffffffffffffff00000000000000ffffffffff000000h".to_string(),
        Curve::Secp256r1);

        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing msg_hash");
        assert!(!success);
    }

    #[test]
    fn test_sign_ok() {
        let result = sign(
            "4794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1".to_string(),
            "100000000000000fffffffffffffffffff00000000000000ffffffffff000000".to_string(),
        );
        let (success, _, _): (bool, String, String) = serde_json::from_str(&result).unwrap();
        assert!(success);
    }

    #[test]
    fn test_sign_wrong_sk() {
        let result = sign(
            "z794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1".to_string(),
            "100000000000000fffffffffffffffffff00000000000000ffffffffff000000".to_string(),
        );
        let (success, _): (bool, String) = serde_json::from_str(&result).unwrap();
        assert!(!success);
    }

    #[test]
    fn test_sign_wrong_hash() {
        let result = sign(
            "4794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1".to_string(),
            "\\00000000000000fffffffffffffffffff00000000000000ffffffffff000000".to_string(),
        );
        let (success, _): (bool, String) = serde_json::from_str(&result).unwrap();
        assert!(!success);
    }
}
