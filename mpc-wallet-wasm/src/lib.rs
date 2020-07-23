/*
 * WASM client interface to MPC-based API keys
 */

use mpc_wallet_lib::bigints::traits::Converter;
use mpc_wallet_lib::bigints::BigInt;
use mpc_wallet_lib::curves::secp256_k1::{Secp256k1Point, Secp256k1Scalar};
use mpc_wallet_lib::curves::secp256_r1::{Secp256r1Point, Secp256r1Scalar};
use mpc_wallet_lib::curves::traits::ECScalar;
use mpc_wallet_lib::paillier::EncryptionKey;
use mpc_wallet_lib::{client, common};
use wasm_bindgen::prelude::*;

/// Generate shared random values using Diffie-Hellman
/// Input: n: number of values to generate, curve: Secp256r1 or Secp256k1
/// Output: dh_secrets: list of (n) DH secret values, dh_publics: list of (n) DH public values
#[wasm_bindgen]
pub fn dh_init(n: usize, curve_str: &str) -> String {
    let curve: common::Curve = match serde_json::from_str(&curve_str) {
        Ok(v) => v,
        Err(_) => return serde_json::to_string(&(false, &"error deserializing curve")).unwrap(),
    };
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

/// Initialize API key creation by setting the full secret key
/// Input: secret_key: full secret key
/// Output: API key creation struct
#[wasm_bindgen]
pub fn init_api_childkey_creator(secret_key_str: &str) -> String {
    let secret_key = match BigInt::from_hex(&secret_key_str) {
        Ok(v) => v,
        Err(_) => {
            return serde_json::to_string(&(false, &"error deserializing secret_key")).unwrap()
        }
    };
    let api_childkey_creator = client::APIchildkeyCreator::init(&secret_key);
    serde_json::to_string(&(true, &api_childkey_creator)).unwrap()
}

/// Initialize api key creation by setting the full secret key and the paillier public key.
/// The Paillier public key must have been verified for correctness before!
/// This facilitates fast API key generation, because the correctness of the Paillier public key needs only be checked once.
/// Input: secret_key: full secret key, paillier_pk: Paillier public key
/// Output: api_childkey_creator: API key creation struct
#[wasm_bindgen]
pub fn init_api_childkey_creator_with_verified_paillier(
    secret_key_str: &str,
    paillier_pk_str: &str,
) -> String {
    let secret_key = match BigInt::from_hex(&secret_key_str) {
        Ok(v) => v,
        Err(_) => {
            return serde_json::to_string(&(false, &"error deserializing secret_key")).unwrap()
        }
    };
    let paillier_pk: EncryptionKey = match serde_json::from_str(&paillier_pk_str) {
        Ok(v) => v,
        Err(_) => {
            return serde_json::to_string(&(false, &"error deserializing paillier_pk")).unwrap()
        }
    };
    let api_childkey_creator =
        client::APIchildkeyCreator::init_with_verified_paillier(&secret_key, &paillier_pk);
    serde_json::to_string(&(true, &api_childkey_creator)).unwrap()
}

/// Verify that the Paillier public key was generated correctly.
/// Input: api_childkey_creator: API key creation struct, paillier_pk: Paillier public key, correct_key_proof: proof
/// Output: api_childkey_creator: API key creation struct
#[wasm_bindgen]
pub fn verify_paillier(
    api_childkey_creator_str: &str,
    paillier_pk_str: &str,
    correct_key_proof_str: &str,
) -> String {
    let api_childkey_creator: client::APIchildkeyCreator =
        match serde_json::from_str(&api_childkey_creator_str) {
            Ok(v) => v,
            Err(_) => {
                return serde_json::to_string(&(false, &"error deserializing api_childkey_creator"))
                    .unwrap()
            }
        };
    let paillier_pk: EncryptionKey = match serde_json::from_str(&paillier_pk_str) {
        Ok(v) => v,
        Err(_) => {
            return serde_json::to_string(&(false, &"error deserializing paillier_pk")).unwrap()
        }
    };
    let correct_key_proof: common::CorrectKeyProof =
        match serde_json::from_str(&correct_key_proof_str) {
            Ok(v) => v,
            Err(_) => {
                return serde_json::to_string(&(false, &"error deserializing correct_key_proof"))
                    .unwrap()
            }
        };
    let api_childkey_creator_new = match api_childkey_creator
        .verify_paillier(&paillier_pk, &correct_key_proof)
    {
        Ok(v) => v,
        Err(_) => return serde_json::to_string(&(false, &"error verifying paillier_pk")).unwrap(),
    };
    serde_json::to_string(&(true, &api_childkey_creator_new)).unwrap()
}

/// Create API childkey
/// Input: api_childkey_creator: API childkey creation struct, curve: Secp256k1 or Secp256r1 curve
/// Output: api_childkey: API childkey struct
#[wasm_bindgen]
pub fn create_api_childkey(api_childkey_creator_str: &str, curve_str: &str) -> String {
    let api_childkey_creator: client::APIchildkeyCreator =
        match serde_json::from_str(&api_childkey_creator_str) {
            Ok(v) => v,
            Err(_) => {
                return serde_json::to_string(&(false, &"error deserializing api_childkey_creator"))
                    .unwrap()
            }
        };
    let curve: common::Curve = match serde_json::from_str(&curve_str) {
        Ok(v) => v,
        Err(_) => return serde_json::to_string(&(false, &"error deserializing curve")).unwrap(),
    };
    let api_childkey = match api_childkey_creator.create_api_childkey(curve) {
        Ok(v) => v,
        Err(_) => {
            return serde_json::to_string(&(false, &"error: paillier_pk not verified yet")).unwrap()
        }
    };
    serde_json::to_string(&(true, &api_childkey)).unwrap()
}

/// Fill pool of random and nonce values to facilitate signature generation with a single message.
/// Input: client_dh_secrets: list of client DH secret values, server_dh_publics: list of server DH public values, curve: Secp256k1 or Secp256r1, paillier_pk: Paillier public key
/// Output: none
#[wasm_bindgen]
pub fn fill_rpool(
    client_dh_secrets_str: &str,
    server_dh_publics_str: &str,
    curve_str: &str,
    paillier_pk_str: &str,
) -> String {
    let curve: common::Curve = match serde_json::from_str(&curve_str) {
        Ok(v) => v,
        Err(_) => return serde_json::to_string(&(false, &"error deserializing curve")).unwrap(),
    };
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
                    return serde_json::to_string(&(
                        false,
                        &"error deserializing client_dh_secrets",
                    ))
                    .unwrap()
                }
            };
        let server_dh_publics: Vec<Secp256k1Point> =
            match serde_json::from_str(&server_dh_publics_str) {
                Ok(v) => v,
                Err(_) => {
                    return serde_json::to_string(&(
                        false,
                        &"error deserializing client_dh_publics",
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
                    return serde_json::to_string(&(
                        false,
                        &"error deserializing client_dh_secrets",
                    ))
                    .unwrap()
                }
            };
        let server_dh_publics: Vec<Secp256r1Point> =
            match serde_json::from_str(&server_dh_publics_str) {
                Ok(v) => v,
                Err(_) => {
                    return serde_json::to_string(&(
                        false,
                        &"error deserializing client_dh_publics",
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
#[wasm_bindgen]
pub fn get_rpool_size(curve_str: &str) -> String {
    let curve: common::Curve = match serde_json::from_str(&curve_str) {
        Ok(v) => v,
        Err(_) => return serde_json::to_string(&(false, &"error deserializing curve")).unwrap(),
    };
    let size = match client::get_rpool_size(curve) {
        Ok(v) => v,
        Err(_) => return serde_json::to_string(&(false, &"error: invalid curve")).unwrap(),
    };
    serde_json::to_string(&(&true, size)).unwrap()
}

/// Compute presignature.
/// Input: api_childkey: API childkey struct, msg_hash: message hash, curve: Secp256k1 or Secp256r1 curve
/// Output: presig: presignature, r: message-independent part of the signature used
#[wasm_bindgen]
pub fn compute_presig(api_childkey_str: &str, msg_hash_str: &str, curve_str: &str) -> String {
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
    let curve: common::Curve = match serde_json::from_str(&curve_str) {
        Ok(v) => v,
        Err(_) => return serde_json::to_string(&(false, &"error deserializing curve")).unwrap(),
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

/// Verify signature.
/// Input: r: r part of the ECDSA signature, s: s part of the ECDSA signature, pubkey: public key, msg_hash: message hash, curve: Secp256k1 or Secp256r1
/// Output: boolean value indicating success
#[wasm_bindgen]
pub fn verify(
    r_str: &str,
    s_str: &str,
    pubkey_str: &str,
    msg_hash_str: &str,
    curve_str: &str,
) -> String {
    let r = match BigInt::from_hex(&r_str) {
        Ok(v) => v,
        Err(_) => return serde_json::to_string(&(false, &"error deserializing r")).unwrap(),
    };
    let s = match BigInt::from_hex(&s_str) {
        Ok(v) => v,
        Err(_) => return serde_json::to_string(&(false, &"error deserializing s")).unwrap(),
    };
    let pubkey: String = match serde_json::from_str(&pubkey_str) {
        Ok(v) => v,
        Err(_) => return serde_json::to_string(&(false, &"error parsing pubkey")).unwrap(),
    };
    let msg_hash = match BigInt::from_hex(&msg_hash_str) {
        Ok(v) => v,
        Err(_) => return serde_json::to_string(&(false, &"error deserializing msg_hash")).unwrap(),
    };
    let curve: common::Curve = match serde_json::from_str(&curve_str) {
        Ok(v) => v,
        Err(_) => return serde_json::to_string(&(false, &"error deserializing curve")).unwrap(),
    };

    let result = match common::verify(&r, &s, &pubkey, &msg_hash, curve) {
        Ok(v) => v,
        Err(_) => {
            return serde_json::to_string(&(false, &"error: invalid pubkey or invalid curve"))
                .unwrap()
        }
    };
    if result {
        serde_json::to_string(&(&true, &"")).unwrap()
    } else {
        serde_json::to_string(&(&false, &"error verifying signature")).unwrap()
    }
}

/// Derive public key from given secret key.
/// Input: secret_key: full secret key, curve: Secp256k1 or Secp256r1 curve
/// Output: public_key
#[wasm_bindgen]
pub fn publickey_from_secretkey(secret_key_str: &str, curve_str: &str) -> String {
    let secret_key = match BigInt::from_hex(&secret_key_str) {
        Ok(v) => v,
        Err(_) => {
            return serde_json::to_string(&(false, &"error deserializing secret_key")).unwrap()
        }
    };
    let curve: common::Curve = match serde_json::from_str(&curve_str) {
        Ok(v) => v,
        Err(_) => return serde_json::to_string(&(false, &"error deserializing curve")).unwrap(),
    };

    let public_key = match common::publickey_from_secretkey(&secret_key, curve) {
        Ok(v) => v,
        Err(_) => return serde_json::to_string(&(false, &"error: invalid curve?")).unwrap(),
    };
    serde_json::to_string(&(&true, &public_key)).unwrap()
}

/// Generate signature for given message hash under given secret key
/// Input: secret_key: full secret key, msg_hash: message hash
/// Output: (r, s): ECDSA signature
#[wasm_bindgen]
pub fn sign(secret_key_str: &str, msg_hash_str: &str) -> String {
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
    serde_json::to_string(&(
        &true,
        &format!("{:0>64}", r.to_hex()),
        &format!("{:0>64}", s.to_hex()),
    ))
    .unwrap()
}

#[cfg(test)]
mod tests {
    use crate::{
        compute_presig, create_api_childkey, dh_init, fill_rpool, get_rpool_size,
        init_api_childkey_creator, init_api_childkey_creator_with_verified_paillier,
        publickey_from_secretkey, sign, verify, verify_paillier,
    };
    use mpc_wallet_lib::client::{APIchildkey, APIchildkeyCreator};

    #[test]
    fn test_dh_init_ok() {
        let result = dh_init(1, "\"Secp256k1\"");
        let (success, _, _): (bool, Vec<String>, Vec<String>) =
            serde_json::from_str(&result).unwrap();
        assert!(success);
    }

    #[test]
    fn test_dh_init_wrong() {
        let result = dh_init(1, "a");
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing curve");
        assert!(!success);
    }

    #[test]
    fn test_init_api_childkey_creator_ok() {
        let result = init_api_childkey_creator(
            "4794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1",
        );
        let (success, _): (bool, APIchildkeyCreator) = serde_json::from_str(&result).unwrap();
        assert!(success);
    }

    #[test]
    fn test_init_api_childkey_creator_wrong() {
        let result = init_api_childkey_creator("u");
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing secret_key");
        assert!(!success);
    }

    #[test]
    fn test_init_api_childkey_creator_with_verified_paillier_ok() {
        let result = init_api_childkey_creator_with_verified_paillier("4794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1", "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}");
        let (success, _): (bool, APIchildkeyCreator) = serde_json::from_str(&result).unwrap();
        assert!(success);
    }

    #[test]
    fn test_init_api_childkey_creator_with_verified_paillier_wrong_secret() {
        let result = init_api_childkey_creator_with_verified_paillier("g", "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}");
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing secret_key");
        assert!(!success);
    }

    #[test]
    fn test_init_api_childkey_creator_with_verified_paillier_wrong_paillier() {
        let result = init_api_childkey_creator_with_verified_paillier("4794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1", "\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}");
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing paillier_pk");
        assert!(!success);
    }

    #[test]
    fn test_verify_paillier_ok() {
        let result = verify_paillier("{\"secret_key\":\"4794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1\",\"paillier_pk\":null}", "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}", "{\"sigma_vec\":[\"14f21d17357e5d0d8d2cb3cf6d0b9439323473be7e1f68db541b77450f87a20941640bf8a317d4ea6272b12923449e73ea5598a6197219fb6c7ca416a3552301c9cc5b47580ce35e4c9e37a97ec0bdbe2b48c2db21cde5bcef9fc04c6e767c59c0500929b76f87901e5a4d8adb38097c44ed790a0ae2e9f6985823f1789aa47a8298d02763751b73942bbee79c4544f9bd2b82e405f15d801cb41d4831012f99172ef49fee6ea33599caadcdb89c1eb768e30b11878f37e12d232b624cbe589a7767af46d958632574535893c0337858399aed65638b97bcaddee45e40fe79a5014fcd1e398b19807439f58236373197653a8ea82ab3a84173d5a8d45bcae823\",\"32beda264c7fde6cb41d48ce44e6e93af5ed0e1cb5c7cd29f7fa3cbf72b78b9bc3e5267c4f9a75de40eb95a4bdc73dd1d8a435799daf2365f9377aed3c4524016d2ea58002c66fd0a8bcb8e74bac9923b723bc9f8752f82d9cba8bec4f414f314a40842031427b0bb8cdc514bfb61a5f85a51d8b7a290ccbd1000af937a6a7fd7a6070ba40a6801a2909e11d71a773958195d82f72995e69b989ab91207b68ac891e6585848f7aea80e1a0693427a0a512c0cbfbfe5d9ffe02462856ca918af9ebd2ad2f9b44a84b628ec7a7ed4d7232e72c52f2af5ef8988e3c09715fbe1a0af871109028335fb95370ae3e7ecf646063c1914ceeff8cf22ca06d250f02904c\",\"27236e62e810849d58c24b57d2061be4223a175224a89b94ce1261ae9f7a61ec058a43589c83aa3029e61c488fa33b0ea8fb72c36f4b3f962f858f4b0dd822a2810124cba42c8c2a42046b324a3c0712799979be7da1e6dff82c466149484246769f43683231ba8a89185587086cef1de589a4d59b74ac20fcbe0310403f9347417a4c8a8b90b78671d265471fe5ca839e509d4b6f5c2ec33ae255abf54aa12700772a174074048bc4edecc142c268b765f8bf4c0ab7b253882f77c1cb0e410e8e21a23ba364ec37adee59e0395920ab403ab77f095ed8bda39fad9b00886c9e2682a8314bd71fc2db9d2b2a8476ac295c262ba16d4657c62af9bb6a4729c214\",\"974e6e3a63e90275733cbf0b1516d940f0b0c8bd6140f16abb22988289b88b327c5a3e2a1de6d00f03e6f78ee934da02590ee45c6b4c0c8f53ccf6adc35cd0e9ee73f5ad88c8b8bc5b2a489c6e2b900cdc5c2b8ef0aaeb4a99dae6bac9a4bbeb12ceacbafc181a43f9176e503d71100b39b71e5f3975daffd3735b8d26c0b3ae43a92737373730bb22bdc3c06b8b281da79a6994c4c21dda8b89e2a0c9767efa559c895da05e127935b4d33eb1e2acab29cd096e5ed73a4812f86f8839aff7ab8e0baff3535098f1cdddb4ae14e1e7eb702674b4bd8253fefe3bd4245afd6dcb365de617df815ff0cc761415f7001a4149825c50626ebbd0aeeb92172be401e2\",\"43e75be1f60bc68a05aaceea143aa14498880ce8ab1417621f7041d8dd76a80e16484e07580060033bb6eeb67a516215f2bdbdcf2bbbe327ae22000b342a51cafe49ea50ce0b459d5e8334b84de284227a3d504d5fcde913b08b27c6997a27b9a307d132379e0688ce6c38f418b1e94ad87b85e86ab48374d736a7c2f402016255b728c258d945591760a314ebc0e98411fdf3c73e6ed8fd7e23cb1cab8a0517d79a33c27de6548be0ab506db1c2b4b573faf7bcb817cbf0d489da9c168a8c8e6bb4ba0edbfcd1fd01f5eddb89ac84d7a218d83635e354e77619725be00426aaaae90221b65c063ef479184599036182098f3e623a57567ff52172fcd0463e23\",\"70ab52b4bde2f26ba9603b1d211ab94ce95d84a8f09fbb1817700897bc1beb4b3bfe24850f61751204cec784ddd182e5a4432a8d6f48ff475a58d4e63ddc70de5b68a4ee392384031d2b3f352a74c5b8b9fe6f8113a046dcab29b6a168203031d783a4321a7d3f2e971761164454af67367c51a4d46218f817034705c3b013162b83b609647944dd7173e37d02f04b0aef42d1ad2f53902b3e88ccf2523c8526b50b3e47a9d51673992d69ed1f0ac39849b473c1ca0fdb5c34c9b344cf820a3b6566d3db80fb0d6646646080e19bf1448f8859ac1c0275c863950779cd22d248a358a3edb4e60676b4ec353d62c25f7b8c836293108be03a353ea8815c3dba9c\",\"84fb3dcc1348efc024c59df79e69c33d0d67d3f7af328cf0af6048d0080862f0ad0eae3bb676851b58b22db6e7c46474cb6aed94a73b35caf65e0c9f36743f55853bbc1d895649435edfeff25977e8130133078577d547c67c8d31236e1dbcac18252f71fac884078e229f97a7b451391f501b85266252137674f898ab9afb505d4f1ca7455e2339ee992395afd3c9a5cb8724733bdb40ed625932106b47dfe890bdea045178a46dffa1608a1ef01b4dda7a7381ee24f4c10fd63b84b1ece8c425435992f567c709d21324aa50a751042fc4cd2afc283ddb8b2867a694945337fe985a2090e45a8df28c68c828a0e6bae3d18f9a8251dbf46e4e7898feb23ca6\",\"23346102965ad3e6d474ac60f0fb4154dff2bf4250204390db22560f1ffcf47047489c38f02708c9776ed349078bcf7822c2bf50e0af9999a610d69e6f14e3d2ff138e706fbad8359bf496d2519ee900a04ac69eaa7e26bb11e4f302288221889bc58ce20608829db11fbc0a64ad066d7cd1704ae730d954dd84a1a35fb03dfab608b8e483d05ad71c2f6e2e38f59afe3005b60d508383ef160f23aed233bf76e108e3d0e3e6a87032b5b6b7b14f50c5b40aeefde5811ea5fa8a601124370b3d58ebca0906fa0ce72e90a23d713d3d74f2d59256d043011c6b350ebb664ba0a96ae7a5611d71f03d60b60d75e328f6a086aa1932f58026a20c3c3ac4f797587e\",\"12786ce1db47ed46d0bd326d844d3c611f9816b59817fb32a0729d4eb7c3975442410b86f5054d3de4be3f9ba442f0750aa0f284269c57e73ad7c644d3182a3ed26f46462ac687287260117abca70255461dc728adced54b9da10206a88fd213dc423ecc7db4842c3b4ff031ee8eb16304178f4e8eaed9db3e2f6c150dca1532a0a6d8e455cf13e7b4beed736ac8525b84b213ba96fced8ab8a9f47d5cdc8fe02e7eede3f417d2dc07ea10eea71486d3b1f9a0b9d6612efc83908702e6b77499a4861d770d136440962c0b35148b4a1af55989b94509a0ca765bdf1fee850eb175be5676581be779c94192a0326513a768c326fa67a202e66d0eaa70a91932d6\",\"354fd63ff01cf79fd2c90928231e364195a4b6c1d7874011ab6440b583f7027990c37eb4a9bd0125c31a61c31bbed0e36850261df09d5395a1885e5faf9f7bbdff0e545495f7e4761894493ace3de65ca7135a2a751aa2f40d21907bdcf65cec2fa896e457eb02889b0e3e8a5bcfdf133847ccec39c886823aef9f7f2ef9650345324efd55d0fc2e349cebffd6b7a542d4b9db9a4353e30da8f4e9aacd35ff5023180d34488261ba80413fd0cb56257db3e543f72e6d2bd82776e24d2db62107f83d6169fbf63eecfb1b33e58058bff6c0a04a6605d14f3ea77c4959293a19c3309e55d86d1ce1d308967bd2b550fbe2df0219444801d842fab7f6b0f26436e4\",\"61186ef51490cf59e822d5e3f84561ffb4f0b921c205581540ac13d8f978765791ab43942dcf470eac454dc13ce375df68bee5e152ee048fd14c5b6edfc053c2d548008e29a50fcf392069e9fe851fcc58c0f3f4ecd14d2885b9940b2a7bc7cc2818910fef3800a7dcf7e7f5a58905fcaedbf7fcd0dbff40293a403148cffedf1a5730554a10a1eed001cfbad38c4051b2a640a79271e43aae09e7733fe3b881fdba14cd397af91a1499f40069f47f65a0bc167d4c66ab5d8c0fcde37383911f75b4d3207a8a5c4dfa6ecf610c6ac20da6e96c0cd691c0642c8bb7a6be2837785774f4bbaac2529bf5291c94ab49961373e8991eb2018aa9d93529f66dd7695a\"]}");
        let (success, _): (bool, APIchildkeyCreator) = serde_json::from_str(&result).unwrap();
        assert!(success);
    }

    #[test]
    fn test_verify_paillier_wrong_apichildkeycreator() {
        let result = verify_paillier("\"secret_key\":\"4794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1\",\"paillier_pk\":null}", "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}", "{\"sigma_vec\":[\"86ba927cc5974e2f9357e4041e097ede786aa519cf2d8499402b60bf0fb1ae9adc529b8fe72ca51baa940cc93eb292eee7f0334f1f7ee16d320b4d8989f8c444109b1745ecb5efc5c7d1d3a796115cb0e04fcb9e98c3b7316b5e23cf331ac599734d51d565a58e9167103eb9e3af74a15f4bfa4120ff311f192dfb852ac1c8f8a572067bbfa7c7ff5513a29936c6a304d142820f930ccdc48abe43b36b23b8010125aa6cb59cafb9e57976bc0bda14d5cb61e9810e06ebcab54182451c8d1c4e06856a99d67cd942f4a5e60564a602215f59e67dc403bfb3edfe16437dbee6cf41de4f0d5b21aa053b10c3669ad38c75bf27692586792963e99fae66df24facb\",\"7381a547eed881e757a55fd6bcaaf2f218fd29e82833527eed79a42203120140dfbceaeb45a23785b3860fcc064d29845795168fc16588ba020d215d973a27c921b9524377da575b271b55e9cceefd281f09af00abf27ad45df938a29caa66af6fc0ab81a0010c2d4ca49a680b2f42aca5dd3647e6852c5e3097803b242bbb272932cd95595dfa47267413a6148f5223bf8adbd2b88628914398ccd1f2d24b0be85de7c810981cb3a5caf845e2f81ebc177da079987286a9d0c4d0bf8cf7f542892cfbf9164c7ae20bb0b57e3508269d43b93c7172048da3306a7d60aef17845157e43d5bf8eeddd2aed1da564bbe971d071d359525b5b3704d4e2e077dcfade\",\"8405adf1195421347ea8043824aca5952875ebcba66d82a2af3f31af42bbb7e038f6547c2b40b45a064be9f8064610116e2f5740e16649e233989d2058a109b2ae10d651c64bce97634596aeee781ddc634305c326c3be6df49cba4557d532a40f911a67826d81865a24c32688cee8f81786ee76511c66ba25fce9d2503978d777fe773b9a2a0357a797adbc77ac0e9bc0cbab37b3a8f6a42227bebf181004f9a55b6a557783c9150d9408792bd73b1c0071b31c23f3c8ec18d5749d46ea0c431e73fcc8c64a57426402cce9917d7809d94687318a39ee27b01ef9041001401f889e436d3d48fbdde1072b7533b0d00f6a13d0bb0bb94020ca9b77c93d42d5f3\",\"570861a8c14df0b19f6b8159131bef4259338ef6faeab481b6c14e1fc7e57ede571e3698f89c9a08ee9d91c58d594fbc2cd98fff4a483d360c1ecc703820361854061b8a516ce86ca82e8a2e1653f3b25b9d710f6f4e84b8e991450126171f0baa1ac2bfd87653b31f7c30619b6ad9684b48b2dde399c229bed057984415ba552a606eb1ab2b4324adf3826b9c9844f1ecc5634d197877f29626fe59399e739e5f73e502d2fb6a0a016862008583125ec0cfd9c18a3f183ed493d1f5bf236f6a3f7ce345998afae9f963bfee2f705a8df3c253407708fa92091d34d6da6f487d8e7df7b38fbf4e919fa093f64b8782e5e96372080006b9b982013aaffa9c0c58\",\"282184ad00cbc48211eb828e33462bd6c87c53f05c98395e2a0b58924732f25a947c8524c2b09dfcab1d6f70730c4684e11a6b0911199d9562be52872463d51091455b792398e56521d90387077f8948c894707d5cfb42ce3b155f65fb7b80575906a5af2e1b663455d8cd898d743bc727a06c3febdf5f55489d9372da4fbfb516e09faa15a9da0008037f6afb90531a34f08a0ff1b843fd3e0b2c20a8458f767ae85925de160facad7014c96f3f3dd39b2511475fde6ae09476def71fb7ba6c072dc33d2e468f31b55ecbc08c50ddbafe710748cc7d72f509260cceee5171f6b8b0c257ffe5bfa2d09c76265bb54672792c22a137111b9b5e1835ecf8decdde\",\"8813fd4a00617a1ed4ab79662a155535bee18bda39897bef30a0273c5e9e880560b6020b272c23e966fcd03ecebf51bb725c8bbae1ff13762a3bf2e6388e0e3d818a47db0e38fb92bc8e1736804349399ad0ab2d057ee577d6206f69df914868c337c68030a77a0dce18d2793fa971eb4c2a9d56980e77ad5ff52679cfdd69972579402d9a1078060f2a760c7a6363d85c6652049cda386612b0362559f691e95c2ce9a4ce279f977dc9b9fa51d58e42f3bba5c95b07256f86453dd745acfef156f5369c8b1c8b3f240982e0ac52ebe5bd3d1aeeb8cb9daeac84aaaa1fd789d06c4644d4d6adf8ac088d65ca401cb58f489d7a31c9b8f00ffd53671901718736\",\"45109996a12ccb5a4af7a33872bd4526266acb2b6fb62de70d1ffa6ee9f642e32dca886d4d178c1b41e10c8a919d1eabe525835e66488d402215e7906d9c853a4a410f85121cfdcc5673e0487c40442d18649cbee8f032134431344c4a94622ab8e374644efac7e188dc3ebfa5ba7d76af30acb2e7465aae40454594f9313ff845c109eb00deca6cf949f3d612eee279e3a3ccd393901043dea0eb07b6568741adce54fc268becb522824a0acc2861c123bc21d70392e037fdbfe46c35b4e85581ffb231e8a3ecf46fe8cea69759113345beb1a5aaf22121b4c5de5ced09e7037467461c6a3f6f4e821a8ee43da3b6bbd3d9bc07f3f854c82a80ab9721dd6830\",\"62ba72d6c9a6403e14a5f49f8dcdd003fa7c01feefbdc17fbc7a40b4c562eb2f2e6f068e05a8e7e5120de1ea350d244c2fe7ec0f2149797d61232cad298859b59ecdf3a6fa270190f25346c04a99ea285ecc4666c6e58f29f6b9e5d2c0929f75a4bdea81641d8d001cd44a5382a1c79856c19b19a8d1e13f5a3230f0e928e5b93e5fdebefde559c29f02f153dfb0ca911102b1d03bf094d799e5e39cc58abd186053f050c7db2646517016763ab185b8d9316ddfc15ae71063159e57d6bc9f548700c7f01c62d2e9b49671ba54d79d9b8b901978056bc13627e17d44fce53c004c6df4e8e225da1f75d2f385b16d8ee2687cfe56934644dad5abc8e3cdcce64d\",\"9a47120575204c8f76a980b4733ffc69dbc34959ca8f565ac277b55985b8b4d9cd3f4887d59ef0f5d2d0b8bb1f10d8fdcd167935380367592a895d134928931dd85f66e4253ec4d3e4a2c1b5ba5b2af4ef0d20c394c8b1526c6010458cd3023f32ce32b917322cee3315d633bfb2f8e16b69cfe362c6df3963bc95b6bfb60661e613e76e0b3a6c3c06c49f26de09343ac38a66a4d1cae8496d4b82a78b9b7f2f2097182812b5d5ab4bf8950f49f1f553584b7aa993cfe1c96d8fd78a2d9201f42af6f56c2ed6373925e2b5cc8ff4dc1e238ccce1754c792ac82a61d45fba4898b3bb6372e7827616b06353535457f6366eaa2d42b7a167e2be4ee086699a1b41\",\"31ad95d0e1ef37d078f0ef74fb6fe8f9ea47db0aa31e78a37420e7ad9bd1b2bca058efb395885d2fea08106ef8ffa898e19be1f562665b2514c4b7cea39fc678449c7c103cd2dc8d8f980dd3b926a6532e113d25d1a9a891e374a33ae0dc21691fc4a4db7c638585158f516d5fb592c540ae2b6266a81905909c3b1fbdc22e248ea3d0e5f0895112769581509581d749486137f057c6b0fc77fd4784da9904250e7f5fe088fe4ced7451bae6829a2b9c8286cbac4e4171caf4e2089edc754912392b906062e101344fe51841c391e4bb7f2d672be01ddb3fae68b44f0c02000ad3cb0be7af954fcca4ed3f19ebcdca8acccaa60e03c035b196eec87ece42f50\",\"3054c555c41509b39eccc86bbf80bade7eb18e8a694947ca4f7ebf0ef309dc4a35690fe2e3fc8a76db33fb5e6554a52f73d32da987d768a220bdff621a54c83aa382092658f6657c95c767456682d5da2aff4a53a0958ce4a7dae61262c1f47e365d52d7981541ea0ed3a00a0c30bad31a6738bc19a254bf78dac870f604aeca1766b9ea5dc1e239819b8b07f02d5d176065bfa087ce000a581b1f92011309d0bb0f0e10d98877a4279e7d56460b40ad9c2909226c510b3938f92459b11a33c3e6c8637b66d8ce6bd81e04e0cfc166cb9fa90622df20482a7d8ac3c3d8877b0477ba41152500c88bf554fa81ac4f1c44a04b814f42104c012dd6b75e10f13271\"]}");
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing api_childkey_creator");
        assert!(!success);
    }

    #[test]
    fn test_verify_paillier_wrong_paillier() {
        let result = verify_paillier("{\"secret_key\":\"4794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1\",\"paillier_pk\":null}", "\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}", "{\"sigma_vec\":[\"86ba927cc5974e2f9357e4041e097ede786aa519cf2d8499402b60bf0fb1ae9adc529b8fe72ca51baa940cc93eb292eee7f0334f1f7ee16d320b4d8989f8c444109b1745ecb5efc5c7d1d3a796115cb0e04fcb9e98c3b7316b5e23cf331ac599734d51d565a58e9167103eb9e3af74a15f4bfa4120ff311f192dfb852ac1c8f8a572067bbfa7c7ff5513a29936c6a304d142820f930ccdc48abe43b36b23b8010125aa6cb59cafb9e57976bc0bda14d5cb61e9810e06ebcab54182451c8d1c4e06856a99d67cd942f4a5e60564a602215f59e67dc403bfb3edfe16437dbee6cf41de4f0d5b21aa053b10c3669ad38c75bf27692586792963e99fae66df24facb\",\"7381a547eed881e757a55fd6bcaaf2f218fd29e82833527eed79a42203120140dfbceaeb45a23785b3860fcc064d29845795168fc16588ba020d215d973a27c921b9524377da575b271b55e9cceefd281f09af00abf27ad45df938a29caa66af6fc0ab81a0010c2d4ca49a680b2f42aca5dd3647e6852c5e3097803b242bbb272932cd95595dfa47267413a6148f5223bf8adbd2b88628914398ccd1f2d24b0be85de7c810981cb3a5caf845e2f81ebc177da079987286a9d0c4d0bf8cf7f542892cfbf9164c7ae20bb0b57e3508269d43b93c7172048da3306a7d60aef17845157e43d5bf8eeddd2aed1da564bbe971d071d359525b5b3704d4e2e077dcfade\",\"8405adf1195421347ea8043824aca5952875ebcba66d82a2af3f31af42bbb7e038f6547c2b40b45a064be9f8064610116e2f5740e16649e233989d2058a109b2ae10d651c64bce97634596aeee781ddc634305c326c3be6df49cba4557d532a40f911a67826d81865a24c32688cee8f81786ee76511c66ba25fce9d2503978d777fe773b9a2a0357a797adbc77ac0e9bc0cbab37b3a8f6a42227bebf181004f9a55b6a557783c9150d9408792bd73b1c0071b31c23f3c8ec18d5749d46ea0c431e73fcc8c64a57426402cce9917d7809d94687318a39ee27b01ef9041001401f889e436d3d48fbdde1072b7533b0d00f6a13d0bb0bb94020ca9b77c93d42d5f3\",\"570861a8c14df0b19f6b8159131bef4259338ef6faeab481b6c14e1fc7e57ede571e3698f89c9a08ee9d91c58d594fbc2cd98fff4a483d360c1ecc703820361854061b8a516ce86ca82e8a2e1653f3b25b9d710f6f4e84b8e991450126171f0baa1ac2bfd87653b31f7c30619b6ad9684b48b2dde399c229bed057984415ba552a606eb1ab2b4324adf3826b9c9844f1ecc5634d197877f29626fe59399e739e5f73e502d2fb6a0a016862008583125ec0cfd9c18a3f183ed493d1f5bf236f6a3f7ce345998afae9f963bfee2f705a8df3c253407708fa92091d34d6da6f487d8e7df7b38fbf4e919fa093f64b8782e5e96372080006b9b982013aaffa9c0c58\",\"282184ad00cbc48211eb828e33462bd6c87c53f05c98395e2a0b58924732f25a947c8524c2b09dfcab1d6f70730c4684e11a6b0911199d9562be52872463d51091455b792398e56521d90387077f8948c894707d5cfb42ce3b155f65fb7b80575906a5af2e1b663455d8cd898d743bc727a06c3febdf5f55489d9372da4fbfb516e09faa15a9da0008037f6afb90531a34f08a0ff1b843fd3e0b2c20a8458f767ae85925de160facad7014c96f3f3dd39b2511475fde6ae09476def71fb7ba6c072dc33d2e468f31b55ecbc08c50ddbafe710748cc7d72f509260cceee5171f6b8b0c257ffe5bfa2d09c76265bb54672792c22a137111b9b5e1835ecf8decdde\",\"8813fd4a00617a1ed4ab79662a155535bee18bda39897bef30a0273c5e9e880560b6020b272c23e966fcd03ecebf51bb725c8bbae1ff13762a3bf2e6388e0e3d818a47db0e38fb92bc8e1736804349399ad0ab2d057ee577d6206f69df914868c337c68030a77a0dce18d2793fa971eb4c2a9d56980e77ad5ff52679cfdd69972579402d9a1078060f2a760c7a6363d85c6652049cda386612b0362559f691e95c2ce9a4ce279f977dc9b9fa51d58e42f3bba5c95b07256f86453dd745acfef156f5369c8b1c8b3f240982e0ac52ebe5bd3d1aeeb8cb9daeac84aaaa1fd789d06c4644d4d6adf8ac088d65ca401cb58f489d7a31c9b8f00ffd53671901718736\",\"45109996a12ccb5a4af7a33872bd4526266acb2b6fb62de70d1ffa6ee9f642e32dca886d4d178c1b41e10c8a919d1eabe525835e66488d402215e7906d9c853a4a410f85121cfdcc5673e0487c40442d18649cbee8f032134431344c4a94622ab8e374644efac7e188dc3ebfa5ba7d76af30acb2e7465aae40454594f9313ff845c109eb00deca6cf949f3d612eee279e3a3ccd393901043dea0eb07b6568741adce54fc268becb522824a0acc2861c123bc21d70392e037fdbfe46c35b4e85581ffb231e8a3ecf46fe8cea69759113345beb1a5aaf22121b4c5de5ced09e7037467461c6a3f6f4e821a8ee43da3b6bbd3d9bc07f3f854c82a80ab9721dd6830\",\"62ba72d6c9a6403e14a5f49f8dcdd003fa7c01feefbdc17fbc7a40b4c562eb2f2e6f068e05a8e7e5120de1ea350d244c2fe7ec0f2149797d61232cad298859b59ecdf3a6fa270190f25346c04a99ea285ecc4666c6e58f29f6b9e5d2c0929f75a4bdea81641d8d001cd44a5382a1c79856c19b19a8d1e13f5a3230f0e928e5b93e5fdebefde559c29f02f153dfb0ca911102b1d03bf094d799e5e39cc58abd186053f050c7db2646517016763ab185b8d9316ddfc15ae71063159e57d6bc9f548700c7f01c62d2e9b49671ba54d79d9b8b901978056bc13627e17d44fce53c004c6df4e8e225da1f75d2f385b16d8ee2687cfe56934644dad5abc8e3cdcce64d\",\"9a47120575204c8f76a980b4733ffc69dbc34959ca8f565ac277b55985b8b4d9cd3f4887d59ef0f5d2d0b8bb1f10d8fdcd167935380367592a895d134928931dd85f66e4253ec4d3e4a2c1b5ba5b2af4ef0d20c394c8b1526c6010458cd3023f32ce32b917322cee3315d633bfb2f8e16b69cfe362c6df3963bc95b6bfb60661e613e76e0b3a6c3c06c49f26de09343ac38a66a4d1cae8496d4b82a78b9b7f2f2097182812b5d5ab4bf8950f49f1f553584b7aa993cfe1c96d8fd78a2d9201f42af6f56c2ed6373925e2b5cc8ff4dc1e238ccce1754c792ac82a61d45fba4898b3bb6372e7827616b06353535457f6366eaa2d42b7a167e2be4ee086699a1b41\",\"31ad95d0e1ef37d078f0ef74fb6fe8f9ea47db0aa31e78a37420e7ad9bd1b2bca058efb395885d2fea08106ef8ffa898e19be1f562665b2514c4b7cea39fc678449c7c103cd2dc8d8f980dd3b926a6532e113d25d1a9a891e374a33ae0dc21691fc4a4db7c638585158f516d5fb592c540ae2b6266a81905909c3b1fbdc22e248ea3d0e5f0895112769581509581d749486137f057c6b0fc77fd4784da9904250e7f5fe088fe4ced7451bae6829a2b9c8286cbac4e4171caf4e2089edc754912392b906062e101344fe51841c391e4bb7f2d672be01ddb3fae68b44f0c02000ad3cb0be7af954fcca4ed3f19ebcdca8acccaa60e03c035b196eec87ece42f50\",\"3054c555c41509b39eccc86bbf80bade7eb18e8a694947ca4f7ebf0ef309dc4a35690fe2e3fc8a76db33fb5e6554a52f73d32da987d768a220bdff621a54c83aa382092658f6657c95c767456682d5da2aff4a53a0958ce4a7dae61262c1f47e365d52d7981541ea0ed3a00a0c30bad31a6738bc19a254bf78dac870f604aeca1766b9ea5dc1e239819b8b07f02d5d176065bfa087ce000a581b1f92011309d0bb0f0e10d98877a4279e7d56460b40ad9c2909226c510b3938f92459b11a33c3e6c8637b66d8ce6bd81e04e0cfc166cb9fa90622df20482a7d8ac3c3d8877b0477ba41152500c88bf554fa81ac4f1c44a04b814f42104c012dd6b75e10f13271\"]}");
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing paillier_pk");
        assert!(!success);
    }

    #[test]
    fn test_verify_paillier_wrong_proof() {
        let result = verify_paillier("{\"secret_key\":\"4794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1\",\"paillier_pk\":null}", "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}", "{\"sigma_Vec\":[\"86ba927cc5974e2f9357e4041e097ede786aa519cf2d8499402b60bf0fb1ae9adc529b8fe72ca51baa940cc93eb292eee7f0334f1f7ee16d320b4d8989f8c444109b1745ecb5efc5c7d1d3a796115cb0e04fcb9e98c3b7316b5e23cf331ac599734d51d565a58e9167103eb9e3af74a15f4bfa4120ff311f192dfb852ac1c8f8a572067bbfa7c7ff5513a29936c6a304d142820f930ccdc48abe43b36b23b8010125aa6cb59cafb9e57976bc0bda14d5cb61e9810e06ebcab54182451c8d1c4e06856a99d67cd942f4a5e60564a602215f59e67dc403bfb3edfe16437dbee6cf41de4f0d5b21aa053b10c3669ad38c75bf27692586792963e99fae66df24facb\",\"7381a547eed881e757a55fd6bcaaf2f218fd29e82833527eed79a42203120140dfbceaeb45a23785b3860fcc064d29845795168fc16588ba020d215d973a27c921b9524377da575b271b55e9cceefd281f09af00abf27ad45df938a29caa66af6fc0ab81a0010c2d4ca49a680b2f42aca5dd3647e6852c5e3097803b242bbb272932cd95595dfa47267413a6148f5223bf8adbd2b88628914398ccd1f2d24b0be85de7c810981cb3a5caf845e2f81ebc177da079987286a9d0c4d0bf8cf7f542892cfbf9164c7ae20bb0b57e3508269d43b93c7172048da3306a7d60aef17845157e43d5bf8eeddd2aed1da564bbe971d071d359525b5b3704d4e2e077dcfade\",\"8405adf1195421347ea8043824aca5952875ebcba66d82a2af3f31af42bbb7e038f6547c2b40b45a064be9f8064610116e2f5740e16649e233989d2058a109b2ae10d651c64bce97634596aeee781ddc634305c326c3be6df49cba4557d532a40f911a67826d81865a24c32688cee8f81786ee76511c66ba25fce9d2503978d777fe773b9a2a0357a797adbc77ac0e9bc0cbab37b3a8f6a42227bebf181004f9a55b6a557783c9150d9408792bd73b1c0071b31c23f3c8ec18d5749d46ea0c431e73fcc8c64a57426402cce9917d7809d94687318a39ee27b01ef9041001401f889e436d3d48fbdde1072b7533b0d00f6a13d0bb0bb94020ca9b77c93d42d5f3\",\"570861a8c14df0b19f6b8159131bef4259338ef6faeab481b6c14e1fc7e57ede571e3698f89c9a08ee9d91c58d594fbc2cd98fff4a483d360c1ecc703820361854061b8a516ce86ca82e8a2e1653f3b25b9d710f6f4e84b8e991450126171f0baa1ac2bfd87653b31f7c30619b6ad9684b48b2dde399c229bed057984415ba552a606eb1ab2b4324adf3826b9c9844f1ecc5634d197877f29626fe59399e739e5f73e502d2fb6a0a016862008583125ec0cfd9c18a3f183ed493d1f5bf236f6a3f7ce345998afae9f963bfee2f705a8df3c253407708fa92091d34d6da6f487d8e7df7b38fbf4e919fa093f64b8782e5e96372080006b9b982013aaffa9c0c58\",\"282184ad00cbc48211eb828e33462bd6c87c53f05c98395e2a0b58924732f25a947c8524c2b09dfcab1d6f70730c4684e11a6b0911199d9562be52872463d51091455b792398e56521d90387077f8948c894707d5cfb42ce3b155f65fb7b80575906a5af2e1b663455d8cd898d743bc727a06c3febdf5f55489d9372da4fbfb516e09faa15a9da0008037f6afb90531a34f08a0ff1b843fd3e0b2c20a8458f767ae85925de160facad7014c96f3f3dd39b2511475fde6ae09476def71fb7ba6c072dc33d2e468f31b55ecbc08c50ddbafe710748cc7d72f509260cceee5171f6b8b0c257ffe5bfa2d09c76265bb54672792c22a137111b9b5e1835ecf8decdde\",\"8813fd4a00617a1ed4ab79662a155535bee18bda39897bef30a0273c5e9e880560b6020b272c23e966fcd03ecebf51bb725c8bbae1ff13762a3bf2e6388e0e3d818a47db0e38fb92bc8e1736804349399ad0ab2d057ee577d6206f69df914868c337c68030a77a0dce18d2793fa971eb4c2a9d56980e77ad5ff52679cfdd69972579402d9a1078060f2a760c7a6363d85c6652049cda386612b0362559f691e95c2ce9a4ce279f977dc9b9fa51d58e42f3bba5c95b07256f86453dd745acfef156f5369c8b1c8b3f240982e0ac52ebe5bd3d1aeeb8cb9daeac84aaaa1fd789d06c4644d4d6adf8ac088d65ca401cb58f489d7a31c9b8f00ffd53671901718736\",\"45109996a12ccb5a4af7a33872bd4526266acb2b6fb62de70d1ffa6ee9f642e32dca886d4d178c1b41e10c8a919d1eabe525835e66488d402215e7906d9c853a4a410f85121cfdcc5673e0487c40442d18649cbee8f032134431344c4a94622ab8e374644efac7e188dc3ebfa5ba7d76af30acb2e7465aae40454594f9313ff845c109eb00deca6cf949f3d612eee279e3a3ccd393901043dea0eb07b6568741adce54fc268becb522824a0acc2861c123bc21d70392e037fdbfe46c35b4e85581ffb231e8a3ecf46fe8cea69759113345beb1a5aaf22121b4c5de5ced09e7037467461c6a3f6f4e821a8ee43da3b6bbd3d9bc07f3f854c82a80ab9721dd6830\",\"62ba72d6c9a6403e14a5f49f8dcdd003fa7c01feefbdc17fbc7a40b4c562eb2f2e6f068e05a8e7e5120de1ea350d244c2fe7ec0f2149797d61232cad298859b59ecdf3a6fa270190f25346c04a99ea285ecc4666c6e58f29f6b9e5d2c0929f75a4bdea81641d8d001cd44a5382a1c79856c19b19a8d1e13f5a3230f0e928e5b93e5fdebefde559c29f02f153dfb0ca911102b1d03bf094d799e5e39cc58abd186053f050c7db2646517016763ab185b8d9316ddfc15ae71063159e57d6bc9f548700c7f01c62d2e9b49671ba54d79d9b8b901978056bc13627e17d44fce53c004c6df4e8e225da1f75d2f385b16d8ee2687cfe56934644dad5abc8e3cdcce64d\",\"9a47120575204c8f76a980b4733ffc69dbc34959ca8f565ac277b55985b8b4d9cd3f4887d59ef0f5d2d0b8bb1f10d8fdcd167935380367592a895d134928931dd85f66e4253ec4d3e4a2c1b5ba5b2af4ef0d20c394c8b1526c6010458cd3023f32ce32b917322cee3315d633bfb2f8e16b69cfe362c6df3963bc95b6bfb60661e613e76e0b3a6c3c06c49f26de09343ac38a66a4d1cae8496d4b82a78b9b7f2f2097182812b5d5ab4bf8950f49f1f553584b7aa993cfe1c96d8fd78a2d9201f42af6f56c2ed6373925e2b5cc8ff4dc1e238ccce1754c792ac82a61d45fba4898b3bb6372e7827616b06353535457f6366eaa2d42b7a167e2be4ee086699a1b41\",\"31ad95d0e1ef37d078f0ef74fb6fe8f9ea47db0aa31e78a37420e7ad9bd1b2bca058efb395885d2fea08106ef8ffa898e19be1f562665b2514c4b7cea39fc678449c7c103cd2dc8d8f980dd3b926a6532e113d25d1a9a891e374a33ae0dc21691fc4a4db7c638585158f516d5fb592c540ae2b6266a81905909c3b1fbdc22e248ea3d0e5f0895112769581509581d749486137f057c6b0fc77fd4784da9904250e7f5fe088fe4ced7451bae6829a2b9c8286cbac4e4171caf4e2089edc754912392b906062e101344fe51841c391e4bb7f2d672be01ddb3fae68b44f0c02000ad3cb0be7af954fcca4ed3f19ebcdca8acccaa60e03c035b196eec87ece42f50\",\"3054c555c41509b39eccc86bbf80bade7eb18e8a694947ca4f7ebf0ef309dc4a35690fe2e3fc8a76db33fb5e6554a52f73d32da987d768a220bdff621a54c83aa382092658f6657c95c767456682d5da2aff4a53a0958ce4a7dae61262c1f47e365d52d7981541ea0ed3a00a0c30bad31a6738bc19a254bf78dac870f604aeca1766b9ea5dc1e239819b8b07f02d5d176065bfa087ce000a581b1f92011309d0bb0f0e10d98877a4279e7d56460b40ad9c2909226c510b3938f92459b11a33c3e6c8637b66d8ce6bd81e04e0cfc166cb9fa90622df20482a7d8ac3c3d8877b0477ba41152500c88bf554fa81ac4f1c44a04b814f42104c012dd6b75e10f13271\"]}");
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing correct_key_proof");
        assert!(!success);
    }

    #[test]
    fn test_create_api_childkey_ok() {
        let result = create_api_childkey("{\"secret_key\":\"4794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1\",\"paillier_pk\":{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}}", "\"Secp256k1\"");
        let (success, _): (bool, APIchildkey) = serde_json::from_str(&result).unwrap();
        assert!(success);
    }

    #[test]
    fn test_create_api_childkey_wrong_apichildkey() {
        let result = create_api_childkey("a{\"secret_key\":\"4794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1\",\"paillier_pk\":{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}}", "\"Secp256k1\"");
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing api_childkey_creator");
        assert!(!success);
    }

    #[test]
    fn test_create_api_childkey_wrong_curve() {
        let result = create_api_childkey("{\"secret_key\":\"4794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1\",\"paillier_pk\":{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}}", "\"Secp256k2\"");
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing curve");
        assert!(!success);
    }

    #[test]
    fn test_get_rpool_size_ok() {
        let result = get_rpool_size("\"Secp256k1\"");
        let (success, _): (bool, usize) = serde_json::from_str(&result).unwrap();
        assert!(success);
    }

    #[test]
    fn test_get_rpool_size_wrong() {
        let result = get_rpool_size("\"Secp256k1");
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing curve");
        assert!(!success);
    }

    #[test]
    fn test_publickey_from_secretkey_ok() {
        let result = publickey_from_secretkey(
            "4794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1",
            "\"Secp256k1\"",
        );
        let (success, _): (bool, String) = serde_json::from_str(&result).unwrap();
        assert!(success);
    }

    #[test]
    fn test_publickey_from_secretkey_wrong_secret() {
        let result = publickey_from_secretkey(
            "g794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1",
            "\"Secp256k1\"",
        );
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing secret_key");
        assert!(!success);
    }

    #[test]
    fn test_publickey_from_secretkey_wrong_curve() {
        let result = publickey_from_secretkey(
            "4794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1",
            "",
        );
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing curve");
        assert!(!success);
    }

    #[test]
    fn test_fill_rpool_k1_ok() {
        let result = fill_rpool(
            "[\"aa75ca8a2fd3f8af94976bfaa7aa476dc31f5d78d9fef8fb86a97a775f611ae5\"]",
            "[\"031241ac15c9c9c070e1cba1dbdb3992018f9c66f0e50a8d9afbebc510aaf355e7\"]",
            "\"Secp256k1\"",
            "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}",
        );
        let (success, _): (bool, String) = serde_json::from_str(&result).unwrap();
        assert!(success);
    }

    #[test]
    fn test_fill_rpool_k1_wrong_dh_secrets() {
        let result = fill_rpool(
            "[a\"aa75ca8a2fd3f8af94976bfaa7aa476dc31f5d78d9fef8fb86a97a775f611ae5\"]",
            "[\"031241ac15c9c9c070e1cba1dbdb3992018f9c66f0e50a8d9afbebc510aaf355e7\"]",
            "\"Secp256k1\"",
            "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}",
        );
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing client_dh_secrets");
        assert!(!success);
    }

    #[test]
    fn test_fill_rpool_k1_wrong_dh_publics() {
        let result = fill_rpool(
            "[\"aa75ca8a2fd3f8af94976bfaa7aa476dc31f5d78d9fef8fb86a97a775f611ae5\"]",
            "\"031241ac15c9c9c070e1cba1dbdb3992018f9c66f0e50a8d9afbebc510aaf355e7\"]",
            "\"Secp256k1\"",
            "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}",
        );
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing client_dh_publics");
        assert!(!success);
    }

    #[test]
    fn test_fill_rpool_k1_wrong_curve() {
        let result = fill_rpool(
            "[\"aa75ca8a2fd3f8af94976bfaa7aa476dc31f5d78d9fef8fb86a97a775f611ae5\"]",
            "[\"031241ac15c9c9c070e1cba1dbdb3992018f9c66f0e50a8d9afbebc510aaf355e7\"]",
            "Secp256k1",
            "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}",
        );
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing curve");
        assert!(!success);
    }

    #[test]
    fn test_fill_rpool_r1_ok() {
        let result = fill_rpool(
            "[\"312a8e55996f72a708929e68c7c0f4dcdcdcddb35d512f9ded388bcd7dce8633\"]",
            "[\"0260b63daf0f1576b1275f4713c2393dd0de89abbc14e70c7b1e209f5a9fbb69f0\"]",
            "\"Secp256r1\"",
            "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}",
        );
        let (success, _): (bool, String) = serde_json::from_str(&result).unwrap();
        assert!(success);
    }

    #[test]
    fn test_fill_rpool_r1_wrong_dh_secrets() {
        let result = fill_rpool(
            "\"312a8e55996f72a708929e68c7c0f4dcdcdcddb35d512f9ded388bcd7dce8633\"]",
            "[\"0260b63daf0f1576b1275f4713c2393dd0de89abbc14e70c7b1e209f5a9fbb69f0\"]",
            "\"Secp256r1\"",
            "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}",
        );
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing client_dh_secrets");
        assert!(!success);
    }

    #[test]
    fn test_fill_rpool_r1_wrong_dh_publics() {
        let result = fill_rpool(
            "[\"312a8e55996f72a708929e68c7c0f4dcdcdcddb35d512f9ded388bcd7dce8633\"]",
            "[\"\"]",
            "\"Secp256r1\"",
            "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}",
        );
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing client_dh_publics");
        assert!(!success);
    }

    #[test]
    fn test_fill_rpool_r1_wrong_curve() {
        let result = fill_rpool(
            "[\"312a8e55996f72a708929e68c7c0f4dcdcdcddb35d512f9ded388bcd7dce8633\"]",
            "[\"0260b63daf0f1576b1275f4713c2393dd0de89abbc14e70c7b1e209f5a9fbb69f0\"]",
            "\"ECDSA\"",
            "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}",
        );
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing curve");
        assert!(!success);
    }

    #[test]
    fn test_compute_presig_k1_ok() {
        fill_rpool(
            "[\"aa75ca8a2fd3f8af94976bfaa7aa476dc31f5d78d9fef8fb86a97a775f611ae5\"]",
            "[\"031241ac15c9c9c070e1cba1dbdb3992018f9c66f0e50a8d9afbebc510aaf355e7\"]",
            "\"Secp256k1\"",
            "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}",
        );
        let result = compute_presig(
        "{\"paillier_pk\":{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"},\"public_key\":\"042f1fa347032efc9cece1e1c5edcbdda64aaff92911949fe0adbb165e8d82c13025485b8c218e56a5dd932cc9ab6efaff611dc42cc3aa3acd0b0ea5ba7f1a8de3\",\"client_secret_share\":\"bc45e8d856be2e179e015dc2429d84a628cb7f4755f63e030784e1ee3ee9f43d\",\"server_secret_share_encrypted\":\"4996ad9776bf178dc7155f4b7994b94a5c85b0c3579b9ecca3c3903c9569845e1f51368ba3cb764819fb739047ccfcffe57a47a0fe640c8ef67d416b8888d4b0235de56418c944a8a38bec9bcde913ff5109d68055b7c843dd4c5e77d4d654305a74493ddc1353eb7261dcf4a8c8545604b48d96e272887aa06c80fa58532e8c3a4f7e44869ea42a73084a7b48d02503b8e8489230660b05a08ace5e4517c1a8f51bca8d50952e99f3c0e84a71dc3831ea4b2ff9cbd9a37ce057320c14b71b2daf0fb66edc7d3a02547b6518f557ceabe7981e3958f8ffa7befc71191bfcfa08d382e7fa60d2bd7f76a59ce33a35c829d89f7326c17142d89e660ab328714e2e3087dff5e0950a2c11c3320257a90d679b7a3bc5cd9c7ab5c03d39d7416f6530dda75e9582fddffb558f637272d26c18c23a54a5f292badd0cb69f758a7bc6cacc38b5bd7e4b1021b62d85af345d5e42bda7e47144e8646d37e999686d479ad91f117fb0b2656026d271f1a56bc8cbeba409e9ccc45ff1f393141dde2e1c4ed1ad1ceb63ea1725a601c050a5789c901b155b180cef078b2c16adf7956640df8c185cf8e973acdb6c1bda1ab408a03849a6cf41a12ae69e5886c087686048c21b0fcc9dff020af065809b8ad9165354669fb77df11cfcb502042da9acc1f7cccbcee5b5ff458130e12bbbc1cec3b26acfad6373cb4b4ea8cc5597af6299836b70\"}",
        "000000000000000fffffffffffffffffff00000000000000ffffffffff000000",
        "\"Secp256k1\"");
        let (success, _, _): (bool, String, String) = serde_json::from_str(&result).unwrap();
        assert!(success);
    }

    #[test]
    fn test_compute_presig_k1_wrong_childkey() {
        fill_rpool(
            "[\"aa75ca8a2fd3f8af94976bfaa7aa476dc31f5d78d9fef8fb86a97a775f611ae5\"]",
            "[\"031241ac15c9c9c070e1cba1dbdb3992018f9c66f0e50a8d9afbebc510aaf355e7\"]",
            "\"Secp256k1\"",
            "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}",
        );
        let result = compute_presig(
        "a{\"paillier_pk\":{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"},\"public_key\":\"042f1fa347032efc9cece1e1c5edcbdda64aaff92911949fe0adbb165e8d82c13025485b8c218e56a5dd932cc9ab6efaff611dc42cc3aa3acd0b0ea5ba7f1a8de3\",\"client_secret_share\":\"bc45e8d856be2e179e015dc2429d84a628cb7f4755f63e030784e1ee3ee9f43d\",\"server_secret_share_encrypted\":\"4996ad9776bf178dc7155f4b7994b94a5c85b0c3579b9ecca3c3903c9569845e1f51368ba3cb764819fb739047ccfcffe57a47a0fe640c8ef67d416b8888d4b0235de56418c944a8a38bec9bcde913ff5109d68055b7c843dd4c5e77d4d654305a74493ddc1353eb7261dcf4a8c8545604b48d96e272887aa06c80fa58532e8c3a4f7e44869ea42a73084a7b48d02503b8e8489230660b05a08ace5e4517c1a8f51bca8d50952e99f3c0e84a71dc3831ea4b2ff9cbd9a37ce057320c14b71b2daf0fb66edc7d3a02547b6518f557ceabe7981e3958f8ffa7befc71191bfcfa08d382e7fa60d2bd7f76a59ce33a35c829d89f7326c17142d89e660ab328714e2e3087dff5e0950a2c11c3320257a90d679b7a3bc5cd9c7ab5c03d39d7416f6530dda75e9582fddffb558f637272d26c18c23a54a5f292badd0cb69f758a7bc6cacc38b5bd7e4b1021b62d85af345d5e42bda7e47144e8646d37e999686d479ad91f117fb0b2656026d271f1a56bc8cbeba409e9ccc45ff1f393141dde2e1c4ed1ad1ceb63ea1725a601c050a5789c901b155b180cef078b2c16adf7956640df8c185cf8e973acdb6c1bda1ab408a03849a6cf41a12ae69e5886c087686048c21b0fcc9dff020af065809b8ad9165354669fb77df11cfcb502042da9acc1f7cccbcee5b5ff458130e12bbbc1cec3b26acfad6373cb4b4ea8cc5597af6299836b70\"}",
        "000000000000000fffffffffffffffffff00000000000000ffffffffff000000",
        "\"Secp256k1\"");
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing api_childkey");
        assert!(!success);
    }

    #[test]
    fn test_compute_presig_k1_wrong_hash() {
        fill_rpool(
            "[\"aa75ca8a2fd3f8af94976bfaa7aa476dc31f5d78d9fef8fb86a97a775f611ae5\"]",
            "[\"031241ac15c9c9c070e1cba1dbdb3992018f9c66f0e50a8d9afbebc510aaf355e7\"]",
            "\"Secp256k1\"",
            "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}",
        );
        let result = compute_presig(
        "{\"paillier_pk\":{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"},\"public_key\":\"042f1fa347032efc9cece1e1c5edcbdda64aaff92911949fe0adbb165e8d82c13025485b8c218e56a5dd932cc9ab6efaff611dc42cc3aa3acd0b0ea5ba7f1a8de3\",\"client_secret_share\":\"bc45e8d856be2e179e015dc2429d84a628cb7f4755f63e030784e1ee3ee9f43d\",\"server_secret_share_encrypted\":\"4996ad9776bf178dc7155f4b7994b94a5c85b0c3579b9ecca3c3903c9569845e1f51368ba3cb764819fb739047ccfcffe57a47a0fe640c8ef67d416b8888d4b0235de56418c944a8a38bec9bcde913ff5109d68055b7c843dd4c5e77d4d654305a74493ddc1353eb7261dcf4a8c8545604b48d96e272887aa06c80fa58532e8c3a4f7e44869ea42a73084a7b48d02503b8e8489230660b05a08ace5e4517c1a8f51bca8d50952e99f3c0e84a71dc3831ea4b2ff9cbd9a37ce057320c14b71b2daf0fb66edc7d3a02547b6518f557ceabe7981e3958f8ffa7befc71191bfcfa08d382e7fa60d2bd7f76a59ce33a35c829d89f7326c17142d89e660ab328714e2e3087dff5e0950a2c11c3320257a90d679b7a3bc5cd9c7ab5c03d39d7416f6530dda75e9582fddffb558f637272d26c18c23a54a5f292badd0cb69f758a7bc6cacc38b5bd7e4b1021b62d85af345d5e42bda7e47144e8646d37e999686d479ad91f117fb0b2656026d271f1a56bc8cbeba409e9ccc45ff1f393141dde2e1c4ed1ad1ceb63ea1725a601c050a5789c901b155b180cef078b2c16adf7956640df8c185cf8e973acdb6c1bda1ab408a03849a6cf41a12ae69e5886c087686048c21b0fcc9dff020af065809b8ad9165354669fb77df11cfcb502042da9acc1f7cccbcee5b5ff458130e12bbbc1cec3b26acfad6373cb4b4ea8cc5597af6299836b70\"}",
        "z000000000000000fffffffffffffffffff00000000000000ffffffffff000000",
        "\"Secp256k1\"");
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing msg_hash");
        assert!(!success);
    }

    #[test]
    fn test_compute_presig_k1_wrong_curve() {
        fill_rpool(
            "[\"aa75ca8a2fd3f8af94976bfaa7aa476dc31f5d78d9fef8fb86a97a775f611ae5\"]",
            "[\"031241ac15c9c9c070e1cba1dbdb3992018f9c66f0e50a8d9afbebc510aaf355e7\"]",
            "\"Secp256k1\"",
            "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}",
        );
        let result = compute_presig(
        "{\"paillier_pk\":{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"},\"public_key\":\"042f1fa347032efc9cece1e1c5edcbdda64aaff92911949fe0adbb165e8d82c13025485b8c218e56a5dd932cc9ab6efaff611dc42cc3aa3acd0b0ea5ba7f1a8de3\",\"client_secret_share\":\"bc45e8d856be2e179e015dc2429d84a628cb7f4755f63e030784e1ee3ee9f43d\",\"server_secret_share_encrypted\":\"4996ad9776bf178dc7155f4b7994b94a5c85b0c3579b9ecca3c3903c9569845e1f51368ba3cb764819fb739047ccfcffe57a47a0fe640c8ef67d416b8888d4b0235de56418c944a8a38bec9bcde913ff5109d68055b7c843dd4c5e77d4d654305a74493ddc1353eb7261dcf4a8c8545604b48d96e272887aa06c80fa58532e8c3a4f7e44869ea42a73084a7b48d02503b8e8489230660b05a08ace5e4517c1a8f51bca8d50952e99f3c0e84a71dc3831ea4b2ff9cbd9a37ce057320c14b71b2daf0fb66edc7d3a02547b6518f557ceabe7981e3958f8ffa7befc71191bfcfa08d382e7fa60d2bd7f76a59ce33a35c829d89f7326c17142d89e660ab328714e2e3087dff5e0950a2c11c3320257a90d679b7a3bc5cd9c7ab5c03d39d7416f6530dda75e9582fddffb558f637272d26c18c23a54a5f292badd0cb69f758a7bc6cacc38b5bd7e4b1021b62d85af345d5e42bda7e47144e8646d37e999686d479ad91f117fb0b2656026d271f1a56bc8cbeba409e9ccc45ff1f393141dde2e1c4ed1ad1ceb63ea1725a601c050a5789c901b155b180cef078b2c16adf7956640df8c185cf8e973acdb6c1bda1ab408a03849a6cf41a12ae69e5886c087686048c21b0fcc9dff020af065809b8ad9165354669fb77df11cfcb502042da9acc1f7cccbcee5b5ff458130e12bbbc1cec3b26acfad6373cb4b4ea8cc5597af6299836b70\"}",
        "000000000000000fffffffffffffffffff00000000000000ffffffffff000000",
        "\"Secp512k1\"");
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing curve");
        assert!(!success);
    }

    #[test]
    fn test_compute_presig_r1_ok() {
        fill_rpool(
            "[\"312a8e55996f72a708929e68c7c0f4dcdcdcddb35d512f9ded388bcd7dce8633\"]",
            "[\"0260b63daf0f1576b1275f4713c2393dd0de89abbc14e70c7b1e209f5a9fbb69f0\"]",
            "\"Secp256r1\"",
            "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}",
        );
        let result = compute_presig(
        "{\"paillier_pk\":{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"},\"public_key\":\"04edb74abcc30629455eccbe8d3a61a8694999656de8b8f0615ad50c4c3ef238e5dcf1956f7877ffb5c927e5d3e479fe913e10a0caa7a34866fe44f8bddf4b0a04\",\"client_secret_share\":\"50dae30585846dd84c7cbf8fc6343937c562ae6e0cc4658b712a6ac3478c12d6\",\"server_secret_share_encrypted\":\"52de7f3c637d3d62853394a388fe092fcc125bbcf23a9507f641771073bdf690a64529eaee5979f411cc9972c12cbbfa13b3c55f5201ad335f382b26ed90d46913d5367a3144553c32e90609416505e60e374adba08c944c375d3c20d3fc3b31c2c2766c4b2572dc8a4434bdab56ea49e4b815d515df6269db07b35f21af1e45b2cef6d1b2acd0777ba0c80c184404c36cfe35ea4b809262dd9217f58c461857ed948874b20c74eb419a0e7c62842edbd500c619e0e390d8807ca3938d6d9229993ef89574212c7581b5abfc4c293d607187d85fdedc8a9a21156c59ad3189d08d61414bfffcba45f91cdfe9c479147fdf5fce2b22bebaa07dae62b0e728176b7787cceba5d1c8b66c4dd2e4197f9ba1911917adc94f149820391ebdc1d031a12f58f4eb3422071b9f236140be1c98010adafb6cf867f52f0d0b1dafa9f08bf42f1c19062e7eb65e441dc38b1fdcb047b2ce879ee3e3c59f22bb29f1d8b7788ef26512ee735987d3ae30fd8eb4308d1f8758dc713e0716564cfdfecaed7244961e90450d761e524a4f538e9b20bd779c7ae6bf81f47226215bb2b20a425ff333cec1cf849d34eeb2f250672ca88ff7400f6d3864bf6e4de701c07a13d0d4d40459c0663a95159fb3112f6375ddcc26c785e10e9956998c848c7cfcb9d8f5692ad544c5109fc9a113cc66950b557e9be737d61a1d05694f0eb90ee918f07ec3a8\"}",
        "000000000000000fffffffffffffffffff00000000000000ffffffffff000000",
        "\"Secp256r1\"");
        let (success, _, _): (bool, String, String) = serde_json::from_str(&result).unwrap();
        assert!(success);
    }

    #[test]
    fn test_compute_presig_r1_wrong_childkey() {
        fill_rpool(
            "[\"312a8e55996f72a708929e68c7c0f4dcdcdcddb35d512f9ded388bcd7dce8633\"]",
            "[\"0260b63daf0f1576b1275f4713c2393dd0de89abbc14e70c7b1e209f5a9fbb69f0\"]",
            "\"Secp256r1\"",
            "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}",
        );
        let result = compute_presig(
        "{\"\":{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"},\"public_key\":\"04edb74abcc30629455eccbe8d3a61a8694999656de8b8f0615ad50c4c3ef238e5dcf1956f7877ffb5c927e5d3e479fe913e10a0caa7a34866fe44f8bddf4b0a04\",\"client_secret_share\":\"50dae30585846dd84c7cbf8fc6343937c562ae6e0cc4658b712a6ac3478c12d6\",\"server_secret_share_encrypted\":\"52de7f3c637d3d62853394a388fe092fcc125bbcf23a9507f641771073bdf690a64529eaee5979f411cc9972c12cbbfa13b3c55f5201ad335f382b26ed90d46913d5367a3144553c32e90609416505e60e374adba08c944c375d3c20d3fc3b31c2c2766c4b2572dc8a4434bdab56ea49e4b815d515df6269db07b35f21af1e45b2cef6d1b2acd0777ba0c80c184404c36cfe35ea4b809262dd9217f58c461857ed948874b20c74eb419a0e7c62842edbd500c619e0e390d8807ca3938d6d9229993ef89574212c7581b5abfc4c293d607187d85fdedc8a9a21156c59ad3189d08d61414bfffcba45f91cdfe9c479147fdf5fce2b22bebaa07dae62b0e728176b7787cceba5d1c8b66c4dd2e4197f9ba1911917adc94f149820391ebdc1d031a12f58f4eb3422071b9f236140be1c98010adafb6cf867f52f0d0b1dafa9f08bf42f1c19062e7eb65e441dc38b1fdcb047b2ce879ee3e3c59f22bb29f1d8b7788ef26512ee735987d3ae30fd8eb4308d1f8758dc713e0716564cfdfecaed7244961e90450d761e524a4f538e9b20bd779c7ae6bf81f47226215bb2b20a425ff333cec1cf849d34eeb2f250672ca88ff7400f6d3864bf6e4de701c07a13d0d4d40459c0663a95159fb3112f6375ddcc26c785e10e9956998c848c7cfcb9d8f5692ad544c5109fc9a113cc66950b557e9be737d61a1d05694f0eb90ee918f07ec3a8\"}",
        "000000000000000fffffffffffffffffff00000000000000ffffffffff000000",
        "\"Secp256r1\"");
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing api_childkey");
        assert!(!success);
    }

    #[test]
    fn test_compute_presig_r1_wrong_hash() {
        fill_rpool(
            "[\"312a8e55996f72a708929e68c7c0f4dcdcdcddb35d512f9ded388bcd7dce8633\"]",
            "[\"0260b63daf0f1576b1275f4713c2393dd0de89abbc14e70c7b1e209f5a9fbb69f0\"]",
            "\"Secp256r1\"",
            "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}",
        );
        let result = compute_presig(
        "{\"paillier_pk\":{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"},\"public_key\":\"04edb74abcc30629455eccbe8d3a61a8694999656de8b8f0615ad50c4c3ef238e5dcf1956f7877ffb5c927e5d3e479fe913e10a0caa7a34866fe44f8bddf4b0a04\",\"client_secret_share\":\"50dae30585846dd84c7cbf8fc6343937c562ae6e0cc4658b712a6ac3478c12d6\",\"server_secret_share_encrypted\":\"52de7f3c637d3d62853394a388fe092fcc125bbcf23a9507f641771073bdf690a64529eaee5979f411cc9972c12cbbfa13b3c55f5201ad335f382b26ed90d46913d5367a3144553c32e90609416505e60e374adba08c944c375d3c20d3fc3b31c2c2766c4b2572dc8a4434bdab56ea49e4b815d515df6269db07b35f21af1e45b2cef6d1b2acd0777ba0c80c184404c36cfe35ea4b809262dd9217f58c461857ed948874b20c74eb419a0e7c62842edbd500c619e0e390d8807ca3938d6d9229993ef89574212c7581b5abfc4c293d607187d85fdedc8a9a21156c59ad3189d08d61414bfffcba45f91cdfe9c479147fdf5fce2b22bebaa07dae62b0e728176b7787cceba5d1c8b66c4dd2e4197f9ba1911917adc94f149820391ebdc1d031a12f58f4eb3422071b9f236140be1c98010adafb6cf867f52f0d0b1dafa9f08bf42f1c19062e7eb65e441dc38b1fdcb047b2ce879ee3e3c59f22bb29f1d8b7788ef26512ee735987d3ae30fd8eb4308d1f8758dc713e0716564cfdfecaed7244961e90450d761e524a4f538e9b20bd779c7ae6bf81f47226215bb2b20a425ff333cec1cf849d34eeb2f250672ca88ff7400f6d3864bf6e4de701c07a13d0d4d40459c0663a95159fb3112f6375ddcc26c785e10e9956998c848c7cfcb9d8f5692ad544c5109fc9a113cc66950b557e9be737d61a1d05694f0eb90ee918f07ec3a8\"}",
        "000000000000000fffffffffffffffffff00000000000000ffffffffff000000h",
        "\"Secp256r1\"");

        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing msg_hash");
        assert!(!success);
    }

    #[test]
    fn test_compute_presig_r1_wrong_curve() {
        fill_rpool(
            "[\"312a8e55996f72a708929e68c7c0f4dcdcdcddb35d512f9ded388bcd7dce8633\"]",
            "[\"0260b63daf0f1576b1275f4713c2393dd0de89abbc14e70c7b1e209f5a9fbb69f0\"]",
            "\"Secp256r1\"",
            "{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"}",
        );
        let result = compute_presig(
        "{\"paillier_pk\":{\"n\":\"9e2f24f407914eff43b7c7df083c5cc9765c05386485e9e9aa55e7b039290300ba39e86f399e2b338fad4bb34a4d7a7a0cd14fd28503eeebb73ff38e8164616942113afadaeaba525bd4cfdafc4ddd3b012d3fbcd9f276acbad4379b8b93bc4f4d6ddc0a2b9af36b34771595f0e6cb62987b961d83f49ba6ec4b088a1350b3dbbea3e21033801f6c4b212ecd830b5b81075effd06b47feecf18f3c9093662c918073dd95a525b4f99478512ea3bf085993c9bf65922d42b65b338431711dddb5491c2004548df31ab6092ec58db564c8a88a309b0f734171de1f8f4361d5f883e38d5bf519dc347036910aec3c80f2058fa8945c38787094f3450774e2b23129\"},\"public_key\":\"04edb74abcc30629455eccbe8d3a61a8694999656de8b8f0615ad50c4c3ef238e5dcf1956f7877ffb5c927e5d3e479fe913e10a0caa7a34866fe44f8bddf4b0a04\",\"client_secret_share\":\"50dae30585846dd84c7cbf8fc6343937c562ae6e0cc4658b712a6ac3478c12d6\",\"server_secret_share_encrypted\":\"52de7f3c637d3d62853394a388fe092fcc125bbcf23a9507f641771073bdf690a64529eaee5979f411cc9972c12cbbfa13b3c55f5201ad335f382b26ed90d46913d5367a3144553c32e90609416505e60e374adba08c944c375d3c20d3fc3b31c2c2766c4b2572dc8a4434bdab56ea49e4b815d515df6269db07b35f21af1e45b2cef6d1b2acd0777ba0c80c184404c36cfe35ea4b809262dd9217f58c461857ed948874b20c74eb419a0e7c62842edbd500c619e0e390d8807ca3938d6d9229993ef89574212c7581b5abfc4c293d607187d85fdedc8a9a21156c59ad3189d08d61414bfffcba45f91cdfe9c479147fdf5fce2b22bebaa07dae62b0e728176b7787cceba5d1c8b66c4dd2e4197f9ba1911917adc94f149820391ebdc1d031a12f58f4eb3422071b9f236140be1c98010adafb6cf867f52f0d0b1dafa9f08bf42f1c19062e7eb65e441dc38b1fdcb047b2ce879ee3e3c59f22bb29f1d8b7788ef26512ee735987d3ae30fd8eb4308d1f8758dc713e0716564cfdfecaed7244961e90450d761e524a4f538e9b20bd779c7ae6bf81f47226215bb2b20a425ff333cec1cf849d34eeb2f250672ca88ff7400f6d3864bf6e4de701c07a13d0d4d40459c0663a95159fb3112f6375ddcc26c785e10e9956998c848c7cfcb9d8f5692ad544c5109fc9a113cc66950b557e9be737d61a1d05694f0eb90ee918f07ec3a8\"}",
        "000000000000000fffffffffffffffffff00000000000000ffffffffff000000",
        "\"Secp128r1\"");
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error deserializing curve");
        assert!(!success);
    }

    #[test]
    fn test_verify_k1_ok() {
        let result = verify(
            "ca44d5cdeab3ad356e6fa2fb715bdfd82219d35d83aa95fdea3bbe2ce472417d",
            "6cc55f9c8a1db21575830c5419b80bc43de466480ccc60c9e5752575d6565eb8",
            "\"042f1fa347032efc9cece1e1c5edcbdda64aaff92911949fe0adbb165e8d82c13025485b8c218e56a5dd932cc9ab6efaff611dc42cc3aa3acd0b0ea5ba7f1a8de3\"",
            "000000000000000fffffffffffffffffff00000000000000ffffffffff000000",
            "\"Secp256k1\""
        );
        let (success, _): (bool, String) = serde_json::from_str(&result).unwrap();
        assert!(success);
    }

    #[test]
    fn test_verify_k1_wrong_r() {
        let result = verify(
            "da44d5cdeab3ad356e6fa2fb715bdfd82219d35d83aa95fdea3bbe2ce472417d",
            "6cc55f9c8a1db21575830c5419b80bc43de466480ccc60c9e5752575d6565eb8",
            "\"042f1fa347032efc9cece1e1c5edcbdda64aaff92911949fe0adbb165e8d82c13025485b8c218e56a5dd932cc9ab6efaff611dc42cc3aa3acd0b0ea5ba7f1a8de3\"",
            "000000000000000fffffffffffffffffff00000000000000ffffffffff000000",
            "\"Secp256k1\""
        );
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error verifying signature");
        assert!(!success);
    }

    #[test]
    fn test_verify_k1_wrong_s() {
        let result = verify(
            "ca44d5cdeab3ad356e6fa2fb715bdfd82219d35d83aa95fdea3bbe2ce472417d",
            "7cc55f9c8a1db21575830c5419b80bc43de466480ccc60c9e5752575d6565eb8",
            "\"042f1fa347032efc9cece1e1c5edcbdda64aaff92911949fe0adbb165e8d82c13025485b8c218e56a5dd932cc9ab6efaff611dc42cc3aa3acd0b0ea5ba7f1a8de3\"",
            "000000000000000fffffffffffffffffff00000000000000ffffffffff000000",
            "\"Secp256k1\""
        );
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error verifying signature");
        assert!(!success);
    }

    #[test]
    fn test_verify_k1_wrong_pk() {
        let result = verify(
            "ca44d5cdeab3ad356e6fa2fb715bdfd82219d35d83aa95fdea3bbe2ce472417d",
            "6cc55f9c8a1db21575830c5419b80bc43de466480ccc60c9e5752575d6565eb8",
            "\"043f1fa347032efc9cece1e1c5edcbdda64aaff92911949fe0adbb165e8d82c13025485b8c218e56a5dd932cc9ab6efaff611dc42cc3aa3acd0b0ea5ba7f1a8de3\"",
            "000000000000000fffffffffffffffffff00000000000000ffffffffff000000",
            "\"Secp256k1\""
        );
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error: invalid pubkey or invalid curve");
        assert!(!success);
    }

    #[test]
    fn test_verify_k1_wrong_hash() {
        let result = verify(
            "ca44d5cdeab3ad356e6fa2fb715bdfd82219d35d83aa95fdea3bbe2ce472417d",
            "6cc55f9c8a1db21575830c5419b80bc43de466480ccc60c9e5752575d6565eb8",
            "\"042f1fa347032efc9cece1e1c5edcbdda64aaff92911949fe0adbb165e8d82c13025485b8c218e56a5dd932cc9ab6efaff611dc42cc3aa3acd0b0ea5ba7f1a8de3\"",
            "100000000000000fffffffffffffffffff00000000000000ffffffffff000000",
            "\"Secp256k1\""
        );
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error verifying signature");
        assert!(!success);
    }

    #[test]
    fn test_verify_k1_wrong_curve() {
        let result = verify(
            "ca44d5cdeab3ad356e6fa2fb715bdfd82219d35d83aa95fdea3bbe2ce472417d",
            "6cc55f9c8a1db21575830c5419b80bc43de466480ccc60c9e5752575d6565eb8",
            "\"042f1fa347032efc9cece1e1c5edcbdda64aaff92911949fe0adbb165e8d82c13025485b8c218e56a5dd932cc9ab6efaff611dc42cc3aa3acd0b0ea5ba7f1a8de3\"",
            "100000000000000fffffffffffffffffff00000000000000ffffffffff000000",
            "\"Secp256r1\""
        );
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error: invalid pubkey or invalid curve");
        assert!(!success);
    }

    #[test]
    fn test_verify_r1_ok() {
        let result = verify(
            "31c7081272937630d061ffec3416e1fefa79e46380a7325de6916dead4b3dfdd",
            "7bb1a85139297b30dd77626082fe9e3d2be1fdca5d32987e38f6de434f82777c",
            "\"04edb74abcc30629455eccbe8d3a61a8694999656de8b8f0615ad50c4c3ef238e5dcf1956f7877ffb5c927e5d3e479fe913e10a0caa7a34866fe44f8bddf4b0a04\"",
            "000000000000000fffffffffffffffffff00000000000000ffffffffff000000",
            "\"Secp256r1\""
        );
        let (success, _): (bool, String) = serde_json::from_str(&result).unwrap();
        assert!(success);
    }

    #[test]
    fn test_verify_r1_wrong_r() {
        let result = verify(
            "41c7081272937630d061ffec3416e1fefa79e46380a7325de6916dead4b3dfdd",
            "7bb1a85139297b30dd77626082fe9e3d2be1fdca5d32987e38f6de434f82777c",
            "\"04edb74abcc30629455eccbe8d3a61a8694999656de8b8f0615ad50c4c3ef238e5dcf1956f7877ffb5c927e5d3e479fe913e10a0caa7a34866fe44f8bddf4b0a04\"",
            "000000000000000fffffffffffffffffff00000000000000ffffffffff000000",
            "\"Secp256r1\""
        );
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error verifying signature");
        assert!(!success);
    }

    #[test]
    fn test_verify_r1_wrong_s() {
        let result = verify(
            "31c7081272937630d061ffec3416e1fefa79e46380a7325de6916dead4b3dfdd",
            "8bb1a85139297b30dd77626082fe9e3d2be1fdca5d32987e38f6de434f82777c",
            "\"04edb74abcc30629455eccbe8d3a61a8694999656de8b8f0615ad50c4c3ef238e5dcf1956f7877ffb5c927e5d3e479fe913e10a0caa7a34866fe44f8bddf4b0a04\"",
            "000000000000000fffffffffffffffffff00000000000000ffffffffff000000",
            "\"Secp256r1\""
        );
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error verifying signature");
        assert!(!success);
    }

    #[test]
    fn test_verify_r1_wrong_pk() {
        let result = verify(
            "31c7081272937630d061ffec3416e1fefa79e46380a7325de6916dead4b3dfdd",
            "7bb1a85139297b30dd77626082fe9e3d2be1fdca5d32987e38f6de434f82777c",
            "\"04fdb74abcc30629455eccbe8d3a61a8694999656de8b8f0615ad50c4c3ef238e5dcf1956f7877ffb5c927e5d3e479fe913e10a0caa7a34866fe44f8bddf4b0a04\"",
            "000000000000000fffffffffffffffffff00000000000000ffffffffff000000",
            "\"Secp256r1\""
        );
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error: invalid pubkey or invalid curve");
        assert!(!success);
    }

    #[test]
    fn test_verify_r1_wrong_hash() {
        let result = verify(
            "31c7081272937630d061ffec3416e1fefa79e46380a7325de6916dead4b3dfdd",
            "7bb1a85139297b30dd77626082fe9e3d2be1fdca5d32987e38f6de434f82777c",
            "\"04edb74abcc30629455eccbe8d3a61a8694999656de8b8f0615ad50c4c3ef238e5dcf1956f7877ffb5c927e5d3e479fe913e10a0caa7a34866fe44f8bddf4b0a04\"",
            "010000000000000fffffffffffffffffff00000000000000ffffffffff000000",
            "\"Secp256r1\""
        );
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error verifying signature");
        assert!(!success);
    }

    #[test]
    fn test_verify_r1_wrong_curve() {
        let result = verify(
            "31c7081272937630d061ffec3416e1fefa79e46380a7325de6916dead4b3dfdd",
            "7bb1a85139297b30dd77626082fe9e3d2be1fdca5d32987e38f6de434f82777c",
            "\"04feb74abcc30629455eccbe8d3a61a8694999656de8b8f0615ad50c4c3ef238e5dcf1956f7877ffb5c927e5d3e479fe913e10a0caa7a34866fe44f8bddf4b0a04\"",
            "000000000000000fffffffffffffffffff00000000000000ffffffffff000000",
            "\"Secp256k1\""
        );
        let (success, msg): (bool, String) = serde_json::from_str(&result).unwrap();
        assert_eq!(msg, "error: invalid pubkey or invalid curve");
        assert!(!success);
    }

    #[test]
    fn test_sign_ok() {
        let result = sign(
            "4794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1",
            "100000000000000fffffffffffffffffff00000000000000ffffffffff000000",
        );
        let (success, _, _): (bool, String, String) = serde_json::from_str(&result).unwrap();
        assert!(success);
    }

    #[test]
    fn test_sign_wrong_sk() {
        let result = sign(
            "z794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1",
            "100000000000000fffffffffffffffffff00000000000000ffffffffff000000",
        );
        let (success, _): (bool, String) = serde_json::from_str(&result).unwrap();
        assert!(!success);
    }

    #[test]
    fn test_sign_wrong_hash() {
        let result = sign(
            "4794853ce9e44b4c7a69c6a3b87db077f8f910f244bb6b966ba5fed83c9756f1",
            "\\00000000000000fffffffffffffffffff00000000000000ffffffffff000000",
        );
        let (success, _): (bool, String) = serde_json::from_str(&result).unwrap();
        assert!(!success);
    }
}
