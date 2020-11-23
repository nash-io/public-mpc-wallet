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
 use neon::prelude::*;
 
 /// Generate shared random values using Diffie-Hellman
 /// Input: n: number of values to generate, curve: Secp256r1 or Secp256k1
 /// Output: dh_secrets: list of (n) DH secret values, dh_publics: list of (n) DH public values
 pub fn dh_init(mut cx: FunctionContext) -> JsResult<JsString> {
     let n = cx.argument::<JsNumber>(0)?.value() as usize;
     let curve = cx.argument::<JsString>(1)?;
 
     let curve = match curve.value().as_str() {
         "Secp256k1" => common::Curve::Secp256k1,
         "Secp256r1" => common::Curve::Secp256r1,
         _ => panic!("Invalid curve")
     };
     let res = if curve == common::Curve::Secp256k1 {
         let (dh_secrets, dh_publics) = match common::dh_init_secp256k1(n) {
             Ok(v) => v,
             Err(_) => return Ok(cx.string(serde_json::to_string(&(false, &"error: n is too big.")).unwrap())),
         };
         serde_json::to_string(&(true, &dh_secrets, &dh_publics)).unwrap()
     } else if curve == common::Curve::Secp256r1 {
         let (dh_secrets, dh_publics) = match common::dh_init_secp256r1(n) {
             Ok(v) => v,
             Err(_) => return Ok(cx.string(serde_json::to_string(&(false, &"error: n is too big.")).unwrap())),
         };
         serde_json::to_string(&(true, &dh_secrets, &dh_publics)).unwrap()
     } else {
         serde_json::to_string(&(false, &"error: invalid curve")).unwrap()
     };
 
     Ok(cx.string(res))
 }
 
 /// Fill pool of random and nonce values to facilitate signature generation with a single message.
 /// Input: client_dh_secrets: list of client DH secret values, server_dh_publics: list of server DH public values, curve: Secp256k1 or Secp256r1, paillier_pk: Paillier public key
 /// Output: none
 fn fill_rpool(mut cx: FunctionContext) ->  JsResult<JsString> {
     let client_dh_secrets_str = cx.argument::<JsString>(0)?.value();
     let server_dh_publics_str = cx.argument::<JsString>(1)?.value();
     let paillier_pk_str = cx.argument::<JsString>(2)?.value();
     let curve = cx.argument::<JsString>(3)?.value();
     
     let curve = match curve.as_str() {
         "Secp256k1" => common::Curve::Secp256k1,
         "Secp256r1" => common::Curve::Secp256r1,
         _ => panic!("Invalid curve")
     };
     let paillier_pk: EncryptionKey = match serde_json::from_str(&paillier_pk_str) {
         Ok(v) => v,
         Err(_) => {
             return Ok(cx.string(serde_json::to_string(&(false, &"error deserializing paillier_pk")).unwrap()))
         }
     };
     if curve == common::Curve::Secp256k1 {
         let client_dh_secrets: Vec<Secp256k1Scalar> =
         match serde_json::from_str(&client_dh_secrets_str) {
             Ok(v) => v,
             Err(_) => {
                 return Ok(cx.string(serde_json::to_string(&(false, &"error deserializing client_dh_secrets"))
                     .unwrap()))
             }
         };
         let server_dh_publics: Vec<Secp256k1Point> =
             match serde_json::from_str(&server_dh_publics_str) {
                 Ok(v) => v,
                 Err(_) => {
                     return Ok(cx.string(serde_json::to_string(&(
                         false,
                         &"error deserializing server_dh_publics",
                     ))
                     .unwrap()))
                 }
             };
         match client::fill_rpool_secp256k1(client_dh_secrets, &server_dh_publics, &paillier_pk) {
             Ok(v) => v,
             Err(_) => return Ok(cx.string(serde_json::to_string(&(false, &"error filling rpool")).unwrap())),
         };
     } else if curve == common::Curve::Secp256r1 {
         let client_dh_secrets: Vec<Secp256r1Scalar> =
         match serde_json::from_str(&client_dh_secrets_str) {
             Ok(v) => v,
             Err(_) => {
                 return Ok(cx.string(serde_json::to_string(&(false, &"error deserializing client_dh_secrets"))
                     .unwrap()))
             }
         };
         let server_dh_publics: Vec<Secp256r1Point> =
             match serde_json::from_str(&server_dh_publics_str) {
                 Ok(v) => v,
                 Err(_) => {
                     return Ok(cx.string(serde_json::to_string(&(
                         false,
                         &"error deserializing server_dh_publics",
                     ))
                     .unwrap()))
                 }
             };
         match client::fill_rpool_secp256r1(client_dh_secrets, &server_dh_publics, &paillier_pk) {
             Ok(v) => v,
             Err(_) => return Ok(cx.string(serde_json::to_string(&(false, &"error filling rpool")).unwrap())),
         };
     } else {
         return Ok(cx.string(serde_json::to_string(&(false, &"error: invalid curve")).unwrap()));
     }
     Ok(cx.string(serde_json::to_string(&(&true, &"rpool filled successfully")).unwrap()))
 }
 
 /// Get current size of pool of r-values.
 /// Input: curve: Secp256k1 or Secp256r1
 /// Output: size of pool
 fn get_rpool_size(mut cx: FunctionContext) ->  JsResult<JsString> {
     let curve = cx.argument::<JsString>(0)?.value();
     let curve = match curve.as_str() {
         "Secp256k1" => common::Curve::Secp256k1,
         "Secp256r1" => common::Curve::Secp256r1,
         _ => panic!("Invalid curve")
     };
     let size = match client::get_rpool_size(curve) {
         Ok(v) => v,
         Err(_) => return Ok(cx.string(serde_json::to_string(&(false, &"error: invalid curve")).unwrap())),
     };
     Ok(cx.string(serde_json::to_string(&(&true, size)).unwrap()))
 }
 
 /// Compute presignature.
 /// Input: api_childkey: API childkey struct, msg_hash: message hash, curve: Secp256k1 or Secp256r1 curve
 /// Output: presig: presignature, r: message-independent part of the signature used
 fn compute_presig(mut cx: FunctionContext) ->  JsResult<JsString> {
     let api_childkey_str =  cx.argument::<JsString>(0)?.value();
     let msg_hash_str = cx.argument::<JsString>(1)?.value();
     let curve = cx.argument::<JsString>(2)?.value();
     let curve = match curve.as_str() {
         "Secp256k1" => common::Curve::Secp256k1,
         "Secp256r1" => common::Curve::Secp256r1,
         _ => panic!("Invalid curve")
     };
     let api_childkey: client::APIchildkey = match serde_json::from_str(&api_childkey_str) {
         Ok(v) => v,
         Err(_) => {
             return Ok(cx.string(serde_json::to_string(&(false, &"error deserializing api_childkey")).unwrap()))
         }
     };
     let msg_hash = match BigInt::from_hex(&msg_hash_str) {
         Ok(v) => v,
         Err(_) => return Ok(cx.string(serde_json::to_string(&(false, &"error deserializing msg_hash")).unwrap())),
     };
     let (presig, r) = match client::compute_presig(&api_childkey, &msg_hash, curve) {
         Ok(v) => v,
         Err(_) => {
             return Ok(cx.string(serde_json::to_string(&(
                 false,
                 &"error: rpool empty, invalid r value, or invalid curve.",
             ))
             .unwrap()))
         }
     };
     // add leading zeros if necessary
     Ok(cx.string(serde_json::to_string(&(
         &true,
         &format!("{:0>1024}", presig.to_hex()),
         &format!("{:0>66}", r.to_hex()),
     ))
     .unwrap()))
 }
 
 /// Generate signature for given message hash under given secret key
 /// Input: secret_key: full secret key, msg_hash: message hash
 /// Output: (r, s): ECDSA signature
 fn sign(mut cx: FunctionContext) ->  JsResult<JsString> {
     let secret_key_str = cx.argument::<JsString>(0)?.value();
     let msg_hash_str = cx.argument::<JsString>(1)?.value();
 
     let secret_key_int = match BigInt::from_hex(&secret_key_str) {
         Ok(v) => v,
         Err(_) => {
             return Ok(cx.string(serde_json::to_string(&(false, &"error deserializing secret_key")).unwrap()))
         }
     };
     let secret_key: Secp256k1Scalar = ECScalar::from(&secret_key_int);
     let msg_hash = match BigInt::from_hex(&msg_hash_str) {
         Ok(v) => v,
         Err(_) => return Ok(cx.string(serde_json::to_string(&(false, &"error deserializing msg_hash")).unwrap())),
     };
     let (r, s) = client::sign(&secret_key, &msg_hash);
     Ok(cx.string(serde_json::to_string(&(&true, &format!("{:0>64}", r.to_hex()), &format!("{:0>64}", s.to_hex()))).unwrap()))
 }
 
 register_module!(mut m, {
     m.export_function("get_rpool_size", get_rpool_size)?;
     m.export_function("fill_rpool", fill_rpool)?;
     m.export_function("dh_init", dh_init)?;
     m.export_function("compute_presig", compute_presig)?;
     m.export_function("sign", sign)
 });
 