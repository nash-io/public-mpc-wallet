pub mod serialize;
pub mod traits;

#[cfg(feature = "rust-gmp")]
pub mod big_gmp;
#[cfg(feature = "rust-gmp")]
pub type BigInt = gmp::mpz::Mpz;
#[cfg(feature = "rust-gmp")]
pub type HexError = gmp::mpz::ParseMpzError;

#[cfg(feature = "num_bigint")]
extern crate num_bigint;
#[cfg(feature = "num_bigint")]
extern crate num_integer;
#[cfg(feature = "num_bigint")]
extern crate num_traits;
#[cfg(feature = "num-bigint")]
pub type BigInt = num_bigint::BigInt;
#[cfg(feature = "num-bigint")]
pub type HexError = num_bigint::ParseBigIntError;
#[cfg(feature = "num-bigint")]
pub mod big_num;
#[cfg(feature = "num-bigint")]
mod big_num_gcd;
