// based on MIT/Apache-licensed https://github.com/KZen-networks/curv/blob/master/src/arithmetic/traits.rs

use super::BigInt;
use super::HexError;
use std::marker::Sized;

pub trait ZeroizeBN {
    fn zeroize_bn(&mut self);
}

pub trait Converter {
    fn to_vec(n: &Self) -> Vec<u8>;
    fn to_hex(&self) -> String;
    fn from_hex(n: &str) -> Result<BigInt, HexError>;
    fn from_bytes(bytes: &[u8]) -> Self;
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait Modulo {
    fn mod_pow(base: &Self, exponent: &Self, modulus: &Self) -> Self;
    fn mod_mul(a: &Self, b: &Self, modulus: &Self) -> Self;
    fn mod_sub(a: &Self, b: &Self, modulus: &Self) -> Self;
    fn mod_add(a: &Self, b: &Self, modulus: &Self) -> Self;
    fn mod_inv(a: &Self, modulus: &Self) -> Self;
}

pub trait Samplable {
    fn sample_below(upper: &Self) -> Self;
    fn sample_range(lower: &Self, upper: &Self) -> Self;
    fn strict_sample_range(lower: &Self, upper: &Self) -> Self;
    fn sample(bitsize: usize) -> Self;
    fn strict_sample(bit_size: usize) -> Self;
}

pub trait NumberTests {
    fn is_zero(_: &Self) -> bool;
    fn is_even(_: &Self) -> bool;
    fn is_negative(_: &Self) -> bool;
    fn bits(_: &Self) -> usize;
}

pub trait EGCD
where
    Self: Sized,
{
    fn egcd(a: &Self, b: &Self) -> (Self, Self, Self);
}

pub trait BitManipulation {
    fn set_bit(self: &mut Self, bit: usize, bit_val: bool);
    fn test_bit(self: &Self, bit: usize) -> bool;
}

pub trait ConvertFrom<T> {
    fn _from(_: &T) -> Self;
}
