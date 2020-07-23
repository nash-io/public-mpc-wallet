/*
    num-bigint support
*/

use super::big_num_gcd::{extended_gcd, ModInverse};
use super::traits::{
    BitManipulation, ConvertFrom, Converter, Modulo, NumberTests, Samplable, ZeroizeBN, EGCD,
};
use super::BigInt;
use getrandom::getrandom;
use num_bigint::ParseBigIntError;
use num_bigint::Sign::Plus;
use num_integer::Integer;
use num_traits::{Num, Pow, ToPrimitive, Zero};
use std::convert::TryInto;
use std::ops::BitAnd;
use std::ptr;
use std::sync::atomic;

impl ZeroizeBN for BigInt {
    fn zeroize_bn(&mut self) {
        unsafe { ptr::write_volatile(self, BigInt::zero()) };
        atomic::fence(atomic::Ordering::SeqCst);
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl Converter for BigInt {
    fn to_vec(value: &BigInt) -> Vec<u8> {
        value.to_bytes_be().1
    }

    fn to_hex(&self) -> String {
        self.to_str_radix(16u8.into())
    }

    fn from_hex(value: &str) -> Result<BigInt, ParseBigIntError> {
        BigInt::from_str_radix(value, 16u8.into())
    }

    fn from_bytes(bytes: &[u8]) -> BigInt {
        BigInt::from_bytes_be(Plus, bytes)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes_be().1
    }
}

impl Modulo for BigInt {
    fn mod_pow(base: &Self, exponent: &Self, modulus: &Self) -> Self {
        base.modpow(exponent, modulus)
    }

    fn mod_mul(a: &Self, b: &Self, modulus: &Self) -> Self {
        (a.mod_floor(modulus) * b.mod_floor(modulus)).mod_floor(modulus)
    }

    fn mod_sub(a: &Self, b: &Self, modulus: &Self) -> Self {
        let a_m = a.mod_floor(modulus);
        let b_m = b.mod_floor(modulus);
        let sub_op = a_m - b_m + modulus;
        sub_op.mod_floor(modulus)
    }

    fn mod_add(a: &Self, b: &Self, modulus: &Self) -> Self {
        (a.mod_floor(modulus) + b.mod_floor(modulus)).mod_floor(modulus)
    }

    fn mod_inv(a: &Self, modulus: &Self) -> Self {
        a.clone().mod_inverse(modulus).unwrap()
    }
}

impl Samplable for BigInt {
    fn sample_below(upper: &Self) -> Self {
        assert!(*upper > BigInt::zero());

        let bits = NumberTests::bits(upper);
        loop {
            let n = Self::sample(bits);
            if n < *upper {
                return n;
            }
        }
    }

    fn sample_range(lower: &Self, upper: &Self) -> Self {
        lower + Self::sample_below(&(upper - lower))
    }

    fn strict_sample_range(lower: &Self, upper: &Self) -> Self {
        Self::sample_range(lower, upper)
    }

    fn sample(bit_size: usize) -> Self {
        let bytes = (bit_size - 1) / 8 + 1;
        let mut buf: Vec<u8> = vec![0; bytes];
        getrandom(&mut buf).unwrap();
        Self::from_bytes(&*buf) >> (bytes * 8 - bit_size)
    }

    fn strict_sample(bit_size: usize) -> Self {
        loop {
            let n = Self::sample(bit_size);
            if NumberTests::bits(&n) == bit_size {
                return n;
            }
        }
    }
}

impl NumberTests for BigInt {
    fn is_zero(me: &Self) -> bool {
        me.is_zero()
    }
    fn is_even(me: &Self) -> bool {
        me.is_even()
    }
    fn is_negative(me: &Self) -> bool {
        *me < BigInt::zero()
    }
    fn bits(me: &Self) -> usize {
        me.bits().try_into().unwrap()
    }
}

impl EGCD for BigInt {
    fn egcd(a: &Self, b: &Self) -> (Self, Self, Self) {
        extended_gcd(&a.to_biguint().unwrap(), &b.to_biguint().unwrap())
    }
}

impl BitManipulation for BigInt {
    fn set_bit(self: &mut Self, bit: usize, bit_val: bool) {
        if bit_val {
            *self = self.clone() | BigInt::from(2).pow(bit as u32);
        } else {
            let all_bits = BigInt::from(2).pow(self.bits() as u32) - 1;
            let specific_bit = BigInt::from(2).pow(bit as u32);
            *self = self.clone() & (all_bits - specific_bit);
        }
    }

    fn test_bit(self: &Self, bit: usize) -> bool {
        self.bitand(BigInt::from(1 << bit)) > BigInt::zero()
    }
}

impl ConvertFrom<BigInt> for u64 {
    fn _from(x: &BigInt) -> u64 {
        x.to_u64().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::{Converter, Modulo, NumberTests, Samplable};
    use num_bigint::BigInt;

    use std::cmp;

    #[test]
    #[should_panic]
    fn sample_below_zero_test() {
        BigInt::sample_below(&BigInt::from(-1));
    }

    #[test]
    fn sample_below_test() {
        let upper_bound = BigInt::from(10);

        for _ in 1..100 {
            let r = BigInt::sample_below(&upper_bound);
            assert!(r < upper_bound);
        }
    }

    #[test]
    #[should_panic]
    fn invalid_range_test() {
        BigInt::sample_range(&BigInt::from(10), &BigInt::from(9));
    }

    #[test]
    fn sample_range_test() {
        let upper_bound = BigInt::from(10);
        let lower_bound = BigInt::from(5);
        for _ in 1..100 {
            let r = BigInt::sample_range(&lower_bound, &upper_bound);
            assert!(r < upper_bound && r >= lower_bound);
        }
    }

    #[test]
    fn strict_sample_range_test() {
        let len = 249;

        for _ in 1..100 {
            let a = BigInt::sample(len);
            let b = BigInt::sample(len);
            let lower_bound = cmp::min(a.clone(), b.clone());
            let upper_bound = cmp::max(a.clone(), b.clone());
            let r = BigInt::strict_sample_range(&lower_bound, &upper_bound);
            assert!(r < upper_bound && r >= lower_bound);
        }
    }

    #[test]
    fn strict_sample_test() {
        let len = 249;
        for _ in 1..100 {
            let a = BigInt::strict_sample(len);
            assert_eq!(NumberTests::bits(&a), len);
        }
    }

    //test mod_sub: a-b mod n where a-b >0
    #[test]
    fn test_mod_sub_modulo() {
        let a = BigInt::from(10);
        let b = BigInt::from(5);
        let modulo = BigInt::from(3);
        let res = BigInt::from(2);
        assert_eq!(res, BigInt::mod_sub(&a, &b, &modulo));
    }

    //test mod_sub: a-b mod n where a-b <0
    #[test]
    fn test_mod_sub_negative_modulo() {
        let a = BigInt::from(5);
        let b = BigInt::from(10);
        let modulo = BigInt::from(3);
        let res = BigInt::from(1);
        assert_eq!(res, BigInt::mod_sub(&a, &b, &modulo));
    }

    #[test]
    fn test_mod_mul() {
        let a = BigInt::from(4);
        let b = BigInt::from(5);
        let modulo = BigInt::from(3);
        let res = BigInt::from(2);
        assert_eq!(res, BigInt::mod_mul(&a, &b, &modulo));
    }

    #[test]
    fn test_mod_pow() {
        let a = BigInt::from(2);
        let b = BigInt::from(3);
        let modulo = BigInt::from(3);
        let res = BigInt::from(2);
        assert_eq!(res, BigInt::mod_pow(&a, &b, &modulo));
    }

    #[test]
    fn test_to_hex() {
        let b = BigInt::from(11);
        assert_eq!("b", b.to_hex());
    }

    #[test]
    fn test_from_hex() {
        let a = BigInt::from(11);
        assert_eq!(BigInt::from_hex(&a.to_hex()).unwrap(), a);
    }
}
