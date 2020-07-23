// copied from MIT/Apache-licensed https://github.com/RustCrypto/RSA/blob/7654e6094b00f5e180bed2343a3fc47e45832b5e/src/math.rs
// because num-bigint currently does not implement modular inverse and extended euclid
// see https://github.com/rust-num/num-bigint/issues/60

use std::borrow::Cow;

use num_bigint::Sign::Plus;
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::{One, Signed, Zero};

/// Generic trait to implement modular inverse
pub trait ModInverse<R: Sized>: Sized {
    /// Function to calculate the [modular multiplicative
    /// inverse](https://en.wikipedia.org/wiki/Modular_multiplicative_inverse) of an integer *a* modulo *m*.
    ///
    /// Returns the modular inverse of `self`.
    /// If none exists it returns `None`.
    fn mod_inverse(self, m: R) -> Option<Self>;
}

impl<'a> ModInverse<&'a BigUint> for BigUint {
    fn mod_inverse(self, m: &'a BigUint) -> Option<BigUint> {
        match mod_inverse(
            Cow::Owned(BigInt::from_biguint(Plus, self)),
            &BigInt::from_biguint(Plus, m.clone()),
        ) {
            Some(res) => res.to_biguint(),
            None => None,
        }
    }
}

impl ModInverse<BigUint> for BigUint {
    fn mod_inverse(self, m: BigUint) -> Option<BigUint> {
        match mod_inverse(
            Cow::Owned(BigInt::from_biguint(Plus, self)),
            &BigInt::from_biguint(Plus, m),
        ) {
            Some(res) => res.to_biguint(),
            None => None,
        }
    }
}

impl<'a> ModInverse<&'a BigInt> for BigInt {
    fn mod_inverse(self, m: &'a BigInt) -> Option<BigInt> {
        mod_inverse(Cow::Owned(self), m)
    }
}

impl ModInverse<BigInt> for BigInt {
    fn mod_inverse(self, m: BigInt) -> Option<BigInt> {
        mod_inverse(Cow::Owned(self), &m)
    }
}

/// Calculate the modular inverse of `a`.
/// Implemenation is based on the naive version from wikipedia.
#[inline]
fn mod_inverse(g: Cow<BigInt>, n: &BigInt) -> Option<BigInt> {
    assert!(g.as_ref() != n, "g must not be equal to n");
    assert!(!n.is_negative(), "negative modulus not supported");

    let n = n.abs();
    let g = if g.is_negative() {
        g.mod_floor(&n).to_biguint().unwrap()
    } else {
        g.to_biguint().unwrap()
    };

    let (d, x, _) = extended_gcd(&g, &n.to_biguint().unwrap());

    if !d.is_one() {
        return None;
    }

    if x.is_negative() {
        Some(x + n)
    } else {
        Some(x)
    }
}

/// Calculates the extended eucledian algorithm.
/// See https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm for details.
/// The returned values are
/// - greatest common divisor (1)
/// - Bezout coefficients (2)
pub fn extended_gcd(a: &BigUint, b: &BigUint) -> (BigInt, BigInt, BigInt) {
    let mut a = BigInt::from_biguint(Plus, a.clone());
    let mut b = BigInt::from_biguint(Plus, b.clone());

    let mut ua = BigInt::one();
    let mut va = BigInt::zero();

    let mut ub = BigInt::zero();
    let mut vb = BigInt::one();

    let mut q;
    let mut tmp;
    let mut r;

    while !b.is_zero() {
        q = &a / &b;
        r = &a % &b;

        a = b;
        b = r;

        tmp = ua;
        ua = ub.clone();
        ub = tmp - &q * &ub;

        tmp = va;
        va = vb.clone();
        vb = tmp - &q * &vb;
    }

    (a, ua, va)
}

#[cfg(test)]
mod tests {
    use super::{extended_gcd, BigInt, BigUint, ModInverse};
    use crate::num_integer::Integer;
    use crate::num_traits::One;
    use crate::traits::Samplable;
    use num_bigint::Sign::Plus;
    use num_traits::FromPrimitive;

    #[test]
    fn test_mod_inverse() {
        let tests = [
            ["1234567", "458948883992"],
	    ["239487239847", "2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919"],
	    ["-10", "13"],
            ["-6193420858199668535", "2881"],
        ];

        for test in &tests {
            let element = BigInt::parse_bytes(test[0].as_bytes(), 10).unwrap();
            let modulus = BigInt::parse_bytes(test[1].as_bytes(), 10).unwrap();

            println!("{} modinv {}", element, modulus);
            let inverse = element.clone().mod_inverse(&modulus).unwrap();
            println!("inverse: {}", &inverse);
            let cmp = (inverse * &element).mod_floor(&modulus);

            assert_eq!(
                cmp,
                BigInt::one(),
                "mod_inverse({}, {}) * {} % {} = {}, not 1",
                &element,
                &modulus,
                &element,
                &modulus,
                &cmp
            );
        }

        // exhaustive tests for small numbers
        for n in 2..100 {
            let modulus = BigInt::from_u64(n).unwrap();
            for x in 1..n {
                for sign in vec![1i64, -1i64] {
                    let element = BigInt::from_i64(sign * x as i64).unwrap();
                    let gcd = element.gcd(&modulus);

                    if !gcd.is_one() {
                        continue;
                    }

                    let inverse = element.clone().mod_inverse(&modulus).unwrap();
                    let cmp = (&inverse * &element).mod_floor(&modulus);
                    println!("inverse: {}", &inverse);
                    assert_eq!(
                        cmp,
                        BigInt::one(),
                        "mod_inverse({}, {}) * {} % {} = {}, not 1",
                        &element,
                        &modulus,
                        &element,
                        &modulus,
                        &cmp
                    );
                }
            }
        }
    }

    #[test]
    fn test_extended_gcd_example() {
        // simple example for wikipedia
        let a = BigUint::from_u32(240).unwrap();
        let b = BigUint::from_u32(46).unwrap();
        let (q, s_k, t_k) = extended_gcd(&a, &b);

        assert_eq!(q, BigInt::from_i32(2).unwrap());
        assert_eq!(s_k, BigInt::from_i32(-9).unwrap());
        assert_eq!(t_k, BigInt::from_i32(47).unwrap());
    }

    #[test]
    fn test_extended_gcd_assumptions() {
        for i in 1..100 {
            let a = BigInt::sample(i * 128).to_biguint().unwrap();
            let b = BigInt::sample(i * 128).to_biguint().unwrap();
            let (q, s_k, t_k) = extended_gcd(&a, &b);

            let lhs = BigInt::from_biguint(Plus, a) * &s_k;
            let rhs = BigInt::from_biguint(Plus, b) * &t_k;
            assert_eq!(q, lhs + &rhs);
        }
    }
}
