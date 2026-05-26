//use core::ops::Shl;
use std::ops::Add;
use std::ops::Shl;
use std::str::FromStr;

use num_bigint::BigInt;
use num_bigint::Sign;
use num_integer::Integer;
use num_traits::Num;
use num_traits::One;
use num_traits::Signed;
use num_traits::Zero;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Curve {
    pub p: BigInt,       // the order of the underlying field
    pub n: BigInt,       // the order of the base point
    pub b: BigInt,       // the constant of the curve equation
    pub gx: BigInt,      // x coordinate of the base point
    pub gy: BigInt,      // y coordinate of the base point
    pub bit_size: usize, // the size of the underlying field
    pub name: String,    // the canonical name of the curve
}

impl Curve {
    pub fn n_minus2(&self) -> BigInt {
        &self.n - BigInt::from(2)
    }

    pub fn params(&self) -> &Self {
        self
    }

    // CurveParams operates, internally, on Jacobian coordinates. For a given
    // (x, y) position on the curve, the Jacobian coordinates are (x1, y1, z1)
    // where x = x1/z1² and y = y1/z1³. The greatest speedups come when the whole
    // calculation can be performed within the transform (as in ScalarMult and
    // ScalarBaseMult). But even for Add and Double, it's faster to apply and
    // reverse the transform than to operate in affine coordinates.

    // polynomial returns x³ - 3x + b reduced mod p (non-negative).
    pub fn polynomial(&self, x: &BigInt) -> BigInt {
        let x3: BigInt = x * x * x; // x^3
        let three_x: BigInt = x.shl(1) + x; // 3x

        let result: BigInt = x3 - three_x + &self.b;
        // F-06: use mod_floor so the result is always in [0, p), even when the
        // unreduced value is negative (which happens for adversarially supplied
        // small x). `%` follows the sign of the dividend in BigInt arithmetic.
        result.mod_floor(&self.p)
    }

    pub fn is_on_curve(&self, x: &BigInt, y: &BigInt) -> bool {
        if !matches_specific_curve(self).is_some() {
            return false; // return matches_specific_curve(self).unwrap().is_on_curve(x, y);
        }

        if x < &BigInt::zero() || x >= &self.p || y < &BigInt::zero() || y >= &self.p {
            // if x < &0 || x >= &self.p || y < &0 || y >= &self.p {
            return false;
        }

        let y2 = (y * y).mod_floor(&self.p);

        self.polynomial(x) == y2
    }

    pub fn z_for_affine(x: &BigInt, y: &BigInt) -> BigInt {
        if x.is_zero() && y.is_zero() { BigInt::zero() } else { BigInt::from(1) }
    }

    pub fn affine_from_jacobian(&self, x: &BigInt, y: &BigInt, z: &BigInt) -> (BigInt, BigInt) {
        if z.is_zero() {
            return (BigInt::zero(), BigInt::zero());
        }

        let z_inv = mod_inverse(&z, &self.p).unwrap(); // Assuming BigInt supports inverse
        let z_inv_sq = (&z_inv * &z_inv).mod_floor(&self.p);

        let x_out = (x * &z_inv_sq).mod_floor(&self.p);
        let z_inv_sq_mul = (z_inv_sq * z_inv).mod_floor(&self.p);
        let y_out = (y * z_inv_sq_mul).mod_floor(&self.p);

        (x_out, y_out)
    }

    pub fn add(&self, x1: &BigInt, y1: &BigInt, x2: &BigInt, y2: &BigInt) -> (BigInt, BigInt) {
        // F-06: fail-closed instead of panicking on attacker-influenced input.
        if matches_specific_curve(self).is_none() {
            return (BigInt::zero(), BigInt::zero());
        }
        if !is_valid_point(self, x1, y1) || !is_valid_point(self, x2, y2) {
            return (BigInt::zero(), BigInt::zero());
        }

        let z1 = Self::z_for_affine(x1, y1);
        let z2 = Self::z_for_affine(x2, y2);

        let point = self.add_jacobian(x1, y1, &z1, x2, y2, &z2);
        self.affine_from_jacobian(&point.0, &point.1, &point.2)
    }

    pub fn add_jacobian(
        &self,
        x1: &BigInt,
        y1: &BigInt,
        z1: &BigInt,
        x2: &BigInt,
        y2: &BigInt,
        z2: &BigInt,
    ) -> (BigInt, BigInt, BigInt) {
        // F-15.5: x3/y3/z3 were zero-initialised then unconditionally
        // overwritten — dead stores. Bind on first computed value below.
        if z1.is_zero() {
            return (x2.clone(), y2.clone(), z2.clone());
        }
        if z2.is_zero() {
            return (x1.clone(), y1.clone(), z1.clone());
        }

        let z1z1 = (z1 * z1).mod_floor(&self.p);
        let z2z2 = (z2 * z2).mod_floor(&self.p);

        let u1 = (x1 * &z2z2).mod_floor(&self.p);
        let u2 = (x2 * &z1z1).mod_floor(&self.p);
        let mut h = u2 - &u1;

        if h.is_negative() {
            h += &self.p;
        }

        let x_equal = h.is_zero();
        let i = &h << 1;
        let i_sq = &i * &i;
        let j = &h * &i_sq;

        let mut s1 = (y1 * z2 * &z2z2).mod_floor(&self.p);
        let s2 = (y2 * z1 * &z1z1).mod_floor(&self.p);
        let mut r = s2 - &s1;

        if r.is_negative() {
            r += &self.p;
        }

        let y_equal = r.is_zero();
        if x_equal && y_equal {
            return self.double_jacobian(x1, y1, z1);
        }

        r <<= 1;
        let v: BigInt = u1 * &i_sq;

        let x3_tmp: BigInt = &r * &r - &j - &v - &v;
        let x3 = x3_tmp.mod_floor(&self.p); // x3 = r^2 - j - 2v

        s1 = s1 * j << 1; // s1 = 2 * y1 * z2 * z2z2
        let y3_tmp: BigInt = r * (v - &x3) - s1;
        let y3 = y3_tmp.mod_floor(&self.p);

        let z3_sum: BigInt = z1 + z2;
        let z3_tmp: BigInt = h * (&z3_sum * &z3_sum - &z1z1 - &z2z2);
        let z3 = z3_tmp.mod_floor(&self.p); // z3 = h*( (z1 + z2)^2 - z1^2 - z2^2)

        (x3, y3, z3)
    }

    pub fn double_jacobian(&self, x: &BigInt, y: &BigInt, z: &BigInt) -> (BigInt, BigInt, BigInt) {
        let delta = (z * z).mod_floor(&self.p);
        let gamma = (y * y).mod_floor(&self.p);

        let mut alpha = x - &delta;
        if alpha.is_negative() {
            alpha += &self.p;
        }

        let alpha2 = (x + &delta).mod_floor(&self.p);
        alpha = alpha * &alpha2;
        let alpha_lsh = &alpha << 1; // Alpha << 1 represents 2α
        alpha = &alpha + &alpha_lsh;

        let beta = x * &gamma;

        let mut x3: BigInt = &alpha * &alpha;
        let beta8_tmp: BigInt = &beta << 3;
        let beta8 = beta8_tmp.mod_floor(&self.p); // (beta * 2^3) % p
        x3 = x3 - &beta8;
        if x3.is_negative() {
            x3 += &self.p;
        }
        x3 = x3.mod_floor(&self.p);

        let mut z3 = y + z;
        z3 = &z3 * &z3 - &gamma;
        if z3.is_negative() {
            z3 += &self.p;
        }
        z3 = z3 - &delta;
        if z3.is_negative() {
            z3 += &self.p;
        }
        z3 = z3.mod_floor(&self.p);

        let mut beta_double: BigInt = beta << 2;
        beta_double = beta_double - &x3;
        if beta_double.is_negative() {
            beta_double += &self.p;
        }

        let mut y3 = alpha * beta_double;

        let gamma_sq: BigInt = &gamma * &gamma;
        let gamma_lsh_tmp: BigInt = gamma_sq << 3;
        let gamma_lsh = gamma_lsh_tmp.mod_floor(&self.p);

        y3 = y3 - &gamma_lsh;
        if y3.is_negative() {
            y3 += &self.p;
        }
        y3 = y3.mod_floor(&self.p);

        (x3, y3, z3)
    }

    pub fn scalar_mult(&self, bx: &BigInt, by: &BigInt, k: &[u8]) -> (BigInt, BigInt) {
        // F-06: fail-closed instead of panicking on attacker-influenced input.
        if matches_specific_curve(self).is_none() {
            return (BigInt::zero(), BigInt::zero());
        }
        if !is_valid_point(self, bx, by) {
            return (BigInt::zero(), BigInt::zero());
        }

        let bz = BigInt::from(1);
        let mut x = BigInt::zero();
        let mut y = BigInt::zero();
        let mut z = BigInt::zero();

        for &byte in k {
            let mut byte = byte;
            for _ in 0..8 {
                (x, y, z) = self.double_jacobian(&x, &y, &z);
                if byte & 0x80 != 0 {
                    (x, y, z) = self.add_jacobian(bx, by, &bz, &x, &y, &z);
                }
                byte <<= 1;
            }
        }
        let res = self.affine_from_jacobian(&x, &y, &z);

        res //self.affine_from_jacobian(&x, &y, &z)
    }

    pub fn scalar_base_mult(&self, k: &[u8]) -> (BigInt, BigInt) {
        // F-06: fail-closed instead of panicking on unknown curve.
        if matches_specific_curve(self).is_none() {
            return (BigInt::zero(), BigInt::zero());
        }
        self.scalar_mult(&self.gx, &self.gy, k)
    }

    /*pub fn point_from_affine(&self, x: &BigUint, y: &BigUint) -> Option<Point> {
        // Reject values that cannot be encoded correctly.
        if x.is_negative() || y.is_negative() {
            return None; // Err("negative coordinate".into());
        }

        if x.bits() > self.bit_size || y.bits() > self.bit_size {
            return None ; // Err("overflowing coordinate".into());
        }

        // encodes the coordinates and lets SetBytes to reject invalid points.
        let byte_len = (&self.bit_size + 7) / 8;
        let mut buf = vec![0u8; 1 + 2 * byte_len];
        buf[0] = 4; // non-compessed point
        buf[1..1 + byte_len].copy_from_slice(&x.to_bytes_le());

        buf[1 + byte_len..1 + 2 * byte_len].copy_from_slice(&y.to_bytes_le());
        Some(self.new_point().set_bytes(&buf))
    }*/
}

// The function checks if the parameters match one of the specific curves
pub fn matches_specific_curve(params: &Curve) -> Option<Curve> {
    for curve in &[p224, p256, p384, p521] {
        //let current_params = (curve)().params();
        if params == (curve)().params() {
            // if params == &(curve)().params() {
            return Some(params.clone());
        }
    }
    None
} /*


const MASK: [u8; 8] = [0xff, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f];

//pub fn generate_key<R: Read>(curve: &Curve, rand: &mut R) -> io::Result<(Vec<u8>, BigInt, BigInt)> {
//let n = curve.params().n.clone();
//let bit_size = n.bits();
//let byte_len = (bit_size + 7) / 8;
//let mut priv_key = vec![0u8; byte_len];

//let mut x = BigInt::zero();
//let mut y = BigInt::zero();

//while x.is_zero() && y.is_zero() {
//rand.read_exact(&mut priv_key)?;

//priv_key[0] &= MASK[(bit_size % 8) as usize];

//priv_key[1] ^= 0x42;

//if BigInt::from_bytes_be(num::BigUint::from_bytes_be(&priv_key)) >= n {
//continue;
//}

//let (new_x, new_y) = curve.scalar_base_mult(&priv_key);
//x = new_x;
//y = new_y;
//}
//Ok((priv_key, x, y))
//}

pub fn marshal(curve: &Curve, x: &BigInt, y: &BigInt) -> Vec<u8> {
panic_if_not_on_curve(curve, x, y);

let byte_len = (curve.params().bit_size + 7) / 8;
let mut ret = vec![0; 1 + 2 * byte_len];

ret[0] = 4; // uncompressed point
ret[1..1 + byte_len].copy_from_slice(&x.to_bytes_be());
ret[1 + byte_len..1 + 2 * byte_len].copy_from_slice(&y.to_bytes_be());

ret
}

pub fn marshal_compressed(curve: &dyn Curve, x: &BigInt, y: &BigInt) -> Vec<u8> {
panic_if_not_on_curve(curve, x, y);
let byte_len = (curve.params().bit_size + 7) / 8;
let mut compressed = vec![0; 1 + byte_len];
compressed[0] = if y.is_odd() { 3 } else { 2 };
compressed[1..].copy_from_slice(&x.to_bytes_be());
compressed
}*/

pub fn unmarshal(curve: &Curve, data: &[u8]) -> (BigInt, BigInt) {
    let byte_len = (&curve.params().bit_size + 7) / 8;
    if data.len() != 1 + 2 * byte_len {
        return (BigInt::zero(), BigInt::zero());
    }
    if data[0] != 4 {
        // uncompressed form
        return (BigInt::zero(), BigInt::zero());
    }
    let p = curve.params().p.clone();
    let x = BigInt::from_bytes_be(Sign::Plus, &data[1..1 + byte_len]);
    let y = BigInt::from_bytes_be(Sign::Plus, &data[1 + byte_len..]);
    if x >= p.clone() || y >= p {
        return (BigInt::zero(), BigInt::zero());
    }
    if !curve.is_on_curve(&x, &y) {
        return (BigInt::zero(), BigInt::zero());
    }
    (x, y)
}

//static INIT_ONCE: Once = ONCE_INIT;
/*
pub fn unmarshal_compressed(curve: &dyn Curve, data: &[u8]) -> (BigInt, BigInt) {
    if let Some(c) = curve.downcast_ref::<dyn Unmarshaler>() {
        return c.unmarshal_compressed(data);
    }

    let byte_len = (curve.params().bit_size + 7) / 8;
    if data.len() != 1 + byte_len {
        return (BigInt::zero(), BigInt::zero());
    }
    if data[0] != 2 && data[0] != 3 { // compressed form
        return (BigInt::zero(), BigInt::zero());
    }
    let p = curve.params().p.clone();
    let x = BigInt::from_bytes_be(&data[1..]);
    if x >= p {
        return (BigInt::zero(), BigInt::zero());
    }
    // y² = x³ - 3x + b
    let mut y = curve.params().polynomial(&x);
    y = y.mod_sqrt(&p);
    if y.is_zero() {
        return (BigInt::zero(), BigInt::zero());
    }
    if (y.is_odd() as u8) != (data[0] & 1) {
        y = -y % &p;
    }
    if !curve.is_on_curve(&x, &y) {
        return (BigInt::zero(), BigInt::zero());
    }
    return (x, y);
}
*/
pub fn panic_if_not_on_curve(curve: &Curve, x: &BigInt, y: &BigInt) {
    if x.is_zero() && y.is_zero() {
        return;
    }

    if !curve.is_on_curve(x, y) {
        panic!("crypto/elliptic: attempted operation on invalid point");
    }
}

// F-06: non-panicking variant. Treats the point at infinity (0,0) as valid
// because the internal Jacobian arithmetic uses it as a sentinel.
pub fn is_valid_point(curve: &Curve, x: &BigInt, y: &BigInt) -> bool {
    if x.is_zero() && y.is_zero() {
        return true;
    }
    curve.is_on_curve(x, y)
}

pub fn p224() -> Curve {
    // -> &'static dyn Curve {

    Curve {
        name: String::from("P-224"),
        bit_size: 224,
        p: BigInt::from_str("26959946667150639794667015087019630673557916260026308143510066298881")
            .unwrap(),
        n: BigInt::from_str("26959946667150639794667015087019625940457807714424391721682722368061")
            .unwrap(),
        b: BigInt::from_str_radix("b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4", 16)
            .unwrap(),
        gx: BigInt::from_str_radix("b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21", 16)
            .unwrap(),
        gy: BigInt::from_str_radix("bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34", 16)
            .unwrap(),
    }
}

pub fn p256() -> Curve {
    Curve {
        name: String::from("P-256"),
        bit_size: 256,
        p: BigInt::from_str(
            "115792089210356248762697446949407573530086143415290314195533631308867097853951",
        )
        .unwrap(),
        n: BigInt::from_str(
            "115792089210356248762697446949407573529996955224135760342422259061068512044369",
        )
        .unwrap(),
        b: BigInt::from_str_radix(
            "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
            16,
        )
        .unwrap(),
        gx: BigInt::from_str_radix(
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            16,
        )
        .unwrap(),
        gy: BigInt::from_str_radix(
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
            16,
        )
        .unwrap(),
    }
}

pub fn p384() -> Curve {
    Curve{
        name: String::from("P-384"),
        bit_size: 384,
        p: BigInt::from_str("39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319").unwrap(),
        n: BigInt::from_str("39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643").unwrap(),
        b: BigInt::from_str_radix("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16).unwrap(),
        gx: BigInt::from_str_radix("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", 16).unwrap(),
        gy: BigInt::from_str_radix("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16).unwrap(),
    }
}

pub fn p521() -> Curve {
    Curve{
        name: String::from("P-521"),
        bit_size: 521,
        p: BigInt::from_str("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151").unwrap(),
        n: BigInt::from_str("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151").unwrap(),
        b: BigInt::from_str_radix("0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", 16).unwrap(),
        gx: BigInt::from_str_radix("00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 16).unwrap(),
        gy: BigInt::from_str_radix("011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", 16).unwrap(),
    }
}

fn hash_to_int(hash: &[u8], c: &Curve) -> BigInt {
    let order_bits = c.params().n.bits() as usize; // num-bigint 0.4 returns u64
    let order_bytes = (order_bits + 7) / 8;
    let mut hash = hash.to_vec();

    if hash.len() > order_bytes {
        hash.truncate(order_bytes);
    }

    let mut ret = BigInt::from_bytes_be(num_bigint::Sign::Plus, &hash);
    let excess = hash.len() * 8 - order_bits;
    if excess > 0 {
        ret >>= excess; // Move to the right
    }
    ret
}

#[derive(Debug, PartialEq)]
pub struct PublicKey {
    pub curve: Curve,
    pub x: BigInt,
    pub y: BigInt,
}

// F-06: validate that the public key is a non-infinity point on the declared
// curve. Without this, an attacker-controlled CA can present an off-curve point
// whose `verify` operation falls into the larger ambient group where ECDSA
// signatures can be forged.
fn validate_public_key(pub_key: &PublicKey) -> bool {
    if matches_specific_curve(&pub_key.curve).is_none() {
        return false;
    }
    if pub_key.x.is_zero() && pub_key.y.is_zero() {
        return false; // point at infinity
    }
    if pub_key.x < BigInt::zero()
        || pub_key.x >= pub_key.curve.p
        || pub_key.y < BigInt::zero()
        || pub_key.y >= pub_key.curve.p
    {
        return false;
    }
    pub_key.curve.is_on_curve(&pub_key.x, &pub_key.y)
}

pub fn verify(pub_key: &PublicKey, hash: &[u8], r: &BigInt, s: &BigInt) -> bool {
    if !validate_public_key(pub_key) {
        return false;
    }
    if r <= &BigInt::from(0) || s <= &BigInt::from(0) {
        return false;
    }

    verify_nistec(pub_key, &hash, &r, &s)
}

pub fn verify_nistec(pub_key: &PublicKey, hash: &[u8], r: &BigInt, s: &BigInt) -> bool {
    let c = &pub_key.curve; // Get the curve
    let n = &c.params().n; // Get the curve's order

    if r.is_zero() || s.is_zero() {
        return false;
    }

    if r >= n || s >= n {
        return false;
    }

    // SEC 1, Version 2.0, Section 4.1.4
    let e = hash_to_int(hash, c);
    let w = mod_inverse(s, n).unwrap(); // Finds the inverse value of s modulo N
    //let w = s.modpow(&c.n_minus2(), &c.n);//s^c.n_minus2()%c.n

    let mut u1 = e * &w;
    u1 = u1 % n; // u1 = e  w mod N
    let mut u2 = r * w;
    u2 = u2 % n; // u2 = r  w mod N

    let (x1, y1) = c.scalar_base_mult(&u1.to_bytes_be().1);
    let (x2, y2) = c.scalar_mult(&pub_key.x, &pub_key.y, &u2.to_bytes_be().1);
    let (x, y) = c.add(&x1, &y1, &x2, &y2); // Adding up the points

    if x.is_zero() && y.is_zero() {
        // Checking if a point is infinity
        return false;
    }

    let x_final = x.modpow(&BigInt::one(), n); // x = x mod N
    x_final == *r // Compare x with r
}

// F-06: mod_inverse is restricted to a **prime** modulus and is called only
// with the curve order `n` (always prime for our supported curves), so the
// Fermat's-little-theorem shortcut g^(n-2) mod n produces the right result.
// Marked `pub(crate)` so a future caller can't accidentally pass a composite
// modulus and silently get a wrong answer (F-06 sub-finding 6.3).
pub(crate) fn mod_inverse(g: &BigInt, n: &BigInt) -> Option<BigInt> {
    let mut n = n.clone();
    let mut g = g.clone();

    if n.sign() == Sign::Minus {
        n = n.abs();
    }
    if g.sign() == Sign::Minus {
        g = g.add(&n);
    }

    let exponent = &n - BigInt::from(2);
    Some(g.modpow(&exponent, &n))
}

// F-06: gcd (extended-Euclidean) was unused and contained a bitwise-AND bug
// (`&q & x1` instead of multiplication). The audit's remediation: "Delete
// dead code (gcd, mod_inverse if unused)" — `gcd` is removed.
