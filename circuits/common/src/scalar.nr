// Scalar operations for embedded curve (Grumpkin)
//
// Grumpkin scalars require 128-bit limb split (lo, hi) because
// the group order exceeds the BN254 scalar field.

use std::embedded_curve_ops::EmbeddedCurveScalar;

/// Convert field element to scalar with proper 128-bit limb split
/// Required because Grumpkin group order > BN254 scalar field
pub fn field_to_scalar(x: Field) -> EmbeddedCurveScalar {
    let bits: [u1; 254] = x.to_le_bits();

    let mut lo: Field = 0;
    let mut base: Field = 1;
    for i in 0..128 {
        lo += (bits[i] as Field) * base;
        base *= 2;
    }

    let mut hi: Field = 0;
    base = 1;
    for i in 128..254 {
        hi += (bits[i] as Field) * base;
        base *= 2;
    }

    EmbeddedCurveScalar { lo, hi }
}

/// Ensure scalar is non-zero to avoid edge cases in ECDH
/// Returns 1 if x == 0, otherwise returns x
/// This is a conditional substitution that avoids field wrap issues
pub fn ensure_nonzero(x: Field) -> Field {
    if x == 0 { 1 } else { x }
}

/// Assert value fits in 160 bits (valid Ethereum address)
/// Prevents overflow attacks when converting Field to address
pub fn assert_is_address(x: Field) {
    let bits: [u1; 254] = x.to_le_bits();
    for i in 160..254 {
        assert(bits[i] == 0, "value exceeds 160 bits");
    }
}

/// Assert value fits in u128 (valid amount)
/// Prevents overflow in value conservation
pub fn assert_is_u128(x: Field) {
    let bits: [u1; 254] = x.to_le_bits();
    for i in 128..254 {
        assert(bits[i] == 0, "value exceeds 128 bits");
    }
}

#[test]
fn test_field_to_scalar_small() {
    let x: Field = 12345;
    let s = field_to_scalar(x);
    // For small values, hi should be 0
    assert(s.hi == 0, "hi should be 0 for small values");
    assert(s.lo == x, "lo should equal original for small values");
}

#[test]
fn test_field_to_scalar_large() {
    // Value larger than 2^128
    let large: Field = 0x100000000000000000000000000000001; // 2^128 + 1
    let s = field_to_scalar(large);
    // lo = 1, hi = 1
    assert(s.lo == 1, "lo should be 1");
    assert(s.hi == 1, "hi should be 1");
}

#[test]
fn test_ensure_nonzero() {
    assert(ensure_nonzero(0) == 1, "0 should become 1");
    assert(ensure_nonzero(5) == 5, "non-zero should stay unchanged");
    assert(ensure_nonzero(1) == 1, "1 should stay 1");
}

#[test]
fn test_assert_is_address_valid() {
    // Valid 160-bit address
    let addr: Field = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
    assert_is_address(addr);
}

#[test(should_fail_with = "value exceeds 160 bits")]
fn test_assert_is_address_invalid() {
    // Value with bits above 160
    let too_large: Field = 0x10000000000000000000000000000000000000000; // 2^160
    assert_is_address(too_large);
}
