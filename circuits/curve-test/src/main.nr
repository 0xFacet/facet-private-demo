// Curve identification test
// Determines which embedded curve Noir uses (expected: Grumpkin)
//
// Run this circuit first to verify curve parameters before implementing ECDH

use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, fixed_base_scalar_mul};

fn main() -> pub (Field, Field, bool) {
    // Compute G * 1 to get the generator point
    let one = EmbeddedCurveScalar { lo: 1, hi: 0 };
    let g = fixed_base_scalar_mul(one);

    // Return generator coordinates and infinity flag
    // Expected for Grumpkin:
    // x = 1
    // y = 17631683881184975370165255887551781615748388533673675138860
    // is_infinite = false
    (g.x, g.y, g.is_infinite)
}

#[test]
fn test_generator_is_grumpkin() {
    let (x, y, is_infinite) = main();

    // Grumpkin generator has x = 1
    assert(x == 1, "Generator x should be 1 for Grumpkin");
    assert(!is_infinite, "Generator should not be infinity");

    // Verify point is on curve: y^2 = x^3 - 17 (Grumpkin equation)
    // For x = 1: y^2 = 1 - 17 = -16 mod p
    // This is a valid square root in the field
    let y_squared = y * y;
    let x_cubed_minus_17 = x * x * x - 17;
    assert(y_squared == x_cubed_minus_17, "Point should be on Grumpkin curve");
}
