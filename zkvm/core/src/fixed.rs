//! Q16.16 fixed-point arithmetic for zkVM guest programs.
//!
//! All computation is integer-only (no floats in RISC-V guest).
//! Represents numbers as i32 with 16 fractional bits:
//!   value = raw / 65536 (i.e. 1.0 == 65536, 0.5 == 32768)

use core::fmt;
use core::ops::{Add, Div, Mul, Neg, Sub};

use serde::{Deserialize, Serialize};

/// Number of fractional bits.
const FRAC_BITS: i32 = 16;
/// Scale factor = 2^16 = 65536.
const SCALE: i32 = 1 << FRAC_BITS;
/// Scale as i64 for intermediate multiplication.
const SCALE_I64: i64 = SCALE as i64;

/// Q16.16 fixed-point number.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Fixed(pub i32);

impl Fixed {
    /// The zero value.
    pub const ZERO: Fixed = Fixed(0);
    /// The value 1.0.
    pub const ONE: Fixed = Fixed(SCALE);
    /// The value 0.5.
    pub const HALF: Fixed = Fixed(SCALE / 2);

    /// Create from an integer (e.g. 3 → 3.0).
    #[inline]
    pub const fn from_int(n: i32) -> Self {
        Fixed(n << FRAC_BITS)
    }

    /// Create from a raw Q16.16 representation.
    #[inline]
    pub const fn from_raw(raw: i32) -> Self {
        Fixed(raw)
    }

    /// Create from numerator/denominator (e.g. from_ratio(3, 10) → 0.3).
    #[inline]
    pub const fn from_ratio(num: i32, den: i32) -> Self {
        Fixed(((num as i64 * SCALE_I64) / den as i64) as i32)
    }

    /// Convert to i32 by truncating the fractional part.
    #[inline]
    pub const fn to_int(self) -> i32 {
        self.0 >> FRAC_BITS
    }

    /// Raw Q16.16 representation.
    #[inline]
    pub const fn raw(self) -> i32 {
        self.0
    }

    /// Approximate conversion to f64 (host-side only, for testing).
    #[cfg(feature = "std")]
    #[inline]
    pub fn to_f64(self) -> f64 {
        self.0 as f64 / SCALE as f64
    }

    /// Create from f64 (host-side only, for testing).
    #[cfg(feature = "std")]
    #[inline]
    pub fn from_f64(v: f64) -> Self {
        Fixed((v * SCALE as f64) as i32)
    }

    /// Clamp to [min, max].
    #[inline]
    pub fn clamp(self, min: Fixed, max: Fixed) -> Fixed {
        if self.0 < min.0 {
            min
        } else if self.0 > max.0 {
            max
        } else {
            self
        }
    }

    /// Absolute value.
    #[inline]
    pub fn abs(self) -> Fixed {
        Fixed(self.0.abs())
    }

    /// Integer square root via Newton's method (16 iterations).
    /// Returns sqrt(self). Requires self >= 0.
    pub fn sqrt(self) -> Fixed {
        if self.0 <= 0 {
            return Fixed::ZERO;
        }
        // Start with a reasonable initial guess
        // Use the raw value shifted to get close
        let mut x = Fixed(self.0);
        // Newton's method: x_{n+1} = (x_n + self/x_n) / 2
        // In fixed-point: we need to scale properly
        // sqrt(a) where a is in Q16.16:
        //   raw_result = sqrt(raw_a * 2^16) = sqrt(raw_a) * 2^8
        // So we compute integer sqrt of (raw_a << 16)
        let val = (self.0 as i64) << FRAC_BITS;
        // Initial guess: rough integer sqrt
        let mut guess: i64 = 1;
        let mut temp = val;
        while temp > 1 {
            temp >>= 2;
            guess <<= 1;
        }

        for _ in 0..16 {
            if guess == 0 {
                break;
            }
            guess = (guess + val / guess) >> 1;
        }

        Fixed(guess as i32)
    }

    /// Taylor-approximated exp(-y) for y >= 0.
    /// Uses 8th-order Taylor expansion for sufficient precision in Q16.16.
    /// Max error ~80 units (~0.0012) at y=2.
    pub fn exp_neg(self) -> Fixed {
        let y = self.abs();
        if y.0 == 0 {
            return Fixed::ONE;
        }
        // For large y, result approaches 0
        if y.0 > Fixed::from_int(4).0 {
            return Fixed::ZERO;
        }

        let y2 = y * y;
        let y3 = y2 * y;
        let y4 = y3 * y;
        let y5 = y4 * y;
        let y6 = y5 * y;
        let y7 = y6 * y;
        let y8 = y7 * y;

        // 1 - y + y²/2 - y³/6 + y⁴/24 - y⁵/120 + y⁶/720 - y⁷/5040 + y⁸/40320
        let result = Fixed::ONE - y
            + y2 * Fixed::HALF
            - y3 * Fixed::from_ratio(1, 6)
            + y4 * Fixed::from_ratio(1, 24)
            - y5 * Fixed::from_ratio(1, 120)
            + y6 * Fixed::from_ratio(1, 720)
            - y7 * Fixed::from_ratio(1, 5040)
            + y8 * Fixed::from_ratio(1, 40320);

        // Clamp to [0, 1] since exp(-y) is always in this range for y >= 0
        result.clamp(Fixed::ZERO, Fixed::ONE)
    }

    /// Natural log approximation: ln(2) ≈ 0.6931
    pub const LN2: Fixed = Fixed(45426); // 0.6931 * 65536 ≈ 45426
}

// ---------------------------------------------------------------------------
// Arithmetic operators
// ---------------------------------------------------------------------------

impl Add for Fixed {
    type Output = Fixed;
    #[inline]
    fn add(self, rhs: Fixed) -> Fixed {
        Fixed(self.0 + rhs.0)
    }
}

impl Sub for Fixed {
    type Output = Fixed;
    #[inline]
    fn sub(self, rhs: Fixed) -> Fixed {
        Fixed(self.0 - rhs.0)
    }
}

impl Mul for Fixed {
    type Output = Fixed;
    #[inline]
    fn mul(self, rhs: Fixed) -> Fixed {
        // Use i64 intermediate to avoid overflow
        Fixed(((self.0 as i64 * rhs.0 as i64) >> FRAC_BITS) as i32)
    }
}

impl Div for Fixed {
    type Output = Fixed;
    #[inline]
    fn div(self, rhs: Fixed) -> Fixed {
        if rhs.0 == 0 {
            // Division by zero: return max value with sign
            return if self.0 >= 0 {
                Fixed(i32::MAX)
            } else {
                Fixed(i32::MIN)
            };
        }
        Fixed(((self.0 as i64 * SCALE_I64) / rhs.0 as i64) as i32)
    }
}

impl Neg for Fixed {
    type Output = Fixed;
    #[inline]
    fn neg(self) -> Fixed {
        Fixed(-self.0)
    }
}

impl fmt::Debug for Fixed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fixed({}≈{})", self.0, self.0 as f64 / SCALE as f64)
    }
}

impl fmt::Display for Fixed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Print with 4 decimal places using integer arithmetic
        let sign = if self.0 < 0 { "-" } else { "" };
        let abs = self.0.unsigned_abs();
        let int_part = abs >> FRAC_BITS;
        let frac = ((abs & (SCALE as u32 - 1)) as u64 * 10000) >> FRAC_BITS;
        write!(f, "{}{}.{:04}", sign, int_part, frac)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn test_from_int() {
        assert_eq!(Fixed::from_int(3).to_int(), 3);
        assert_eq!(Fixed::from_int(-1).to_int(), -1);
    }

    #[test]
    fn test_from_ratio() {
        let half = Fixed::from_ratio(1, 2);
        assert_eq!(half.0, SCALE / 2);
        let third = Fixed::from_ratio(1, 3);
        let diff = (third.0 - SCALE / 3).abs();
        assert!(diff <= 1, "from_ratio(1,3) off by {}", diff);
    }

    #[test]
    fn test_arithmetic() {
        let a = Fixed::from_ratio(3, 10); // 0.3
        let b = Fixed::from_ratio(7, 10); // 0.7
        let sum = a + b;
        let diff = (sum.0 - SCALE).abs();
        assert!(diff <= 1, "0.3 + 0.7 off by {}", diff);
    }

    #[test]
    fn test_mul() {
        let a = Fixed::from_ratio(1, 2);
        let b = Fixed::from_ratio(1, 2);
        let product = a * b;
        let expected = Fixed::from_ratio(1, 4);
        let diff = (product.0 - expected.0).abs();
        assert!(diff <= 1, "0.5 * 0.5 off by {}", diff);
    }

    #[test]
    fn test_div() {
        let a = Fixed::from_int(3);
        let b = Fixed::from_int(2);
        let result = a / b;
        let expected = Fixed::from_ratio(3, 2);
        let diff = (result.0 - expected.0).abs();
        assert!(diff <= 1, "3 / 2 off by {}", diff);
    }

    #[test]
    fn test_sqrt() {
        let four = Fixed::from_int(4);
        let result = four.sqrt();
        let expected = Fixed::from_int(2);
        let diff = (result.0 - expected.0).abs();
        assert!(diff <= 2, "sqrt(4) off by {}", diff);

        let quarter = Fixed::from_ratio(1, 4);
        let result = quarter.sqrt();
        let expected = Fixed::HALF;
        let diff = (result.0 - expected.0).abs();
        assert!(diff <= 2, "sqrt(0.25) off by {}", diff);
    }

    #[test]
    fn test_exp_neg() {
        // exp(0) = 1
        let result = Fixed::ZERO.exp_neg();
        assert_eq!(result.0, Fixed::ONE.0);

        // exp(-1) ≈ 0.3679
        let result = Fixed::ONE.exp_neg();
        let expected = Fixed::from_f64(0.3679);
        let diff = (result.0 - expected.0).abs();
        assert!(diff <= 200, "exp(-1) off by {} (got {})", diff, result.to_f64());

        // exp(-2) ≈ 0.1353
        let two = Fixed::from_int(2);
        let result = two.exp_neg();
        let expected = Fixed::from_f64(0.1353);
        let diff = (result.0 - expected.0).abs();
        assert!(diff <= 200, "exp(-2) off by {} (got {})", diff, result.to_f64());
    }

    #[test]
    fn test_clamp() {
        let val = Fixed::from_ratio(15, 10); // 1.5
        let clamped = val.clamp(Fixed::ZERO, Fixed::ONE);
        assert_eq!(clamped, Fixed::ONE);

        let val = Fixed::from_ratio(-5, 10); // -0.5
        let clamped = val.clamp(Fixed::ZERO, Fixed::ONE);
        assert_eq!(clamped, Fixed::ZERO);
    }
}
