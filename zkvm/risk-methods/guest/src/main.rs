//! RISC Zero guest program for individual risk assessment proofs.
//!
//! This binary runs inside the zkVM and proves that the risk score was
//! computed deterministically from the input reputation components and
//! violation history. It uses context weighting, recency decay,
//! confidence penalty, and composite scoring — all in fixed-point
//! arithmetic.

#![no_main]
#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use risc0_zkvm::guest::env;
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};

use aip_zkvm_core::fixed::Fixed;

risc0_zkvm::guest::entry!(main);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Reputation component scores (each 0–1000 scale as Fixed).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReputationComponents {
    pub integrity: Fixed,
    pub reliability: Fixed,
    pub competence: Fixed,
    pub transparency: Fixed,
    pub alignment: Fixed,
}

/// A single violation record.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ViolationRecord {
    /// Severity weight (0–1 scale as Fixed): low=0.2, medium=0.5, high=0.8, critical=1.0
    pub severity_weight: Fixed,
    /// Days since the violation occurred.
    pub days_since: Fixed,
}

/// Input to the individual risk guest program.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RiskGuestInput {
    /// Reputation component scores (0–1000 scale).
    pub reputation: ReputationComponents,
    /// Historical violation records.
    pub violations: Vec<ViolationRecord>,
    /// Action type being evaluated (e.g. "tool_call", "response", "code_execution").
    pub action_type: String,
    /// Risk tolerance level (e.g. "conservative", "moderate", "aggressive").
    pub risk_tolerance: String,
}

/// Output committed by the individual risk guest program.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RiskGuestOutput {
    /// Computed risk score (0–1 scale).
    pub risk_score: Fixed,
    /// Risk level classification.
    pub risk_level: String,
    /// Recommended action.
    pub recommendation: String,
    /// SHA-256 hash of the serialized input.
    pub input_hash: String,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Context weights for action types
const TOOL_CALL_WEIGHT: Fixed = Fixed::from_ratio(120, 100);   // 1.2x
const CODE_EXEC_WEIGHT: Fixed = Fixed::from_ratio(150, 100);   // 1.5x
const RESPONSE_WEIGHT: Fixed = Fixed::from_ratio(80, 100);     // 0.8x
const DEFAULT_WEIGHT: Fixed = Fixed::ONE;                       // 1.0x

// Reputation component weights (sum to 1.0)
const W_INTEGRITY: Fixed = Fixed::from_ratio(30, 100);     // 0.30
const W_RELIABILITY: Fixed = Fixed::from_ratio(20, 100);   // 0.20
const W_COMPETENCE: Fixed = Fixed::from_ratio(15, 100);    // 0.15
const W_TRANSPARENCY: Fixed = Fixed::from_ratio(15, 100);  // 0.15
const W_ALIGNMENT: Fixed = Fixed::from_ratio(20, 100);     // 0.20

// Recency decay half-life in days
const DECAY_HALF_LIFE: Fixed = Fixed::from_int(30);

// Maximum violation impact
const MAX_VIOLATION_IMPACT: Fixed = Fixed::from_ratio(60, 100); // 0.6

// Confidence penalty constants
const HIGH_CONFIDENCE: Fixed = Fixed::from_ratio(95, 100);
const MEDIUM_CONFIDENCE: Fixed = Fixed::from_ratio(80, 100);
const LOW_CONFIDENCE: Fixed = Fixed::from_ratio(60, 100);

// Scale factor for 0-1000 to 0-1
const THOUSAND: Fixed = Fixed::from_int(1000);

// Risk level thresholds
const THRESHOLD_LOW: Fixed = Fixed::from_ratio(25, 100);       // 0.25
const THRESHOLD_MEDIUM: Fixed = Fixed::from_ratio(50, 100);    // 0.50
const THRESHOLD_HIGH: Fixed = Fixed::from_ratio(75, 100);      // 0.75

// ---------------------------------------------------------------------------
// Computation
// ---------------------------------------------------------------------------

fn main() {
    // 1. Read input from host
    let input: RiskGuestInput = env::read();

    // 2. Hash the input for binding
    let input_json = serde_json::to_string(&input).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(input_json.as_bytes());
    let hash_result = hasher.finalize();
    let input_hash = hex::encode(hash_result);

    // 3. Compute weighted reputation score (0-1)
    let rep = &input.reputation;
    let weighted_rep = W_INTEGRITY * (rep.integrity / THOUSAND)
        + W_RELIABILITY * (rep.reliability / THOUSAND)
        + W_COMPETENCE * (rep.competence / THOUSAND)
        + W_TRANSPARENCY * (rep.transparency / THOUSAND)
        + W_ALIGNMENT * (rep.alignment / THOUSAND);
    let weighted_rep = weighted_rep.clamp(Fixed::ZERO, Fixed::ONE);

    // 4. Compute base risk from reputation (inverse: high rep = low risk)
    let base_risk = Fixed::ONE - weighted_rep;

    // 5. Compute violation impact with recency decay
    let violation_impact = compute_violation_impact(&input.violations);

    // 6. Apply context weight for action type
    let context_weight = match input.action_type.as_str() {
        "tool_call" => TOOL_CALL_WEIGHT,
        "code_execution" => CODE_EXEC_WEIGHT,
        "response" => RESPONSE_WEIGHT,
        _ => DEFAULT_WEIGHT,
    };

    // 7. Compute confidence penalty from reputation variance
    let confidence = compute_confidence(&input.reputation);
    let confidence_penalty = compute_confidence_penalty(confidence);

    // 8. Composite risk score
    //    risk = context_weight * (0.5 * base_risk + 0.3 * violation_impact + 0.2 * confidence_penalty)
    let composite = Fixed::HALF * base_risk
        + Fixed::from_ratio(30, 100) * violation_impact
        + Fixed::from_ratio(20, 100) * confidence_penalty;
    let risk_score = (context_weight * composite).clamp(Fixed::ZERO, Fixed::ONE);

    // 9. Apply risk tolerance adjustment
    let risk_score = apply_risk_tolerance(risk_score, &input.risk_tolerance);

    // 10. Classify risk level and recommendation
    let (risk_level, recommendation) = classify_risk(risk_score);

    // 11. Commit output
    let output = RiskGuestOutput {
        risk_score,
        risk_level,
        recommendation,
        input_hash,
    };

    env::commit(&output);
}

/// Compute violation impact with exponential recency decay.
/// Each violation contributes: severity_weight * exp(-ln(2) * days_since / half_life)
/// Total is clamped to MAX_VIOLATION_IMPACT.
fn compute_violation_impact(violations: &[ViolationRecord]) -> Fixed {
    if violations.is_empty() {
        return Fixed::ZERO;
    }

    let mut total = Fixed::ZERO;

    for v in violations {
        // decay = exp(-ln(2) * days / half_life)
        let decay_exponent = Fixed::LN2 * v.days_since / DECAY_HALF_LIFE;
        let decay = decay_exponent.exp_neg();
        total = total + v.severity_weight * decay;
    }

    // Normalize by number of violations and clamp
    let n = Fixed::from_int(violations.len() as i32);
    let normalized = total / n;
    normalized.clamp(Fixed::ZERO, MAX_VIOLATION_IMPACT)
}

/// Compute confidence from reputation component variance.
/// Low variance = high confidence, high variance = low confidence.
fn compute_confidence(rep: &ReputationComponents) -> Fixed {
    let components = [
        rep.integrity / THOUSAND,
        rep.reliability / THOUSAND,
        rep.competence / THOUSAND,
        rep.transparency / THOUSAND,
        rep.alignment / THOUSAND,
    ];

    // Mean
    let mut sum = Fixed::ZERO;
    for &c in &components {
        sum = sum + c;
    }
    let mean = sum / Fixed::from_int(5);

    // Variance
    let mut var_sum = Fixed::ZERO;
    for &c in &components {
        let diff = c - mean;
        var_sum = var_sum + diff * diff;
    }
    let variance = var_sum / Fixed::from_int(5);
    let stddev = variance.sqrt();

    // Map stddev to confidence: low stddev = high confidence
    // stddev 0.0 -> 0.95, stddev 0.2 -> 0.60, stddev >= 0.3 -> 0.40
    if stddev < Fixed::from_ratio(5, 100) {
        HIGH_CONFIDENCE
    } else if stddev < Fixed::from_ratio(15, 100) {
        MEDIUM_CONFIDENCE
    } else if stddev < Fixed::from_ratio(25, 100) {
        LOW_CONFIDENCE
    } else {
        Fixed::from_ratio(40, 100) // insufficient
    }
}

/// Compute confidence penalty (higher penalty for lower confidence).
fn compute_confidence_penalty(confidence: Fixed) -> Fixed {
    // penalty = 1 - confidence (so high confidence = low penalty)
    (Fixed::ONE - confidence).clamp(Fixed::ZERO, Fixed::ONE)
}

/// Apply risk tolerance adjustment.
/// Conservative: scale up by 1.2x
/// Moderate: no change
/// Aggressive: scale down by 0.8x
fn apply_risk_tolerance(risk: Fixed, tolerance: &str) -> Fixed {
    let adjusted = match tolerance {
        "conservative" => risk * Fixed::from_ratio(120, 100),
        "aggressive" => risk * Fixed::from_ratio(80, 100),
        _ => risk, // "moderate" or unknown
    };
    adjusted.clamp(Fixed::ZERO, Fixed::ONE)
}

/// Classify risk score into level and recommendation.
fn classify_risk(score: Fixed) -> (String, String) {
    if score < THRESHOLD_LOW {
        (
            String::from("low"),
            String::from("continue"),
        )
    } else if score < THRESHOLD_MEDIUM {
        (
            String::from("medium"),
            String::from("log_and_continue"),
        )
    } else if score < THRESHOLD_HIGH {
        (
            String::from("high"),
            String::from("pause_for_review"),
        )
    } else {
        (
            String::from("critical"),
            String::from("deny_and_escalate"),
        )
    }
}
