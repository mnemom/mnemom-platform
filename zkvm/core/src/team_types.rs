//! Team risk assessment types for zkVM guest programs.
//!
//! All types use `Fixed` (Q16.16) for numeric values to ensure
//! deterministic computation inside the guest.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::fixed::Fixed;

/// A single agent's profile for team risk computation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentProfile {
    pub agent_id: String,
    /// Reputation score (0–1000 scale, stored as Fixed for computation).
    pub reputation_score: Fixed,
    /// Individual risk score (0–1 scale).
    pub individual_risk: Fixed,
    /// Confidence level encoded as Fixed: 0.95 (high), 0.80 (medium), 0.60 (low), 0.40 (insufficient).
    pub confidence: Fixed,
}

/// Pairwise coherence data between two agents.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairwiseCoherence {
    pub agent_a: String,
    pub agent_b: String,
    /// Value overlap score (0–1000 scale).
    pub value_overlap: Fixed,
    /// Priority alignment score (0–1000 scale).
    pub priority_alignment: Fixed,
    /// Behavioral correlation penalty (0–1000 scale, higher = more penalty).
    pub behavioral_corr_penalty: Fixed,
    /// Boundary compatibility score (0–1000 scale).
    pub boundary_compatibility: Fixed,
}

/// Input to the team risk guest program.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeamRiskInput {
    pub agents: Vec<AgentProfile>,
    pub pairwise: Vec<PairwiseCoherence>,
    /// Circuit breaker threshold for minimum reputation.
    pub circuit_breaker_min_reputation: Fixed,
    /// Circuit breaker threshold for minimum boundary compatibility.
    pub circuit_breaker_min_boundary_compat: Fixed,
}

/// Per-agent Shapley value in the output.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShapleyEntry {
    pub agent_id: String,
    pub shapley_value: Fixed,
}

/// Outlier detected in the team.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeamOutlierOutput {
    pub agent_id: String,
    pub individual_risk: Fixed,
    pub shapley_value: Fixed,
    pub systemic_contribution: Fixed,
}

/// Output from the team risk guest program.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeamRiskOutput {
    /// Composite team risk score (0–1).
    pub team_risk_score: Fixed,
    /// Three pillar values.
    pub aggregate_quality: Fixed,
    pub coherence_quality: Fixed,
    pub structural_risk: Fixed,
    /// Team coherence (composite of three pillars, 0–1).
    pub team_coherence: Fixed,
    /// Shapley values per agent.
    pub shapley_values: Vec<ShapleyEntry>,
    /// Outlier agents.
    pub outliers: Vec<TeamOutlierOutput>,
    /// Whether a circuit breaker was triggered.
    pub circuit_breaker_triggered: bool,
    /// Synergy indicator: positive = synergistic, near-zero = neutral, negative = anti-synergistic.
    pub diversification_benefit: Fixed,
    /// SHA-256 hash of the input for binding.
    pub input_hash: String,
}
