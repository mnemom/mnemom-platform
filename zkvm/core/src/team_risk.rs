//! Team risk computation — deterministic, no_std+alloc, fixed-point.
//!
//! Three-pillar model:
//!   - Aggregate Quality (AQ): tail-risk-weighted reputation average (CoVaR-inspired)
//!   - Coherence Quality (CQ): pairwise coherence with variance penalty (Markowitz-inspired)
//!   - Structural Risk (SR): contagion analysis (DebtRank-inspired)
//!
//! Composition: TeamCoherence = 0.30*AQ + 0.45*CQ + 0.25*(1-SR)
//! TeamRisk = 1 - TeamCoherence

use alloc::string::String;
use alloc::vec::Vec;

use crate::fixed::Fixed;
use crate::team_types::*;

// ---------------------------------------------------------------------------
// Constants (in Fixed)
// ---------------------------------------------------------------------------

const W_AQ: Fixed = Fixed::from_ratio(30, 100);  // 0.30
const W_CQ: Fixed = Fixed::from_ratio(45, 100);  // 0.45
const W_SR: Fixed = Fixed::from_ratio(25, 100);  // 0.25

// Coherence sub-weights
const W_VALUE_OVERLAP: Fixed = Fixed::from_ratio(35, 100);
const W_PRIORITY: Fixed = Fixed::from_ratio(25, 100);
const W_BEHAVIORAL: Fixed = Fixed::from_ratio(15, 100);
const W_BOUNDARY: Fixed = Fixed::from_ratio(25, 100);

// Structural risk weights
const SR_MAX_WEIGHT: Fixed = Fixed::from_ratio(70, 100);
const SR_CONTAGION_WEIGHT: Fixed = Fixed::from_ratio(30, 100);

// Variance penalty multiplier
const VARIANCE_PENALTY: Fixed = Fixed::HALF;

const THOUSAND: Fixed = Fixed::from_int(1000);
const TWO: Fixed = Fixed::from_int(2);

// ---------------------------------------------------------------------------
// Pillar 1: Aggregate Quality (AQ)
// ---------------------------------------------------------------------------

/// Tail-risk-weighted reputation average.
/// w_i = exp(-2 * R_i) where R_i is individual risk.
/// AQ = sum(w_i * R_i) / sum(w_i)
/// Low-reputation agents get exponentially higher weight.
pub fn compute_aggregate_quality(agents: &[AgentProfile]) -> Fixed {
    if agents.is_empty() {
        return Fixed::ZERO;
    }

    let mut weighted_sum = Fixed::ZERO;
    let mut weight_total = Fixed::ZERO;

    for agent in agents {
        // w_i = exp(-2 * individual_risk)
        let exponent = TWO * agent.individual_risk;
        let w_i = exponent.exp_neg();

        weighted_sum = weighted_sum + w_i * agent.individual_risk;
        weight_total = weight_total + w_i;
    }

    if weight_total.raw() == 0 {
        return Fixed::ZERO;
    }

    // AQ is a risk metric (higher = more risk)
    weighted_sum / weight_total
}

// ---------------------------------------------------------------------------
// Pillar 2: Coherence Quality (CQ)
// ---------------------------------------------------------------------------

/// Compute pairwise coherence score (0-1) from raw sub-components.
pub fn compute_pairwise_score(pw: &PairwiseCoherence) -> Fixed {
    // Normalize from 0-1000 to 0-1
    let vo = pw.value_overlap / THOUSAND;
    let pa = pw.priority_alignment / THOUSAND;
    let bc = pw.boundary_compatibility / THOUSAND;
    // Behavioral correlation penalty: higher raw value = more penalty = less coherence
    let bp = Fixed::ONE - pw.behavioral_corr_penalty / THOUSAND;

    W_VALUE_OVERLAP * vo + W_PRIORITY * pa + W_BEHAVIORAL * bp + W_BOUNDARY * bc
}

/// Mean pairwise coherence with variance penalty.
/// CQ = mean(C_ij) - 0.5 * stddev(C_ij)
pub fn compute_coherence_quality(pairwise: &[PairwiseCoherence]) -> Fixed {
    if pairwise.is_empty() {
        return Fixed::ZERO;
    }

    let n = Fixed::from_int(pairwise.len() as i32);
    let mut sum = Fixed::ZERO;
    let mut scores = Vec::with_capacity(pairwise.len());

    for pw in pairwise {
        let score = compute_pairwise_score(pw);
        scores.push(score);
        sum = sum + score;
    }

    let mean = sum / n;

    // Variance = sum((x - mean)^2) / n
    let mut var_sum = Fixed::ZERO;
    for &s in &scores {
        let diff = s - mean;
        var_sum = var_sum + diff * diff;
    }
    let variance = var_sum / n;
    let stddev = variance.sqrt();

    // CQ as quality (1 - risk): higher coherence = less risk
    // But we return the coherence value; caller inverts to risk
    let cq = mean - VARIANCE_PENALTY * stddev;
    cq.clamp(Fixed::ZERO, Fixed::ONE)
}

// ---------------------------------------------------------------------------
// Pillar 3: Structural Risk (SR)
// ---------------------------------------------------------------------------

/// DebtRank-style contagion analysis.
/// V_ij = (1 - C_ij) * (1 - R_j): vulnerability if agent j fails.
/// SR_i = mean(V_ij for j != i): agent i's systemic risk.
/// SR = 0.7 * max(SR_i) + 0.3 * contagion_effect.
pub fn compute_structural_risk(
    agents: &[AgentProfile],
    pairwise: &[PairwiseCoherence],
) -> (Fixed, Vec<Fixed>) {
    let n = agents.len();
    if n <= 1 {
        return (Fixed::ZERO, alloc::vec![Fixed::ZERO; n]);
    }

    // Build coherence matrix (indexed by agent position)
    // We need a lookup from (agent_a, agent_b) → coherence score
    let mut sr_per_agent = Vec::with_capacity(n);

    for (i, agent_i) in agents.iter().enumerate() {
        let mut vulnerability_sum = Fixed::ZERO;
        let mut count = 0i32;

        for (j, agent_j) in agents.iter().enumerate() {
            if i == j {
                continue;
            }

            // Find the pairwise coherence between i and j
            let c_ij = find_pairwise_score(pairwise, &agent_i.agent_id, &agent_j.agent_id);

            // V_ij = (1 - C_ij) * (1 - R_j)
            // This represents: if agent j fails (R_j is high), and coherence is low,
            // then agent i is vulnerable
            let v_ij = (Fixed::ONE - c_ij) * (Fixed::ONE - agent_j.individual_risk);
            vulnerability_sum = vulnerability_sum + v_ij;
            count += 1;
        }

        let sr_i = if count > 0 {
            vulnerability_sum / Fixed::from_int(count)
        } else {
            Fixed::ZERO
        };

        sr_per_agent.push(sr_i);
    }

    // Max systemic risk
    let max_sr = sr_per_agent.iter().copied().max().unwrap_or(Fixed::ZERO);

    // Contagion effect: average of all SR_i
    let mut sr_sum = Fixed::ZERO;
    for &s in &sr_per_agent {
        sr_sum = sr_sum + s;
    }
    let avg_sr = sr_sum / Fixed::from_int(n as i32);

    let sr = SR_MAX_WEIGHT * max_sr + SR_CONTAGION_WEIGHT * avg_sr;

    (sr.clamp(Fixed::ZERO, Fixed::ONE), sr_per_agent)
}

/// Find pairwise coherence score between two agents.
fn find_pairwise_score(pairwise: &[PairwiseCoherence], a: &str, b: &str) -> Fixed {
    for pw in pairwise {
        if (pw.agent_a == a && pw.agent_b == b) || (pw.agent_a == b && pw.agent_b == a) {
            return compute_pairwise_score(pw);
        }
    }
    // Default: medium coherence if not found
    Fixed::HALF
}

// ---------------------------------------------------------------------------
// LOO Shapley Approximation
// ---------------------------------------------------------------------------

/// Compute LOO (Leave-One-Out) Shapley values.
/// MC_i = TeamCoherence(all) - TeamCoherence(all \ {i})
pub fn compute_shapley_values(
    agents: &[AgentProfile],
    pairwise: &[PairwiseCoherence],
    full_coherence: Fixed,
) -> Vec<ShapleyEntry> {
    let n = agents.len();
    let mut entries = Vec::with_capacity(n);

    for i in 0..n {
        // Build the subset without agent i
        let subset_agents: Vec<AgentProfile> = agents.iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, a)| a.clone())
            .collect();

        let subset_pairwise: Vec<PairwiseCoherence> = pairwise.iter()
            .filter(|pw| pw.agent_a != agents[i].agent_id && pw.agent_b != agents[i].agent_id)
            .cloned()
            .collect();

        let subset_coherence = compute_team_coherence_raw(&subset_agents, &subset_pairwise);
        let marginal = full_coherence - subset_coherence;

        entries.push(ShapleyEntry {
            agent_id: agents[i].agent_id.clone(),
            shapley_value: marginal,
        });
    }

    entries
}

// ---------------------------------------------------------------------------
// Outlier Detection
// ---------------------------------------------------------------------------

/// Detect agents >1σ below the fleet mean in risk or coherence.
pub fn detect_outliers(
    agents: &[AgentProfile],
    shapley_values: &[ShapleyEntry],
    sr_per_agent: &[Fixed],
) -> Vec<TeamOutlierOutput> {
    let n = agents.len();
    if n < 3 {
        return Vec::new(); // Need at least 3 agents for meaningful outlier detection
    }

    // Compute mean and stddev of individual risk
    let n_fixed = Fixed::from_int(n as i32);
    let mut risk_sum = Fixed::ZERO;
    for agent in agents {
        risk_sum = risk_sum + agent.individual_risk;
    }
    let mean_risk = risk_sum / n_fixed;

    let mut var_sum = Fixed::ZERO;
    for agent in agents {
        let diff = agent.individual_risk - mean_risk;
        var_sum = var_sum + diff * diff;
    }
    let stddev_risk = (var_sum / n_fixed).sqrt();

    let threshold = mean_risk + stddev_risk;
    let mut outliers = Vec::new();

    for (i, agent) in agents.iter().enumerate() {
        if agent.individual_risk > threshold {
            let shapley = shapley_values.iter()
                .find(|s| s.agent_id == agent.agent_id)
                .map(|s| s.shapley_value)
                .unwrap_or(Fixed::ZERO);

            let systemic = if i < sr_per_agent.len() { sr_per_agent[i] } else { Fixed::ZERO };

            outliers.push(TeamOutlierOutput {
                agent_id: agent.agent_id.clone(),
                individual_risk: agent.individual_risk,
                shapley_value: shapley,
                systemic_contribution: systemic,
            });
        }
    }

    outliers
}

// ---------------------------------------------------------------------------
// Circuit Breakers
// ---------------------------------------------------------------------------

/// Check if any circuit breaker is triggered.
pub fn check_circuit_breakers(input: &TeamRiskInput) -> bool {
    // Any agent reputation < threshold
    for agent in &input.agents {
        if agent.reputation_score < input.circuit_breaker_min_reputation {
            return true;
        }
    }

    // Any pairwise boundary_compatibility < threshold
    for pw in &input.pairwise {
        if pw.boundary_compatibility < input.circuit_breaker_min_boundary_compat {
            return true;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Composition
// ---------------------------------------------------------------------------

/// Raw team coherence computation (used internally and by Shapley LOO).
pub fn compute_team_coherence_raw(
    agents: &[AgentProfile],
    pairwise: &[PairwiseCoherence],
) -> Fixed {
    if agents.is_empty() {
        return Fixed::ZERO;
    }
    if agents.len() == 1 {
        // Single agent: team coherence = 1 - individual risk
        return Fixed::ONE - agents[0].individual_risk;
    }

    let aq = compute_aggregate_quality(agents);
    let cq = compute_coherence_quality(pairwise);
    let (sr, _) = compute_structural_risk(agents, pairwise);

    // TeamCoherence = 0.30 * (1 - AQ) + 0.45 * CQ + 0.25 * (1 - SR)
    // AQ is a risk metric, so we invert: higher AQ = more risk = less quality
    let coherence = W_AQ * (Fixed::ONE - aq) + W_CQ * cq + W_SR * (Fixed::ONE - sr);
    coherence.clamp(Fixed::ZERO, Fixed::ONE)
}

/// Full team risk computation.
pub fn compute_team_risk(input: &TeamRiskInput) -> TeamRiskOutput {
    let n = input.agents.len();

    // Check circuit breakers first
    let circuit_breaker_triggered = check_circuit_breakers(input);

    // Compute three pillars
    let aq = compute_aggregate_quality(&input.agents);
    let cq = compute_coherence_quality(&input.pairwise);
    let (sr, sr_per_agent) = compute_structural_risk(&input.agents, &input.pairwise);

    // Team coherence
    let team_coherence = W_AQ * (Fixed::ONE - aq) + W_CQ * cq + W_SR * (Fixed::ONE - sr);
    let team_coherence = team_coherence.clamp(Fixed::ZERO, Fixed::ONE);

    // Team risk = 1 - coherence
    let team_risk_score = if circuit_breaker_triggered {
        // Circuit breaker: force critical risk
        Fixed::ONE
    } else {
        (Fixed::ONE - team_coherence).clamp(Fixed::ZERO, Fixed::ONE)
    };

    // Shapley values
    let shapley_values = compute_shapley_values(&input.agents, &input.pairwise, team_coherence);

    // Outlier detection
    let outliers = detect_outliers(&input.agents, &shapley_values, &sr_per_agent);

    // Diversification benefit: avg individual risk - team risk
    let mut individual_risk_sum = Fixed::ZERO;
    for agent in &input.agents {
        individual_risk_sum = individual_risk_sum + agent.individual_risk;
    }
    let avg_individual_risk = if n > 0 {
        individual_risk_sum / Fixed::from_int(n as i32)
    } else {
        Fixed::ZERO
    };
    let diversification_benefit = avg_individual_risk - team_risk_score;

    // Compute input hash (placeholder — actual hash computed in guest main)
    let input_hash = String::new();

    TeamRiskOutput {
        team_risk_score,
        aggregate_quality: aq,
        coherence_quality: cq,
        structural_risk: sr,
        team_coherence,
        shapley_values,
        outliers,
        circuit_breaker_triggered,
        diversification_benefit,
        input_hash,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use alloc::string::ToString;

    fn make_agent(id: &str, rep: i32, risk_f64: f64) -> AgentProfile {
        AgentProfile {
            agent_id: id.to_string(),
            reputation_score: Fixed::from_int(rep),
            individual_risk: Fixed::from_f64(risk_f64),
            confidence: Fixed::from_f64(0.95),
        }
    }

    fn make_pairwise(a: &str, b: &str, vo: i32, pa: i32, bp: i32, bc: i32) -> PairwiseCoherence {
        PairwiseCoherence {
            agent_a: a.to_string(),
            agent_b: b.to_string(),
            value_overlap: Fixed::from_int(vo),
            priority_alignment: Fixed::from_int(pa),
            behavioral_corr_penalty: Fixed::from_int(bp),
            boundary_compatibility: Fixed::from_int(bc),
        }
    }

    #[test]
    fn test_identical_agents_team_risk_equals_individual() {
        let agents = vec![
            make_agent("a", 800, 0.2),
            make_agent("b", 800, 0.2),
        ];
        let pairwise = vec![
            make_pairwise("a", "b", 900, 900, 100, 900),
        ];
        let input = TeamRiskInput {
            agents,
            pairwise,
            circuit_breaker_min_reputation: Fixed::from_int(200),
            circuit_breaker_min_boundary_compat: Fixed::from_int(100),
        };
        let output = compute_team_risk(&input);
        // Team risk should be close to individual risk for identical, well-coherent agents
        let diff = (output.team_risk_score - Fixed::from_f64(0.2)).abs();
        assert!(diff < Fixed::from_f64(0.15), "team risk {} too far from 0.2", output.team_risk_score);
    }

    #[test]
    fn test_circuit_breaker_low_reputation() {
        let agents = vec![
            make_agent("good", 800, 0.1),
            make_agent("bad", 100, 0.9), // reputation < 200
        ];
        let pairwise = vec![
            make_pairwise("good", "bad", 500, 500, 200, 500),
        ];
        let input = TeamRiskInput {
            agents,
            pairwise,
            circuit_breaker_min_reputation: Fixed::from_int(200),
            circuit_breaker_min_boundary_compat: Fixed::from_int(100),
        };
        let output = compute_team_risk(&input);
        assert!(output.circuit_breaker_triggered);
        assert_eq!(output.team_risk_score, Fixed::ONE);
    }

    #[test]
    fn test_shapley_values_exist_for_all_agents() {
        let agents = vec![
            make_agent("a", 800, 0.1),
            make_agent("b", 700, 0.3),
            make_agent("c", 600, 0.5),
        ];
        let pairwise = vec![
            make_pairwise("a", "b", 800, 800, 100, 800),
            make_pairwise("a", "c", 600, 600, 200, 600),
            make_pairwise("b", "c", 700, 700, 150, 700),
        ];
        let input = TeamRiskInput {
            agents,
            pairwise,
            circuit_breaker_min_reputation: Fixed::from_int(200),
            circuit_breaker_min_boundary_compat: Fixed::from_int(100),
        };
        let output = compute_team_risk(&input);
        assert_eq!(output.shapley_values.len(), 3);
    }
}
