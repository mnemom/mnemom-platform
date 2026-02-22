//! Proving and verification functions.

use aip_zkvm_core::team_types::{TeamRiskInput, TeamRiskOutput};
use aip_zkvm_core::{GuestInput, GuestOutput};
use aip_zkvm_methods::AIP_ZKVM_GUEST_ELF;
use anyhow::{Context, Result};
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};

use crate::server::{RiskGuestInput, RiskGuestOutput};

/// Prove that the verdict was correctly derived from the analysis.
///
/// Returns the STARK receipt and the committed guest output.
pub fn prove_verdict_derivation(
    analysis_json: &str,
    thinking_hash: &str,
    card_hash: &str,
    values_hash: &str,
    model: &str,
) -> Result<(Receipt, GuestOutput)> {
    let input = GuestInput {
        analysis_json: analysis_json.to_string(),
        thinking_hash: thinking_hash.to_string(),
        card_hash: card_hash.to_string(),
        values_hash: values_hash.to_string(),
        model: model.to_string(),
    };

    let env = ExecutorEnv::builder()
        .write(&input)
        .context("Failed to write input to executor env")?
        .build()
        .context("Failed to build executor env")?;

    let prover = default_prover();
    let prove_info = prover
        .prove(env, AIP_ZKVM_GUEST_ELF)
        .context("Failed to generate proof")?;

    let receipt = prove_info.receipt;
    let output: GuestOutput = receipt
        .journal
        .decode()
        .context("Failed to decode journal output")?;

    Ok((receipt, output))
}

/// Verify a STARK receipt and extract the guest output.
///
/// Verifies both the STARK proof integrity and the image ID match.
pub fn verify_verdict_proof(receipt: &Receipt) -> Result<GuestOutput> {
    // Verify the receipt against the expected image ID
    receipt
        .verify(aip_zkvm_methods::AIP_ZKVM_GUEST_ID)
        .context("Receipt verification failed")?;

    let output: GuestOutput = receipt
        .journal
        .decode()
        .context("Failed to decode journal output")?;

    Ok(output)
}

/// Prove an individual risk assessment.
///
/// Returns the STARK receipt and the committed risk output.
pub fn prove_risk_assessment(input: RiskGuestInput) -> Result<(Receipt, RiskGuestOutput)> {
    let env = ExecutorEnv::builder()
        .write(&input)
        .context("Failed to write risk input to executor env")?
        .build()
        .context("Failed to build executor env")?;

    let prover = default_prover();
    let prove_info = prover
        .prove(env, risk_zkvm_methods::RISK_ZKVM_GUEST_ELF)
        .context("Failed to generate risk proof")?;

    let receipt = prove_info.receipt;
    let output: RiskGuestOutput = receipt
        .journal
        .decode()
        .context("Failed to decode risk journal output")?;

    Ok((receipt, output))
}

/// Prove a team risk assessment.
///
/// Returns the STARK receipt and the committed team risk output.
pub fn prove_team_risk_assessment(input: TeamRiskInput) -> Result<(Receipt, TeamRiskOutput)> {
    let env = ExecutorEnv::builder()
        .write(&input)
        .context("Failed to write team risk input to executor env")?
        .build()
        .context("Failed to build executor env")?;

    let prover = default_prover();
    let prove_info = prover
        .prove(env, team_risk_zkvm_methods::TEAM_RISK_ZKVM_GUEST_ELF)
        .context("Failed to generate team risk proof")?;

    let receipt = prove_info.receipt;
    let output: TeamRiskOutput = receipt
        .journal
        .decode()
        .context("Failed to decode team risk journal output")?;

    Ok((receipt, output))
}

/// Serialize a receipt to bytes for transport/storage.
pub fn receipt_to_bytes(receipt: &Receipt) -> Result<Vec<u8>> {
    bincode::serialize(receipt).context("Failed to serialize receipt")
}

/// Deserialize a receipt from bytes.
pub fn receipt_from_bytes(bytes: &[u8]) -> Result<Receipt> {
    bincode::deserialize(bytes).context("Failed to deserialize receipt")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test fixtures — these mirror the TypeScript test vectors
    const CLEAR_JSON: &str = include_str!("../../tests/fixtures/clear.json");
    const REVIEW_JSON: &str = include_str!("../../tests/fixtures/review_needed.json");
    const BOUNDARY_INJECTION_JSON: &str = include_str!("../../tests/fixtures/boundary_injection.json");
    const BOUNDARY_DECEPTION_JSON: &str = include_str!("../../tests/fixtures/boundary_deception.json");

    #[test]
    #[ignore] // Requires RISC Zero toolchain installed
    fn test_prove_clear() {
        let (receipt, output) = prove_verdict_derivation(
            CLEAR_JSON, "abc123", "def456", "ghi789", "test-model",
        ).expect("Proving failed");

        assert_eq!(output.verdict, aip_zkvm_core::Verdict::Clear);
        assert_eq!(output.action, aip_zkvm_core::Action::Continue);

        let verified = verify_verdict_proof(&receipt).expect("Verification failed");
        assert_eq!(verified.verdict, output.verdict);
    }

    #[test]
    #[ignore] // Requires RISC Zero toolchain installed
    fn test_prove_boundary_injection() {
        let (receipt, output) = prove_verdict_derivation(
            BOUNDARY_INJECTION_JSON, "abc123", "def456", "ghi789", "test-model",
        ).expect("Proving failed");

        assert_eq!(output.verdict, aip_zkvm_core::Verdict::BoundaryViolation);
        assert_eq!(output.action, aip_zkvm_core::Action::DenyAndEscalate);

        let verified = verify_verdict_proof(&receipt).expect("Verification failed");
        assert_eq!(verified.verdict, output.verdict);
    }

    #[test]
    #[ignore] // Requires RISC Zero toolchain installed
    fn test_receipt_roundtrip() {
        let (receipt, _) = prove_verdict_derivation(
            CLEAR_JSON, "abc123", "def456", "ghi789", "test-model",
        ).expect("Proving failed");

        let bytes = receipt_to_bytes(&receipt).expect("Serialization failed");
        let restored = receipt_from_bytes(&bytes).expect("Deserialization failed");
        let output = verify_verdict_proof(&restored).expect("Verification failed");
        assert_eq!(output.verdict, aip_zkvm_core::Verdict::Clear);
    }
}
