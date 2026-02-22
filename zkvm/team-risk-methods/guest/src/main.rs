//! RISC Zero guest program for team risk assessment proofs.
//!
//! This binary runs inside the zkVM and proves that the team risk score
//! was computed deterministically from the agent profiles and pairwise
//! coherence data using the three-pillar model (Aggregate Quality,
//! Coherence Quality, Structural Risk) with Shapley attribution and
//! outlier detection.

#![no_main]
#![no_std]

extern crate alloc;

use alloc::string::String;
use risc0_zkvm::guest::env;
use sha2::{Sha256, Digest};

use aip_zkvm_core::team_types::TeamRiskInput;
use aip_zkvm_core::team_risk::compute_team_risk;

risc0_zkvm::guest::entry!(main);

fn main() {
    // 1. Read input from host
    let input: TeamRiskInput = env::read();

    // 2. Hash the serialized input for binding
    let input_json = serde_json::to_string(&input).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(input_json.as_bytes());
    let hash_result = hasher.finalize();
    let input_hash: String = hex::encode(hash_result);

    // 3. Compute team risk using core library
    let mut output = compute_team_risk(&input);

    // 4. Set the input hash on the output
    output.input_hash = input_hash;

    // 5. Commit output to journal
    env::commit(&output);
}
