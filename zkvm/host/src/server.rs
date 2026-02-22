//! Axum HTTP proving service.
//!
//! Routes:
//!   POST /prove            — accept verdict proof request, spawn proving task
//!   POST /prove/risk       — accept risk proof request, spawn proving task
//!   POST /prove/team-risk  — accept team risk proof request, spawn proving task
//!   GET  /prove/:id        — proof status
//!   POST /prove/verify     — verify a receipt
//!   GET  /health           — health check

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing::{error, info, warn};

use aip_zkvm_core::fixed::Fixed;
use aip_zkvm_core::team_types::{TeamRiskInput, TeamRiskOutput};

use crate::prover;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub prover_key: Option<String>,
}

/// Proof request payload from the API worker.
#[derive(Deserialize)]
pub struct ProofRequest {
    pub proof_id: String,
    pub checkpoint_id: String,
    pub analysis_json: String,
    pub thinking_hash: String,
    pub card_hash: String,
    pub values_hash: String,
    pub model: String,
}

/// Proof response.
#[derive(Serialize)]
pub struct ProofResponse {
    pub proof_id: String,
    pub status: String,
}

/// Proof status response.
#[derive(Serialize)]
pub struct ProofStatusResponse {
    pub proof_id: String,
    pub status: String,
    pub proving_duration_ms: Option<i32>,
    pub verified: bool,
    pub error_message: Option<String>,
}

/// Verify request.
#[derive(Deserialize)]
pub struct VerifyRequest {
    pub receipt: String, // base64-encoded receipt bytes
    pub image_id: Option<String>,
}

/// Verify response.
#[derive(Serialize)]
pub struct VerifyResponse {
    pub valid: bool,
    pub verdict: Option<String>,
    pub action: Option<String>,
    pub concerns_hash: Option<String>,
    pub error: Option<String>,
}

/// Health check response.
#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

// ---------------------------------------------------------------------------
// Risk proof types
// ---------------------------------------------------------------------------

/// Reputation component scores (mirrors the guest-side type).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReputationComponents {
    pub integrity: Fixed,
    pub reliability: Fixed,
    pub competence: Fixed,
    pub transparency: Fixed,
    pub alignment: Fixed,
}

/// A single violation record (mirrors the guest-side type).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ViolationRecord {
    pub severity_weight: Fixed,
    pub days_since: Fixed,
}

/// Input to the individual risk guest program (mirrors the guest-side type).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RiskGuestInput {
    pub reputation: ReputationComponents,
    pub violations: Vec<ViolationRecord>,
    pub action_type: String,
    pub risk_tolerance: String,
}

/// Output committed by the individual risk guest program (mirrors the guest-side type).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RiskGuestOutput {
    pub risk_score: Fixed,
    pub risk_level: String,
    pub recommendation: String,
    pub input_hash: String,
}

/// Risk proof request payload.
#[derive(Deserialize)]
pub struct RiskProofRequest {
    pub proof_id: String,
    pub assessment_id: String,
    pub input_data: serde_json::Value,
}

/// Team risk proof request payload.
#[derive(Deserialize)]
pub struct TeamRiskProofRequest {
    pub proof_id: String,
    pub assessment_id: String,
    pub input_data: serde_json::Value,
}

/// Build the Axum router.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/prove", post(handle_prove))
        .route("/prove/risk", post(handle_prove_risk))
        .route("/prove/team-risk", post(handle_prove_team_risk))
        .route("/prove/{id}", get(handle_proof_status))
        .route("/prove/verify", post(handle_verify))
        .route("/health", get(handle_health))
        .layer(CorsLayer::permissive())
        .with_state(Arc::new(state))
}

/// Authenticate requests using X-Prover-Key header.
fn check_auth(headers: &HeaderMap, state: &AppState) -> Result<(), StatusCode> {
    if let Some(expected) = &state.prover_key {
        match headers.get("X-Prover-Key") {
            Some(key) if key.to_str().unwrap_or("") == expected => Ok(()),
            _ => Err(StatusCode::UNAUTHORIZED),
        }
    } else {
        Ok(()) // No key configured = auth disabled
    }
}

/// POST /prove — accept a proof request and spawn a background task.
async fn handle_prove(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ProofRequest>,
) -> Result<Json<ProofResponse>, StatusCode> {
    check_auth(&headers, &state)?;

    info!(proof_id = %req.proof_id, checkpoint_id = %req.checkpoint_id, "Received proof request");

    // Update status to 'proving'
    let _ = sqlx::query("UPDATE verdict_proofs SET status = 'proving', updated_at = now() WHERE proof_id = $1")
        .bind(&req.proof_id)
        .execute(&state.db)
        .await;

    // Spawn proving task in background
    let db = state.db.clone();
    let proof_id = req.proof_id.clone();
    tokio::spawn(async move {
        let start = std::time::Instant::now();

        match prover::prove_verdict_derivation(
            &req.analysis_json,
            &req.thinking_hash,
            &req.card_hash,
            &req.values_hash,
            &req.model,
        ) {
            Ok((receipt, output)) => {
                let duration_ms = start.elapsed().as_millis() as i32;
                let receipt_bytes = match prover::receipt_to_bytes(&receipt) {
                    Ok(b) => b,
                    Err(e) => {
                        error!(proof_id = %proof_id, "Failed to serialize receipt: {}", e);
                        let _ = sqlx::query(
                            "SELECT fail_proof($1, $2)"
                        )
                        .bind(&proof_id)
                        .bind(format!("Receipt serialization failed: {}", e))
                        .execute(&db)
                        .await;
                        return;
                    }
                };

                let journal_bytes = receipt.journal.bytes.clone();
                let verdict_str = serde_json::to_string(&output.verdict).unwrap_or_default();
                let image_id_hex: String = aip_zkvm_methods::AIP_ZKVM_GUEST_ID
                    .iter()
                    .flat_map(|w| w.to_le_bytes())
                    .map(|b| format!("{:02x}", b))
                    .collect();

                // Self-verify before writing
                let verified = prover::verify_verdict_proof(&receipt).is_ok();

                info!(
                    proof_id = %proof_id,
                    verdict = %verdict_str,
                    duration_ms = duration_ms,
                    verified = verified,
                    "Proof completed"
                );

                match sqlx::query(
                    "SELECT complete_proof($1, $2, $3, $4, $5, $6::numeric, $7, $8)"
                )
                .bind(&proof_id)
                .bind(&image_id_hex)
                .bind(&receipt_bytes)
                .bind(&journal_bytes)
                .bind(duration_ms)
                .bind(0.005f64) // estimated cost — explicit ::numeric cast for sqlx
                .bind(verified)
                .bind(if verified { Some(chrono::Utc::now()) } else { None })
                .execute(&db)
                .await {
                    Ok(_) => info!(proof_id = %proof_id, "Proof persisted to DB"),
                    Err(e) => error!(proof_id = %proof_id, "Failed to persist proof: {}", e),
                }
            }
            Err(e) => {
                error!(proof_id = %proof_id, "Proving failed: {}", e);
                let _ = sqlx::query(
                    "SELECT fail_proof($1, $2)"
                )
                .bind(&proof_id)
                .bind(format!("Proving failed: {}", e))
                .execute(&db)
                .await;
            }
        }
    });

    Ok(Json(ProofResponse {
        proof_id: req.proof_id,
        status: "proving".to_string(),
    }))
}

/// POST /prove/risk — accept a risk proof request and spawn a background task.
async fn handle_prove_risk(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<RiskProofRequest>,
) -> Result<Json<ProofResponse>, StatusCode> {
    check_auth(&headers, &state)?;

    info!(proof_id = %req.proof_id, assessment_id = %req.assessment_id, "Received risk proof request");

    // Deserialize input_data into the risk guest input
    let guest_input: RiskGuestInput = serde_json::from_value(req.input_data)
        .map_err(|e| {
            error!(proof_id = %req.proof_id, "Invalid risk input_data: {}", e);
            StatusCode::BAD_REQUEST
        })?;

    // Update status to 'proving'
    let _ = sqlx::query("UPDATE risk_proofs SET status = 'proving', updated_at = now() WHERE proof_id = $1")
        .bind(&req.proof_id)
        .execute(&state.db)
        .await;

    // Spawn proving task in background
    let db = state.db.clone();
    let proof_id = req.proof_id.clone();
    tokio::spawn(async move {
        let start = std::time::Instant::now();

        // Build ExecutorEnv with the input
        let env = match risc0_zkvm::ExecutorEnv::builder()
            .write(&guest_input)
            .and_then(|b| b.build())
        {
            Ok(e) => e,
            Err(e) => {
                error!(proof_id = %proof_id, "Failed to build executor env: {}", e);
                let _ = sqlx::query("SELECT fail_risk_proof($1, $2)")
                    .bind(&proof_id)
                    .bind(format!("Executor env build failed: {}", e))
                    .execute(&db)
                    .await;
                return;
            }
        };

        // Prove with the risk guest ELF
        match risc0_zkvm::default_prover()
            .prove(env, risk_zkvm_methods::RISK_ZKVM_GUEST_ELF)
        {
            Ok(prove_info) => {
                let duration_ms = start.elapsed().as_millis() as i32;
                let receipt = prove_info.receipt;

                // Decode journal
                let output: RiskGuestOutput = match receipt.journal.decode() {
                    Ok(o) => o,
                    Err(e) => {
                        error!(proof_id = %proof_id, "Failed to decode risk journal: {}", e);
                        let _ = sqlx::query("SELECT fail_risk_proof($1, $2)")
                            .bind(&proof_id)
                            .bind(format!("Journal decode failed: {}", e))
                            .execute(&db)
                            .await;
                        return;
                    }
                };

                let receipt_bytes = match prover::receipt_to_bytes(&receipt) {
                    Ok(b) => b,
                    Err(e) => {
                        error!(proof_id = %proof_id, "Failed to serialize risk receipt: {}", e);
                        let _ = sqlx::query("SELECT fail_risk_proof($1, $2)")
                            .bind(&proof_id)
                            .bind(format!("Receipt serialization failed: {}", e))
                            .execute(&db)
                            .await;
                        return;
                    }
                };

                let journal_bytes = receipt.journal.bytes.clone();
                let image_id_hex: String = risk_zkvm_methods::RISK_ZKVM_GUEST_ID
                    .iter()
                    .flat_map(|w| w.to_le_bytes())
                    .map(|b| format!("{:02x}", b))
                    .collect();

                // Self-verify receipt
                let verified = receipt
                    .verify(risk_zkvm_methods::RISK_ZKVM_GUEST_ID)
                    .is_ok();

                info!(
                    proof_id = %proof_id,
                    risk_level = %output.risk_level,
                    risk_score = ?output.risk_score,
                    duration_ms = duration_ms,
                    verified = verified,
                    "Risk proof completed"
                );

                match sqlx::query(
                    "SELECT complete_risk_proof($1, $2, $3, $4, $5, $6::numeric, $7, $8)"
                )
                .bind(&proof_id)
                .bind(&image_id_hex)
                .bind(&receipt_bytes)
                .bind(&journal_bytes)
                .bind(duration_ms)
                .bind(0.005f64)
                .bind(verified)
                .bind(if verified { Some(chrono::Utc::now()) } else { None })
                .execute(&db)
                .await {
                    Ok(_) => info!(proof_id = %proof_id, "Risk proof persisted to DB"),
                    Err(e) => error!(proof_id = %proof_id, "Failed to persist risk proof: {}", e),
                }
            }
            Err(e) => {
                error!(proof_id = %proof_id, "Risk proving failed: {}", e);
                let _ = sqlx::query("SELECT fail_risk_proof($1, $2)")
                    .bind(&proof_id)
                    .bind(format!("Proving failed: {}", e))
                    .execute(&db)
                    .await;
            }
        }
    });

    Ok(Json(ProofResponse {
        proof_id: req.proof_id,
        status: "proving".to_string(),
    }))
}

/// POST /prove/team-risk — accept a team risk proof request and spawn a background task.
async fn handle_prove_team_risk(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<TeamRiskProofRequest>,
) -> Result<Json<ProofResponse>, StatusCode> {
    check_auth(&headers, &state)?;

    info!(proof_id = %req.proof_id, assessment_id = %req.assessment_id, "Received team risk proof request");

    // Deserialize input_data into the team risk input
    let guest_input: TeamRiskInput = serde_json::from_value(req.input_data)
        .map_err(|e| {
            error!(proof_id = %req.proof_id, "Invalid team risk input_data: {}", e);
            StatusCode::BAD_REQUEST
        })?;

    // Update status to 'proving'
    let _ = sqlx::query("UPDATE risk_proofs SET status = 'proving', updated_at = now() WHERE proof_id = $1")
        .bind(&req.proof_id)
        .execute(&state.db)
        .await;

    // Spawn proving task in background
    let db = state.db.clone();
    let proof_id = req.proof_id.clone();
    tokio::spawn(async move {
        let start = std::time::Instant::now();

        // Build ExecutorEnv with the input
        let env = match risc0_zkvm::ExecutorEnv::builder()
            .write(&guest_input)
            .and_then(|b| b.build())
        {
            Ok(e) => e,
            Err(e) => {
                error!(proof_id = %proof_id, "Failed to build executor env: {}", e);
                let _ = sqlx::query("SELECT fail_risk_proof($1, $2)")
                    .bind(&proof_id)
                    .bind(format!("Executor env build failed: {}", e))
                    .execute(&db)
                    .await;
                return;
            }
        };

        // Prove with the team risk guest ELF
        match risc0_zkvm::default_prover()
            .prove(env, team_risk_zkvm_methods::TEAM_RISK_ZKVM_GUEST_ELF)
        {
            Ok(prove_info) => {
                let duration_ms = start.elapsed().as_millis() as i32;
                let receipt = prove_info.receipt;

                // Decode journal
                let output: TeamRiskOutput = match receipt.journal.decode() {
                    Ok(o) => o,
                    Err(e) => {
                        error!(proof_id = %proof_id, "Failed to decode team risk journal: {}", e);
                        let _ = sqlx::query("SELECT fail_risk_proof($1, $2)")
                            .bind(&proof_id)
                            .bind(format!("Journal decode failed: {}", e))
                            .execute(&db)
                            .await;
                        return;
                    }
                };

                let receipt_bytes = match prover::receipt_to_bytes(&receipt) {
                    Ok(b) => b,
                    Err(e) => {
                        error!(proof_id = %proof_id, "Failed to serialize team risk receipt: {}", e);
                        let _ = sqlx::query("SELECT fail_risk_proof($1, $2)")
                            .bind(&proof_id)
                            .bind(format!("Receipt serialization failed: {}", e))
                            .execute(&db)
                            .await;
                        return;
                    }
                };

                let journal_bytes = receipt.journal.bytes.clone();
                let image_id_hex: String = team_risk_zkvm_methods::TEAM_RISK_ZKVM_GUEST_ID
                    .iter()
                    .flat_map(|w| w.to_le_bytes())
                    .map(|b| format!("{:02x}", b))
                    .collect();

                // Self-verify receipt
                let verified = receipt
                    .verify(team_risk_zkvm_methods::TEAM_RISK_ZKVM_GUEST_ID)
                    .is_ok();

                info!(
                    proof_id = %proof_id,
                    team_risk_score = ?output.team_risk_score,
                    circuit_breaker = output.circuit_breaker_triggered,
                    duration_ms = duration_ms,
                    verified = verified,
                    "Team risk proof completed"
                );

                match sqlx::query(
                    "SELECT complete_risk_proof($1, $2, $3, $4, $5, $6::numeric, $7, $8)"
                )
                .bind(&proof_id)
                .bind(&image_id_hex)
                .bind(&receipt_bytes)
                .bind(&journal_bytes)
                .bind(duration_ms)
                .bind(0.005f64)
                .bind(verified)
                .bind(if verified { Some(chrono::Utc::now()) } else { None })
                .execute(&db)
                .await {
                    Ok(_) => info!(proof_id = %proof_id, "Team risk proof persisted to DB"),
                    Err(e) => error!(proof_id = %proof_id, "Failed to persist team risk proof: {}", e),
                }
            }
            Err(e) => {
                error!(proof_id = %proof_id, "Team risk proving failed: {}", e);
                let _ = sqlx::query("SELECT fail_risk_proof($1, $2)")
                    .bind(&proof_id)
                    .bind(format!("Proving failed: {}", e))
                    .execute(&db)
                    .await;
            }
        }
    });

    Ok(Json(ProofResponse {
        proof_id: req.proof_id,
        status: "proving".to_string(),
    }))
}

/// GET /prove/:id — get proof status.
async fn handle_proof_status(
    State(state): State<Arc<AppState>>,
    Path(proof_id): Path<String>,
) -> Result<Json<ProofStatusResponse>, StatusCode> {
    let row = sqlx::query_as::<_, (String, String, Option<i32>, bool, Option<String>)>(
        "SELECT proof_id, status, proving_duration_ms, verified, error_message FROM verdict_proofs WHERE proof_id = $1"
    )
    .bind(&proof_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match row {
        Some((id, status, duration, verified, error)) => Ok(Json(ProofStatusResponse {
            proof_id: id,
            status,
            proving_duration_ms: duration,
            verified,
            error_message: error,
        })),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// POST /prove/verify — verify a receipt.
async fn handle_verify(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<VerifyRequest>,
) -> Json<VerifyResponse> {
    if let Err(_) = check_auth(&headers, &state) {
        return Json(VerifyResponse {
            valid: false,
            verdict: None,
            action: None,
            concerns_hash: None,
            error: Some("Unauthorized".to_string()),
        });
    }

    // Decode base64 receipt
    let receipt_bytes = match base64_decode(&req.receipt) {
        Ok(b) => b,
        Err(e) => {
            return Json(VerifyResponse {
                valid: false,
                verdict: None,
                action: None,
                concerns_hash: None,
                error: Some(format!("Invalid receipt encoding: {}", e)),
            });
        }
    };

    let receipt = match prover::receipt_from_bytes(&receipt_bytes) {
        Ok(r) => r,
        Err(e) => {
            return Json(VerifyResponse {
                valid: false,
                verdict: None,
                action: None,
                concerns_hash: None,
                error: Some(format!("Invalid receipt: {}", e)),
            });
        }
    };

    match prover::verify_verdict_proof(&receipt) {
        Ok(output) => Json(VerifyResponse {
            valid: true,
            verdict: Some(serde_json::to_string(&output.verdict).unwrap_or_default().trim_matches('"').to_string()),
            action: Some(serde_json::to_string(&output.action).unwrap_or_default().trim_matches('"').to_string()),
            concerns_hash: Some(output.concerns_hash),
            error: None,
        }),
        Err(e) => Json(VerifyResponse {
            valid: false,
            verdict: None,
            action: None,
            concerns_hash: None,
            error: Some(format!("Verification failed: {}", e)),
        }),
    }
}

/// GET /health — health check.
async fn handle_health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// Simple base64 decode (avoiding extra deps).
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    use base64_engine::*;
    STANDARD.decode(input).map_err(|e| e.to_string())
}

mod base64_engine {
    pub use base64::engine::general_purpose::STANDARD;
    pub use base64::Engine;
}

/// Row returned by the updated get_pending_proofs function.
#[derive(sqlx::FromRow)]
struct PendingProof {
    proof_id: String,
    #[allow(dead_code)]
    checkpoint_id: String,
    retry_count: i32,
    #[allow(dead_code)]
    created_at: chrono::DateTime<chrono::Utc>,
    analysis_json: Option<String>,
    thinking_hash: Option<String>,
    card_hash: Option<String>,
    values_hash: Option<String>,
    model: Option<String>,
}

/// Row returned by get_pending_risk_proofs.
#[derive(sqlx::FromRow)]
struct PendingRiskProof {
    proof_id: String,
    #[allow(dead_code)]
    assessment_id: String,
    proof_type: String,
    retry_count: i32,
    #[allow(dead_code)]
    created_at: chrono::DateTime<chrono::Utc>,
    input_data: Option<serde_json::Value>,
}

/// Background retry loop for pending proofs.
///
/// Every 30 seconds, fetches pending proofs that have stored input data
/// and spawns proving tasks for them — the same logic as handle_prove.
pub async fn retry_loop(db: PgPool) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;

        // Self-ping: make an HTTP request to our own health endpoint so
        // Fly.io sees sustained HTTP activity and doesn't auto-stop us.
        let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
        if let Ok(mut stream) = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await {
            use tokio::io::AsyncWriteExt;
            let _ = stream.write_all(
                format!("GET /health HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n", port).as_bytes()
            ).await;
        }

        let pending = sqlx::query_as::<_, PendingProof>(
            "SELECT proof_id, checkpoint_id, retry_count, created_at, \
                    analysis_json, thinking_hash, card_hash, values_hash, model \
             FROM get_pending_proofs(5)"
        )
        .fetch_all(&db)
        .await;

        match pending {
            Ok(rows) if !rows.is_empty() => {
                info!(count = rows.len(), "Retrying pending proofs");
                for row in rows {
                    let analysis_json = match row.analysis_json {
                        Some(v) if !v.is_empty() => v,
                        _ => {
                            warn!(proof_id = %row.proof_id, "Skipping retry: missing analysis_json");
                            continue;
                        }
                    };
                    let thinking_hash = row.thinking_hash.unwrap_or_default();
                    let card_hash = row.card_hash.unwrap_or_default();
                    let values_hash = row.values_hash.unwrap_or_default();
                    let model = row.model.unwrap_or_else(|| "unknown".to_string());

                    info!(proof_id = %row.proof_id, retry_count = row.retry_count, "Spawning retry proof");

                    // Mark as proving
                    let _ = sqlx::query(
                        "UPDATE verdict_proofs SET status = 'proving', updated_at = now() WHERE proof_id = $1"
                    )
                    .bind(&row.proof_id)
                    .execute(&db)
                    .await;

                    // Spawn proving task (same logic as handle_prove)
                    let db_clone = db.clone();
                    let proof_id = row.proof_id.clone();
                    tokio::spawn(async move {
                        let start = std::time::Instant::now();

                        match prover::prove_verdict_derivation(
                            &analysis_json,
                            &thinking_hash,
                            &card_hash,
                            &values_hash,
                            &model,
                        ) {
                            Ok((receipt, output)) => {
                                let duration_ms = start.elapsed().as_millis() as i32;
                                let receipt_bytes = match prover::receipt_to_bytes(&receipt) {
                                    Ok(b) => b,
                                    Err(e) => {
                                        error!(proof_id = %proof_id, "Failed to serialize receipt: {}", e);
                                        let _ = sqlx::query("SELECT fail_proof($1, $2)")
                                            .bind(&proof_id)
                                            .bind(format!("Receipt serialization failed: {}", e))
                                            .execute(&db_clone)
                                            .await;
                                        return;
                                    }
                                };

                                let journal_bytes = receipt.journal.bytes.clone();
                                let verdict_str = serde_json::to_string(&output.verdict).unwrap_or_default();
                                let image_id_hex: String = aip_zkvm_methods::AIP_ZKVM_GUEST_ID
                                    .iter()
                                    .flat_map(|w| w.to_le_bytes())
                                    .map(|b| format!("{:02x}", b))
                                    .collect();

                                let verified = prover::verify_verdict_proof(&receipt).is_ok();

                                info!(
                                    proof_id = %proof_id,
                                    verdict = %verdict_str,
                                    duration_ms = duration_ms,
                                    verified = verified,
                                    "Retry proof completed"
                                );

                                let _ = sqlx::query(
                                    "SELECT complete_proof($1, $2, $3, $4, $5, $6::numeric, $7, $8)"
                                )
                                .bind(&proof_id)
                                .bind(&image_id_hex)
                                .bind(&receipt_bytes)
                                .bind(&journal_bytes)
                                .bind(duration_ms)
                                .bind(0.005f64)
                                .bind(verified)
                                .bind(if verified { Some(chrono::Utc::now()) } else { None })
                                .execute(&db_clone)
                                .await;
                            }
                            Err(e) => {
                                error!(proof_id = %proof_id, "Retry proving failed: {}", e);
                                let _ = sqlx::query("SELECT fail_proof($1, $2)")
                                    .bind(&proof_id)
                                    .bind(format!("Proving failed: {}", e))
                                    .execute(&db_clone)
                                    .await;
                            }
                        }
                    });
                }
            }
            Ok(_) => {} // No pending proofs
            Err(e) => {
                warn!("Failed to query pending proofs: {}", e);
            }
        }

        // --- Risk proofs retry ---
        let pending_risk = sqlx::query_as::<_, PendingRiskProof>(
            "SELECT proof_id, assessment_id, proof_type, retry_count, created_at, input_data \
             FROM get_pending_risk_proofs(5)"
        )
        .fetch_all(&db)
        .await;

        match pending_risk {
            Ok(rows) if !rows.is_empty() => {
                info!(count = rows.len(), "Retrying pending risk proofs");
                for row in rows {
                    let input_data = match row.input_data {
                        Some(v) => v,
                        None => {
                            warn!(proof_id = %row.proof_id, "Skipping risk retry: missing input_data");
                            continue;
                        }
                    };

                    info!(proof_id = %row.proof_id, proof_type = %row.proof_type, retry_count = row.retry_count, "Spawning risk proof retry");

                    // Mark as proving
                    let _ = sqlx::query(
                        "UPDATE risk_proofs SET status = 'proving', updated_at = now() WHERE proof_id = $1"
                    )
                    .bind(&row.proof_id)
                    .execute(&db)
                    .await;

                    let db_clone = db.clone();
                    let proof_id = row.proof_id.clone();
                    let proof_type = row.proof_type.clone();

                    tokio::spawn(async move {
                        let start = std::time::Instant::now();

                        if proof_type == "team_risk" {
                            // --- Team risk proof ---
                            let guest_input: TeamRiskInput = match serde_json::from_value(input_data) {
                                Ok(v) => v,
                                Err(e) => {
                                    error!(proof_id = %proof_id, "Failed to deserialize team risk input: {}", e);
                                    let _ = sqlx::query("SELECT fail_risk_proof($1, $2)")
                                        .bind(&proof_id)
                                        .bind(format!("Input deserialization failed: {}", e))
                                        .execute(&db_clone)
                                        .await;
                                    return;
                                }
                            };

                            let env = match risc0_zkvm::ExecutorEnv::builder()
                                .write(&guest_input)
                                .and_then(|b| b.build())
                            {
                                Ok(e) => e,
                                Err(e) => {
                                    error!(proof_id = %proof_id, "Failed to build executor env: {}", e);
                                    let _ = sqlx::query("SELECT fail_risk_proof($1, $2)")
                                        .bind(&proof_id)
                                        .bind(format!("Executor env build failed: {}", e))
                                        .execute(&db_clone)
                                        .await;
                                    return;
                                }
                            };

                            match risc0_zkvm::default_prover()
                                .prove(env, team_risk_zkvm_methods::TEAM_RISK_ZKVM_GUEST_ELF)
                            {
                                Ok(prove_info) => {
                                    let duration_ms = start.elapsed().as_millis() as i32;
                                    let receipt = prove_info.receipt;
                                    let receipt_bytes = match prover::receipt_to_bytes(&receipt) {
                                        Ok(b) => b,
                                        Err(e) => {
                                            error!(proof_id = %proof_id, "Failed to serialize receipt: {}", e);
                                            let _ = sqlx::query("SELECT fail_risk_proof($1, $2)")
                                                .bind(&proof_id)
                                                .bind(format!("Receipt serialization failed: {}", e))
                                                .execute(&db_clone)
                                                .await;
                                            return;
                                        }
                                    };

                                    let journal_bytes = receipt.journal.bytes.clone();
                                    let image_id_hex: String = team_risk_zkvm_methods::TEAM_RISK_ZKVM_GUEST_ID
                                        .iter()
                                        .flat_map(|w| w.to_le_bytes())
                                        .map(|b| format!("{:02x}", b))
                                        .collect();
                                    let verified = receipt.verify(team_risk_zkvm_methods::TEAM_RISK_ZKVM_GUEST_ID).is_ok();

                                    info!(proof_id = %proof_id, duration_ms = duration_ms, verified = verified, "Retry team risk proof completed");

                                    let _ = sqlx::query("SELECT complete_risk_proof($1, $2, $3, $4, $5, $6::numeric, $7, $8)")
                                        .bind(&proof_id)
                                        .bind(&image_id_hex)
                                        .bind(&receipt_bytes)
                                        .bind(&journal_bytes)
                                        .bind(duration_ms)
                                        .bind(0.005f64)
                                        .bind(verified)
                                        .bind(if verified { Some(chrono::Utc::now()) } else { None })
                                        .execute(&db_clone)
                                        .await;
                                }
                                Err(e) => {
                                    error!(proof_id = %proof_id, "Retry team risk proving failed: {}", e);
                                    let _ = sqlx::query("SELECT fail_risk_proof($1, $2)")
                                        .bind(&proof_id)
                                        .bind(format!("Proving failed: {}", e))
                                        .execute(&db_clone)
                                        .await;
                                }
                            }
                        } else {
                            // --- Individual risk proof ---
                            let guest_input: RiskGuestInput = match serde_json::from_value(input_data) {
                                Ok(v) => v,
                                Err(e) => {
                                    error!(proof_id = %proof_id, "Failed to deserialize risk input: {}", e);
                                    let _ = sqlx::query("SELECT fail_risk_proof($1, $2)")
                                        .bind(&proof_id)
                                        .bind(format!("Input deserialization failed: {}", e))
                                        .execute(&db_clone)
                                        .await;
                                    return;
                                }
                            };

                            let env = match risc0_zkvm::ExecutorEnv::builder()
                                .write(&guest_input)
                                .and_then(|b| b.build())
                            {
                                Ok(e) => e,
                                Err(e) => {
                                    error!(proof_id = %proof_id, "Failed to build executor env: {}", e);
                                    let _ = sqlx::query("SELECT fail_risk_proof($1, $2)")
                                        .bind(&proof_id)
                                        .bind(format!("Executor env build failed: {}", e))
                                        .execute(&db_clone)
                                        .await;
                                    return;
                                }
                            };

                            match risc0_zkvm::default_prover()
                                .prove(env, risk_zkvm_methods::RISK_ZKVM_GUEST_ELF)
                            {
                                Ok(prove_info) => {
                                    let duration_ms = start.elapsed().as_millis() as i32;
                                    let receipt = prove_info.receipt;
                                    let receipt_bytes = match prover::receipt_to_bytes(&receipt) {
                                        Ok(b) => b,
                                        Err(e) => {
                                            error!(proof_id = %proof_id, "Failed to serialize receipt: {}", e);
                                            let _ = sqlx::query("SELECT fail_risk_proof($1, $2)")
                                                .bind(&proof_id)
                                                .bind(format!("Receipt serialization failed: {}", e))
                                                .execute(&db_clone)
                                                .await;
                                            return;
                                        }
                                    };

                                    let journal_bytes = receipt.journal.bytes.clone();
                                    let image_id_hex: String = risk_zkvm_methods::RISK_ZKVM_GUEST_ID
                                        .iter()
                                        .flat_map(|w| w.to_le_bytes())
                                        .map(|b| format!("{:02x}", b))
                                        .collect();
                                    let verified = receipt.verify(risk_zkvm_methods::RISK_ZKVM_GUEST_ID).is_ok();

                                    info!(proof_id = %proof_id, duration_ms = duration_ms, verified = verified, "Retry risk proof completed");

                                    let _ = sqlx::query("SELECT complete_risk_proof($1, $2, $3, $4, $5, $6::numeric, $7, $8)")
                                        .bind(&proof_id)
                                        .bind(&image_id_hex)
                                        .bind(&receipt_bytes)
                                        .bind(&journal_bytes)
                                        .bind(duration_ms)
                                        .bind(0.005f64)
                                        .bind(verified)
                                        .bind(if verified { Some(chrono::Utc::now()) } else { None })
                                        .execute(&db_clone)
                                        .await;
                                }
                                Err(e) => {
                                    error!(proof_id = %proof_id, "Retry risk proving failed: {}", e);
                                    let _ = sqlx::query("SELECT fail_risk_proof($1, $2)")
                                        .bind(&proof_id)
                                        .bind(format!("Proving failed: {}", e))
                                        .execute(&db_clone)
                                        .await;
                                }
                            }
                        }
                    });
                }
            }
            Ok(_) => {} // No pending risk proofs
            Err(e) => {
                warn!("Failed to query pending risk proofs: {}", e);
            }
        }
    }
}
