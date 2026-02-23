/**
 * Integrity certificate format module.
 *
 * Defines a machine-readable integrity certificate modeled on C2PA content
 * credentials and W3C Verifiable Credentials. The certificate bundles all
 * cryptographic evidence for a checkpoint into a single, self-describing
 * document that can be independently verified.
 *
 * Types:
 * - IntegrityCertificate — the full certificate envelope
 * - CertificateInput — builder input for constructing a certificate
 * - SignedPayloadInput — input for building the canonical signed payload
 *
 * Functions:
 * - buildCertificate — assembles an IntegrityCertificate from analysis outputs
 * - buildSignedPayload — constructs the deterministic JSON string that gets signed
 * - generateCertificateId — produces a "cert-{8 random chars}" identifier
 */

// ============================================
// Types
// ============================================

export interface IntegrityCertificate {
  '@context': 'https://mnemom.ai/aip/v1';
  type: 'IntegrityCertificate';
  version: '1.0.0';
  certificate_id: string;
  issued_at: string;

  subject: {
    checkpoint_id: string;
    agent_id: string;
    session_id: string;
    card_id: string;
  };

  claims: {
    verdict: string;
    concerns: Array<{
      category: string;
      severity: string;
      description: string;
    }>;
    confidence: number;
    reasoning_summary: string;
    analysis_model: string;
    analysis_duration_ms: number;
  };

  input_commitments: {
    thinking_block_hash: string;
    card_hash: string;
    values_hash: string;
    context_hash: string;
    model_version: string;
    combined_commitment: string;
  };

  proofs: {
    signature: {
      algorithm: 'Ed25519';
      key_id: string;
      value: string;
      signed_payload: string;
    };
    chain: {
      chain_hash: string;
      prev_chain_hash: string | null;
      position: number;
    };
    merkle: {
      leaf_hash: string;
      leaf_index: number;
      root: string;
      tree_size: number;
      inclusion_proof: Array<{ hash: string; position: 'left' | 'right' }>;
    } | null;
    verdict_derivation: null;
  };

  verification: {
    keys_url: string;
    certificate_url: string;
    verify_url: string;
  };
}

export interface CertificateInput {
  checkpointId: string;
  agentId: string;
  sessionId: string;
  cardId: string;
  verdict: string;
  concerns: Array<{ category: string; severity: string; description: string }>;
  confidence: number;
  reasoningSummary: string;
  analysisModel: string;
  analysisDurationMs: number;
  thinkingBlockHash: string;
  cardHash: string;
  valuesHash: string;
  contextHash: string;
  modelVersion: string;
  inputCommitment: string;
  signatureKeyId: string;
  signatureValue: string;
  signedPayload: string;
  chainHash: string;
  prevChainHash: string | null;
  chainPosition: number;
  merkleData: {
    leafHash: string;
    leafIndex: number;
    root: string;
    treeSize: number;
    inclusionProof: Array<{ hash: string; position: 'left' | 'right' }>;
  } | null;
}

export interface SignedPayloadInput {
  checkpointId: string;
  agentId: string;
  verdict: string;
  thinkingBlockHash: string;
  inputCommitment: string;
  chainHash: string;
  timestamp: string;
}

// ============================================
// ID generation
// ============================================

/**
 * Generate a certificate ID in the format "cert-{8 random chars}".
 * Uses crypto.getRandomValues for cryptographic safety.
 */
export function generateCertificateId(): string {
  const bytes = new Uint8Array(4);
  crypto.getRandomValues(bytes);
  const id = Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  return `cert-${id}`;
}

// ============================================
// Signed payload
// ============================================

/**
 * Build the canonical string that gets signed for a checkpoint.
 *
 * The payload is a JSON string with sorted keys to ensure deterministic
 * output regardless of property insertion order. This exact string is
 * what the Ed25519 signature covers, allowing independent verification.
 */
export function buildSignedPayload(input: SignedPayloadInput): string {
  const payload = {
    agent_id: input.agentId,
    chain_hash: input.chainHash,
    checkpoint_id: input.checkpointId,
    input_commitment: input.inputCommitment,
    thinking_block_hash: input.thinkingBlockHash,
    timestamp: input.timestamp,
    verdict: input.verdict,
  };
  return JSON.stringify(payload, Object.keys(payload).sort());
}

// ============================================
// Certificate builder
// ============================================

/**
 * Assemble a complete IntegrityCertificate from analysis outputs.
 *
 * The certificate is a self-describing, machine-readable document that
 * bundles the analysis verdict, input commitments, cryptographic proofs
 * (signature, hash chain, Merkle inclusion), and verification endpoints
 * into a single envelope. Modeled on C2PA content credentials and W3C
 * Verifiable Credentials.
 */
export function buildCertificate(input: CertificateInput): IntegrityCertificate {
  return {
    '@context': 'https://mnemom.ai/aip/v1',
    type: 'IntegrityCertificate',
    version: '1.0.0',
    certificate_id: generateCertificateId(),
    issued_at: new Date().toISOString(),

    subject: {
      checkpoint_id: input.checkpointId,
      agent_id: input.agentId,
      session_id: input.sessionId,
      card_id: input.cardId,
    },

    claims: {
      verdict: input.verdict,
      concerns: input.concerns,
      confidence: input.confidence,
      reasoning_summary: input.reasoningSummary,
      analysis_model: input.analysisModel,
      analysis_duration_ms: input.analysisDurationMs,
    },

    input_commitments: {
      thinking_block_hash: input.thinkingBlockHash,
      card_hash: input.cardHash,
      values_hash: input.valuesHash,
      context_hash: input.contextHash,
      model_version: input.modelVersion,
      combined_commitment: input.inputCommitment,
    },

    proofs: {
      signature: {
        algorithm: 'Ed25519',
        key_id: input.signatureKeyId,
        value: input.signatureValue,
        signed_payload: input.signedPayload,
      },
      chain: {
        chain_hash: input.chainHash,
        prev_chain_hash: input.prevChainHash,
        position: input.chainPosition,
      },
      merkle: input.merkleData
        ? {
            leaf_hash: input.merkleData.leafHash,
            leaf_index: input.merkleData.leafIndex,
            root: input.merkleData.root,
            tree_size: input.merkleData.treeSize,
            inclusion_proof: input.merkleData.inclusionProof,
          }
        : null,
      verdict_derivation: null,
    },

    verification: {
      keys_url: 'https://api.mnemom.ai/v1/keys',
      certificate_url: `https://api.mnemom.ai/v1/checkpoints/${input.checkpointId}/certificate`,
      verify_url: 'https://api.mnemom.ai/v1/verify',
    },
  };
}
