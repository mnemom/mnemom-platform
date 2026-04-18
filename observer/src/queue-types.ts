/**
 * Queue message types for Step 50 / ADR-010.
 *
 * Messages are reference-shaped — they carry pointers to source data (R2
 * object + index, or a CF AI Gateway polling log id) plus enough plaintext
 * metadata to filter / route without re-fetching. The consumer re-fetches
 * the full record on demand. This sidesteps the 128 KB CF Queue per-message
 * cap for records with large bodies, at the cost of one R2 GET per record.
 *
 * Messages are ≤1 KB each.
 */

export type ObserverSource = 'r2' | 'polling';

export interface ObserverQueueMessageR2 {
  source: 'r2';
  /** R2 object key, e.g. `20260418/20260418T000210Z_..._a3cfe972.log.gz`. */
  objectKey: string;
  /** Zero-based index of this record within the NDJSON object. */
  recordIndex: number;
  /** Plaintext header fields from the ai_gateway_events record. */
  gateway: string;
  provider: string;
  model: string;
  statusCode: number;
}

export interface ObserverQueueMessagePolling {
  source: 'polling';
  /** CF AI Gateway log id — the ULID from the REST `/logs` endpoint. */
  pollingLogId: string;
  /** Plaintext header fields from the CF polling response. */
  provider: string;
  model: string;
  success: boolean;
}

export type ObserverQueueMessage =
  | ObserverQueueMessageR2
  | ObserverQueueMessagePolling;
