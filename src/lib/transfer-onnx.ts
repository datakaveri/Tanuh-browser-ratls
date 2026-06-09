/**
 * Secure ONNX model transfer — three-step protocol:
 *
 * 1. SHA-256 hash each file in 16 MB streaming chunks (peak: ~16 MB)
 * 2. POST /v1/submit  (HPKE-encrypted, tiny)
 *    { dataset_id, model_sha256, weights_sha256 }
 *    → Buffer TEE creates job, returns { job_id }
 * 3. PUT /v1/upload/:job_id/model   (AES-256-GCM-CHUNKED-v1, 16 MB chunks)
 *    PUT /v1/upload/:job_id/weights  (same)
 *    → Buffer TEE: HPKE-unwraps AES key, decrypts chunks, verifies SHA-256, forwards to Flask
 *
 * SHA-256 hashes are committed via HPKE before files arrive, so a MITM cannot
 * substitute files even if they intercept the upload channel.
 * AES-256-GCM per-chunk authentication tags prevent any in-transit modification.
 * HPKE key-wrap ensures only the attested TEE can decrypt the AES key.
 */

import { sha256 as nobleSha256 } from "@noble/hashes/sha256"
import { attestAndOpen } from "./index"
import type { OpenedSession } from "./types"

const HASH_CHUNK = 16 * 1024 * 1024  // 16 MB — streaming hash chunk

export type StepName =
  | "attest_start"
  | "attest_done"
  | "model_hash"
  | "submit_meta"
  | "upload_model"
  | "upload_weights"
  | "done"
  | "error"

export interface TransferOptions {
  teeUrl:      string
  modelFile:   File
  weightsFile: File
  datasetId:   1 | 2 | 3
  onStep?:     (step: StepName, detail: string) => void
}

export interface TransferResult {
  oidc:      OpenedSession["oidc"]
  response:  unknown
  elapsedMs: number
}

export async function transferOnnxModel(opts: TransferOptions): Promise<TransferResult> {
  const { teeUrl, modelFile, weightsFile, datasetId, onStep = () => {} } = opts
  const t0 = performance.now()

  // ── 1. RA-TLS attestation ─────────────────────────────────────────────────
  onStep("attest_start", `Attesting Buffer TEE at ${teeUrl}…`)
  let session: OpenedSession
  try {
    session = await attestAndOpen({ attestUrl: teeUrl })
  } catch (err) {
    onStep("error", `Attestation failed: ${err instanceof Error ? err.message : err}`)
    throw err
  }
  onStep("attest_done",
    `Digest: ${session.oidc.submods?.container?.image_digest ?? "—"} · HW: ${session.oidc.hwmodel ?? "—"}`)

  // ── 2. Streaming SHA-256 (16 MB at a time, ~16 MB peak) ──────────────────
  onStep("model_hash", `Hashing model (${fmt(modelFile.size)})…`)
  const modelSHA256 = await computeSHA256Streaming(modelFile)

  onStep("model_hash", `Hashing weights (${fmt(weightsFile.size)})…`)
  const weightsSHA256 = await computeSHA256Streaming(weightsFile)
  onStep("model_hash", "SHA-256 computed")

  // ── 3. HPKE-encrypt tiny metadata → POST /v1/submit ──────────────────────
  onStep("submit_meta", "Sending HPKE-encrypted job metadata…")
  let response: unknown
  try {
    response = await session.send("/v1/submit", {
      dataset_id:     datasetId,
      model_sha256:   modelSHA256,
      weights_sha256: weightsSHA256,
    })
  } catch (err) {
    onStep("error", `Metadata submit failed: ${err instanceof Error ? err.message : err}`)
    throw err
  }

  const jobResult = response as Record<string, unknown>
  const jobId = jobResult.job_id as string
  if (!jobId) throw new Error(`No job_id in response: ${JSON.stringify(response)}`)

  // ── 4. Envelope-encrypted chunked upload ─────────────────────────────────
  onStep("upload_model", `Encrypting + uploading model (${fmt(modelFile.size)})…`)
  try {
    await session.uploadEncrypted(
      `/v1/upload/${jobId}/model`,
      modelFile,
      modelSHA256,
      pct => onStep("upload_model", `${pct}%`),
    )
  } catch (err) {
    onStep("error", `Model upload failed: ${err instanceof Error ? err.message : err}`)
    throw err
  }

  onStep("upload_weights", `Encrypting + uploading weights (${fmt(weightsFile.size)})…`)
  let finalResponse: unknown
  try {
    await session.uploadEncrypted(
      `/v1/upload/${jobId}/weights`,
      weightsFile,
      weightsSHA256,
      pct => onStep("upload_weights", `${pct}%`),
    )
    finalResponse = { job_id: jobId, status: "queued" }
  } catch (err) {
    onStep("error", `Weights upload failed: ${err instanceof Error ? err.message : err}`)
    throw err
  }

  const elapsedMs = Math.round(performance.now() - t0)
  onStep("done", `Job queued in ${elapsedMs}ms`)

  return { oidc: session.oidc, response: finalResponse, elapsedMs }
}

async function computeSHA256Streaming(file: File): Promise<string> {
  const hasher = nobleSha256.create()
  let offset = 0
  while (offset < file.size) {
    const buf = await file.slice(offset, offset + HASH_CHUNK).arrayBuffer()
    hasher.update(new Uint8Array(buf))
    offset += HASH_CHUNK
  }
  const digest = hasher.digest()
  return Array.from(digest).map(b => b.toString(16).padStart(2, "0")).join("")
}

function fmt(n: number): string {
  if (n < 1024)        return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(2)} MB`
}
