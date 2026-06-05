/**
 * Secure ONNX model transfer — two-step protocol:
 *
 * 1. POST /v1/submit  (HPKE-encrypted, tiny)
 *    { action, dataset_id, model_sha256, weights_sha256, submitted_by }
 *    → Buffer TEE creates job, returns { job_id }
 *
 * 2. PUT /v1/upload/:job_id/model   (binary, TLS-encrypted in transit)
 *    PUT /v1/upload/:job_id/weights  (binary, TLS-encrypted in transit)
 *    → Buffer TEE verifies SHA256 against committed hashes, queues job
 *
 * SHA256 hashes are committed via HPKE before the files arrive,
 * so a MITM cannot swap the files without detection.
 */

import { attestAndOpen } from "./index"
import type { OpenedSession } from "./types"

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
  teeUrl:       string
  modelFile:    File
  weightsFile:  File
  datasetId:    1 | 2 | 3
  submittedBy?: string
  onStep?:      (step: StepName, detail: string) => void
}

export interface TransferResult {
  oidc:      OpenedSession["oidc"]
  response:  unknown
  elapsedMs: number
}

export async function transferOnnxModel(opts: TransferOptions): Promise<TransferResult> {
  const { teeUrl, modelFile, weightsFile, datasetId,
          submittedBy = "tanuh-browser", onStep = () => {} } = opts
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

  // ── 2. SHA256 both files (native WebCrypto — fast) ────────────────────────
  onStep("model_hash", `Hashing model (${fmt(modelFile.size)}) + weights (${fmt(weightsFile.size)})…`)

  const [modelBuf, weightsBuf] = await Promise.all([
    modelFile.arrayBuffer(),
    weightsFile.arrayBuffer(),
  ])
  const [modelHashBuf, weightsHashBuf] = await Promise.all([
    crypto.subtle.digest("SHA-256", modelBuf),
    crypto.subtle.digest("SHA-256", weightsBuf),
  ])
  const modelSHA256   = hex(modelHashBuf)
  const weightsSHA256 = hex(weightsHashBuf)
  onStep("model_hash", `SHA256 computed`)

  // ── 3. HPKE-encrypt tiny metadata → POST /v1/submit ──────────────────────
  onStep("submit_meta", "Sending HPKE-encrypted job metadata…")
  let response: unknown
  try {
    response = await session.send("/v1/submit", {
      action:         "submit_job",
      dataset_id:     datasetId,
      model_sha256:   modelSHA256,
      weights_sha256: weightsSHA256,
      submitted_by:   submittedBy,
    })
  } catch (err) {
    onStep("error", `Metadata submit failed: ${err instanceof Error ? err.message : err}`)
    throw err
  }

  const jobResult = response as Record<string, unknown>
  const jobId = jobResult.job_id as string
  if (!jobId) throw new Error(`No job_id in response: ${JSON.stringify(response)}`)

  // ── 4. Upload binary files over TLS ───────────────────────────────────────
  const uploadBase = teeUrl ? teeUrl : ""

  onStep("upload_model", `Uploading model (${fmt(modelFile.size)}) over TLS…`)
  const modelResp = await fetch(`${uploadBase}/v1/upload/${jobId}/model`, {
    method:  "PUT",
    headers: { "Content-Type": "application/octet-stream" },
    body:    modelBuf,
  })
  if (!modelResp.ok) throw new Error(`model upload failed: ${modelResp.status}`)

  onStep("upload_weights", `Uploading weights (${fmt(weightsFile.size)}) over TLS…`)
  const weightsResp = await fetch(`${uploadBase}/v1/upload/${jobId}/weights`, {
    method:  "PUT",
    headers: { "Content-Type": "application/octet-stream" },
    body:    weightsBuf,
  })
  if (!weightsResp.ok) throw new Error(`weights upload failed: ${weightsResp.status}`)

  const elapsedMs = Math.round(performance.now() - t0)
  onStep("done", `Job queued in ${elapsedMs}ms`)

  return { oidc: session.oidc, response: await weightsResp.json(), elapsedMs }
}

function hex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("")
}

function fmt(n: number): string {
  if (n < 1024)        return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(2)} MB`
}
