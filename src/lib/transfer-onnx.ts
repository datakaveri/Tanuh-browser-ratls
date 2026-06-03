/**
 * Secure ONNX model transfer over an RA-TLS attested HPKE channel.
 *
 * Usage:
 *   import { transferOnnxModel } from "./demo/transfer-onnx"
 *
 *   const result = await transferOnnxModel({
 *     teeUrl:   "https://35.239.166.229:8443",
 *     file:     fileInputEl.files[0],
 *     endpoint: "/v1/model/upload",
 *     onStep:   (step, detail) => console.log(step, detail),
 *   })
 *
 * Flow:
 *   1. Nonce generated in browser
 *   2. GET /v1/attest  → AttestBundle
 *   3. Bundle verified: OIDC sig, image digest, eat_nonce bindings, liveness ECDSA
 *   4. HPKE session opened (X25519 / AES-256-GCM)
 *   5. Model base64-encoded and HPKE-sealed → POST endpoint
 *   6. TEE response HPKE-decrypted and returned
 */

import { attestAndOpen } from "./index"
import type { OpenedSession } from "./types"

export type StepName =
  | "attest_start"
  | "attest_done"
  | "model_read"
  | "encrypt_send"
  | "done"
  | "error"

export interface TransferOptions {
  /** Base URL of the TEE, e.g. "https://35.239.166.229:8443" */
  teeUrl: string
  /** ONNX model file selected by the user */
  file: File
  /** TEE API path to POST the model to, e.g. "/v1/model/upload" */
  endpoint?: string
  /**
   * Optional progress callback.
   * Called at each step with a label and human-readable detail string.
   */
  onStep?: (step: StepName, detail: string) => void
}

export interface TransferResult {
  /** Verified OIDC claims from the TEE (image digest, hw model, etc.) */
  oidc: OpenedSession["oidc"]
  /** Raw response from the TEE after HPKE decryption */
  response: unknown
  /** Milliseconds taken for attestation + transfer */
  elapsedMs: number
}

/**
 * End-to-end secure ONNX model transfer:
 *   attest TEE → open HPKE session → encrypt model → POST → decrypt response
 */
export async function transferOnnxModel(opts: TransferOptions): Promise<TransferResult> {
  const { teeUrl, file, endpoint = "/v1/model/upload", onStep = () => {} } = opts
  const t0 = performance.now()

  // ── Step 1: RA-TLS attestation ───────────────────────────────────────────
  onStep("attest_start", `Attesting TEE at ${teeUrl}…`)

  let session: OpenedSession
  try {
    session = await attestAndOpen({ attestUrl: teeUrl })
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    onStep("error", `Attestation failed: ${msg}`)
    throw err
  }

  onStep("attest_done", [
    `Digest: ${session.oidc.submods?.container?.image_digest ?? "—"}`,
    `HW: ${session.oidc.hwmodel ?? "—"}`,
  ].join(" · "))

  // ── Step 2: Read the ONNX file into memory ───────────────────────────────
  onStep("model_read", `Reading ${file.name} (${formatBytes(file.size)})…`)
  const modelBytes = await file.arrayBuffer()

  // Encode binary ONNX bytes as base64 for JSON transport.
  // The HPKE layer encrypts this payload end-to-end before it leaves the browser.
  const modelB64 = arrayBufferToBase64(modelBytes)
  onStep("model_read", `${file.name} · ${formatBytes(file.size)} · ready for encryption`)

  // ── Step 3: HPKE-seal and POST ───────────────────────────────────────────
  onStep("encrypt_send", `Encrypting and sending to ${endpoint}…`)

  let response: unknown
  try {
    response = await session.send(endpoint, {
      filename:    file.name,
      size_bytes:  file.size,
      model_b64:   modelB64,
      content_type: "application/octet-stream",
    })
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    onStep("error", `Transfer failed: ${msg}`)
    throw err
  }

  const elapsedMs = Math.round(performance.now() - t0)
  onStep("done", `Transfer complete in ${elapsedMs}ms`)

  return { oidc: session.oidc, response, elapsedMs }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function arrayBufferToBase64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf)
  let binary = ""
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(2)} MB`
}
