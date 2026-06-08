# @datakaveri/tanuh-ratls-verifier

Browser-side TypeScript library for securely submitting ONNX models to a [TANUH Buffer TEE](https://github.com/datakaveri/Tanuh-buffer-tee-ratls) running on Google Confidential Space (AMD SEV).

The library performs three things before any data leaves the browser:

1. **RA-TLS attestation** — fetches and cryptographically verifies the enclave's identity (OIDC token, image digest, hardware model, liveness nonce)
2. **HPKE key exchange** — derives a browser-to-enclave encrypted channel; plaintext never touches the network
3. **Chunked AES-256-GCM upload** — encrypts files in 16 MB chunks with per-chunk authentication tags; HPKE-wraps the AES key so only the attested TEE can decrypt

---

## Installation

```bash
npm install @datakaveri/tanuh-ratls-verifier
```

**Peer dependencies** — install alongside:

```bash
npm install @hpke/core @noble/hashes jose
```

**Requirements**

- Modern browser (Chrome 90+, Firefox 90+, Safari 15+) — uses Web Crypto API and Web Workers
- Bundler with Web Worker support: **Vite** (recommended), webpack 5+
- ES2020 target or higher

---

## Quick start

### 1. Attest and open a secure session

```typescript
import { attestAndOpen } from "@datakaveri/tanuh-ratls-verifier"

const session = await attestAndOpen({
    attestUrl: "https://your-buffer-tee.example.com:8443",
})

// session.oidc contains the verified OIDC claims:
console.log(session.oidc.submods.container.image_digest)
console.log(session.oidc.hwmodel)  // "GCP_AMD_SEV_SNP"
```

### 2. Send an HPKE-encrypted JSON message

```typescript
const response = await session.send("/v1/submit", {
    action:         "submit_job",
    dataset_id:     1,
    model_sha256:   "<hex-sha256-of-model-onnx>",
    weights_sha256: "<hex-sha256-of-weights>",
    submitted_by:   "my-app",
}) as { job_id: string; status: string }
```

`send` encrypts the payload with HPKE (X25519 + AES-256-GCM), posts it to the TEE, and decrypts the encrypted response — all transparently.

### 3. Upload an encrypted file

```typescript
// Compute SHA-256 before uploading (committed via HPKE in step 2)
import { computeSHA256 } from "@datakaveri/tanuh-ratls-verifier"

const modelSha256 = await computeSHA256(modelFile)

await session.uploadEncrypted(
    `/v1/upload/${jobId}/model`,
    modelFile,          // File object (e.g. from <input type="file">)
    modelSha256,        // hex SHA-256 of plaintext
    (pct) => console.log(`Upload progress: ${pct}%`),
)
```

The file is encrypted in 16 MB chunks using AES-256-GCM. The AES key is HPKE-wrapped so only the attested TEE can decrypt it.

---

## Full ONNX transfer (high-level)

`transferOnnxModel` does everything in one call: attest → hash → submit metadata → upload model → upload weights.

```typescript
import { transferOnnxModel } from "@datakaveri/tanuh-ratls-verifier"

const result = await transferOnnxModel({
    teeUrl:       "https://your-buffer-tee.example.com:8443",
    modelFile,          // File — model.onnx
    weightsFile,        // File — weights binary
    datasetId:    1,    // 1 | 2 | 3
    submittedBy:  "my-app",
    onStep: (step, detail) => {
        console.log(`[${step}] ${detail}`)
    },
})

console.log(result.response)   // { job_id: "job-abc123", status: "queued" }
console.log(result.elapsedMs)
```

`onStep` fires with these `StepName` values in order:
`attest_start` → `attest_done` → `model_hash` → `submit_meta` → `upload_model` → `upload_weights` → `done`

---

## API reference

### Core

| Export | Description |
|--------|-------------|
| `attestAndOpen(opts: AttestOptions): Promise<OpenedSession>` | Attest the TEE and open a secure session. Main entry point. |
| `transferOnnxModel(opts: TransferOptions): Promise<TransferResult>` | High-level: hash + submit metadata + chunked upload for both files. |

### `OpenedSession` methods

| Method | Description |
|--------|-------------|
| `send(path, body): Promise<unknown>` | HPKE-encrypt a JSON payload, POST to TEE, decrypt response. |
| `uploadEncrypted(path, file, sha256hex, onProgress?): Promise<void>` | AES-256-GCM chunked upload with HPKE-wrapped key. |
| `hpkePub: Uint8Array` | Verified enclave HPKE public key (32 bytes). |
| `oidc: CSOidcPayload` | Verified OIDC claims from the attestation token. |

### Low-level

| Export | Description |
|--------|-------------|
| `verifyBundle(bundle, nonce, verifyOIDCFn?): Promise<VerifiedSession>` | Verify an `AttestBundle` manually (custom OIDC verifier, liveness check). |
| `Session` | HPKE session class for direct key operations (`encryptRequest`, `decryptResponse`, `sealSymmetricKey`). |
| `uploadChunked(url, data, sha256hex, session): Promise<Response>` | Low-level chunked upload from a `Uint8Array` (useful in Node.js tests). |

### Types

```typescript
AttestOptions       // { attestUrl: string }
OpenedSession       // session object returned by attestAndOpen
AttestBundle        // raw bundle JSON from GET /v1/attest
CSOidcPayload       // verified OIDC claims
VerifiedSession     // { hpkePub, verifiedAt, oidc }
OIDCVerifyFn        // (token, bindingSPKI, hpkePub) => Promise<CSOidcPayload>
TransferOptions     // options for transferOnnxModel
TransferResult      // { oidc, response, elapsedMs }
StepName            // union of step name strings
EncryptedRequest    // { enc, ciphertext, aad } — base64 fields
EncryptedResponse   // same shape as EncryptedRequest
```

### Constants

| Export | Value |
|--------|-------|
| `EXPECTED_IMAGE_DIGEST` | `"sha256:565af9d1..."` — current Buffer TEE image |
| `OIDC_AUDIENCE` | `"ratls-browser"` |
| `OIDC_ISSUER` | `"https://confidentialcomputing.googleapis.com"` |

### Debug / testing

```typescript
import { verifyOIDCDebug } from "@datakaveri/tanuh-ratls-verifier"
import { verifyBundle } from "@datakaveri/tanuh-ratls-verifier"

// Use verifyOIDCDebug with verifyBundle when the TEE has dbgstat=enabled.
// This skips the STABLE support_attributes check that Google omits on debug enclaves.
// NEVER use verifyOIDCDebug in production.
const session = await verifyBundle(bundle, nonce, verifyOIDCDebug)
```

---

## Security guarantees

| Property | Mechanism |
|----------|-----------|
| TEE identity verified before any data is sent | OIDC token (signed by Google), image digest check, liveness ECDSA signature over fresh nonce |
| Only the attested TEE can decrypt uploads | HPKE (X25519-HKDF-SHA256 + AES-256-GCM) — AES key wrapped to enclave's HPKE public key |
| Upload integrity per-chunk | AES-256-GCM authentication tag on every 16 MB chunk; chunk index and file ID in AAD prevent reorder/splice attacks |
| Plaintext hash committed before upload | SHA-256 sent inside HPKE-encrypted metadata before binary upload begins; TEE verifies hash on reassembly |
| HPKE channel bound to browser session | Browser ephemeral key in `X-RATLS-Browser-HPKE` header is bound into HPKE `info` — replay to a different browser key is rejected |

---

## Updating the TEE image digest

When the Buffer TEE container image is rebuilt and redeployed, update `EXPECTED_IMAGE_DIGEST` in [src/lib/constants.ts](src/lib/constants.ts):

```typescript
export const EXPECTED_IMAGE_DIGEST = "sha256:<new-digest>"
```

The new digest is the output of `docker inspect --format='{{index .RepoDigests 0}}' <image>` or the Artifact Registry console.

---

## Running tests

```bash
# Unit tests (no network required)
npm test

# Integration tests against a live TEE (debug enclave)
TEE_URL=https://<tee-ip>:8443 npm run test:integration
```

Integration tests cover: attestation bundle verification, liveness nonce rejection, HPKE submit round-trip, and chunked AES-GCM upload of model + weights.

---

## Wire protocol reference

**`POST /v1/submit`** — HPKE-encrypted JSON metadata:

```json
{
  "action":         "submit_job",
  "dataset_id":     1,
  "model_sha256":   "<hex>",
  "weights_sha256": "<hex>",
  "submitted_by":   "my-app"
}
```

**`PUT /v1/upload/:job_id/model`** and **`PUT /v1/upload/:job_id/weights`** — AES-256-GCM-CHUNKED-v1 framed binary:

```
[4 bytes BE]  header JSON length
[N bytes]     header JSON:
              { algorithm, file_id, enc, wrapped_key, file_nonce, total_chunks, plaintext_sha256 }
for each chunk i in 0..total_chunks-1:
  [4 bytes BE]  ciphertext length (plaintext + 16-byte GCM tag)
  [M bytes]     AES-256-GCM ciphertext
                  nonce = fileNonce[0:8] || uint32BE(i)[8:12]
                  AAD   = "{i}:{total_chunks}:{file_id}" UTF-8
```
