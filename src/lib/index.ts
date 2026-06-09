import { b64urlEncode, b64encode } from "./util/base64"
import { Session } from "./hpke"
import type { AttestBundle, EncryptedResponse, AttestOptions, OpenedSession } from "./types"
import type { CSOidcPayload } from "./oidc"
import { WORKER_TIMEOUT_MS } from "./constants"

const CHUNK_SIZE = 16 * 1024 * 1024   // 16 MB per AES-GCM chunk

// Use Vite's ?worker suffix for correct bundling
import VerifierWorker from "./worker.ts?worker"

type WorkerResponse =
    | { type: "verify_ok"; session: { hpkePub: ArrayBuffer; verifiedAt: number; oidc: CSOidcPayload } }
    | { type: "encrypt_ok"; request: import("./types").EncryptedRequest }
    | { type: "error"; message: string }

function runInWorker<T>(
    message: object,
    transferables: ArrayBuffer[],
): Promise<T> {
    return new Promise((resolve, reject) => {
        const worker = new VerifierWorker()

        // Timeout: kill hung worker after 30s
        const timeout = setTimeout(() => {
            worker.terminate()
            reject(new Error(`Worker timeout after ${WORKER_TIMEOUT_MS / 1000}s`))
        }, WORKER_TIMEOUT_MS)

        worker.onmessage = (e: MessageEvent<WorkerResponse>) => {
            clearTimeout(timeout)
            if (e.data.type === "error") {
                reject(new Error(e.data.message))
            } else {
                resolve(e.data as T)
            }
            // self.close() already called inside worker — no terminate needed here
        }

        worker.onerror = (e: ErrorEvent) => {
            clearTimeout(timeout)
            worker.terminate()
            reject(new Error(`Worker error: ${e.message ?? "unknown"}`))
        }

        worker.onmessageerror = () => {
            clearTimeout(timeout)
            worker.terminate()
            reject(new Error("Worker message serialization error"))
        }

        // Transfer: main thread loses access to these ArrayBuffers after this call
        worker.postMessage(message, transferables)
    })
}

export async function attestAndOpen(opts: AttestOptions): Promise<OpenedSession> {
    // 1. Generate fresh liveness nonce
    const nonce = crypto.getRandomValues(new Uint8Array(32))

    // 2. Fetch bundle — nonce goes in header as base64url (RawURLEncoding, no padding)
    const resp = await fetch(opts.attestUrl + "/v1/attest", {
        headers: { "X-RATLS-Nonce": b64urlEncode(nonce) },
    })
    if (!resp.ok) throw new Error(`attest failed: ${resp.status}`)
    const bundle = await resp.json() as AttestBundle

    // 3. Verify in worker — transfer nonce (main thread loses access)
    const { session } = await runInWorker<{
        session: { hpkePub: ArrayBuffer; verifiedAt: number; oidc: CSOidcPayload }
    }>(
        { type: "verify", bundle, nonce: nonce.buffer },
        [nonce.buffer],
    )

    // 4. Build HPKE session with verified enclave pub
    const enclaveHpkePub = new Uint8Array(session.hpkePub)
    const hpkeSession = new Session(enclaveHpkePub)
    await hpkeSession.init()

    return {
        hpkePub: enclaveHpkePub,
        oidc:    session.oidc,

        // Encrypt File using AES-256-GCM-CHUNKED-v1, 16 MB per chunk.
        // Encrypts in 16 MB pieces (peak: ~32 MB during encryption),
        // then sends the assembled body in one fetch — works through any proxy.
        // sha256hex must be the pre-computed hex SHA-256 of the plaintext file.
        async uploadEncrypted(path: string, file: File, sha256hex: string, onProgress?: (pct: number) => void): Promise<void> {
            const totalChunks = Math.max(1, Math.ceil(file.size / CHUNK_SIZE))
            const fileId      = crypto.randomUUID()

            const rawKey = crypto.getRandomValues(new Uint8Array(32))
            const aesKey = await crypto.subtle.importKey(
                "raw", rawKey, { name: "AES-GCM" }, false, ["encrypt"],
            )
            const { enc, wrappedKey } = await hpkeSession.sealSymmetricKey(rawKey)

            const fileNonce = crypto.getRandomValues(new Uint8Array(8))

            const header      = JSON.stringify({
                file_id:          fileId,
                enc,
                wrapped_key:      wrappedKey,
                file_nonce:       b64encode(fileNonce),
                total_chunks:     totalChunks,
                plaintext_sha256: sha256hex,
            })
            const headerBytes = new TextEncoder().encode(header)

            // Pre-allocate the full body:
            //   4 bytes header-len + header + per-chunk (4 bytes len + plaintext + 16 GCM tag)
            const bodySize = 4 + headerBytes.length
                + totalChunks * 4
                + file.size + totalChunks * 16
            const body = new Uint8Array(bodySize)
            const dv   = new DataView(body.buffer)
            let   off  = 0

            // Write header frame
            dv.setUint32(off, headerBytes.length, false); off += 4
            body.set(headerBytes, off);                   off += headerBytes.length

            // Encrypt and write each chunk
            const iv = new Uint8Array(12)
            iv.set(fileNonce, 0)

            for (let i = 0; i < totalChunks; i++) {
                const plaintext = await file.slice(
                    i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE,
                ).arrayBuffer()

                new DataView(iv.buffer).setUint32(8, i, false)
                const aad = new TextEncoder().encode(`${i}:${totalChunks}:${fileId}`)

                const ct = new Uint8Array(await crypto.subtle.encrypt(
                    { name: "AES-GCM", iv: iv.slice(), additionalData: aad, tagLength: 128 },
                    aesKey,
                    plaintext,
                ))

                dv.setUint32(off, ct.length, false); off += 4
                body.set(ct, off);                   off += ct.length

                onProgress?.(Math.round((i + 1) / totalChunks * 100))
            }

            const url = opts.attestUrl ? new URL(path, opts.attestUrl).toString() : path
            const resp = await fetch(url, {
                method:  "PUT",
                headers: {
                    "Content-Type":         "application/octet-stream",
                    "X-RATLS-Browser-HPKE": hpkeSession.browserPubB64Url(),
                },
                body,
            })
            if (!resp.ok) {
                const msg = await resp.text().catch(() => "")
                throw new Error(`upload failed: ${resp.status}${msg ? " — " + msg : ""}`)
            }
        },

        async send(path: string, body: unknown): Promise<unknown> {
            const plaintext = new TextEncoder().encode(JSON.stringify(body))
            const aad = new TextEncoder().encode(JSON.stringify({
                rid:  crypto.randomUUID(),
                ts:   Date.now(),
                path,
            }))

            // Encrypt with hpkeSession directly — the worker would create a NEW browser
            // ephemeral key, making the HPKE info mismatch the X-RATLS-Browser-HPKE header.
            // hpkeSession.encryptRequest() zeroes `plaintext` after sealing.
            const request = await hpkeSession.encryptRequest(plaintext, aad)

            // When attestUrl is empty the Vite proxy handles routing via relative paths.
            const submitUrl = opts.attestUrl ? new URL(path, opts.attestUrl).toString() : path
            const r = await fetch(submitUrl, {
                method:  "POST",
                headers: {
                    "Content-Type":         "application/json",
                    "X-RATLS-Browser-HPKE": hpkeSession.browserPubB64Url(),
                },
                body: JSON.stringify(request),
            })
            if (!r.ok) throw new Error(`submit failed: ${r.status}`)

            const er = await r.json() as EncryptedResponse
            const pt = await hpkeSession.decryptResponse(er)
            return JSON.parse(new TextDecoder().decode(pt))
        },
    }
}
