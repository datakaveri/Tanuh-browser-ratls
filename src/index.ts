import { b64urlEncode } from "./util/base64"
import { Session } from "./hpke"
import type { AttestBundle, EncryptedResponse, AttestOptions, OpenedSession } from "./types"
import type { CSOidcPayload } from "./oidc"
import { WORKER_TIMEOUT_MS } from "./constants"

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

        async send(path: string, body: unknown): Promise<unknown> {
            const plaintext = new TextEncoder().encode(JSON.stringify(body))
            const aad = new TextEncoder().encode(JSON.stringify({
                rid:  crypto.randomUUID(),
                ts:   Date.now(),
                path,
            }))

            // Encrypt in worker — plaintext transferred + zeroed inside worker
            const { request } = await runInWorker<{
                request: import("./types").EncryptedRequest
            }>(
                {
                    type:           "encrypt",
                    plaintext:      plaintext.buffer,
                    aad:            aad.buffer,
                    enclaveHpkePub: enclaveHpkePub,
                },
                [plaintext.buffer, aad.buffer],
            )

            const r = await fetch(new URL(path, opts.attestUrl), {
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
