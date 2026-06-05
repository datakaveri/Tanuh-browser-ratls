// Web Worker: used for main-thread responsiveness ONLY.
// NOT a security boundary — same origin as host page.
// Single-use: self.close() called after every task.

import { verifyBundle, type VerifiedSession } from "./bundle"
import { verifyOIDCDebug } from "./oidc_debug"
import { Session } from "./hpke"
import { validateBuffer, zeroBuffer } from "./util/bytes"
import type { AttestBundle, EncryptedRequest } from "./types"
import type { CSOidcPayload } from "./oidc"

type WorkerRequest =
    | { type: "verify"; bundle: AttestBundle; nonce: ArrayBuffer }
    | { type: "encrypt"; plaintext: ArrayBuffer; aad: ArrayBuffer;
        enclaveHpkePub: Uint8Array }

type SerializedSession = {
    hpkePub:    ArrayBuffer
    verifiedAt: number
    oidc:       CSOidcPayload
}

self.onmessage = async (event: MessageEvent<WorkerRequest>) => {
    const req = event.data

    if (req.type !== "verify" && req.type !== "encrypt") {
        self.postMessage({ type: "error", message: "unknown message type" })
        self.close()
        return
    }

    try {
        if (req.type === "verify") {
            const nonce = new Uint8Array(req.nonce)
            let result: VerifiedSession
            try {
                validateBuffer(nonce, "liveness_nonce")
                result = await verifyBundle(req.bundle, nonce, verifyOIDCDebug)
            } finally {
                zeroBuffer(nonce)
            }
            const session: SerializedSession = {
                hpkePub:    result.hpkePub.buffer,
                verifiedAt: result.verifiedAt,
                oidc:       result.oidc,
            }
            self.postMessage({ type: "verify_ok", session },
                [session.hpkePub])
        }

        if (req.type === "encrypt") {
            const plaintext = new Uint8Array(req.plaintext)
            const aad       = new Uint8Array(req.aad)
            let ct: EncryptedRequest
            try {
                const session = new Session(req.enclaveHpkePub)
                await session.init()
                ct = await session.encryptRequest(plaintext, aad)
                // session.encryptRequest zeros plaintext internally
                // belt-and-suspenders: zero again
            } finally {
                zeroBuffer(plaintext)
            }
            self.postMessage({ type: "encrypt_ok", request: ct })
        }
    } catch (err) {
        self.postMessage({
            type:    "error",
            message: err instanceof Error ? err.message : "unknown worker error",
        })
    } finally {
        self.close()
    }
}
