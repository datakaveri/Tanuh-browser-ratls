// End-to-end integration test against a live debug enclave (dbgstat=enabled).
// Requires network access to TEE_URL. Set the TEE_URL env var or edit the default.
// Run with: npm run test:integration

import { describe, it, expect } from "vitest"
import { verifyBundle } from "../../src/lib/bundle"
import { verifyOIDCDebug } from "../../src/lib/oidc_debug"
import { Session, uploadChunked } from "../../src/lib/hpke"
import { b64urlEncode } from "../../src/lib/util/base64"
import { zeroBuffer } from "../../src/lib/util/bytes"
import { attestAndOpen } from "../../src/lib/index"
import type { AttestBundle } from "../../src/lib/types"

const TEE_URL = process.env["TEE_URL"] ?? "https://35.253.174.203:8443"

// Skip the whole suite if the TEE is unreachable — don't fail CI on network issues.
// To force-run: TEE_URL=https://... npm run test:integration
async function teeReachable(): Promise<boolean> {
    try {
        const r = await fetch(TEE_URL + "/v1/attest", {
            method:  "GET",
            headers: { "X-RATLS-Nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
            signal:  AbortSignal.timeout(5000),
        })
        return r.status < 500
    } catch {
        return false
    }
}

describe("E2E — debug enclave (dbgstat=enabled)", () => {
    it("fetches bundle, verifies attestation, and opens an HPKE session", async () => {
        if (!await teeReachable()) {
            console.warn(`TEE unreachable at ${TEE_URL} — skipping integration test`)
            return
        }

        // 1. Generate fresh liveness nonce
        const nonce = crypto.getRandomValues(new Uint8Array(32))

        // 2. Fetch bundle from live TEE
        const resp = await fetch(TEE_URL + "/v1/attest", {
            headers: { "X-RATLS-Nonce": b64urlEncode(nonce) },
            signal:  AbortSignal.timeout(10_000),
        })
        expect(resp.ok, `attest endpoint returned ${resp.status}`).toBe(true)

        const bundle = await resp.json() as AttestBundle
        expect(bundle.bundle_version).toBe("ratls-cs-v1")
        expect(bundle.oidc_token).toBeTruthy()
        expect(bundle.binding_pubkey_b64).toBeTruthy()
        expect(bundle.hpke_pubkey_b64).toBeTruthy()
        expect(bundle.nonce_sig_b64).toBeTruthy()

        // 3. Full bundle verification using debug OIDC verifier
        let session
        try {
            session = await verifyBundle(bundle, nonce, verifyOIDCDebug)
        } finally {
            zeroBuffer(nonce)
        }

        expect(session.hpkePub).toHaveLength(32)
        expect(session.hpkePub.some(b => b !== 0)).toBe(true)
        expect(session.verifiedAt).toBeGreaterThan(0)
        expect(session.oidc.swname).toBe("CONFIDENTIAL_SPACE")
        expect(session.oidc.hwmodel).toMatch(/^GCP_AMD_SEV/)
        expect(session.oidc.submods.container.image_digest).toMatch(/^sha256:/)

        // 4. Build HPKE session with the verified enclave pubkey
        const hpkeSession = new Session(session.hpkePub)
        await hpkeSession.init()

        const browserPub = hpkeSession.browserPubB64Url()
        expect(browserPub.length).toBeGreaterThan(0)
        expect(browserPub).not.toContain("=")   // URL-safe, no padding

        console.log("✓ Attestation verified")
        console.log(`  image_digest : ${session.oidc.submods.container.image_digest}`)
        console.log(`  hwmodel      : ${session.oidc.hwmodel}`)
        console.log(`  eat_nonce    : ${JSON.stringify(session.oidc.eat_nonce)}`)
        console.log(`  browser HPKE : ${browserPub.slice(0, 16)}...`)
    }, 20_000)   // 20s timeout for network round-trip + crypto

    it("rejects a bundle with a tampered liveness nonce", async () => {
        if (!await teeReachable()) {
            console.warn(`TEE unreachable at ${TEE_URL} — skipping integration test`)
            return
        }

        const nonce = crypto.getRandomValues(new Uint8Array(32))
        const wrongNonce = crypto.getRandomValues(new Uint8Array(32))

        const resp = await fetch(TEE_URL + "/v1/attest", {
            headers: { "X-RATLS-Nonce": b64urlEncode(nonce) },
            signal:  AbortSignal.timeout(10_000),
        })
        expect(resp.ok).toBe(true)
        const bundle = await resp.json() as AttestBundle

        // Verify with the WRONG nonce — liveness sig must fail
        await expect(
            verifyBundle(bundle, wrongNonce, verifyOIDCDebug)
        ).rejects.toThrow("liveness signature invalid")

        zeroBuffer(nonce)
        zeroBuffer(wrongNonce)
    }, 20_000)

    it("submits a tiny HPKE-encrypted job and gets a queued response", async () => {
        if (!await teeReachable()) {
            console.warn(`TEE unreachable at ${TEE_URL} — skipping`)
            return
        }

        // 1. Attest (same as first test)
        const nonce = crypto.getRandomValues(new Uint8Array(32))
        const resp = await fetch(TEE_URL + "/v1/attest", {
            headers: { "X-RATLS-Nonce": b64urlEncode(nonce) },
            signal:  AbortSignal.timeout(10_000),
        })
        expect(resp.ok).toBe(true)
        const bundle = await resp.json() as AttestBundle

        let session
        try {
            session = await verifyBundle(bundle, nonce, verifyOIDCDebug)
        } finally {
            zeroBuffer(nonce)
        }
        expect(session.oidc.hwmodel).toMatch(/^GCP_AMD_SEV/)

        // 2. Open HPKE session using the VERIFIED enclave pub — same key as the header
        const hpkeSession = new Session(session.hpkePub)
        await hpkeSession.init()

        // 3. Encrypt a tiny payload using hpkeSession (not a worker — avoids key mismatch)
        const tinyBytes = new TextEncoder().encode("tiny-model-bytes")
        const tinyHashBuf = await crypto.subtle.digest("SHA-256", tinyBytes)
        const tinyHex = Array.from(new Uint8Array(tinyHashBuf))
            .map(b => b.toString(16).padStart(2, "0")).join("")

        const body      = {
            dataset_id: 1,
            model_sha256:   tinyHex,
            weights_sha256: tinyHex,
        }
        const aad     = new TextEncoder().encode(JSON.stringify({ rid: crypto.randomUUID(), ts: Date.now() }))
        const request = await hpkeSession.encryptRequest(
            new TextEncoder().encode(JSON.stringify(body)), aad)

        // 4. POST to /v1/submit with matching X-RATLS-Browser-HPKE header
        const submitResp = await fetch(TEE_URL + "/v1/submit", {
            method:  "POST",
            headers: {
                "Content-Type":         "application/json",
                "X-RATLS-Browser-HPKE": hpkeSession.browserPubB64Url(),
            },
            body:   JSON.stringify(request),
            signal: AbortSignal.timeout(20_000),
        })
        expect(submitResp.ok, `submit returned ${submitResp.status}`).toBe(true)

        // 5. Decrypt the encrypted response
        const encResp  = await submitResp.json()
        const plainPt  = await hpkeSession.decryptResponse(encResp)
        const response = JSON.parse(new TextDecoder().decode(plainPt)) as Record<string, unknown>

        console.log("✓ HPKE submit round-trip succeeded")
        console.log(`  job_id : ${response.job_id}`)
        console.log(`  status : ${response.status}`)

        // After HPKE metadata submit, job is pending_upload (awaiting binary files)
        expect(["pending_upload", "queued"]).toContain(response.status)
        expect(typeof response.job_id).toBe("string")

        // Upload tiny binary files using AES-256-GCM-CHUNKED-v1 envelope encryption
        const jobId = response.job_id as string

        const modelUp = await uploadChunked(
            `${TEE_URL}/v1/upload/${jobId}/model`,
            tinyBytes, tinyHex, hpkeSession,
        )
        expect(modelUp.ok, `model upload returned ${modelUp.status}`).toBe(true)

        const weightsUp = await uploadChunked(
            `${TEE_URL}/v1/upload/${jobId}/weights`,
            tinyBytes, tinyHex, hpkeSession,
        )
        expect(weightsUp.ok, `weights upload returned ${weightsUp.status}`).toBe(true)

        const finalStatus = (await weightsUp.json()) as Record<string, unknown>
        console.log(`  final status: ${finalStatus.status}`)
        expect(typeof finalStatus.job_id === "string" || finalStatus.status !== undefined).toBe(true)
    }, 30_000)
})
