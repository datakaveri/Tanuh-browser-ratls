// End-to-end integration test against a live debug enclave (dbgstat=enabled).
// Requires network access to TEE_URL. Set the TEE_URL env var or edit the default.
// Run with: npm run test:integration

import { describe, it, expect } from "vitest"
import { verifyBundle } from "../../src/bundle"
import { verifyOIDCDebug } from "../../src/oidc_debug"
import { Session } from "../../src/hpke"
import { b64urlEncode } from "../../src/util/base64"
import { zeroBuffer } from "../../src/util/bytes"
import type { AttestBundle } from "../../src/types"

const TEE_URL = process.env["TEE_URL"] ?? "https://35.239.166.229:8443"

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
        expect(session.oidc.hwmodel).toMatch(/^GCP_AMD_SEV_SNP/)
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
})
