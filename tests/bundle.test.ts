import { describe, it, expect, vi, beforeAll, afterEach } from "vitest"

// ── Hoisted mutable state for per-test constant overrides ──────────────────
const mockState = vi.hoisted(() => ({
    imageDigest: "sha256:deadbeef",
}))

vi.mock("../src/constants", () => ({
    get EXPECTED_IMAGE_DIGEST() { return mockState.imageDigest },
    BUNDLE_VERSION:    "ratls-cs-v1",
    OIDC_ISSUER:       "https://confidentialcomputing.googleapis.com",
    OIDC_AUDIENCE:     "ratls-browser",
    OIDC_JWKS_URL:     "https://example.com/.well-known/jwks.json",
    HPKE_INFO_PREFIX:  "ratls-cs-v1|",
    WORKER_TIMEOUT_MS: 30_000,
}))

vi.mock("../src/oidc", () => ({
    verifyOIDC: vi.fn(),
}))

import { verifyBundle } from "../src/bundle"
import { verifyOIDC } from "../src/oidc"
import { b64encode } from "../src/util/base64"
import type { AttestBundle } from "../src/types"

// ── Test fixtures ──────────────────────────────────────────────────────────

let bindingKeyPair: CryptoKeyPair
let bindingSPKIBytes: Uint8Array
let bindingSPKIB64: string
let hpkePub: Uint8Array
let hpkePubB64: string

// Converts WebCrypto raw r||s (64 bytes) → ASN.1 DER SEQUENCE
function rawToDer(raw: Uint8Array): Uint8Array {
    const r = raw.slice(0, 32)
    const s = raw.slice(32, 64)
    function encodeInt(val: Uint8Array): Uint8Array {
        const needsPad = val[0] >= 0x80
        const out = new Uint8Array(needsPad ? val.length + 1 : val.length)
        if (needsPad) out[0] = 0
        out.set(val, needsPad ? 1 : 0)
        return out
    }
    const rDer = encodeInt(r)
    const sDer = encodeInt(s)
    const seqLen = 2 + rDer.length + 2 + sDer.length
    const der = new Uint8Array(2 + seqLen)
    let off = 0
    der[off++] = 0x30; der[off++] = seqLen
    der[off++] = 0x02; der[off++] = rDer.length
    der.set(rDer, off); off += rDer.length
    der[off++] = 0x02; der[off++] = sDer.length
    der.set(sDer, off)
    return der
}

async function signBytes(data: Uint8Array): Promise<string> {
    const rawSig = new Uint8Array(
        await crypto.subtle.sign(
            { name: "ECDSA", hash: "SHA-256" },
            bindingKeyPair.privateKey,
            data,
        )
    )
    return b64encode(rawToDer(rawSig))
}

async function makeBundle(nonce: Uint8Array, overrideHpkePub?: Uint8Array): Promise<AttestBundle> {
    const pub = overrideHpkePub ?? hpkePub
    return {
        bundle_version:     "ratls-cs-v1",
        oidc_token:         "mock-token",
        binding_pubkey_b64: bindingSPKIB64,
        hpke_pubkey_b64:    b64encode(pub),
        nonce_sig_b64:      await signBytes(nonce),
        hpke_sig_b64:       await signBytes(pub),   // Variation 2: binding_privkey signs hpke_pubkey
        issued_at:          Math.floor(Date.now() / 1000),
    }
}

const mockOidcPayload = {
    iss:       "https://confidentialcomputing.googleapis.com",
    aud:       "ratls-browser",
    exp:       Math.floor(Date.now() / 1000) + 3600,
    iat:       Math.floor(Date.now() / 1000) - 60,
    swname:    "CONFIDENTIAL_SPACE",
    hwmodel:   "GCP_AMD_SEV_SNP",
    eat_nonce: ["nonce0", "nonce1"],
    submods: {
        container:           { image_digest: "sha256:deadbeef" },
        confidential_space:  { support_attributes: ["STABLE"] },
    },
}

beforeAll(async () => {
    bindingKeyPair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign", "verify"],
    )
    bindingSPKIBytes = new Uint8Array(
        await crypto.subtle.exportKey("spki", bindingKeyPair.publicKey))
    bindingSPKIB64 = b64encode(bindingSPKIBytes)

    hpkePub = new Uint8Array(32)
    for (let i = 0; i < 32; i++) hpkePub[i] = i + 1
    hpkePubB64 = b64encode(hpkePub)
})

afterEach(() => {
    mockState.imageDigest = "sha256:deadbeef"
    vi.mocked(verifyOIDC).mockReset()
})

// ── Tests ──────────────────────────────────────────────────────────────────

describe("verifyBundle", () => {
    it("happy path — verifies correctly and returns VerifiedSession", async () => {
        vi.mocked(verifyOIDC).mockResolvedValue(mockOidcPayload as never)
        const nonce = crypto.getRandomValues(new Uint8Array(32))
        const bundle = await makeBundle(nonce)

        const session = await verifyBundle(bundle, nonce)

        expect(session.hpkePub).toEqual(hpkePub)
        expect(session.oidc.swname).toBe("CONFIDENTIAL_SPACE")
        expect(session.verifiedAt).toBeGreaterThan(0)
    })

    it("throws 'misconfigured' when EXPECTED_IMAGE_DIGEST is empty", async () => {
        mockState.imageDigest = ""
        const nonce = crypto.getRandomValues(new Uint8Array(32))
        const bundle = await makeBundle(nonce)

        await expect(verifyBundle(bundle, nonce))
            .rejects.toThrow("verifier misconfigured: EXPECTED_IMAGE_DIGEST empty")
    })

    it("rejects wrong bundle_version", async () => {
        const nonce = crypto.getRandomValues(new Uint8Array(32))
        const bundle = {
            ...await makeBundle(nonce),
            bundle_version: "ratls-cs-v0" as "ratls-cs-v1",
        }

        await expect(verifyBundle(bundle, nonce))
            .rejects.toThrow("unknown bundle version")
    })

    it("rejects when oidc_token is tampered (verifyOIDC throws)", async () => {
        vi.mocked(verifyOIDC).mockRejectedValue(new Error("signature verification failed"))
        const nonce = crypto.getRandomValues(new Uint8Array(32))
        const bundle = { ...await makeBundle(nonce), oidc_token: "tampered" }

        await expect(verifyBundle(bundle, nonce))
            .rejects.toThrow("signature verification failed")
    })

    it("rejects eat_nonce[0] mismatch (verifyOIDC throws)", async () => {
        vi.mocked(verifyOIDC).mockRejectedValue(
            new Error("eat_nonce[0] does not match binding pubkey"))
        const nonce = crypto.getRandomValues(new Uint8Array(32))
        const bundle = await makeBundle(nonce)

        await expect(verifyBundle(bundle, nonce))
            .rejects.toThrow("eat_nonce[0]")
    })

    it("rejects eat_nonce[1] mismatch (verifyOIDC throws)", async () => {
        vi.mocked(verifyOIDC).mockRejectedValue(
            new Error("eat_nonce[1] does not match HPKE pubkey"))
        const nonce = crypto.getRandomValues(new Uint8Array(32))
        const bundle = await makeBundle(nonce)

        await expect(verifyBundle(bundle, nonce))
            .rejects.toThrow("eat_nonce[1]")
    })

    it("rejects wrong image_digest (verifyOIDC throws)", async () => {
        vi.mocked(verifyOIDC).mockRejectedValue(new Error("image_digest mismatch"))
        const nonce = crypto.getRandomValues(new Uint8Array(32))
        const bundle = await makeBundle(nonce)

        await expect(verifyBundle(bundle, nonce))
            .rejects.toThrow("image_digest mismatch")
    })

    it("rejects missing STABLE (verifyOIDC throws)", async () => {
        vi.mocked(verifyOIDC).mockRejectedValue(
            new Error("support_attributes does not include STABLE"))
        const nonce = crypto.getRandomValues(new Uint8Array(32))
        const bundle = await makeBundle(nonce)

        await expect(verifyBundle(bundle, nonce))
            .rejects.toThrow("STABLE")
    })

    it("rejects wrong liveness nonce (sig was made for a different nonce)", async () => {
        vi.mocked(verifyOIDC).mockResolvedValue(mockOidcPayload as never)
        const correctNonce = crypto.getRandomValues(new Uint8Array(32))
        const wrongNonce   = crypto.getRandomValues(new Uint8Array(32))
        // bundle signed with correctNonce, but we verify with wrongNonce
        const bundle = await makeBundle(correctNonce)

        await expect(verifyBundle(bundle, wrongNonce))
            .rejects.toThrow("liveness signature invalid")
    })

    it("rejects all-zero liveness nonce (validateBuffer)", async () => {
        const nonce = new Uint8Array(32)  // all zeros
        const bundle = {
            bundle_version:     "ratls-cs-v1" as const,
            oidc_token:         "mock-token",
            binding_pubkey_b64: bindingSPKIB64,
            hpke_pubkey_b64:    hpkePubB64,
            nonce_sig_b64:      b64encode(new Uint8Array(8)),
            hpke_sig_b64:       b64encode(new Uint8Array(8)),
            issued_at:          Math.floor(Date.now() / 1000),
        }

        await expect(verifyBundle(bundle, nonce))
            .rejects.toThrow("all zeros")
    })

    it("rejects hpke pubkey with wrong length", async () => {
        vi.mocked(verifyOIDC).mockResolvedValue(mockOidcPayload as never)
        const nonce = crypto.getRandomValues(new Uint8Array(32))
        const badHpke = new Uint8Array(16).fill(1)
        const bundle: AttestBundle = {
            bundle_version:     "ratls-cs-v1",
            oidc_token:         "mock-token",
            binding_pubkey_b64: bindingSPKIB64,
            hpke_pubkey_b64:    b64encode(badHpke),
            nonce_sig_b64:      await signBytes(nonce),
            hpke_sig_b64:       await signBytes(badHpke),
            issued_at:          Math.floor(Date.now() / 1000),
        }

        await expect(verifyBundle(bundle, nonce))
            .rejects.toThrow("hpke pubkey wrong length")
    })

    // ── Variation 2 specific tests ─────────────────────────────────────────

    it("[Variation 2] rejects when hpke_sig is signed by a different key", async () => {
        vi.mocked(verifyOIDC).mockResolvedValue(mockOidcPayload as never)
        const nonce = crypto.getRandomValues(new Uint8Array(32))

        // Rogue keypair — attacker trying to substitute their own HPKE sig
        const rogueKP = await crypto.subtle.generateKey(
            { name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
        const rogueRawSig = new Uint8Array(await crypto.subtle.sign(
            { name: "ECDSA", hash: "SHA-256" }, rogueKP.privateKey, hpkePub))
        const bundle: AttestBundle = {
            ...await makeBundle(nonce),
            hpke_sig_b64: b64encode(rawToDer(rogueRawSig)),
        }

        await expect(verifyBundle(bundle, nonce))
            .rejects.toThrow("hpke key signature invalid")
    })

    it("[Variation 2] rejects when hpke_sig is over wrong payload", async () => {
        vi.mocked(verifyOIDC).mockResolvedValue(mockOidcPayload as never)
        const nonce = crypto.getRandomValues(new Uint8Array(32))
        const bundle = await makeBundle(nonce)

        // Reuse nonce_sig as hpke_sig — valid sig but over the wrong data
        const tampered: AttestBundle = {
            ...bundle,
            hpke_sig_b64: bundle.nonce_sig_b64,
        }

        await expect(verifyBundle(tampered, nonce))
            .rejects.toThrow("hpke key signature invalid")
    })

    it("[Variation 2] rejects when hpke_pubkey is swapped but hpke_sig not updated", async () => {
        vi.mocked(verifyOIDC).mockResolvedValue(mockOidcPayload as never)
        const nonce = crypto.getRandomValues(new Uint8Array(32))
        const originalBundle = await makeBundle(nonce)

        // Attacker swaps hpke_pubkey but leaves hpke_sig signing the original key
        const tampered: AttestBundle = {
            ...originalBundle,
            hpke_pubkey_b64: b64encode(new Uint8Array(32).fill(0xff)),
        }

        await expect(verifyBundle(tampered, nonce))
            .rejects.toThrow("hpke key signature invalid")
    })
})
