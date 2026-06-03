import { describe, it, expect, vi, beforeEach } from "vitest"
import { sha256 } from "@noble/hashes/sha256"
import { b64urlEncode } from "../src/util/base64"

// ── Mock constants so tests are independent of the filled digest value ─────
// vi.mock is hoisted, so the value must also be hoisted with vi.hoisted.

const { TEST_IMAGE_DIGEST } = vi.hoisted(() => ({
    TEST_IMAGE_DIGEST: "sha256:test-digest-for-unit-tests",
}))

vi.mock("../src/constants", () => ({
    EXPECTED_IMAGE_DIGEST: TEST_IMAGE_DIGEST,
    OIDC_AUDIENCE:         "ratls-browser",
    OIDC_ISSUER:           "https://confidentialcomputing.googleapis.com",
    OIDC_JWKS_URL:         "https://example.com/.well-known/jwks.json",
    HPKE_INFO_PREFIX:      "ratls-cs-v1|",
    BUNDLE_VERSION:        "ratls-cs-v1",
    WORKER_TIMEOUT_MS:     30_000,
}))

// ── Mock jose before importing oidc ────────────────────────────────────────

vi.mock("jose", () => ({
    createRemoteJWKSet: vi.fn(() => "mock-jwks"),
    jwtVerify:          vi.fn(),
}))

// Import after mocks are registered
import { verifyOIDC } from "../src/oidc"
import { jwtVerify } from "jose"

// ── Helpers ────────────────────────────────────────────────────────────────

const NOW = Math.floor(Date.now() / 1000)

function makeSPKI(): Uint8Array {
    // 32-byte non-zero buffer as a stand-in for SPKI
    return new Uint8Array(32).fill(0xaa)
}

function makeHpkePub(): Uint8Array {
    return new Uint8Array(32).fill(0xbb)
}

function makeValidPayload(spki: Uint8Array, hpkePub: Uint8Array) {
    const nonce0 = b64urlEncode(sha256(spki))
    const nonce1 = b64urlEncode(hpkePub)
    return {
        iss:       "https://confidentialcomputing.googleapis.com",
        aud:       "ratls-browser",
        exp:       NOW + 3600,
        iat:       NOW - 60,
        swname:    "CONFIDENTIAL_SPACE",
        hwmodel:   "GCP_AMD_SEV_SNP",
        eat_nonce: [nonce0, nonce1],
        submods: {
            container: { image_digest: TEST_IMAGE_DIGEST },
            confidential_space: { support_attributes: ["STABLE"] },
        },
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe("verifyOIDC", () => {
    beforeEach(() => {
        vi.mocked(jwtVerify).mockReset()
    })

    it("happy path — passes all checks", async () => {
        const spki    = makeSPKI()
        const hpkePub = makeHpkePub()
        const payload = makeValidPayload(spki, hpkePub)
        vi.mocked(jwtVerify).mockResolvedValue({ payload } as never)

        await expect(verifyOIDC("token", spki, hpkePub)).resolves.toMatchObject({
            swname: "CONFIDENTIAL_SPACE",
        })
    })

    it("rejects wrong swname", async () => {
        const spki    = makeSPKI()
        const hpkePub = makeHpkePub()
        const payload = { ...makeValidPayload(spki, hpkePub), swname: "UNKNOWN" }
        vi.mocked(jwtVerify).mockResolvedValue({ payload } as never)

        await expect(verifyOIDC("token", spki, hpkePub))
            .rejects.toThrow("swname not CONFIDENTIAL_SPACE")
    })

    it("rejects wrong hwmodel", async () => {
        const spki    = makeSPKI()
        const hpkePub = makeHpkePub()
        const payload = { ...makeValidPayload(spki, hpkePub), hwmodel: "UNKNOWN" }
        vi.mocked(jwtVerify).mockResolvedValue({ payload } as never)

        await expect(verifyOIDC("token", spki, hpkePub))
            .rejects.toThrow("hwmodel not GCP_AMD_SEV_SNP")
    })

    it("rejects wrong image_digest", async () => {
        const spki    = makeSPKI()
        const hpkePub = makeHpkePub()
        const base    = makeValidPayload(spki, hpkePub)
        const payload = {
            ...base,
            submods: { ...base.submods, container: { image_digest: "sha256:wrong" } },
        }
        vi.mocked(jwtVerify).mockResolvedValue({ payload } as never)

        await expect(verifyOIDC("token", spki, hpkePub))
            .rejects.toThrow("image_digest mismatch")
    })

    it("rejects missing STABLE in support_attributes", async () => {
        const spki    = makeSPKI()
        const hpkePub = makeHpkePub()
        const base    = makeValidPayload(spki, hpkePub)
        const payload = {
            ...base,
            submods: {
                ...base.submods,
                confidential_space: { support_attributes: ["USABLE"] },
            },
        }
        vi.mocked(jwtVerify).mockResolvedValue({ payload } as never)

        await expect(verifyOIDC("token", spki, hpkePub))
            .rejects.toThrow("STABLE")
    })

    it("rejects expired token", async () => {
        const spki    = makeSPKI()
        const hpkePub = makeHpkePub()
        const payload = { ...makeValidPayload(spki, hpkePub), exp: NOW - 1 }
        vi.mocked(jwtVerify).mockResolvedValue({ payload } as never)

        await expect(verifyOIDC("token", spki, hpkePub))
            .rejects.toThrow("token expired")
    })

    it("rejects token that is too old (iat far in the past)", async () => {
        const spki    = makeSPKI()
        const hpkePub = makeHpkePub()
        const payload = { ...makeValidPayload(spki, hpkePub), iat: NOW - 7200 }
        vi.mocked(jwtVerify).mockResolvedValue({ payload } as never)

        await expect(verifyOIDC("token", spki, hpkePub))
            .rejects.toThrow("token too old")
    })

    it("rejects eat_nonce[0] mismatch (wrong binding key hash)", async () => {
        const spki    = makeSPKI()
        const hpkePub = makeHpkePub()
        const base    = makeValidPayload(spki, hpkePub)
        const nonces  = Array.isArray(base.eat_nonce) ? [...base.eat_nonce] : [base.eat_nonce]
        nonces[0]     = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        const payload = { ...base, eat_nonce: nonces }
        vi.mocked(jwtVerify).mockResolvedValue({ payload } as never)

        await expect(verifyOIDC("token", spki, hpkePub))
            .rejects.toThrow("eat_nonce[0] does not match binding pubkey")
    })

    it("rejects eat_nonce[1] mismatch (wrong HPKE key)", async () => {
        const spki    = makeSPKI()
        const hpkePub = makeHpkePub()
        const base    = makeValidPayload(spki, hpkePub)
        const nonces  = Array.isArray(base.eat_nonce) ? [...base.eat_nonce] : [base.eat_nonce]
        nonces[1]     = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        const payload = { ...base, eat_nonce: nonces }
        vi.mocked(jwtVerify).mockResolvedValue({ payload } as never)

        await expect(verifyOIDC("token", spki, hpkePub))
            .rejects.toThrow("eat_nonce[1] does not match HPKE pubkey")
    })

    it("rejects missing eat_nonce (undefined second element)", async () => {
        const spki    = makeSPKI()
        const hpkePub = makeHpkePub()
        const base    = makeValidPayload(spki, hpkePub)
        const payload = { ...base, eat_nonce: ["only-one-nonce"] }
        vi.mocked(jwtVerify).mockResolvedValue({ payload } as never)

        await expect(verifyOIDC("token", spki, hpkePub))
            .rejects.toThrow("eat_nonce missing expected values")
    })

    it("rejects when jose jwtVerify throws (bad signature)", async () => {
        vi.mocked(jwtVerify).mockRejectedValue(new Error("signature verification failed"))

        await expect(verifyOIDC("bad-token", makeSPKI(), makeHpkePub()))
            .rejects.toThrow("signature verification failed")
    })
})
