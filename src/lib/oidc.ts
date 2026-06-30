import { createRemoteJWKSet, jwtVerify } from "jose"
import { sha256 } from "@noble/hashes/sha256"
import {
    OIDC_ISSUER, OIDC_AUDIENCE, OIDC_JWKS_URL,
    EXPECTED_IMAGE_DIGEST,
} from "./constants"
import { b64urlEncode } from "./util/base64"

const jwks = createRemoteJWKSet(new URL(OIDC_JWKS_URL))

export interface CSOidcPayload {
    iss:       string
    aud:       string | string[]
    exp:       number
    iat:       number
    swname:    string
    hwmodel:   string
    secboot?:  boolean
    dbgstat?:  string
    eat_nonce: string | string[]
    submods: {
        container: { image_digest: string; image_reference?: string }
        confidential_space: { support_attributes?: string[] }
    }
}

export async function verifyOIDC(
    token: string,
    bindingSPKI: Uint8Array,
    hpkePub: Uint8Array,
): Promise<CSOidcPayload> {
    // Step 1: Cryptographic signature verification — mandatory, done first
    const { payload } = await jwtVerify(token, jwks, {
        issuer:   OIDC_ISSUER,
        audience: OIDC_AUDIENCE,
    })
    const p = payload as unknown as CSOidcPayload

    // Step 2: CS-specific claim checks
    if (p.swname !== "CONFIDENTIAL_SPACE")
        throw new Error("swname not CONFIDENTIAL_SPACE")
    if (!p.hwmodel?.startsWith("GCP_INTEL_TDX"))
        throw new Error("hwmodel not GCP_INTEL_TDX")
    if (p.submods?.container?.image_digest !== EXPECTED_IMAGE_DIGEST)
        throw new Error("image_digest mismatch")
    // support_attributes is a GCP SLA-tier label (STABLE/LATEST/…), not a security property.
    // Some GCP regions omit it entirely. We accept absent, STABLE, or LATEST; reject anything
    // else (e.g. NON_PRODUCTION) to guard against debug-mode TEEs.
    const attrs: string[] = Array.isArray(p.submods?.confidential_space?.support_attributes)
        ? p.submods.confidential_space.support_attributes : []
    if (attrs.length > 0 && !attrs.includes("STABLE") && !attrs.includes("LATEST"))
        throw new Error(`support_attributes unexpected: ${JSON.stringify(attrs)}`)

    const now = Math.floor(Date.now() / 1000)
    if (!p.exp || p.exp <= now)        throw new Error("token expired")
    if (!p.iat || p.iat < now - 3600)  throw new Error("token too old")

    // Step 3: eat_nonce binding checks
    const nonces = Array.isArray(p.eat_nonce) ? p.eat_nonce : [p.eat_nonce]
    if (!nonces[0] || !nonces[1])
        throw new Error("eat_nonce missing expected values")

    // eat_nonce[0] == base64url(sha256(binding_pubkey_SPKI))
    const expectedBk = b64urlEncode(sha256(bindingSPKI))
    if (nonces[0] !== expectedBk)
        throw new Error("eat_nonce[0] does not match binding pubkey")

    // eat_nonce[1] == base64url(hpke_pubkey_raw_32_bytes)
    const expectedHk = b64urlEncode(hpkePub)
    if (nonces[1] !== expectedHk)
        throw new Error("eat_nonce[1] does not match HPKE pubkey")

    return p
}
