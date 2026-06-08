import { EXPECTED_IMAGE_DIGEST, BUNDLE_VERSION } from "./constants"
import { b64decode } from "./util/base64"
import { validateBuffer } from "./util/bytes"
import { derToRaw } from "./util/ecdsa"
import { verifyOIDC, type CSOidcPayload } from "./oidc"
import type { AttestBundle } from "./types"

export type OIDCVerifyFn = (
    token: string,
    bindingSPKI: Uint8Array,
    hpkePub: Uint8Array,
) => Promise<CSOidcPayload>

export interface VerifiedSession {
    hpkePub:    Uint8Array
    verifiedAt: number
    oidc:       CSOidcPayload
}

export async function verifyBundle(
    bundle: AttestBundle,
    livenessNonce: Uint8Array,  // 32 raw bytes — caller must zeroBuffer() after this returns
    verifyOIDCFn: OIDCVerifyFn = verifyOIDC,  // swap to verifyOIDCDebug for debug enclaves
): Promise<VerifiedSession> {

    // Guard: constants filled
    if (!EXPECTED_IMAGE_DIGEST)
        throw new Error("verifier misconfigured: EXPECTED_IMAGE_DIGEST empty")
    if (bundle.bundle_version !== BUNDLE_VERSION)
        throw new Error(`unknown bundle version: ${bundle.bundle_version}`)

    // Guard: nonce
    if (livenessNonce.length !== 32)
        throw new Error("liveness nonce must be 32 bytes")
    validateBuffer(livenessNonce, "liveness_nonce")

    const bindingSPKI = b64decode(bundle.binding_pubkey_b64)
    const hpkePub     = b64decode(bundle.hpke_pubkey_b64)
    const nonceSig    = b64decode(bundle.nonce_sig_b64)
    const hpkeSig     = b64decode(bundle.hpke_sig_b64)

    if (hpkePub.length !== 32)
        throw new Error("hpke pubkey wrong length: expected 32 bytes")

    // Step 1: OIDC — signature verify + CS claims + eat_nonce[0] + eat_nonce[1]
    const oidc = await verifyOIDCFn(bundle.oidc_token, bindingSPKI, hpkePub)

    // Step 2: Import binding pubkey — used for both liveness + HPKE sig checks
    const bindingKey = await crypto.subtle.importKey(
        "spki",
        bindingSPKI,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"],
    )

    // Step 3: Liveness — ECDSA sig over raw nonce, proves TEE holds binding_privkey right now
    const nonceSigRaw = derToRaw(nonceSig, 32)   // P-256: coordSize = 32
    const nonceOk = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        bindingKey,
        nonceSigRaw,
        livenessNonce,
    )
    if (!nonceOk) throw new Error("liveness signature invalid")

    // Step 4 (Variation 2): HPKE key binding — ECDSA sig over raw hpke_pubkey bytes,
    // proves the HPKE key was produced by the same TEE that holds binding_privkey.
    // This is an additional guarantee on top of the eat_nonce[1] OIDC binding.
    const hpkeSigRaw = derToRaw(hpkeSig, 32)
    const hpkeOk = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        bindingKey,
        hpkeSigRaw,
        hpkePub,        // signed message = the raw 32-byte X25519 public key
    )
    if (!hpkeOk) throw new Error("hpke key signature invalid")

    return { hpkePub, verifiedAt: Date.now(), oidc }
}
