import type { CSOidcPayload } from "./oidc"

export interface AttestBundle {
    bundle_version:     "ratls-cs-v1"
    oidc_token:         string    // JWT
    binding_pubkey_b64: string    // SPKI DER, standard base64 with padding
    hpke_pubkey_b64:    string    // X25519 raw 32 bytes, standard base64 with padding
    nonce_sig_b64:      string    // ASN.1 DER ECDSA sig over liveness_nonce
    hpke_sig_b64:       string    // ASN.1 DER ECDSA sig over hpke_pubkey raw bytes (Variation 2)
    issued_at:          number    // Unix seconds
}

export interface EncryptedRequest {
    enc:        string    // base64, HPKE encapsulated key (32 bytes for X25519)
    ciphertext: string    // base64, AES-256-GCM output
    aad:        string    // base64, associated data
}
export type EncryptedResponse = EncryptedRequest

export interface AttestOptions {
    attestUrl: string    // e.g. "https://tee.example.com:8443"
}

export interface OpenedSession {
    hpkePub:    Uint8Array
    oidc:       CSOidcPayload
    send(path: string, body: unknown): Promise<unknown>
}
