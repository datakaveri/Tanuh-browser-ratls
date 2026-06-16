import type { CSOidcPayload } from "./oidc"

export interface AttestBundle {
    oidc_token:         string    // JWT
    binding_pubkey_b64: string    // SPKI DER, standard base64 with padding
    hpke_pubkey_b64:    string    // X25519 raw 32 bytes, standard base64 with padding
    nonce_sig_b64:      string    // ASN.1 DER ECDSA sig, standard base64 with padding
    issued_at:          number    // Unix seconds
}

export interface EncryptedRequest {
    enc:        string    // base64, HPKE encapsulated key (32 bytes for X25519)
    ciphertext: string    // base64, AES-256-GCM output
    aad:        string    // base64, associated data
}
export type EncryptedResponse = EncryptedRequest

export interface AttestOptions {
    attestUrl:      string    // e.g. "https://tee.example.com:8443"
    keycloakToken?: string    // Keycloak Bearer token — forwarded as Authorization header on all TEE requests
}

export interface OpenedSession {
    hpkePub:    Uint8Array
    oidc:       CSOidcPayload
    send(path: string, body: unknown): Promise<unknown>
    // Upload a File using AES-256-GCM-CHUNKED-v1 envelope encryption.
    // sha256hex is the pre-computed hex SHA-256 of the plaintext file.
    uploadEncrypted(path: string, file: File, sha256hex: string, onProgress?: (pct: number) => void): Promise<void>
}
