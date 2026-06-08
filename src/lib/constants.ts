// Buffer TEE image digest — update whenever buffer-tee image is rebuilt.
export const EXPECTED_IMAGE_DIGEST = "sha256:565af9d1e21898c3bec4164cf91ffe0b9e0999a4385c59b9ed5f6e12ec9c8728"
export const OIDC_AUDIENCE         = "ratls-browser"

// TEE base URL.
// Empty string → relative URLs (production: UI served from the Go server itself).
// In dev, set via VITE_TEE_URL env or the UI config field.
export const DEFAULT_TEE_URL = import.meta.env.VITE_TEE_URL as string ?? ""
export const OIDC_ISSUER           = "https://confidentialcomputing.googleapis.com"
export const OIDC_JWKS_URL         =
    "https://www.googleapis.com/service_accounts/v1/metadata/jwk/" +
    "signer@confidentialspace-sign.iam.gserviceaccount.com"
export const HPKE_INFO_PREFIX      = "ratls-cs-v1|"
export const BUNDLE_VERSION        = "ratls-cs-v1"
export const WORKER_TIMEOUT_MS     = 30_000
