// Buffer TEE image digest — update whenever buffer-tee image is rebuilt.
export const EXPECTED_IMAGE_DIGEST = "sha256:9a09b2dd1037f4bf150d10281467142142655da09487cabb2ff5af0a122cf05e"
export const OIDC_AUDIENCE         = "ratls-browser"

export const OIDC_ISSUER           = "https://confidentialcomputing.googleapis.com"
export const OIDC_JWKS_URL         =
    "https://www.googleapis.com/service_accounts/v1/metadata/jwk/" +
    "signer@confidentialspace-sign.iam.gserviceaccount.com"
export const HPKE_INFO_PREFIX      = "ratls-cs-v1|"
export const WORKER_TIMEOUT_MS     = 30_000
