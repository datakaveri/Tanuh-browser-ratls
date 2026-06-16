// Buffer TEE image digest — update whenever buffer-tee image is rebuilt.
export const EXPECTED_IMAGE_DIGEST = "sha256:8de9705db25f9c3fd038ea348c822e938e00df6370c770d3adc575e3ce9ac031"
export const OIDC_AUDIENCE         = "ratls-browser"

export const OIDC_ISSUER           = "https://confidentialcomputing.googleapis.com"
export const OIDC_JWKS_URL         =
    "https://www.googleapis.com/service_accounts/v1/metadata/jwk/" +
    "signer@confidentialspace-sign.iam.gserviceaccount.com"
export const HPKE_INFO_PREFIX      = "ratls-cs-v1|"
export const WORKER_TIMEOUT_MS     = 30_000

// Link to the Buffer TEE source code — set once the repo is made public.
export const BUFFER_TEE_SOURCE_REPO_URL = ""
