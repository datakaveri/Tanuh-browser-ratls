// MUST be filled before deployment.
// These values are automatically updated by CI/CD when TEE images change.
// verifyBundle throws "verifier misconfigured" if EXPECTED_IMAGE_DIGEST is empty.

export const EXPECTED_IMAGE_DIGEST            = "sha256:9bb13e7384a55f6c856ae5b463ae3436b0676461a93801e253451e4822ffaffb"
export const EXPECTED_PROCESSING_IMAGE_DIGEST = "sha256:"

export const OIDC_AUDIENCE     = "ratls-browser"
export const OIDC_ISSUER       = "https://confidentialcomputing.googleapis.com"
export const OIDC_JWKS_URL     =
    "https://www.googleapis.com/service_accounts/v1/metadata/jwk/" +
    "signer@confidentialspace-sign.iam.gserviceaccount.com"
export const HPKE_INFO_PREFIX  = "ratls-cs-v1|"
export const BUNDLE_VERSION    = "ratls-cs-v1"
export const WORKER_TIMEOUT_MS = 30_000
