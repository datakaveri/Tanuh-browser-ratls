// MUST be filled before deployment.
// These values are automatically updated by CI/CD when TEE images change.
// verifyBundle throws "verifier misconfigured" if EXPECTED_IMAGE_DIGEST is empty.

export const EXPECTED_IMAGE_DIGEST            = "sha256:7b7209d9b5c457b9d0cac991819ff1bd20f290932a392385d3a16e4894229da5"
export const EXPECTED_PROCESSING_IMAGE_DIGEST = "sha256:"

export const OIDC_AUDIENCE     = "ratls-browser"
export const OIDC_ISSUER       = "https://confidentialcomputing.googleapis.com"
export const OIDC_JWKS_URL     =
    "https://www.googleapis.com/service_accounts/v1/metadata/jwk/" +
    "signer@confidentialspace-sign.iam.gserviceaccount.com"
export const HPKE_INFO_PREFIX  = "ratls-cs-v1|"
export const BUNDLE_VERSION    = "ratls-cs-v1"
export const WORKER_TIMEOUT_MS = 30_000
