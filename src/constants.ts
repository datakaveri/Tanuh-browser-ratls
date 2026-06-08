// MUST be filled before deployment.
// verifyBundle throws "verifier misconfigured" if EXPECTED_IMAGE_DIGEST is empty.

export const EXPECTED_IMAGE_DIGEST = "sha256:e4688085f5084a9818ef4171f326277462f14b53b97f978fb52778318dd3d4f5"
export const OIDC_AUDIENCE         = "ratls-browser"
export const OIDC_ISSUER           = "https://confidentialcomputing.googleapis.com"
export const OIDC_JWKS_URL         =
    "https://www.googleapis.com/service_accounts/v1/metadata/jwk/" +
    "signer@confidentialspace-sign.iam.gserviceaccount.com"
export const HPKE_INFO_PREFIX      = "ratls-cs-v1|"
export const BUNDLE_VERSION        = "ratls-cs-v1"
export const WORKER_TIMEOUT_MS     = 30_000
