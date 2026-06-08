import {
    CipherSuite,
    DhkemX25519HkdfSha256,
    HkdfSha256,
    Aes256Gcm,
} from "@hpke/core"
import { sha256 } from "@noble/hashes/sha256"
import { HPKE_INFO_PREFIX } from "./constants"
import { b64encode, b64decode, b64urlEncode } from "./util/base64"
import { concat, validateBuffer, zeroBuffer } from "./util/bytes"
import type { EncryptedRequest, EncryptedResponse } from "./types"

const CHUNK_SIZE   = 16 * 1024 * 1024  // 16 MB per AES-GCM chunk
const ALGORITHM    = "AES-256-GCM-CHUNKED-v1"

const suite = new CipherSuite({
    kem:  new DhkemX25519HkdfSha256(),
    kdf:  new HkdfSha256(),
    aead: new Aes256Gcm(),
})

// Must match enclave exactly:
//   "ratls-cs-v1|" || sha256(enclavePub) || sha256(browserPub)
//   = 12 + 32 + 32 = 76 bytes
function contextInfo(enclavePub: Uint8Array, browserPub: Uint8Array): Uint8Array {
    return concat(
        new TextEncoder().encode(HPKE_INFO_PREFIX),
        sha256(enclavePub),
        sha256(browserPub),
    )
}

export class Session {
    private kp!: { publicKey: CryptoKey; privateKey: CryptoKey }
    private browserPubRaw!: Uint8Array
    private info!: Uint8Array

    constructor(private readonly enclaveHpkePub: Uint8Array) {}

    async init(): Promise<void> {
        this.kp = await suite.kem.generateKeyPair()
        this.browserPubRaw = new Uint8Array(
            await suite.kem.serializePublicKey(this.kp.publicKey))
        this.info = contextInfo(this.enclaveHpkePub, this.browserPubRaw)
    }

    browserPubB64Url(): string {
        return b64urlEncode(this.browserPubRaw)
    }

    get keypair() { return this.kp }

    // Browser → Enclave
    // plaintext is zeroed after sealing (memory hygiene)
    async encryptRequest(
        plaintext: Uint8Array,
        aad?: Uint8Array,
    ): Promise<EncryptedRequest> {
        validateBuffer(plaintext, "plaintext")
        const recipKey = await suite.kem.deserializePublicKey(this.enclaveHpkePub)
        const sender   = await suite.createSenderContext({
            recipientPublicKey: recipKey,
            info: this.info,
        })
        let ct: Uint8Array
        try {
            ct = new Uint8Array(await sender.seal(plaintext, aad))
        } finally {
            zeroBuffer(plaintext)
        }
        return {
            enc:        b64encode(new Uint8Array(sender.enc)),
            ciphertext: b64encode(ct),
            aad:        b64encode(aad ?? new Uint8Array()),
        }
    }

    // Enclave → Browser
    async decryptResponse(resp: EncryptedResponse): Promise<Uint8Array> {
        const recip = await suite.createRecipientContext({
            recipientKey: this.kp,
            enc:          b64decode(resp.enc),
            info:         this.info,
        })
        return new Uint8Array(
            await recip.open(b64decode(resp.ciphertext), b64decode(resp.aad)))
    }

    // HPKE-seal a 32-byte AES key.
    // keyBytes is zeroed after sealing.
    async sealSymmetricKey(keyBytes: Uint8Array): Promise<{enc: string; wrappedKey: string}> {
        const req = await this.encryptRequest(keyBytes)  // zeroes keyBytes
        return { enc: req.enc, wrappedKey: req.ciphertext }
    }
}

// uploadChunked sends `data` as an AES-256-GCM-CHUNKED-v1 framed PUT request.
// sha256hex is the hex SHA-256 of `data` (already computed by caller).
// Used by: integration tests (tiny data), and OpenedSession.uploadEncrypted for production.
export async function uploadChunked(
    url: string,
    data: Uint8Array,
    sha256hex: string,
    hpkeSession: Session,
): Promise<Response> {
    const totalChunks = Math.max(1, Math.ceil(data.length / CHUNK_SIZE))
    const fileId      = crypto.randomUUID()

    // Generate AES-256 key and HPKE-seal it
    const rawKey = crypto.getRandomValues(new Uint8Array(32))
    const aesKey = await crypto.subtle.importKey(
        "raw", rawKey, { name: "AES-GCM" }, false, ["encrypt"],
    )
    const { enc, wrappedKey } = await hpkeSession.sealSymmetricKey(rawKey)

    const fileNonce = crypto.getRandomValues(new Uint8Array(8))

    const header      = JSON.stringify({
        algorithm:    ALGORITHM,
        file_id:      fileId,
        enc,
        wrapped_key:  wrappedKey,
        file_nonce:   b64encode(fileNonce),
        total_chunks: totalChunks,
        plaintext_sha256: sha256hex,
    })
    const headerBytes = new TextEncoder().encode(header)

    // Build the full framed body in memory (suitable for test-sized data)
    const frames: Uint8Array[] = []

    const u32 = (n: number): Uint8Array => {
        const b = new Uint8Array(4)
        new DataView(b.buffer).setUint32(0, n, false)
        return b
    }

    frames.push(u32(headerBytes.length), headerBytes)

    const iv = new Uint8Array(12)
    iv.set(fileNonce, 0)

    for (let i = 0; i < totalChunks; i++) {
        const plaintext = data.slice(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE)
        new DataView(iv.buffer).setUint32(8, i, false)
        const aad = new TextEncoder().encode(`${i}:${totalChunks}:${fileId}`)
        const ct  = new Uint8Array(await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv.slice(), additionalData: aad, tagLength: 128 },
            aesKey,
            plaintext,
        ))
        frames.push(u32(ct.length), ct)
    }

    const bodyLen  = frames.reduce((s, f) => s + f.length, 0)
    const body     = new Uint8Array(bodyLen)
    let   offset   = 0
    for (const f of frames) { body.set(f, offset); offset += f.length }

    return fetch(url, {
        method:  "PUT",
        headers: {
            "Content-Type":         "application/octet-stream",
            "X-RATLS-Browser-HPKE": hpkeSession.browserPubB64Url(),
        },
        body,
    })
}
