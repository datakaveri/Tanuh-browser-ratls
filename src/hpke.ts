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
}
