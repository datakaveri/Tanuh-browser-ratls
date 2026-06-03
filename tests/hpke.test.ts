import { describe, it, expect } from "vitest"
import {
    CipherSuite,
    DhkemX25519HkdfSha256,
    HkdfSha256,
    Aes256Gcm,
} from "@hpke/core"
import { sha256 } from "@noble/hashes/sha256"
import { Session } from "../src/hpke"
import { b64encode, b64decode } from "../src/util/base64"
import { concat } from "../src/util/bytes"

// ── Helpers ────────────────────────────────────────────────────────────────

const suite = new CipherSuite({
    kem:  new DhkemX25519HkdfSha256(),
    kdf:  new HkdfSha256(),
    aead: new Aes256Gcm(),
})

async function makeEnclaveKP() {
    return suite.kem.generateKeyPair()
}

async function getEnclavePubRaw(kp: { publicKey: CryptoKey }): Promise<Uint8Array> {
    return new Uint8Array(await suite.kem.serializePublicKey(kp.publicKey))
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe("Session — Browser → Enclave", () => {
    it("encrypts and decrypts round-trip", async () => {
        const enclaveKP  = await makeEnclaveKP()
        const enclavePub = await getEnclavePubRaw(enclaveKP)

        const session = new Session(enclavePub)
        await session.init()

        const plaintext = new TextEncoder().encode("hello enclave")
        const aad       = new TextEncoder().encode("test-aad")
        const req       = await session.encryptRequest(plaintext.slice(), aad)

        // Enclave side: reconstruct info and open
        const browserPubRaw = b64decode(
            session.browserPubB64Url()
                .replace(/-/g, "+").replace(/_/g, "/")
                + "=".repeat((4 - session.browserPubB64Url().length % 4) % 4)
        )
        const info = concat(
            new TextEncoder().encode("ratls-cs-v1|"),
            sha256(enclavePub),
            sha256(browserPubRaw),
        )

        const encBytes = b64decode(req.enc)
        const recipient = await suite.createRecipientContext({
            recipientKey: enclaveKP,
            enc:          encBytes,
            info,
        })
        const pt = await recipient.open(b64decode(req.ciphertext), b64decode(req.aad))
        expect(new TextDecoder().decode(pt)).toBe("hello enclave")
    })

    it("zeroes plaintext after sealing", async () => {
        const enclaveKP  = await makeEnclaveKP()
        const enclavePub = await getEnclavePubRaw(enclaveKP)
        const session    = new Session(enclavePub)
        await session.init()

        const plaintext = new TextEncoder().encode("secret data")
        await session.encryptRequest(plaintext)
        // After sealing, plaintext should be zeroed
        expect(plaintext.every(b => b === 0)).toBe(true)
    })

    it("throws if plaintext is all zeros (validateBuffer)", async () => {
        const enclaveKP  = await makeEnclaveKP()
        const enclavePub = await getEnclavePubRaw(enclaveKP)
        const session    = new Session(enclavePub)
        await session.init()

        await expect(session.encryptRequest(new Uint8Array(16)))
            .rejects.toThrow("all zeros")
    })
})

describe("Session — Enclave → Browser", () => {
    it("decrypts a message encrypted by the enclave side", async () => {
        const enclaveKP  = await makeEnclaveKP()
        const enclavePub = await getEnclavePubRaw(enclaveKP)

        const session = new Session(enclavePub)
        await session.init()

        const browserPubRaw = b64decode(
            session.browserPubB64Url()
                .replace(/-/g, "+").replace(/_/g, "/")
                + "=".repeat((4 - session.browserPubB64Url().length % 4) % 4)
        )
        const info = concat(
            new TextEncoder().encode("ratls-cs-v1|"),
            sha256(enclavePub),
            sha256(browserPubRaw),
        )

        const browserCryptoKey = await suite.kem.deserializePublicKey(browserPubRaw)
        const sender = await suite.createSenderContext({
            recipientPublicKey: browserCryptoKey,
            info,
        })
        const msg     = new TextEncoder().encode("from enclave")
        const aadBytes = new TextEncoder().encode("resp-aad")
        const ct      = new Uint8Array(await sender.seal(msg, aadBytes))

        const encResponse = {
            enc:        b64encode(new Uint8Array(sender.enc)),
            ciphertext: b64encode(ct),
            aad:        b64encode(aadBytes),
        }

        const pt = await session.decryptResponse(encResponse)
        expect(new TextDecoder().decode(pt)).toBe("from enclave")
    })
})

describe("Session — wrong info string", () => {
    it("fails to open when info does not match", async () => {
        const enclaveKP  = await makeEnclaveKP()
        const enclavePub = await getEnclavePubRaw(enclaveKP)

        const session = new Session(enclavePub)
        await session.init()

        const browserPubRaw = b64decode(
            session.browserPubB64Url()
                .replace(/-/g, "+").replace(/_/g, "/")
                + "=".repeat((4 - session.browserPubB64Url().length % 4) % 4)
        )
        // Use wrong info prefix
        const wrongInfo = concat(
            new TextEncoder().encode("wrong-prefix|"),
            sha256(enclavePub),
            sha256(browserPubRaw),
        )

        const browserCryptoKey = await suite.kem.deserializePublicKey(browserPubRaw)
        const sender = await suite.createSenderContext({
            recipientPublicKey: browserCryptoKey,
            info: wrongInfo,
        })
        const ct = new Uint8Array(await sender.seal(
            new TextEncoder().encode("msg"),
            new Uint8Array(0),
        ))
        const encResponse = {
            enc:        b64encode(new Uint8Array(sender.enc)),
            ciphertext: b64encode(ct),
            aad:        b64encode(new Uint8Array(0)),
        }

        await expect(session.decryptResponse(encResponse)).rejects.toThrow()
    })
})

describe("Session — tampered ciphertext", () => {
    it("throws when ciphertext is bit-flipped", async () => {
        const enclaveKP  = await makeEnclaveKP()
        const enclavePub = await getEnclavePubRaw(enclaveKP)

        const session = new Session(enclavePub)
        await session.init()

        const msg = new TextEncoder().encode("original")
        const req = await session.encryptRequest(msg.slice())

        // Flip a byte in the ciphertext
        const ctBytes = b64decode(req.ciphertext)
        ctBytes[0] ^= 0xff
        const tampered = {
            ...req,
            ciphertext: b64encode(ctBytes),
        }

        // Reconstruct from the browser side to use decryptResponse
        const browserPubRaw = b64decode(
            session.browserPubB64Url()
                .replace(/-/g, "+").replace(/_/g, "/")
                + "=".repeat((4 - session.browserPubB64Url().length % 4) % 4)
        )
        const info = concat(
            new TextEncoder().encode("ratls-cs-v1|"),
            sha256(enclavePub),
            sha256(browserPubRaw),
        )

        // Enclave encrypts a response; we tamper with it before the browser decrypts
        const enclaveKey = await suite.kem.deserializePublicKey(browserPubRaw)
        const sender = await suite.createSenderContext({
            recipientPublicKey: enclaveKey,
            info,
        })
        const resp = new Uint8Array(await sender.seal(
            new TextEncoder().encode("response"),
            new Uint8Array(0),
        ))
        const respBytes = b64decode(b64encode(resp))
        respBytes[0] ^= 0xff
        const tamperedResp = {
            enc:        b64encode(new Uint8Array(sender.enc)),
            ciphertext: b64encode(respBytes),
            aad:        b64encode(new Uint8Array(0)),
        }

        await expect(session.decryptResponse(tamperedResp)).rejects.toThrow()
    })
})
