import { describe, it, expect } from "vitest"
import { b64encode, b64decode, b64urlEncode, b64urlDecode } from "../src/lib/util/base64"
import { concat, constantTimeEqual, toHex, zeroBuffer, validateBuffer } from "../src/lib/util/bytes"
import { derToRaw } from "../src/lib/util/ecdsa"

// ── base64 ─────────────────────────────────────────────────────────────────

describe("b64encode / b64decode", () => {
    it("round-trips arbitrary bytes", () => {
        const input = new Uint8Array([0, 1, 2, 127, 128, 255])
        expect(b64decode(b64encode(input))).toEqual(input)
    })

    it("produces standard base64 with padding", () => {
        // [1] → "AQ=="
        expect(b64encode(new Uint8Array([1]))).toBe("AQ==")
    })

    it("round-trips empty array", () => {
        const empty = new Uint8Array(0)
        expect(b64decode(b64encode(empty))).toEqual(empty)
    })
})

describe("b64urlEncode / b64urlDecode", () => {
    it("round-trips arbitrary bytes", () => {
        const input = new Uint8Array([0xfb, 0xff, 0xfe, 0x00, 0x01])
        expect(b64urlDecode(b64urlEncode(input))).toEqual(input)
    })

    it("produces no padding characters", () => {
        const s = b64urlEncode(new Uint8Array([1, 2, 3]))
        expect(s).not.toContain("=")
    })

    it("replaces + with - and / with _", () => {
        // Find a byte sequence that produces + or / in standard base64
        // 0xfb = 11111011 → produces + / chars
        const s = b64urlEncode(new Uint8Array([0xfb, 0xff]))
        expect(s).not.toContain("+")
        expect(s).not.toContain("/")
    })

    it("round-trips a 32-byte array (common case)", () => {
        const input = new Uint8Array(32)
        for (let i = 0; i < 32; i++) input[i] = i + 1
        expect(b64urlDecode(b64urlEncode(input))).toEqual(input)
    })
})

// ── bytes ───────────────────────────────────────────────────────────────────

describe("concat", () => {
    it("concatenates multiple arrays", () => {
        const a = new Uint8Array([1, 2])
        const b = new Uint8Array([3, 4])
        const c = new Uint8Array([5])
        expect(concat(a, b, c)).toEqual(new Uint8Array([1, 2, 3, 4, 5]))
    })

    it("handles empty arrays", () => {
        const a = new Uint8Array([1])
        const b = new Uint8Array(0)
        expect(concat(a, b)).toEqual(new Uint8Array([1]))
    })
})

describe("constantTimeEqual", () => {
    it("returns true for equal arrays", () => {
        const a = new Uint8Array([1, 2, 3])
        const b = new Uint8Array([1, 2, 3])
        expect(constantTimeEqual(a, b)).toBe(true)
    })

    it("returns false for different values", () => {
        const a = new Uint8Array([1, 2, 3])
        const b = new Uint8Array([1, 2, 4])
        expect(constantTimeEqual(a, b)).toBe(false)
    })

    it("returns false for different lengths", () => {
        const a = new Uint8Array([1, 2])
        const b = new Uint8Array([1, 2, 3])
        expect(constantTimeEqual(a, b)).toBe(false)
    })

    it("returns true for two empty arrays", () => {
        expect(constantTimeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true)
    })
})

describe("toHex", () => {
    it("produces lowercase hex", () => {
        expect(toHex(new Uint8Array([0x0f, 0xff, 0xab]))).toBe("0fffab")
    })
})

describe("zeroBuffer", () => {
    it("fills all bytes with 0", () => {
        const buf = new Uint8Array([1, 2, 3, 4, 5])
        zeroBuffer(buf)
        expect(buf.every(b => b === 0)).toBe(true)
    })
})

describe("validateBuffer", () => {
    it("throws on null", () => {
        expect(() => validateBuffer(null, "test")).toThrow("buffer is empty")
    })

    it("throws on undefined", () => {
        expect(() => validateBuffer(undefined, "test")).toThrow("buffer is empty")
    })

    it("throws on empty array", () => {
        expect(() => validateBuffer(new Uint8Array(0), "test")).toThrow("buffer is empty")
    })

    it("throws on all-zero array", () => {
        expect(() => validateBuffer(new Uint8Array(4), "test")).toThrow("all zeros")
    })

    it("passes on a valid buffer", () => {
        expect(() => validateBuffer(new Uint8Array([0, 0, 1]), "test")).not.toThrow()
    })
})

// ── ecdsa ───────────────────────────────────────────────────────────────────

describe("derToRaw", () => {
    it("converts a real P-256 DER signature to raw r||s", async () => {
        // Generate a real key pair and sign something to get a DER signature
        const keyPair = await crypto.subtle.generateKey(
            { name: "ECDSA", namedCurve: "P-256" },
            false,
            ["sign", "verify"],
        )
        const data = new Uint8Array([1, 2, 3, 4, 5])
        const derSig = new Uint8Array(
            await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keyPair.privateKey, data)
        )
        // WebCrypto sign() returns raw r||s (64 bytes for P-256)
        // We can't get DER from WebCrypto directly, so we'll build a minimal DER manually
        // from the raw sig and then verify that derToRaw inverts it.
        // Build DER from raw: r = first 32 bytes, s = last 32 bytes
        const r = derSig.slice(0, 32)
        const s = derSig.slice(32, 64)

        // Pad r/s with 0x00 if high bit set (DER positive integer encoding)
        function encodeInt(val: Uint8Array): Uint8Array {
            const needsPad = val[0] >= 0x80
            const out = new Uint8Array(needsPad ? val.length + 1 : val.length)
            if (needsPad) out[0] = 0
            out.set(val, needsPad ? 1 : 0)
            return out
        }
        const rDer = encodeInt(r)
        const sDer = encodeInt(s)
        const seqLen = 2 + rDer.length + 2 + sDer.length
        const der = new Uint8Array(2 + seqLen)
        let off = 0
        der[off++] = 0x30
        der[off++] = seqLen
        der[off++] = 0x02
        der[off++] = rDer.length
        der.set(rDer, off); off += rDer.length
        der[off++] = 0x02
        der[off++] = sDer.length
        der.set(sDer, off)

        const raw = derToRaw(der, 32)
        expect(raw.length).toBe(64)

        // Verify the reconstructed raw sig against the original WebCrypto signature
        const ok = await crypto.subtle.verify(
            { name: "ECDSA", hash: "SHA-256" },
            keyPair.publicKey,
            raw,
            data,
        )
        expect(ok).toBe(true)
    })

    it("handles a DER sig with leading 0x00 padding on r", () => {
        // Minimal synthetic DER: r=[0x00,0x81], s=[0x01] (just checks parsing)
        // 0x30 0x07  0x02 0x02 0x00 0x81  0x02 0x01 0x01
        const der = new Uint8Array([0x30, 0x07, 0x02, 0x02, 0x00, 0x81, 0x02, 0x01, 0x01])
        const raw = derToRaw(der, 2)
        // r=0x0081 → last 2 bytes: [0x00, 0x81]
        // s=0x01   → last 2 bytes: [0x00, 0x01]
        expect(raw[0]).toBe(0x00)
        expect(raw[1]).toBe(0x81)
        expect(raw[2]).toBe(0x00)
        expect(raw[3]).toBe(0x01)
    })
})
