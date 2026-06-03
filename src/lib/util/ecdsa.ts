// ASN.1 DER → raw r||s for WebCrypto's ECDSA.verify
// WebCrypto expects: r (coordSize bytes) || s (coordSize bytes), big-endian
// DER encodes: 0x30 len 0x02 rLen r 0x02 sLen s (with possible leading 0x00 padding)
export function derToRaw(der: Uint8Array, coordSize: number): Uint8Array {
    let offset = 2                        // skip 0x30 + total length
    if (der[offset] === 0x81) offset++    // long form length
    offset++                              // skip 0x02
    const rLen = der[offset++]
    const r = der.slice(offset, offset + rLen)
    offset += rLen
    offset++                              // skip 0x02
    const sLen = der[offset++]
    const s = der.slice(offset, offset + sLen)

    const raw = new Uint8Array(coordSize * 2)
    raw.set(r.slice(-coordSize), coordSize - Math.min(r.length, coordSize))
    raw.set(s.slice(-coordSize), coordSize * 2 - Math.min(s.length, coordSize))
    return raw
}
