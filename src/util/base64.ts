export function b64encode(bytes: Uint8Array): string {
    let bin = ""
    bytes.forEach(b => { bin += String.fromCharCode(b) })
    return btoa(bin)
}

export function b64decode(s: string): Uint8Array {
    const bin = atob(s)
    const out = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
    return out
}

export function b64urlEncode(bytes: Uint8Array): string {
    return b64encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "")
}

export function b64urlDecode(s: string): Uint8Array {
    const padded = s.replace(/-/g, "+").replace(/_/g, "/")
    const pad = padded.length % 4
    return b64decode(pad ? padded + "=".repeat(4 - pad) : padded)
}
