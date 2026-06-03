export function concat(...arrs: Uint8Array[]): Uint8Array {
    const total = arrs.reduce((n, a) => n + a.length, 0)
    const out = new Uint8Array(total)
    let offset = 0
    for (const a of arrs) { out.set(a, offset); offset += a.length }
    return out
}

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false
    let diff = 0
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
    return diff === 0
}

export function toHex(b: Uint8Array): string {
    return Array.from(b).map(x => x.toString(16).padStart(2, "0")).join("")
}

export function zeroBuffer(buf: Uint8Array): void {
    buf.fill(0)
}

export function validateBuffer(buf: Uint8Array | null | undefined, name: string): void {
    if (!buf || buf.length === 0)
        throw new Error(`${name}: buffer is empty`)
    if (buf.every(b => b === 0))
        throw new Error(`${name}: buffer is all zeros — already cleared?`)
}
