import { useState, useRef } from "react"
import { attestAndOpen, transferOnnxModel } from "./lib"
import type { OpenedSession } from "./lib"
import { sha256 } from "@noble/hashes/sha256"

// When running via `npm run dev`, the Vite proxy forwards /v1/* to the TEE.
// Set VITE_TEE_URL in .env.local to point at a different TEE.
const TEE_URL = import.meta.env.VITE_TEE_URL as string ?? ""

const CHUNK = 16 * 1024 * 1024

async function computeSHA256(file: File): Promise<string> {
    const hasher = sha256.create()
    let offset = 0
    while (offset < file.size) {
        const buf = await file.slice(offset, offset + CHUNK).arrayBuffer()
        hasher.update(new Uint8Array(buf))
        offset += CHUNK
    }
    return Array.from(hasher.digest()).map(b => b.toString(16).padStart(2, "0")).join("")
}

// ── Styles (inline — no CSS files needed for this test app) ──────────────────

const s = {
    page:    { fontFamily: "monospace", maxWidth: 640, margin: "40px auto", padding: "0 20px" } as const,
    card:    { border: "1px solid #ccc", borderRadius: 8, padding: 24, marginBottom: 16 } as const,
    row:     { display: "flex", flexDirection: "column" as const, gap: 8, marginBottom: 16 },
    label:   { fontSize: 13, color: "#555" } as const,
    input:   { padding: "6px 8px", border: "1px solid #ccc", borderRadius: 4, fontSize: 14 } as const,
    btn:     { padding: "8px 18px", borderRadius: 4, border: "none", cursor: "pointer", fontSize: 14 } as const,
    primary: { background: "#1a56db", color: "#fff" } as const,
    success: { background: "#057a55", color: "#fff" } as const,
    pre:     { background: "#f4f4f4", padding: 12, borderRadius: 4, fontSize: 12, overflowX: "auto" as const, whiteSpace: "pre-wrap" as const },
    bar:     { width: "100%", height: 8, marginTop: 4 } as const,
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function App() {
    const [modelFile,   setModelFile]   = useState<File | null>(null)
    const [weightsFile, setWeightsFile] = useState<File | null>(null)
    const [datasetId,   setDatasetId]   = useState<1 | 2 | 3>(1)

    const [attested,  setAttested]  = useState(false)
    const [teeInfo,   setTeeInfo]   = useState<string | null>(null)
    const [log,       setLog]       = useState<string[]>([])
    const [modelPct,  setModelPct]  = useState(0)
    const [weightsPct,setWeightsPct]= useState(0)
    const [busy,      setBusy]      = useState(false)
    const [jobId,     setJobId]     = useState<string | null>(null)

    const sessionRef = useRef<OpenedSession | null>(null)

    function addLog(msg: string) {
        setLog(prev => [...prev, `${new Date().toLocaleTimeString()} ${msg}`])
    }

    // ── Attest ──────────────────────────────────────────────────────────────
    async function handleAttest() {
        setBusy(true)
        setLog([])
        setTeeInfo(null)
        setAttested(false)
        try {
            addLog("Fetching attestation bundle…")
            const session = await attestAndOpen({ attestUrl: TEE_URL })
            sessionRef.current = session
            const digest = session.oidc.submods.container.image_digest
            const hw     = session.oidc.hwmodel
            setTeeInfo(`Hardware : ${hw}\nImage    : ${digest}`)
            setAttested(true)
            addLog("✓ TEE attested and verified")
        } catch (err) {
            addLog(`✗ Attestation failed: ${err instanceof Error ? err.message : String(err)}`)
        } finally {
            setBusy(false)
        }
    }

    // ── Send ─────────────────────────────────────────────────────────────────
    async function handleSend() {
        if (!sessionRef.current || !modelFile || !weightsFile) return
        const session = sessionRef.current
        setBusy(true)
        setModelPct(0)
        setWeightsPct(0)

        try {
            addLog(`Hashing model (${(modelFile.size / 1024 / 1024).toFixed(1)} MB)…`)
            const modelSha256 = await computeSHA256(modelFile)

            addLog(`Hashing weights (${(weightsFile.size / 1024 / 1024).toFixed(1)} MB)…`)
            const weightsSha256 = await computeSHA256(weightsFile)

            addLog("Submitting job metadata (HPKE-encrypted)…")
            const result = await session.send("/v1/submit", {
                dataset_id:     datasetId,
                model_sha256:   modelSha256,
                weights_sha256: weightsSha256,
            }) as { job_id: string; status: string }

            const id = result.job_id
            setJobId(id)
            addLog(`Job created: ${id}`)

            addLog("Uploading model (AES-256-GCM chunked)…")
            await session.uploadEncrypted(
                `/v1/upload/${id}/model`,
                modelFile,
                modelSha256,
                pct => setModelPct(pct),
            )
            addLog("✓ Model uploaded")

            addLog("Uploading weights…")
            await session.uploadEncrypted(
                `/v1/upload/${id}/weights`,
                weightsFile,
                weightsSha256,
                pct => setWeightsPct(pct),
            )
            addLog(`✓ Weights uploaded — job ${id} queued`)
        } catch (err) {
            addLog(`✗ Error: ${err instanceof Error ? err.message : String(err)}`)
        } finally {
            setBusy(false)
        }
    }

    // ── OR: single-button flow using transferOnnxModel ───────────────────────
    async function handleSubmitAll() {
        if (!modelFile || !weightsFile) return
        setBusy(true)
        setLog([])
        setJobId(null)
        setModelPct(0)
        setWeightsPct(0)
        try {
            const result = await transferOnnxModel({
                teeUrl:      TEE_URL,
                modelFile,
                weightsFile,
                datasetId,
                onStep: (step, detail) => addLog(`[${step}] ${detail}`),
            })
            const r = result.response as { job_id: string; status: string }
            setJobId(r.job_id)
            addLog(`✓ Done in ${result.elapsedMs}ms — Job ID: ${r.job_id}`)
        } catch (err) {
            addLog(`✗ Failed: ${err instanceof Error ? err.message : String(err)}`)
        } finally {
            setBusy(false)
        }
    }

    const canSend = attested && !!modelFile && !!weightsFile && !busy

    return (
        <div style={s.page}>
            <h2 style={{ marginBottom: 24 }}>TANUH — Secure Model Submit (test app)</h2>

            {/* ── Files + Dataset ── */}
            <div style={s.card}>
                <div style={s.row}>
                    <label style={s.label}>Model file (.onnx)</label>
                    <input style={s.input} type="file" accept=".onnx"
                        onChange={e => setModelFile(e.target.files?.[0] ?? null)} />
                </div>
                <div style={s.row}>
                    <label style={s.label}>Weights file</label>
                    <input style={s.input} type="file"
                        onChange={e => setWeightsFile(e.target.files?.[0] ?? null)} />
                </div>
                <div style={s.row}>
                    <label style={s.label}>Dataset ID</label>
                    <select style={s.input} value={datasetId}
                        onChange={e => setDatasetId(+e.target.value as 1 | 2 | 3)}>
                        <option value={1}>1</option>
                        <option value={2}>2</option>
                        <option value={3}>3</option>
                    </select>
                </div>
            </div>

            {/* ── Two-step flow ── */}
            <div style={s.card}>
                <p style={{ marginTop: 0, fontSize: 13, color: "#555" }}>
                    <strong>Option A</strong> — Attest first, then Send separately
                </p>
                <div style={{ display: "flex", gap: 10 }}>
                    <button style={{ ...s.btn, ...s.primary }}
                        onClick={handleAttest} disabled={busy || attested}>
                        {busy && !attested ? "Attesting…" : attested ? "✓ Attested" : "Attest TEE"}
                    </button>
                    <button style={{ ...s.btn, ...s.success }}
                        onClick={handleSend} disabled={!canSend}>
                        {busy && attested ? "Sending…" : "Send"}
                    </button>
                </div>

                {teeInfo && (
                    <pre style={{ ...s.pre, marginTop: 12 }}>{teeInfo}</pre>
                )}
            </div>

            {/* ── Single-step flow ── */}
            <div style={s.card}>
                <p style={{ marginTop: 0, fontSize: 13, color: "#555" }}>
                    <strong>Option B</strong> — Attest + Send in one click
                </p>
                <button style={{ ...s.btn, ...s.primary }}
                    onClick={handleSubmitAll}
                    disabled={busy || !modelFile || !weightsFile}>
                    {busy ? "Working…" : "Attest & Submit"}
                </button>
            </div>

            {/* ── Progress ── */}
            {(modelPct > 0 || weightsPct > 0) && (
                <div style={s.card}>
                    <div>Model upload <progress style={s.bar} value={modelPct} max={100} /> {modelPct}%</div>
                    <div style={{ marginTop: 8 }}>Weights upload <progress style={s.bar} value={weightsPct} max={100} /> {weightsPct}%</div>
                </div>
            )}

            {/* ── Log ── */}
            {log.length > 0 && (
                <div style={s.card}>
                    <pre style={s.pre}>{log.join("\n")}</pre>
                    {jobId && <p style={{ marginBottom: 0 }}><strong>Job ID:</strong> {jobId}</p>}
                </div>
            )}
        </div>
    )
}
