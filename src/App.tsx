import { useState } from "react"
import { transferOnnxModel } from "./lib"
import type { StepName } from "./lib"

// When running via `npm run dev`, the Vite proxy forwards /v1/* to the TEE.
// Set VITE_TEE_URL in .env.local to point at a different TEE.
const TEE_URL = import.meta.env.VITE_TEE_URL as string ?? ""

const s = {
    page:    { fontFamily: "monospace", maxWidth: 640, margin: "40px auto", padding: "0 20px" } as const,
    card:    { border: "1px solid #ccc", borderRadius: 8, padding: 24, marginBottom: 16 } as const,
    row:     { display: "flex", flexDirection: "column" as const, gap: 8, marginBottom: 16 },
    label:   { fontSize: 13, color: "#555" } as const,
    input:   { padding: "6px 8px", border: "1px solid #ccc", borderRadius: 4, fontSize: 14 } as const,
    btn:     { padding: "8px 18px", borderRadius: 4, border: "none", cursor: "pointer", fontSize: 14 } as const,
    primary: { background: "#1a56db", color: "#fff" } as const,
    pre:     { background: "#f4f4f4", padding: 12, borderRadius: 4, fontSize: 12, overflowX: "auto" as const, whiteSpace: "pre-wrap" as const },
    bar:     { width: "100%", height: 8, marginTop: 4 } as const,
}

const STEP_LABEL: Record<StepName, string> = {
    attest_start:   "Attesting TEE…",
    attest_done:    "TEE verified",
    model_hash:     "Hashing files…",
    submit_meta:    "Submitting job metadata…",
    upload_model:   "Uploading model…",
    upload_weights: "Uploading weights…",
    done:           "Done",
    error:          "Error",
}

export default function App() {
    const [modelFile,    setModelFile]    = useState<File | null>(null)
    const [weightsFile,  setWeightsFile]  = useState<File | null>(null)
    const [datasetId,    setDatasetId]    = useState<1 | 2 | 3>(1)
    const [log,          setLog]          = useState<string[]>([])
    const [modelPct,     setModelPct]     = useState(0)
    const [weightsPct,   setWeightsPct]   = useState(0)
    const [busy,         setBusy]         = useState(false)
    const [jobId,        setJobId]        = useState<string | null>(null)
    const [currentStep,  setCurrentStep]  = useState<StepName | null>(null)

    function addLog(msg: string) {
        setLog(prev => [...prev, `${new Date().toLocaleTimeString()} ${msg}`])
    }

    async function handleSubmit() {
        if (!modelFile || !weightsFile) return
        setBusy(true)
        setLog([])
        setJobId(null)
        setModelPct(0)
        setWeightsPct(0)
        setCurrentStep(null)

        try {
            const result = await transferOnnxModel({
                teeUrl:      TEE_URL,
                modelFile,
                weightsFile,
                datasetId,
                onStep(step, detail) {
                    setCurrentStep(step)
                    if (step === "upload_model") {
                        const pct = parseInt(detail)
                        if (!isNaN(pct)) { setModelPct(pct); return }
                    }
                    if (step === "upload_weights") {
                        const pct = parseInt(detail)
                        if (!isNaN(pct)) { setWeightsPct(pct); return }
                    }
                    addLog(`[${STEP_LABEL[step]}] ${detail}`)
                },
            })
            const r = result.response as { job_id: string; status: string }
            setJobId(r.job_id)
        } catch (err) {
            addLog(`✗ ${err instanceof Error ? err.message : String(err)}`)
        } finally {
            setBusy(false)
            setCurrentStep(null)
        }
    }

    const canSubmit = !!modelFile && !!weightsFile && !busy

    return (
        <div style={s.page}>
            <h2 style={{ marginBottom: 24 }}>TANUH — Secure Model Submit</h2>

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
                <button style={{ ...s.btn, ...s.primary }}
                    onClick={handleSubmit} disabled={!canSubmit}>
                    {busy && currentStep ? STEP_LABEL[currentStep] : "Attest & Submit"}
                </button>
            </div>

            {(modelPct > 0 || weightsPct > 0) && (
                <div style={s.card}>
                    <div>
                        Model
                        <progress style={s.bar} value={modelPct} max={100} />
                        {modelPct}%
                    </div>
                    <div style={{ marginTop: 8 }}>
                        Weights
                        <progress style={s.bar} value={weightsPct} max={100} />
                        {weightsPct}%
                    </div>
                </div>
            )}

            {log.length > 0 && (
                <div style={s.card}>
                    <pre style={s.pre}>{log.join("\n")}</pre>
                    {jobId && (
                        <p style={{ marginBottom: 0, marginTop: 12 }}>
                            <strong>Job ID:</strong> {jobId}
                        </p>
                    )}
                </div>
            )}
        </div>
    )
}
