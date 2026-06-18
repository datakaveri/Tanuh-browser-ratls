import { useState, useEffect, useRef } from "react"
import { transferOnnxModel } from "./lib"
import type { StepName, CSOidcPayload } from "./lib"

// When running via `npm run dev`, the Vite proxy forwards /v1/* to the TEE.
// Set VITE_TEE_URL in .env.local to point at a different TEE.
const TEE_URL = import.meta.env.VITE_TEE_URL as string ?? ""

const s = {
    page:    { fontFamily: "monospace", maxWidth: 680, margin: "40px auto", padding: "0 20px" } as const,
    card:    { border: "1px solid #ccc", borderRadius: 8, padding: 20, marginBottom: 16 } as const,
    row:     { display: "flex", flexDirection: "column" as const, gap: 8, marginBottom: 16 },
    label:   { fontSize: 13, color: "#555" } as const,
    input:   { padding: "6px 8px", border: "1px solid #ccc", borderRadius: 4, fontSize: 14 } as const,
    btn:     { padding: "8px 18px", borderRadius: 4, border: "none", cursor: "pointer", fontSize: 14 } as const,
    primary: { background: "#1a56db", color: "#fff" } as const,
    pre:     { background: "#f4f4f4", padding: 12, borderRadius: 4, fontSize: 11, overflowX: "auto" as const, whiteSpace: "pre-wrap" as const, margin: 0 },
    bar:     { width: "100%", height: 8, marginTop: 4 } as const,
    h3:      { margin: "0 0 12px", fontSize: 14, fontWeight: 700, letterSpacing: "0.02em" } as const,
    kv:      { display: "grid", gridTemplateColumns: "160px 1fr", gap: "4px 12px", fontSize: 12 } as const,
    key:     { color: "#666" } as const,
    val:     { wordBreak: "break-all" as const } as const,
    badge:   (ok: boolean) => ({
        display: "inline-block", padding: "1px 7px", borderRadius: 10, fontSize: 11,
        background: ok ? "#d1fae5" : "#fee2e2", color: ok ? "#065f46" : "#991b1b",
    } as const),
}

const STEP_LABEL: Record<StepName, string> = {
    attest_start:   "Attesting TEE…",
    attest_done:    "TEE verified",
    model_hash:     "Hashing files…",
    submit_meta:    "Submitting job metadata…",
    upload_model:   "Uploading model…",
    upload_weights: "Uploading weights…",
    upload_python:  "Uploading Python script…",
    done:           "Done",
    error:          "Error",
}

type QueueInfo = { position: number; total: number; status: string }
type JobResults = Record<string, unknown>

function AttestCard({ oidc }: { oidc: CSOidcPayload }) {
    const digest = oidc.submods?.container?.image_digest ?? "—"
    const isDebug = oidc.dbgstat === "enabled"
    return (
        <div style={s.card}>
            <div style={s.h3}>Buffer TEE Attestation Report</div>
            <div style={s.kv}>
                <span style={s.key}>Hardware</span>
                <span style={s.val}>{oidc.hwmodel ?? "—"}</span>

                <span style={s.key}>Software</span>
                <span style={s.val}>{oidc.swname ?? "—"}</span>

                <span style={s.key}>Secure Boot</span>
                <span style={s.val}><span style={s.badge(!!oidc.secboot)}>{oidc.secboot ? "enabled" : "disabled"}</span></span>

                <span style={s.key}>Mode</span>
                <span style={s.val}>
                    <span style={s.badge(!isDebug)}>{isDebug ? "debug" : "production"}</span>
                </span>

                <span style={s.key}>Image digest</span>
                <span style={s.val} title={digest}>{digest.slice(0, 23)}…</span>

                <span style={s.key}>Issuer</span>
                <span style={s.val}>{oidc.iss ?? "—"}</span>
            </div>
        </div>
    )
}

function QueueCard({ jobId, info }: { jobId: string; info: QueueInfo }) {
    const statusLabel: Record<string, string> = {
        pending_upload: "Waiting for upload",
        queued:         "Queued",
        dispatched:     "Running on Processing TEE",
        complete:       "Complete",
        error:          "Error",
    }
    return (
        <div style={s.card}>
            <div style={s.h3}>Job Status</div>
            <div style={s.kv}>
                <span style={s.key}>Job ID</span>
                <span style={s.val}>{jobId}</span>

                <span style={s.key}>Status</span>
                <span style={s.val}><span style={s.badge(info.status === "complete")}>{statusLabel[info.status] ?? info.status}</span></span>

                {info.status === "queued" && info.position > 0 && (
                    <>
                        <span style={s.key}>Queue position</span>
                        <span style={s.val}>{info.position} of {info.total}</span>
                    </>
                )}

                {info.status === "dispatched" && (
                    <>
                        <span style={s.key}>Processing TEE</span>
                        <span style={s.val}>Running inference…</span>
                    </>
                )}
            </div>
        </div>
    )
}

function ResultsCard({ results }: { results: JobResults }) {
    const att = results.attestation as Record<string, unknown> | undefined
    return (
        <div style={s.card}>
            <div style={s.h3}>Evaluation Results</div>
            <div style={s.kv}>
                <span style={s.key}>Accuracy</span>
                <span style={s.val}>{typeof results.accuracy === "number" ? `${(results.accuracy * 100).toFixed(1)}%` : "—"}</span>

                <span style={s.key}>Samples</span>
                <span style={s.val}>{String(results.num_samples ?? "—")}</span>

                <span style={s.key}>Elapsed</span>
                <span style={s.val}>{typeof results.elapsed_seconds === "number" ? `${results.elapsed_seconds}s` : "—"}</span>

                <span style={s.key}>Providers</span>
                <span style={s.val}>{Array.isArray(results.onnx_runtime_providers) ? (results.onnx_runtime_providers as string[]).join(", ") : "—"}</span>

                <span style={s.key}>Model SHA-256</span>
                <span style={s.val} title={String(results.model_sha256 ?? "")}>{String(results.model_sha256 ?? "—").slice(0, 20)}…</span>
            </div>

            {att && typeof att.hwmodel === "string" && att.hwmodel && (
                <>
                    <div style={{ ...s.h3, marginTop: 16 }}>Processing TEE Attestation</div>
                    <div style={s.kv}>
                        <span style={s.key}>Hardware</span>
                        <span style={s.val}>{String(att.hwmodel)}</span>

                        <span style={s.key}>Secure Boot</span>
                        <span style={s.val}><span style={s.badge(!!att.secboot)}>{att.secboot ? "enabled" : "disabled"}</span></span>

                        <span style={s.key}>Image digest</span>
                        <span style={s.val} title={String(att.image_digest ?? "")}>
                            {String(att.image_digest ?? "—").slice(0, 23)}…
                        </span>
                    </div>
                </>
            )}

            <details style={{ marginTop: 12 }}>
                <summary style={{ cursor: "pointer", fontSize: 12, color: "#555" }}>Raw JSON</summary>
                <pre style={{ ...s.pre, marginTop: 8 }}>{JSON.stringify(results, null, 2)}</pre>
            </details>
        </div>
    )
}

export default function App() {
    const [modelFile,    setModelFile]    = useState<File | null>(null)
    const [weightsFile,  setWeightsFile]  = useState<File | null>(null)
    const [pythonFile,   setPythonFile]   = useState<File | null>(null)
    const [datasetId,    setDatasetId]    = useState<1 | 2 | 3>(1)
    const [log,          setLog]          = useState<string[]>([])
    const [modelPct,     setModelPct]     = useState(0)
    const [weightsPct,   setWeightsPct]   = useState(0)
    const [pythonPct,    setPythonPct]    = useState(0)
    const [busy,         setBusy]         = useState(false)
    const [currentStep,  setCurrentStep]  = useState<StepName | null>(null)
    const [attestInfo,   setAttestInfo]   = useState<CSOidcPayload | null>(null)
    const [jobId,        setJobId]        = useState<string | null>(null)
    const [queueInfo,    setQueueInfo]    = useState<QueueInfo | null>(null)
    const [jobResults,   setJobResults]   = useState<JobResults | null>(null)

    const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null)

    function stopPolling() {
        if (pollingRef.current !== null) {
            clearInterval(pollingRef.current)
            pollingRef.current = null
        }
    }

    useEffect(() => stopPolling, [])

    function startPolling(jid: string) {
        stopPolling()
        const base = TEE_URL  // empty → relative paths through Vite proxy

        async function poll() {
            try {
                // Job status
                const sr = await fetch(`${base}/v1/status/${jid}`)
                if (!sr.ok) return
                const sd = await sr.json() as { job?: { status: string } }
                const status = sd.job?.status ?? "unknown"

                // Queue position (only meaningful when queued)
                let position = -1, total = 0
                if (status === "queued") {
                    const qr = await fetch(`${base}/v1/queue`)
                    if (qr.ok) {
                        const qd = await qr.json() as { queued_job_ids?: string[] }
                        const ids = qd.queued_job_ids ?? []
                        total    = ids.length
                        position = ids.indexOf(jid) + 1  // 1-based; 0 means not found
                    }
                }

                setQueueInfo({ position, total, status })

                if (status === "complete") {
                    stopPolling()
                    const rr = await fetch(`${base}/v1/results/${jid}`)
                    if (rr.ok) setJobResults(await rr.json())
                } else if (status === "error") {
                    stopPolling()
                }
            } catch {
                // non-fatal — keep polling
            }
        }

        poll()  // immediate first call
        pollingRef.current = setInterval(poll, 5000)
    }

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
        setPythonPct(0)
        setCurrentStep(null)
        setAttestInfo(null)
        setQueueInfo(null)
        setJobResults(null)
        stopPolling()

        try {
            const result = await transferOnnxModel({
                teeUrl:      TEE_URL,
                modelFile,
                weightsFile,
                ...(pythonFile ? { pythonFile } : {}),
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
                    if (step === "upload_python") {
                        const pct = parseInt(detail)
                        if (!isNaN(pct)) { setPythonPct(pct); return }
                    }
                    addLog(`[${STEP_LABEL[step]}] ${detail}`)
                },
            })

            if (result.oidc) setAttestInfo(result.oidc)

            const r = result.response as { job_id: string; status: string }
            setJobId(r.job_id)
            if (r.job_id) startPolling(r.job_id)
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

            {/* ── Submit form ───────────────────────────────────────── */}
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
                    <label style={s.label}>Python script (.py) — optional</label>
                    <input style={s.input} type="file" accept=".py"
                        onChange={e => setPythonFile(e.target.files?.[0] ?? null)} />
                </div>
                <div style={s.row}>
                    <label style={s.label}>Dataset ID</label>
                    <select style={s.input} value={datasetId}
                        onChange={e => setDatasetId(+e.target.value as 1 | 2 | 3)}>
                        <option value={1}>1 — Binary bright-center dataset</option>
                        <option value={2}>2 — Three-class stripe dataset</option>
                        <option value={3}>3 — Binary diagonal-pattern dataset</option>
                    </select>
                </div>
                <button style={{ ...s.btn, ...s.primary }}
                    onClick={handleSubmit} disabled={!canSubmit}>
                    {busy && currentStep ? STEP_LABEL[currentStep] : "Attest & Submit"}
                </button>
            </div>

            {/* ── Upload progress ────────────────────────────────────── */}
            {(modelPct > 0 || weightsPct > 0 || pythonPct > 0) && (
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
                    {pythonFile && (
                        <div style={{ marginTop: 8 }}>
                            Python script
                            <progress style={s.bar} value={pythonPct} max={100} />
                            {pythonPct}%
                        </div>
                    )}
                </div>
            )}

            {/* ── Step log ───────────────────────────────────────────── */}
            {log.length > 0 && (
                <div style={s.card}>
                    <div style={s.h3}>Transfer Log</div>
                    <pre style={s.pre}>{log.join("\n")}</pre>
                </div>
            )}

            {/* ── Buffer TEE attestation report ─────────────────────── */}
            {attestInfo && <AttestCard oidc={attestInfo} />}

            {/* ── Queue position / job status ───────────────────────── */}
            {jobId && queueInfo && <QueueCard jobId={jobId} info={queueInfo} />}

            {/* ── Evaluation results + Processing TEE attestation ───── */}
            {jobResults && <ResultsCard results={jobResults} />}
        </div>
    )
}
