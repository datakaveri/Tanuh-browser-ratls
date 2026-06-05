import { useState, useRef, useEffect, DragEvent, ChangeEvent } from "react"
import { transferOnnxModel, type StepName } from "../lib/transfer-onnx"
import type { CSOidcPayload } from "../lib/oidc"
import styles from "./ModelTransfer.module.css"

type StepState = "idle" | "active" | "done" | "error"

interface Step { id: string; title: string; description: string }
const STEPS: Step[] = [
  { id: "nonce",    title: "Generate liveness nonce",                          description: "crypto.getRandomValues(32 bytes)" },
  { id: "fetch",    title: "Fetch attestation bundle  GET /v1/attest",         description: "X-RATLS-Nonce: <nonce>" },
  { id: "verify",   title: "Verify bundle (OIDC · eat_nonce · liveness ECDSA)", description: "jwtVerify · image_digest · binding key" },
  { id: "model_hash", title: "SHA256 hash model + weights",                        description: "WebCrypto native hash — fast" },
  { id: "submit_meta", title: "HPKE-encrypt metadata  POST /v1/submit",            description: "Tiny payload: hashes + dataset_id" },
  { id: "upload_model", title: "Upload model binary  PUT /v1/upload/:id/model",   description: "Raw bytes over TLS 1.3" },
  { id: "upload_weights", title: "Upload weights binary  PUT /v1/upload/:id/weights", description: "Raw bytes over TLS 1.3" },
  
]

type JobStatus = "queued" | "dispatched" | "complete" | "rejected" | "error" | "unknown"

interface JobPoll {
  jobId: string
  teeUrl: string
  status: JobStatus
  queuePos: number | null
  queueLen: number
  dispatchedAt: number | null
  results: Record<string, unknown> | null
  gcsUri: string | null
  errorMsg: string | null
}

function formatBytes(n: number): string {
  if (n < 1024)        return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(2)} MB`
}

function elapsed(unix: number): string {
  const s = Math.floor((Date.now() / 1000) - unix)
  if (s < 60) return `${s}s ago`
  return `${Math.floor(s / 60)}m ${s % 60}s ago`
}

export default function ModelTransfer() {
  const [teeUrl, setTeeUrl]           = useState("")
  const [modelFile, setModelFile]     = useState<File | null>(null)
  const [weightsFile, setWeightsFile] = useState<File | null>(null)
  const [datasetId, setDatasetId]     = useState<1|2|3>(1)
  const [draggingM, setDraggingM]     = useState(false)
  const [draggingW, setDraggingW]     = useState(false)
  const [running, setRunning]         = useState(false)
  const [started, setStarted]         = useState(false)

  const [stepStates, setStepStates]   = useState<Record<string, StepState>>({})
  const [stepDetails, setStepDetails] = useState<Record<string, string>>({})
  const [oidc, setOidc]               = useState<CSOidcPayload | null>(null)
  const [errorMsg, setErrorMsg]       = useState<string | null>(null)

  // Live job tracking
  const [poll, setPoll]               = useState<JobPoll | null>(null)
  const pollRef                       = useRef<ReturnType<typeof setInterval> | null>(null)

  const modelInputRef   = useRef<HTMLInputElement>(null)
  const weightsInputRef = useRef<HTMLInputElement>(null)

  // Cleanup polling on unmount
  useEffect(() => () => { if (pollRef.current) clearInterval(pollRef.current) }, [])

  function setStep(id: string, state: StepState, detail?: string) {
    setStepStates(prev => ({ ...prev, [id]: state }))
    if (detail !== undefined) setStepDetails(prev => ({ ...prev, [id]: detail }))
  }

  function handleStepCallback(step: StepName, detail: string) {
    if (step === "attest_start") {
      setStep("nonce", "done", "crypto.getRandomValues(32 bytes) ✓")
      setStep("fetch", "active", detail)
    } else if (step === "attest_done") {
      setStep("fetch",  "done", "AttestBundle received ✓")
      setStep("verify", "done", detail)
    } else if (step === "model_hash") {
      setStep("model_hash", "active", detail)
    } else if (step === "submit_meta") {
      setStep("model_hash", "done", "SHA256 committed ✓")
      setStep("submit_meta", "active", detail)
    } else if (step === "upload_model") {
      setStep("submit_meta", "done", "Job created ✓")
      setStep("upload_model", "active", detail)
    } else if (step === "upload_weights") {
      setStep("upload_model", "done", "Model uploaded ✓")
      setStep("upload_weights", "active", detail)
    } else if (step === "done") {
      setStep("upload_weights", "done", detail)
    } else if (step === "error") {
      setStepStates(prev => {
        const next = { ...prev }
        for (const id of Object.keys(next)) if (next[id] === "active") next[id] = "error"
        return next
      })
    }
  }

  async function startPolling(jobId: string, url: string) {
    const initial: JobPoll = {
      jobId, teeUrl: url, status: "queued",
      queuePos: null, queueLen: 0, dispatchedAt: null,
      results: null, gcsUri: null, errorMsg: null,
    }
    setPoll(initial)

    const tick = async () => {
      try {
        // Get job status
        const jr = await fetch(`${url}/v1/status/${jobId}`, { signal: AbortSignal.timeout(8000) })
        if (!jr.ok) return
        const jd = await jr.json() as { job?: Record<string,unknown>; status?: string }
        const job = (jd.job ?? jd) as Record<string,unknown>
        const status = (job.status ?? "unknown") as JobStatus

        // Get queue to calculate position
        const qr = await fetch(`${url}/v1/queue`, { signal: AbortSignal.timeout(8000) })
        let queuePos: number | null = null
        let queueLen = 0
        if (qr.ok) {
          const qd = await qr.json() as { queued_job_ids?: string[] }
          const ids = qd.queued_job_ids ?? []
          queueLen = ids.length
          const idx = ids.indexOf(jobId)
          queuePos = idx >= 0 ? idx + 1 : null
        }

        let results: Record<string, unknown> | null = null
        let gcsUri: string | null = (job.gcs_results_uri as string) ?? null

        if (status === "complete") {
          const rr = await fetch(`${url}/v1/results/${jobId}`, { signal: AbortSignal.timeout(8000) })
          if (rr.ok) results = await rr.json() as Record<string,unknown>
          if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null }
        }

        setPoll(prev => prev ? {
          ...prev, status, queuePos, queueLen,
          dispatchedAt: (job.dispatched_at_unix as number) ?? prev.dispatchedAt,
          results, gcsUri,
        } : prev)
      } catch {
        // transient — keep polling
      }
    }

    await tick()
    pollRef.current = setInterval(tick, 5000)
  }

  async function run() {
    if (!modelFile || !weightsFile) return
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null }
    setPoll(null)
    setStarted(true)
    setRunning(true)
    setOidc(null)
    setErrorMsg(null)
    setStepStates({ nonce: "active" })
    setStepDetails({
      nonce:    "Generating…",
      fetch:    `GET ${teeUrl}/v1/attest`,
      verify:   "jwtVerify · image_digest · eat_nonce · ECDSA liveness",
      encrypt:  "Sealing model + weights in browser",
      transfer: "POST /v1/submit → HPKE ciphertext only in transit",
    })

    try {
      const result = await transferOnnxModel({
        teeUrl, modelFile, weightsFile, datasetId, onStep: handleStepCallback,
      })
      setOidc(result.oidc)
      const resp = result.response as { job_id?: string }
      if (resp?.job_id) startPolling(resp.job_id, teeUrl)
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err))
    } finally {
      setRunning(false)
    }
  }

  function statusLabel(p: JobPoll): string {
    if (p.status === "queued") {
      if (p.queuePos !== null) return `Queued — position ${p.queuePos} of ${p.queueLen}`
      return "Queued — waiting for position info…"
    }
    if (p.status === "dispatched") {
      const ago = p.dispatchedAt ? ` (${elapsed(p.dispatchedAt)})` : ""
      return `Running on Processing TEE (TDX + H100)${ago}`
    }
    if (p.status === "complete") return "✅ Inference complete"
    if (p.status === "rejected") return "❌ Job rejected"
    return p.status
  }

  function statusColor(s: JobStatus) {
    if (s === "complete") return "#22c55e"
    if (s === "rejected" || s === "error") return "#ef4444"
    if (s === "dispatched") return "#60a5fa"
    return "#f59e0b"
  }

  return (
    <div className={styles.page}>
      <header className={styles.header}>
        <h1>Tanuh · Secure ONNX Transfer</h1>
        <p>RA-TLS · AMD SEV-SNP · Google Confidential Space · HPKE encrypted channel</p>
      </header>

      {/* Config */}
      <div className={styles.card}>
        <h2 className={styles.cardTitle}>Configuration</h2>
        <label className={styles.label}>Buffer TEE URL</label>
        <input className={styles.input} type="url" value={teeUrl}
          onChange={e => setTeeUrl(e.target.value)} disabled={running} />
        <label className={styles.label} style={{marginTop:"0.8rem"}}>Dataset</label>
        <select className={styles.input} value={datasetId}
          onChange={e => setDatasetId(parseInt(e.target.value) as 1|2|3)} disabled={running}>
          <option value={1}>Dataset 1 — Binary bright-center images</option>
          <option value={2}>Dataset 2 — Three-class stripe-position images</option>
          <option value={3}>Dataset 3 — Binary diagonal-pattern images</option>
        </select>
        <div className={styles.certHint}>
          Using proxy mode (empty URL) — browser talks to Vite, Vite forwards to Buffer TEE over TLS 1.3. Or fill in the URL field and first accept the cert at <a href="https://8.35.197.50:8443" target="_blank" rel="noopener noreferrer">https://8.35.197.50:8443</a>.
        </div>
      </div>

      {/* Files */}
      <div className={styles.card}>
        <h2 className={styles.cardTitle}>ONNX Model Files</h2>

        <label className={styles.label}>model.onnx</label>
        <div className={`${styles.dropZone} ${draggingM ? styles.dragOver : ""}`}
          onClick={() => modelInputRef.current?.click()}
          onDragOver={e => { e.preventDefault(); setDraggingM(true) }}
          onDragLeave={() => setDraggingM(false)}
          onDrop={(e: DragEvent<HTMLDivElement>) => {
            e.preventDefault(); setDraggingM(false)
            const f = e.dataTransfer.files[0]; if (f?.name.endsWith(".onnx")) setModelFile(f)
          }}>
          <input ref={modelInputRef} type="file" accept=".onnx" style={{ display: "none" }}
            onChange={(e: ChangeEvent<HTMLInputElement>) => {
              const f = e.target.files?.[0]; if (f?.name.endsWith(".onnx")) setModelFile(f)
            }} />
          <div className={styles.dzIcon}>🧠</div>
          {modelFile
            ? <><div className={styles.dzFileName}>{modelFile.name}</div><div className={styles.dzFileSize}>{formatBytes(modelFile.size)}</div></>
            : <><div className={styles.dzMain}>Drop <strong>model.onnx</strong> or click to browse</div><div className={styles.dzSub}>Encrypted before leaving browser</div></>}
        </div>

        <label className={styles.label} style={{marginTop:"1rem"}}>model.onnx.data (external weights)</label>
        <div className={`${styles.dropZone} ${draggingW ? styles.dragOver : ""}`}
          onClick={() => weightsInputRef.current?.click()}
          onDragOver={e => { e.preventDefault(); setDraggingW(true) }}
          onDragLeave={() => setDraggingW(false)}
          onDrop={(e: DragEvent<HTMLDivElement>) => {
            e.preventDefault(); setDraggingW(false); setWeightsFile(e.dataTransfer.files[0] ?? null)
          }}>
          <input ref={weightsInputRef} type="file" style={{ display: "none" }}
            onChange={(e: ChangeEvent<HTMLInputElement>) => setWeightsFile(e.target.files?.[0] ?? null)} />
          <div className={styles.dzIcon}>⚖️</div>
          {weightsFile
            ? <><div className={styles.dzFileName}>{weightsFile.name}</div><div className={styles.dzFileSize}>{formatBytes(weightsFile.size)}</div></>
            : <><div className={styles.dzMain}>Drop <strong>.onnx.data</strong> weights or click</div><div className={styles.dzSub}>Encrypted together with model.onnx</div></>}
        </div>

        <button className={styles.goBtn} onClick={run} disabled={!modelFile || !weightsFile || running}>
          {running ? "Attesting & Transferring…" : "Attest & Transfer"}
        </button>
      </div>

      {/* RA-TLS progress */}
      {started && (
        <div className={styles.card}>
          <h2 className={styles.cardTitle}>Attestation &amp; Transfer</h2>
          <div className={styles.steps}>
            {STEPS.map((s, idx) => {
              const state  = stepStates[s.id] ?? "idle"
              const detail = stepDetails[s.id] ?? s.description
              return (
                <div key={s.id} className={`${styles.step} ${styles[state]}`}>
                  <div className={styles.stepNum}>
                    {state === "done" ? "✓" : state === "error" ? "✗" : idx + 1}
                  </div>
                  <div className={styles.stepBody}>
                    <div className={styles.stepTitle}>{s.title}</div>
                    <div className={styles.stepDetail}>{detail}</div>
                  </div>
                </div>
              )
            })}
          </div>
          {errorMsg && <div className={styles.errorBox}>{errorMsg}</div>}
        </div>
      )}

      {/* Live job status */}
      {poll && (
        <div className={styles.card}>
          <h2 className={styles.cardTitle}>Job Status</h2>
          <div style={{ display:"flex", flexDirection:"column", gap:"0.6rem" }}>

            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center" }}>
              <span style={{ color:"#9ca3af", fontSize:"0.82rem" }}>Job ID</span>
              <code style={{ color:"#e0e0e0", fontSize:"0.8rem" }}>{poll.jobId}</code>
            </div>

            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center" }}>
              <span style={{ color:"#9ca3af", fontSize:"0.82rem" }}>Status</span>
              <span style={{ color: statusColor(poll.status), fontWeight:600 }}>
                {statusLabel(poll)}
                {poll.status !== "complete" && poll.status !== "rejected" &&
                  <span style={{ marginLeft:"0.4rem", fontSize:"0.75rem" }}>⟳</span>}
              </span>
            </div>

            {poll.status === "queued" && poll.queueLen > 0 && (
              <div>
                <div style={{ fontSize:"0.78rem", color:"#6b7280", marginBottom:"0.3rem" }}>
                  Queue ({poll.queueLen} job{poll.queueLen !== 1 ? "s" : ""})
                </div>
                <div style={{ background:"#0f1a0f", borderRadius:"4px", padding:"0.4rem 0.6rem", fontSize:"0.78rem", color:"#6b7280" }}>
                  Your job is <strong style={{color:"#f59e0b"}}>#{poll.queuePos ?? "?"}</strong> — Processing TEE
                  will be allocated and started automatically
                </div>
              </div>
            )}

            {poll.status === "dispatched" && (
              <div style={{ background:"#1e3a5f", borderRadius:"4px", padding:"0.5rem 0.8rem", fontSize:"0.82rem", color:"#60a5fa" }}>
                🔄 Model is being processed on the TDX + H100 Processing TEE.
                ONNX inference running…
              </div>
            )}

            {poll.status === "complete" && poll.results && (
              <div style={{ background:"#0f1a0f", border:"1px solid #166534", borderRadius:"6px", padding:"0.8rem" }}>
                <div style={{ color:"#4ade80", fontWeight:600, marginBottom:"0.4rem" }}>
                  ✅ Inference complete
                </div>
                {[
                  ["Accuracy",  `${((poll.results.accuracy as number) * 100).toFixed(1)}%`],
                  ["Samples",   String(poll.results.num_samples)],
                  ["Classes",   String(poll.results.num_classes)],
                  ["Elapsed",   `${poll.results.elapsed_seconds}s`],
                  ["Providers", (poll.results.onnx_runtime_providers as string[]).join(", ")],
                  ["Model SHA256", `${(poll.results.model_sha256 as string).substring(0,20)}…`],
                ].map(([k, v]) => (
                  <div key={k} style={{ display:"flex", justifyContent:"space-between", padding:"0.25rem 0",
                    borderBottom:"1px solid #1a2e1a", fontSize:"0.82rem" }}>
                    <span style={{ color:"#6b7280" }}>{k}</span>
                    <span style={{ color:"#d1d5db" }}>{v}</span>
                  </div>
                ))}
                {poll.gcsUri && (
                  <div style={{ marginTop:"0.6rem", fontSize:"0.78rem" }}>
                    <span style={{ color:"#6b7280" }}>Full results: </span>
                    <code style={{ color:"#4ade80" }}>{poll.gcsUri}</code>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Verified TEE identity */}
      {oidc && (
        <div className={styles.card}>
          <h2 className={styles.cardTitle}>✅ Verified Buffer TEE Identity</h2>
          <div className={styles.claimsGrid}>
            {([
              ["Image digest", oidc.submods?.container?.image_digest ?? "—"],
              ["Hardware model", oidc.hwmodel ?? "—"],
              ["OIDC issuer", oidc.iss],
              ["Audience", Array.isArray(oidc.aud) ? oidc.aud.join(", ") : String(oidc.aud)],
              ["Issued at", new Date(oidc.iat * 1000).toISOString()],
              ["Expires at", new Date(oidc.exp * 1000).toISOString()],
            ] as [string,string][]).map(([k, v]) => (
              <>
                <div key={`k-${k}`} className={styles.claimKey}>{k}</div>
                <div key={`v-${k}`} className={styles.claimVal}>{v}</div>
              </>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
