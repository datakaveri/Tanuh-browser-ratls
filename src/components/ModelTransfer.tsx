import { useState, useRef, DragEvent, ChangeEvent } from "react"
import { transferOnnxModel, type StepName } from "../lib/transfer-onnx"
import type { CSOidcPayload } from "../lib/oidc"
import styles from "./ModelTransfer.module.css"

type StepState = "idle" | "active" | "done" | "error"

interface Step {
  id: string
  title: string
  description: string
}

const STEPS: Step[] = [
  { id: "nonce",    title: "Generate liveness nonce",                         description: "crypto.getRandomValues(32 bytes)" },
  { id: "fetch",    title: "Fetch attestation bundle from TEE",               description: "GET /v1/attest · X-RATLS-Nonce: <nonce>" },
  { id: "verify",   title: "Verify bundle (OIDC · eat_nonce · liveness ECDSA)", description: "jwtVerify · image_digest · binding key · HPKE key" },
  { id: "encrypt",  title: "Encrypt model — HPKE X25519 / AES-256-GCM",      description: "Sealing payload in browser" },
  { id: "transfer", title: "Transfer to TEE · decrypt response",              description: "POST → HPKE-sealed ciphertext only in transit" },
]

function formatBytes(n: number): string {
  if (n < 1024)        return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(2)} MB`
}

export default function ModelTransfer() {
  const [teeUrl, setTeeUrl]       = useState("https://35.239.166.229:8443")
  const [endpoint, setEndpoint]   = useState("/v1/model/upload")
  const [file, setFile]           = useState<File | null>(null)
  const [dragging, setDragging]   = useState(false)
  const [running, setRunning]     = useState(false)
  const [started, setStarted]     = useState(false)

  const [stepStates, setStepStates]     = useState<Record<string, StepState>>({})
  const [stepDetails, setStepDetails]   = useState<Record<string, string>>({})
  const [oidc, setOidc]                 = useState<CSOidcPayload | null>(null)
  const [response, setResponse]         = useState<unknown>(null)
  const [elapsedMs, setElapsedMs]       = useState<number | null>(null)
  const [errorMsg, setErrorMsg]         = useState<string | null>(null)

  const fileInputRef = useRef<HTMLInputElement>(null)

  function setStep(id: string, state: StepState, detail?: string) {
    setStepStates(prev => ({ ...prev, [id]: state }))
    if (detail !== undefined) setStepDetails(prev => ({ ...prev, [id]: detail }))
  }

  function handleStepCallback(step: StepName, detail: string) {
    if (step === "attest_start") {
      setStep("nonce",  "done",   "crypto.getRandomValues(32 bytes) ✓")
      setStep("fetch",  "active", detail)
    } else if (step === "attest_done") {
      setStep("fetch",  "done",   "AttestBundle received ✓")
      setStep("verify", "done",   detail)
    } else if (step === "model_read") {
      setStep("encrypt", "active", detail)
    } else if (step === "encrypt_send") {
      setStep("encrypt",  "done",   "HPKE sealed ✓")
      setStep("transfer", "active", detail)
    } else if (step === "done") {
      setStep("transfer", "done", detail)
    } else if (step === "error") {
      // caller marks the failed step
    }
  }

  function pickFile(f: File | undefined | null) {
    if (!f || !f.name.endsWith(".onnx")) return
    setFile(f)
  }

  function onFileChange(e: ChangeEvent<HTMLInputElement>) {
    pickFile(e.target.files?.[0])
  }

  function onDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault()
    setDragging(false)
    pickFile(e.dataTransfer.files[0])
  }

  async function run() {
    if (!file) return

    // reset
    setStarted(true)
    setRunning(true)
    setOidc(null)
    setResponse(null)
    setElapsedMs(null)
    setErrorMsg(null)
    setStepStates({ nonce: "active" })
    setStepDetails({
      nonce:    "Generating…",
      fetch:    "GET /v1/attest · X-RATLS-Nonce: <nonce>",
      verify:   "jwtVerify · image_digest · binding key · HPKE key",
      encrypt:  "Sealing payload in browser",
      transfer: "POST → HPKE-sealed ciphertext only in transit",
    })

    try {
      const result = await transferOnnxModel({
        teeUrl,
        file,
        endpoint: endpoint || "/v1/model/upload",
        onStep:   handleStepCallback,
      })
      setOidc(result.oidc)
      setResponse(result.response)
      setElapsedMs(result.elapsedMs)
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      setErrorMsg(msg)
      // mark whichever step is still "active" as error
      setStepStates(prev => {
        const next = { ...prev }
        for (const id of Object.keys(next)) {
          if (next[id] === "active") next[id] = "error"
        }
        return next
      })
    } finally {
      setRunning(false)
    }
  }

  const certUrl = teeUrl || "#"

  return (
    <div className={styles.page}>
      <header className={styles.header}>
        <h1>Tanuh · Secure ONNX Transfer</h1>
        <p>RA-TLS · AMD SEV-SNP · Google Confidential Space · HPKE encrypted channel</p>
      </header>

      {/* Config */}
      <div className={styles.card}>
        <h2 className={styles.cardTitle}>Configuration</h2>

        <label className={styles.label}>TEE URL</label>
        <input
          className={styles.input}
          type="url"
          value={teeUrl}
          onChange={e => setTeeUrl(e.target.value)}
          disabled={running}
        />

        <label className={styles.label}>Upload Endpoint</label>
        <input
          className={styles.input}
          type="text"
          value={endpoint}
          onChange={e => setEndpoint(e.target.value)}
          disabled={running}
        />

        <div className={styles.certHint}>
          ⚠️ TEE uses a self-signed cert.&nbsp;
          <a href={certUrl} target="_blank" rel="noopener noreferrer">
            Open TEE URL → accept certificate
          </a>
          &nbsp;before running attestation.
        </div>
      </div>

      {/* Upload */}
      <div className={styles.card}>
        <h2 className={styles.cardTitle}>ONNX Model</h2>

        <div
          className={`${styles.dropZone} ${dragging ? styles.dragOver : ""}`}
          onClick={() => fileInputRef.current?.click()}
          onDragOver={e => { e.preventDefault(); setDragging(true) }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".onnx"
            style={{ display: "none" }}
            onChange={onFileChange}
          />
          <div className={styles.dzIcon}>🧠</div>
          {file ? (
            <>
              <div className={styles.dzFileName}>{file.name}</div>
              <div className={styles.dzFileSize}>{formatBytes(file.size)}</div>
            </>
          ) : (
            <>
              <div className={styles.dzMain}>Drop your <strong>.onnx</strong> model here or click to browse</div>
              <div className={styles.dzSub}>File never leaves without attestation — encrypted before transit</div>
            </>
          )}
        </div>

        <button
          className={styles.goBtn}
          onClick={run}
          disabled={!file || running}
        >
          {running ? "Attesting & Transferring…" : "Attest & Transfer"}
        </button>
      </div>

      {/* Progress */}
      {started && (
        <div className={styles.card}>
          <h2 className={styles.cardTitle}>Attestation &amp; Transfer</h2>
          <div className={styles.steps}>
            {STEPS.map(s => {
              const state = stepStates[s.id] ?? "idle"
              const detail = stepDetails[s.id] ?? s.description
              return (
                <div key={s.id} className={`${styles.step} ${styles[state]}`}>
                  <div className={styles.stepNum}>
                    {state === "done"  ? "✓" :
                     state === "error" ? "✗" :
                     STEPS.findIndex(x => x.id === s.id) + 1}
                  </div>
                  <div className={styles.stepBody}>
                    <div className={styles.stepTitle}>{s.title}</div>
                    <div className={styles.stepDetail}>{detail}</div>
                  </div>
                </div>
              )
            })}
          </div>

          {errorMsg && (
            <div className={styles.errorBox}>
              {errorMsg}
            </div>
          )}
        </div>
      )}

      {/* Verified claims */}
      {oidc && (
        <div className={styles.card}>
          <h2 className={styles.cardTitle}>✅ Verified TEE Identity</h2>
          <div className={styles.claimsGrid}>
            {[
              ["Image digest",   oidc.submods?.container?.image_digest ?? "—"],
              ["Hardware model", oidc.hwmodel ?? "—"],
              ["OIDC issuer",    oidc.iss],
              ["Audience",       Array.isArray(oidc.aud) ? oidc.aud.join(", ") : String(oidc.aud)],
              ["Issued at",      new Date(oidc.iat * 1000).toISOString()],
              ["Expires at",     new Date(oidc.exp * 1000).toISOString()],
              ...(oidc.submods?.confidential_space?.support_attributes
                ? [["Support attrs", oidc.submods.confidential_space.support_attributes.join(", ")]]
                : []),
            ].map(([k, v]) => (
              <>
                <div key={`k-${k}`} className={styles.claimKey}>{k}</div>
                <div key={`v-${k}`} className={styles.claimVal}>{v}</div>
              </>
            ))}
          </div>
        </div>
      )}

      {/* Response */}
      {response !== null && (
        <div className={styles.card}>
          <h2 className={styles.cardTitle}>TEE Response</h2>
          <pre className={styles.responseBox}>
            {JSON.stringify(response, null, 2)}
          </pre>
          {elapsedMs !== null && (
            <div className={styles.elapsed}>Total: {elapsedMs}ms</div>
          )}
        </div>
      )}
    </div>
  )
}
