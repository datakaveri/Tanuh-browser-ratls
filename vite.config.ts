import { defineConfig } from "vite"
import react from "@vitejs/plugin-react"

// When the UI is served from the Go buffer-server (same origin), all /v1/* calls
// are relative and work with no CORS or SSL issues.
// In dev mode, set VITE_TEE_URL to proxy through Vite to avoid cert issues.
const TEE_URL = process.env.VITE_TEE_URL ?? "https://8.35.197.50:8443"

export default defineConfig({
  plugins: [react()],
  worker: { format: "es" },
  server: {
    port: 5173,
    open: false,
    // Proxy /v1/* to the Buffer TEE in dev — browser never touches the self-signed cert
    proxy: TEE_URL ? {
      "/v1":      { target: TEE_URL, changeOrigin: true, secure: false },
      "/healthz": { target: TEE_URL, changeOrigin: true, secure: false },
    } : {},
  },
})
