import { defineConfig } from "vite"
import react from "@vitejs/plugin-react"

const TEE_URL = process.env.VITE_TEE_URL ?? "https://34.75.210.33:8443"

export default defineConfig({
    plugins: [react()],
    worker: { format: "es" },
    server: {
        port: 5173,
        proxy: {
            "/v1":      { target: TEE_URL, changeOrigin: true, secure: false },
            "/healthz": { target: TEE_URL, changeOrigin: true, secure: false },
        },
    },
})
