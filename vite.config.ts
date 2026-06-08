import { defineConfig } from "vite"
import dts from "vite-plugin-dts"
import { resolve } from "path"

export default defineConfig({
    plugins: [
        dts({
            include:      ["src/lib"],
            rollupTypes:  true,
            tsconfigPath: "./tsconfig.lib.json",
        }),
    ],
    build: {
        lib: {
            entry:    resolve(__dirname, "src/lib/index.ts"),
            formats:  ["es"],
            fileName: "index",
        },
        rollupOptions: {
            // Peer deps — consumers install their own copies
            external: ["@hpke/core", "@noble/hashes/sha256", "jose"],
        },
    },
    // Workers must be ES modules so the inline blob URL works in modern browsers
    worker: { format: "es" },
})
