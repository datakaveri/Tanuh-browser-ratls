import { defineConfig } from "vitest/config"

export default defineConfig({
    test: {
        environment: "node",
        globals: true,
        include: ["tests/integration/**/*.test.ts"],
        testTimeout: 30_000,
        hookTimeout: 10_000,
    },
})
