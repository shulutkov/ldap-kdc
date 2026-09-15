import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The bundle is served by the management API under /ui/ and written straight into the Go package
// that embeds it, so `go build` needs no node. `vite dev` proxies the API to a service running
// locally, so the page can be worked on against a real directory.
export default defineConfig({
  plugins: [react()],
  resolve: {
    // rjsf's ajv validator is never used: see src/no-ajv.ts.
    alias: { '@rjsf/validator-ajv8': '/src/no-ajv.ts' },
  },
  base: '/ui/',
  build: {
    outDir: '../internal/api/ui/dist',
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:5555',
    },
  },
})
