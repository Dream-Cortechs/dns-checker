import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// En développement, /api est relayé vers le backend local (uvicorn :8507).
// En production, le backend sert dist/ : mêmes origines, aucun proxy.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { '/api': { target: 'http://127.0.0.1:8507', changeOrigin: true } },
  },
  build: { outDir: 'dist', emptyOutDir: true },
})
