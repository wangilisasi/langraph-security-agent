import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// During `npm run dev`, forward API and OpenAPI paths to the FastAPI server.
const apiTarget = process.env.VITE_DEV_API ?? 'http://127.0.0.1:8000'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      '/health': apiTarget,
      '/analyze': apiTarget,
      '/incidents': apiTarget,
      '/stats': apiTarget,
      '/ip': apiTarget,
      '/request': apiTarget,
      '/docs': apiTarget,
      '/redoc': apiTarget,
      '/openapi.json': apiTarget,
    },
  },
})
