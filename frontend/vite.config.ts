import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/scan': 'http://localhost:8000',
      '/graph': 'http://localhost:8000',
      '/risk': 'http://localhost:8000',
      '/remediation': 'http://localhost:8000',
      '/execute': 'http://localhost:8000',
      '/report': 'http://localhost:8000',
      '/health': 'http://localhost:8000',
      '/ws': {
        target: 'ws://localhost:8000',
        ws: true,
      },
    },
  },
})