import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    host: '0.0.0.0',
    port: 5173,
    // Use polling for file watching — required on Windows/Docker volume mounts
    // where OS file events don't cross the host/container boundary.
    watch: {
      usePolling: true,
      interval: 300,
    },
    proxy: {
      // Proxy /api requests to the backend.
      // The target uses 'backend' (the Docker service name) because Vite is
      // running inside the container; backend is reachable via the internal
      // Docker network. From your laptop's browser, requests still go to
      // localhost:5173/api/* which Vite forwards.
      '/api': {
        target: 'http://backend:8000',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
})