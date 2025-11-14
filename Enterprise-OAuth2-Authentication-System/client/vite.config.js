import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],

  // ⚠️ Needed for SPA routing on Render
  base: "/",

  server: {
    port: 5173,
    host: true,

    // Local development proxy ONLY
    proxy: {
      '/auth': {
        target: 'http://localhost:5000',
        changeOrigin: true
      }
    }
  },

  build: {
    outDir: "dist",   // Render static uses this folder
  }
})
