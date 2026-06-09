import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    proxy: {
      // Proxy API calls to the FastAPI backend during development.
      '/api': 'http://localhost:8000',
    },
  },
})
