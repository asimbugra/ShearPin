import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import path from 'path';
import { readFileSync } from 'fs';

// the admin token lives in the root .env — the proxy injects it into
// /api POSTs server-side, so the browser bundle never sees it.
function adminToken(): string {
  try {
    const env = readFileSync(path.resolve(__dirname, '../../.env'), 'utf8');
    return env.match(/^SHEARPIN_ADMIN_TOKEN=(.+)$/m)?.[1]?.trim() ?? '';
  } catch {
    return '';
  }
}
const TOKEN = adminToken();

const proxy: Record<string, object> = {
  '/api': {
    target: 'http://127.0.0.1:8787',
    changeOrigin: true,
    rewrite: (p) => p.replace(/^\/api/, ''),
    headers: TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {},
  },
};

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5173,
    proxy,
  },
  preview: {
    port: 4173,
    proxy,
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
});