import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import path from 'path';
import { readFileSync } from 'fs';

// the admin token lives in the root .env — the proxy injects it into
// /api POSTs server-side, so the browser bundle never sees it.
function adminToken(): string {
  try {
    const env = readFileSync(path.resolve(process.cwd(), '../.env'), 'utf8');
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
    configure: (proxy) => {
      // inject the admin token ONLY for requests originating from our own
      // dashboard. a foreign site can fire a cross-site form-POST at
      // localhost:5173 from the operator's browser — CORS blocks reading
      // the response, but the REQUEST itself lands; without this origin
      // check the proxy would attach the admin token to it.
      proxy.on('proxyReq', (proxyReq, req) => {
        const origin = req.headers.origin;
        if (TOKEN && origin === 'http://localhost:5173') {
          proxyReq.setHeader('Authorization', `Bearer ${TOKEN}`);
        }
      });
    },
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