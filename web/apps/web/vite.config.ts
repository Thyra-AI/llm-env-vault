import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import path from 'node:path'
import { defineConfig, type Plugin } from 'vite'

const csp: Plugin = {
  name: 'inject-csp',
  apply: 'build',
  transformIndexHtml: () => [
    {
      tag: 'meta',
      injectTo: 'head-prepend',
      attrs: {
        'http-equiv': 'Content-Security-Policy',
        content:
          "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
      },
    },
  ],
}

export default defineConfig({
  plugins: [react(), tailwindcss(), csp],
  resolve: { alias: { '@': path.resolve(__dirname, 'src') } },
  server: { host: '127.0.0.1', port: 5173, strictPort: true },
  // The build is embedded in the Python plugin (thyra_vault/web_dist) and reviewed as
  // source: keep it readable (no minification) and free of binary assets.
  build: { minify: false, sourcemap: false, assetsInlineLimit: 0 },
})
