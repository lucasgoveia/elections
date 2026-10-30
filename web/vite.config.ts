import { resolve } from 'node:path';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { viteSingleFile } from 'vite-plugin-singlefile';

// Three pages: Início (lay explanation and FAQ), Técnico (the maths, with
// proofs) and Oficina (the Urna Lab with its guided tour).
//
// `vite build --mode single` produces one self-contained oficina.html (wasm,
// JS and CSS inlined) that can be hosted anywhere, including as a single page.
export default defineConfig(({ mode }) => ({
  plugins: mode === 'single' ? [react(), viteSingleFile()] : [react()],
  build:
    mode === 'single'
      ? { outDir: 'dist-single', assetsInlineLimit: Infinity, rollupOptions: { input: resolve(__dirname, 'oficina.html') } }
      : {
          rollupOptions: {
            input: {
              inicio: resolve(__dirname, 'index.html'),
              tecnico: resolve(__dirname, 'tecnico.html'),
              oficina: resolve(__dirname, 'oficina.html'),
            },
          },
        },
  assetsInclude: ['**/*.wasm'],
  server: { port: 5173 },
}));
