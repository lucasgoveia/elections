import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { viteSingleFile } from "vite-plugin-singlefile";

// `vite build --mode single` produces one self-contained index.html (wasm,
// JS and CSS inlined) that can be hosted anywhere, including as a single page.
export default defineConfig(({ mode }) => ({
  plugins: mode === "single" ? [react(), viteSingleFile()] : [react()],
  build: mode === "single" ? { outDir: "dist-single", assetsInlineLimit: Infinity } : {},
  assetsInclude: ["**/*.wasm"],
  server: { port: 5173 },
}));
