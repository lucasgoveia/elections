import { createRoot } from 'react-dom/client';
import init from './wasm/eg_wasm.js';
import { SimProvider } from './sim';
import { App } from './App';
import './styles.css';

// The page shows "Loading cryptography…" (index.html) until the wasm is ready.
const root = createRoot(document.getElementById('root')!);

// The single-file build (for hosting as one HTML page) embeds the wasm as a
// base64 data URL and hands the bytes to init, so nothing is fetched.
async function wasmSource(): Promise<{ module_or_path: BufferSource } | undefined> {
  if (import.meta.env.MODE !== 'single') return undefined;
  const { default: dataUrl } = await import('./wasm/eg_wasm_bg.wasm?inline');
  const b64 = dataUrl.slice(dataUrl.indexOf(',') + 1);
  const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  return { module_or_path: bytes };
}

wasmSource().then(init).then(
  () => {
    root.render(
      <SimProvider>
        <App />
      </SimProvider>,
    );
  },
  (e: unknown) => {
    const msg = e instanceof Error ? e.message : String(e);
    root.render(
      <p className="boot-loading" role="alert">
        The cryptography did not load: {msg}. Reload the page. If it fails again, the wasm build in
        src/wasm may be missing.
      </p>,
    );
  },
);
