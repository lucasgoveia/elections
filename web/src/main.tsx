import { createRoot } from 'react-dom/client';
import init from './wasm/eg_wasm.js';
import { SimProvider } from './sim';
import { App } from './App';
import './styles.css';

// A página mostra "Carregando criptografia…" (index.html) até o wasm ficar pronto.
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
        A criptografia não carregou: {msg}. Recarregue a página. Se falhar de novo, o build do wasm em
        src/wasm pode estar faltando.
      </p>,
    );
  },
);
