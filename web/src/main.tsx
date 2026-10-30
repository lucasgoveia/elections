import { createRoot } from 'react-dom/client';
import init from './wasm/eg_wasm.js';
import { SimProvider } from './sim';
import { App } from './App';
import './styles.css';

// The page shows "Loading cryptography…" (index.html) until the wasm is ready.
const root = createRoot(document.getElementById('root')!);

init().then(
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
