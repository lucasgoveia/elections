// The Técnico page: typeset every \( … \) and \[ … \] with KaTeX.
import 'katex/dist/katex.min.css';
import renderMathInElement from 'katex/contrib/auto-render';
import './site.css';

renderMathInElement(document.querySelector('main')!, {
  delimiters: [
    { left: '\\[', right: '\\]', display: true },
    { left: '\\(', right: '\\)', display: false },
  ],
  throwOnError: false,
  strict: 'ignore',
});
