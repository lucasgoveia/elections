import { useMemo } from 'react';
import qrcode from 'qrcode-generator';

/** A QR code as an inline SVG. The library's output is markup it generated itself. */
export function Qr({ data, label }: { data: string; label: string }) {
  const svg = useMemo(() => {
    const qr = qrcode(0, 'M');
    qr.addData(data);
    qr.make();
    return qr.createSvgTag({ cellSize: 2, margin: 0, scalable: true });
  }, [data]);
  return (
    <div className="strip-qr" role="img" aria-label={label} dangerouslySetInnerHTML={{ __html: svg }} />
  );
}
