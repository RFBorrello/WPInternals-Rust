import { useEffect, useRef, useState } from 'react';
import { ArrowDownToLine, LockKeyhole } from 'lucide-react';
import * as backend from './backend';
import { bytes } from './format';
import type { BootReport, ImportedArtifact, SpecAImport, SpecAPreparation as Report } from './types';

export function SpecAPreparation({ artifact, disabled, task }: { artifact: ImportedArtifact; disabled: boolean; task: (name: string, action: () => Promise<void>) => Promise<void> }) {
  const [sbl3, setSbl3] = useState<SpecAImport | null>(null);
  const [loaders, setLoaders] = useState<SpecAImport[]>([]);
  const [report, setReport] = useState<Report | null>(null);
  const sblPicker = useRef<HTMLInputElement>(null);
  const loaderPicker = useRef<HTMLInputElement>(null);
  useEffect(() => { setReport(null); }, [artifact, sbl3, loaders]);
  async function choose(multiple: boolean) {
    if (!backend.desktop) { (multiple ? loaderPicker : sblPicker).current?.click(); return; }
    await task('Selecting local boot files', async () => {
      const files = await backend.chooseSpecAImports(multiple);
      if (files.length) { if (multiple) setLoaders(files); else setSbl3(files[0]); }
    });
  }
  return <section className="card capability-card recovery-card" aria-label="Spec A offline preparation">
    <div className="section-heading"><h3><LockKeyhole size={18} /> Spec A bootloader preparation</h3><span className="subtle-badge">OFFLINE</span></div>
    <p>Inspect SBL1, SBL2 and SBL3 from this FFU, preview exact patch locations, and compare imported V1 loader certificate fingerprints. This check does not contact or unlock the phone. Spec B and WP7 need separate workflows.</p>
    <div className="mode-actions">
      <button className="secondary-button compact" disabled={disabled} onClick={() => void choose(false)}>Import raw SBL3</button>
      <button className="secondary-button compact" disabled={disabled} onClick={() => void choose(true)}>Import local loaders</button>
      <button className="primary-button compact" disabled={disabled} onClick={() => void task('Checking Spec A boot files', async () => { setReport(null); setReport(await backend.prepareSpecA(artifact, sbl3, loaders)); })}>Check boot files</button>
      {(sbl3 || loaders.length > 0) && <button className="text-button" disabled={disabled} onClick={() => { setSbl3(null); setLoaders([]); }}>Clear imports</button>}
    </div>
    <p className="muted">SBL3: {sbl3?.name ?? 'No external image selected'} · Loaders: {loaders.map(v => v.name).join(', ') || 'None selected'}</p>
    <input ref={sblPicker} hidden aria-label="Select raw SBL3" type="file" accept=".bin,.img,.mbn" onChange={e => { const file = e.currentTarget.files?.[0]; if (file) setSbl3({ name: file.name, file }); e.currentTarget.value = ''; }} />
    <input ref={loaderPicker} hidden aria-label="Select local loaders" type="file" multiple accept=".hex,.mbn,.bin" onChange={e => { setLoaders(Array.from(e.currentTarget.files ?? []).map(file => ({ name: file.name, file }))); e.currentTarget.value = ''; }} />
    {report && <>
      <div className="info-note">Offline report ready. Unlocking remains unavailable. A matching fingerprint or patch pattern does not establish engineering status, device compatibility, or mass-storage support.</div>
      <div className="table-scroll"><table><thead><tr><th>Boot image</th><th>Size</th><th>Parser / patch preview</th></tr></thead><tbody>
        {report.stock.map(v => <BootRow key={v.name} value={v} />)}
        {report.external_sbl3 && <BootRow value={report.external_sbl3} />}
      </tbody></table></div>
      {report.external_sbl3_fits !== null && <p>External SBL3 {report.external_sbl3_fits ? 'fits' : 'exceeds'} the stock SBL3 partition size. Size alone does not establish compatibility.</p>}
      {report.loaders.length > 0 && <div className="table-scroll"><table><thead><tr><th>Loader</th><th>V1 marker</th><th>Stock SBL1 root fingerprint</th><th>Parsing</th></tr></thead><tbody>{report.loaders.map((v, i) => <tr key={i}><td>{v.name}</td><td>{v.v1_marker_present ? 'Present' : 'Not found'}</td><td>{v.matches_stock_sbl1_root ? 'Matches' : 'No match established'}</td><td>{v.error ?? v.decoded?.error ?? 'Parsed; signatures unverified'}</td></tr>)}</tbody></table></div>}
      <p>Remaining requirements:</p><ul>{report.blockers.map(v => <li key={v}>{v}</li>)}</ul>
      <button className="secondary-button compact" onClick={() => backend.download(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }), 'spec-a-preparation.json')}><ArrowDownToLine size={15} /> Export boot preparation</button>
    </>}
  </section>;
}
function BootRow({ value }: { value: BootReport }) {
  return <tr><td><strong>{value.name}</strong></td><td>{bytes(value.size)}</td><td>{value.error ?? `${value.image?.header_kind} header; ${value.image?.certificate_sha256.length} certificates. ${value.patch ? value.patch.status === 'unique' ? `Unique patch at 0x${value.patch.offset?.toString(16)}: ${value.patch.expected} → ${value.patch.replacement} (preview only).` : `Patch ${value.patch.status}.` : 'Fingerprint only.'}`}</td></tr>;
}
