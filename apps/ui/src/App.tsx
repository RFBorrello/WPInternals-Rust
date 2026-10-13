import { useEffect, useRef, useState } from 'react';
import { ArrowDownToLine, ArrowRight, Check, ChevronRight, CircleHelp, Cpu, FileCode2, FileUp, FolderOpen, HardDrive, Info, Layers3, LoaderCircle, LockKeyhole, Monitor, Radio, RefreshCw, ShieldCheck, Smartphone, Terminal, Unplug, Usb, X } from 'lucide-react';
import * as backend from './backend';
import { bytes, hexId, label, partitionRange } from './format';
import type { CapabilityReport, DeviceIdentity, ImportedArtifact, ModelProfile, RecoveryPreparation } from './types';

type Page = 'workspace' | 'firmware' | 'compatibility' | 'activity';
interface Activity { time: string; message: string; kind: 'info' | 'success' | 'error' }
const navigation: { page: Page; label: string; icon: typeof Smartphone }[] = [
  { page: 'workspace', label: 'Workspace', icon: Layers3 },
  { page: 'firmware', label: 'Firmware & images', icon: HardDrive },
  { page: 'compatibility', label: 'Compatibility', icon: ShieldCheck },
  { page: 'activity', label: 'Activity', icon: Terminal },
];

export default function App() {
  const [page, setPage] = useState<Page>('workspace');
  const [ready, setReady] = useState(false);
  const [devices, setDevices] = useState<DeviceIdentity[]>([]);
  const [selected, setSelected] = useState<DeviceIdentity | null>(null);
  const [models, setModels] = useState<ModelProfile[]>([]);
  const [report, setReport] = useState<CapabilityReport | null>(null);
  const [artifact, setArtifact] = useState<ImportedArtifact | null>(null);
  const [preparation, setPreparation] = useState<RecoveryPreparation | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [activity, setActivity] = useState<Activity[]>([]);
  const [help, setHelp] = useState(false);
  const picker = useRef<HTMLInputElement>(null);
  const connectionEpoch = useRef(0);
  useEffect(() => { setPreparation(null); }, [artifact, selected]);
  function log(message: string, kind: Activity['kind'] = 'info') {
    setActivity(items => [{ time: new Date().toLocaleTimeString(), message, kind }, ...items].slice(0, 200));
  }
  useEffect(() => {
    let active = true;
    backend.startup().then(data => { if (!active) return; setModels(data.models); setReport(data.capabilities); setReady(true); })
      .catch(e => { if (active) setError(`Cannot load the Rust engine: ${String(e)}`); });
    return () => { active = false; };
  }, []);
  useEffect(() => {
    if (!ready) return;
    let active = true;
    backend.capabilities(selected).then(r => { if (active) setReport(r); }).catch(e => { if (active) setError(String(e)); });
    return () => { active = false; };
  }, [selected, ready]);
  useEffect(() => {
    if (backend.desktop) return;
    const usb = (navigator as Navigator & { usb?: EventTarget }).usb;
    const disconnect = () => { connectionEpoch.current++; setSelected(null); setDevices([]); log('USB connection changed. Scan and reselect the device before continuing.'); };
    usb?.addEventListener('disconnect', disconnect);
    return () => usb?.removeEventListener('disconnect', disconnect);
  }, []);
  async function task(name: string, action: () => Promise<void>) {
    if (busy) return;
    setBusy(name); setError(null);
    try { await action(); }
    catch (e) { const message = e instanceof Error ? e.message : String(e); if (!message.includes('AbortError') && !message.includes('NotFoundError')) { setError(message); log(message, 'error'); } }
    finally { setBusy(null); setProgress(null); }
  }
  async function scan() {
    await task('Scanning USB interfaces', async () => {
      const found = await backend.discover(); setDevices(found);
      if (selected && !found.some(d => d.id === selected.id)) setSelected(null);
      if (found.length === 1) setSelected(found[0]);
      log(found.length ? `Found ${found.length} recognized USB interface${found.length === 1 ? '' : 's'}.` : 'No Lumia interfaces found. Check the USB cable, phone mode, and host permissions.');
    });
  }
  async function connect() {
    await task('Connecting to your phone', async () => {
      if (backend.desktop) { const found = await backend.discover(); setDevices(found); if (found.length === 1) setSelected(found[0]); log(found.length ? `Found ${found.length} device interface(s). Select one below.` : 'No Lumia connected. Try a data-capable USB cable and scan again.'); }
      else { const device = await backend.connect(); if (!device) return; setSelected(device); setDevices(await backend.discover()); log('USB access granted. Device descriptors read locally.', 'success'); }
    });
  }
  async function readDeviceInfo() {
    if (!selected) return;
    const epoch = connectionEpoch.current;
    await task('Reading device information', async () => {
      const result = await backend.probe(selected);
      if (epoch !== connectionEpoch.current) return;
      setSelected(result.device);
      log('Read device model and application information. No phone storage was written.', 'success');
    });
  }
  async function load(file?: File) {
    await task('Inspecting local image', async () => {
      const imported = backend.desktop ? await backend.importDesktopFile() : file ? await backend.importBrowserFile(file) : null;
      if (imported) { setArtifact(imported); setPage('firmware'); log(`Inspected ${imported.name}. ${imported.inspection.gpt?.partitions.length ?? 0} partitions found.`, 'success'); }
    });
  }
  async function prepareRecovery() {
    if (!artifact) return;
    const epoch = connectionEpoch.current;
    await task('Checking recovery preparation', async () => {
      const result = await backend.prepareRecovery(artifact, selected, (done, total) => setProgress({ done, total }));
      if (epoch !== connectionEpoch.current) return;
      setPreparation(result);
      log('Recovery checklist prepared locally. Recovery execution remains unavailable.');
    });
  }
  const usbAvailable = backend.desktop || (Boolean((navigator as Navigator & { usb?: unknown }).usb) && window.isSecureContext);
  const disabled = !ready || Boolean(busy);
  const title = navigation.find(n => n.page === page)!.label;
  const partitions = artifact?.inspection.gpt?.partitions ?? [];

  const imagePicker = <input ref={picker} type="file" accept=".ffu,.bin,.img" hidden onChange={e => { const file = e.target.files?.[0]; if (file) void load(file); e.target.value = ''; }} />;
  function chooseFile() { if (backend.desktop) void load(); else picker.current?.click(); }

  return <div className="app">
    <aside className="sidebar">
      <a className="brand" href="#" onClick={e => { e.preventDefault(); setPage('workspace'); }} aria-label="WPInternals workspace"><span className="brand-icon"><Layers3 size={24} /></span><span>WPInternals<small>RUST EDITION</small></span></a>
      <div className="sidebar-label">YOUR WORKBENCH</div>
      <nav>{navigation.map(item => <button key={item.page} className={`nav-item ${page === item.page ? 'active' : ''}`} onClick={() => setPage(item.page)}><item.icon size={18} />{item.label}{item.page === 'activity' && activity.length > 0 && <span className="nav-count">{activity.length}</span>}</button>)}</nav>
      <div className="sidebar-bottom">
        <div className="local-note"><ShieldCheck size={20} /><div>Everything stays local<small>Your files and phone data<br />never leave this computer.</small></div></div>
        <button className="help-button" onClick={() => setHelp(true)}><CircleHelp size={17} /> Connection guide <ChevronRight size={14} /></button>
        <div className="version">v0.1.0 <span>DEVELOPMENT</span></div>
      </div>
    </aside>
    <div className="main-shell">
      <header className="topbar"><div className="breadcrumb">Workbench <ChevronRight size={14} /> <span>{title}</span></div><div className="topbar-right"><span className="local-pill"><span className="dot" /> Local session</span><span className="runtime"><Cpu size={15} /> {backend.desktop ? 'Native engine' : 'Rust + WebAssembly'}</span></div></header>
      <main>
        <div className="page-heading"><div><div className="eyebrow">LUMIA, REIMAGINED</div><h1>{page === 'workspace' ? 'Your phone. Your possibilities.' : title}</h1><p>{page === 'workspace' ? 'Connect a Lumia or explore its firmware. All on your computer.' : page === 'firmware' ? 'Inspect and extract local images with the shared Rust engine.' : page === 'compatibility' ? 'Know what’s implemented, and what still needs validation.' : 'A record of this session’s operations. Nothing is uploaded.'}</p></div><span className="build-badge"><span className="dot amber" /> Early development</span></div>
        {error && <div className="error-banner" role="alert"><Info size={18} /><span>{error}</span><button aria-label="Dismiss error" onClick={() => setError(null)}><X size={16} /></button></div>}
        {!ready && !error && <div className="engine-loading" role="status"><LoaderCircle size={18} className="spin" /> Loading the Rust engine…</div>}
        {busy && <div className="operation-banner" role="status"><LoaderCircle className="spin" size={17} /><span>{busy}{progress && ` · ${bytes(progress.done)} / ${bytes(progress.total)}`}</span>{progress && <><progress value={progress.done} max={progress.total} /><button className="text-button" onClick={() => backend.cancel()}>Cancel</button></>}</div>}

        {page === 'workspace' && <>
          <section className="hero-card">
            <div className="hero-content"><span className="hero-label"><Usb size={14} /> DEVICE WORKSPACE</span><h2>A new chapter<br />for your Lumia.</h2><p>Start with a USB connection. Inspect the device,<br className="desktop-break" /> understand its capabilities, and explore its firmware.</p><div className="button-row"><button className="primary-button" disabled={disabled || !usbAvailable} onClick={() => void connect()}><Usb size={17} /> Connect a device <ArrowRight size={16} /></button><button className="hero-secondary" disabled={disabled} onClick={chooseFile}>Open an image <FolderOpen size={16} /></button></div><span className="hero-caption">{usbAvailable ? backend.desktop ? 'Native USB · Windows, macOS & Linux' : 'WebUSB · Chrome & Edge over HTTPS' : 'USB access needs Chrome/Edge or the desktop app'}</span></div>
            <div className="phone-scene" aria-hidden="true"><div className="orb orb-one" /><div className="orb orb-two" /><div className="phone"><div className="phone-speaker" /><div className="phone-screen"><div className="phone-time">10:20</div><div className="tile-grid"><span /><span /><span /><span /><span /><span /></div><div className="phone-wordmark">LUMIA</div></div><div className="phone-bottom"><span>‹</span><span>⊞</span><span>⌕</span></div></div><div className="floating-tag"><span className="dot" /> Possibility, preserved.</div></div>
          </section>
          <div className="workspace-grid">
            <section className="card device-card"><div className="section-heading"><h3><Smartphone size={18} /> Your device</h3><button className="icon-button" aria-label="Scan USB devices" disabled={disabled || !usbAvailable} onClick={() => void scan()}><RefreshCw size={16} /></button></div>{selected ? <DeviceDetails device={selected} /> : <div className="empty-device"><div className="empty-icon"><Unplug size={25} /></div><h4>No device selected</h4><p>Connect your Lumia with a USB data cable.<br />Then grant access or scan for interfaces.</p><button className="text-button" disabled={disabled || !usbAvailable} onClick={() => void connect()}>Connect a Lumia <ArrowRight size={14} /></button></div>}{devices.length > 1 && <label className="select-label">Select interface<select disabled={disabled} value={selected?.id ?? ''} onChange={e => setSelected(devices.find(d => d.id === e.target.value) ?? null)}><option value="">Choose device</option>{devices.map(d => <option key={d.id} value={d.id}>{d.product ?? 'Lumia interface'} · {label(d.mode)}</option>)}</select></label>}{selected && <button className="secondary-button wide" disabled={disabled || !report?.capabilities.find(c => c.operation === 'device_info')?.executable} onClick={() => void readDeviceInfo()}><Radio size={16} /> Read device information</button>}</section>
            <section className="card import-card" onDragOver={e => { if (!backend.desktop) e.preventDefault(); }} onDrop={e => { e.preventDefault(); if (!backend.desktop && !disabled && e.dataTransfer.files[0]) void load(e.dataTransfer.files[0]); }}><div className="section-heading"><h3><FileCode2 size={18} /> Explore firmware</h3><span className="subtle-badge">OFFLINE</span></div><div className="import-body"><div className="import-icon"><FileUp size={29} /></div><h4>Start with a local image</h4><p>Inspect firmware, browse partitions, and extract<br />the pieces you need. Your originals stay intact.</p><button className="secondary-button" disabled={disabled} onClick={chooseFile}><FolderOpen size={16} /> Browse files</button><span className="supported-files">FFU · GPT / BIN · RAW IMG · FAT / NTFS</span></div></section>
          </div>
          <section className="validation-note"><div className="validation-icon"><LockKeyhole size={20} /></div><div><h4>Built carefully, validated honestly.</h4><p>Unlocking, flashing, and phone backup/restore are not available in this development release. The Lumia 1020 and 730 are the first hardware validation targets.</p></div><button className="text-button" onClick={() => setPage('compatibility')}>View capabilities <ArrowRight size={15} /></button></section>
        </>}

        {page === 'firmware' && <>
          {!artifact ? <section className="card big-empty"><FileUp size={42} /><h2>Look inside your firmware.</h2><p>Open a local FFU, GPT, disk image, or filesystem image.<br />Inspection runs on this computer with bounded memory.</p><button className="primary-button" disabled={disabled} onClick={chooseFile}><FolderOpen size={17} /> Open local image</button></section> : <>
            <section className="card artifact-heading"><div className="artifact-icon"><HardDrive size={24} /></div><div><span className="eyebrow">LOCAL ARTIFACT</span><h2>{artifact.name}</h2><p>{artifact.inspection.format} <span>·</span> {bytes(artifact.inspection.size)} <span>·</span> Original preserved</p></div><button className="secondary-button" disabled={disabled} onClick={chooseFile}>Change image</button></section>
            <div className="stat-grid"><Stat label="Platform ID" value={artifact.inspection.ffu?.platform_id || 'Not specified'} /><Stat label="Partitions" value={String(partitions.length)} /><Stat label="Chunk size" value={artifact.inspection.ffu ? bytes(artifact.inspection.ffu.chunk_size) : '512 B sectors'} /><Stat label="Validation" value={artifact.inspection.gpt ? 'GPT CRCs checked' : 'Boot sector parsed'} /></div>
            {artifact.inspection.notes.map(note => <div className="info-note" key={note}><Info size={16} />{note}</div>)}
            {artifact.inspection.ffu && <section className="card capability-card recovery-card">
              <div className="section-heading"><h3><ShieldCheck size={18} /> Recovery preparation</h3><button className="secondary-button compact" disabled={disabled} onClick={() => void prepareRecovery()}>Check preparation</button></div>
              <p>Check your local firmware and phone information before planning recovery. This check does not change phone modes or start flashing.</p>
              {preparation && <>
                <div className="info-note">Recovery is unavailable. Missing checks and implementation must be resolved before phone writes can be enabled.</div>
                <div className="table-scroll"><table><thead><tr><th>Check</th><th>Status</th><th>Result / next step</th></tr></thead><tbody>{preparation.checks.map(check => <tr key={check.key}><td><strong>{check.label}</strong></td><td><span className={`status-badge ${check.status === 'passed' ? 'experimental' : 'blocked'}`}>{label(check.status)}</span></td><td>{check.message}</td></tr>)}</tbody></table></div>
                <button className="secondary-button compact" onClick={() => backend.download(new Blob([JSON.stringify(preparation, null, 2)], { type: 'application/json' }), 'recovery-preparation.json')}><ArrowDownToLine size={15} /> Export preparation</button>
              </>}
            </section>}
            {artifact.inspection.filesystem && <section className="card"><h3>Filesystem geometry</h3><dl className="details-list"><dt>Filesystem</dt><dd>{artifact.inspection.filesystem.kind}</dd><dt>Sector size</dt><dd>{bytes(artifact.inspection.filesystem.bytes_per_sector)}</dd><dt>Sectors per cluster</dt><dd>{artifact.inspection.filesystem.sectors_per_cluster}</dd><dt>Volume serial</dt><dd>{artifact.inspection.filesystem.volume_serial}</dd></dl></section>}
            {partitions.length > 0 && <section className="card partition-card"><div className="section-heading"><h3><Layers3 size={18} /> Partition map</h3><button className="secondary-button compact" disabled={disabled} onClick={() => void task('Exporting partition table', async () => { await backend.exportGpt(artifact); log('Exported Partitions.xml.', 'success'); })}><ArrowDownToLine size={15} /> Export XML</button></div><div className="table-scroll"><table><thead><tr><th>Partition</th><th>Start sector</th><th>Size</th><th>Action</th></tr></thead><tbody>{partitions.map(p => <tr key={p.guid}><td><span className="partition-symbol"><Layers3 size={15} /></span><strong>{p.name}</strong></td><td className="mono">{p.first_sector.toLocaleString()}</td><td>{bytes(partitionRange(p.first_sector, p.last_sector).length)}</td><td><button className="table-action" disabled={disabled} onClick={() => void task(`Extracting ${p.name}`, async () => { await backend.extract(artifact, p.name, (done, total) => setProgress({ done, total })); log(`Finished export workflow for ${p.name}.`, 'success'); })}><ArrowDownToLine size={14} /> Extract</button></td></tr>)}</tbody></table></div><div className="table-footer">Extraction writes a local file. It does not flash your phone.</div></section>}
          </>}
        </>}

        {page === 'compatibility' && <>
          <section className="info-note compatibility-note"><ShieldCheck size={20} /><span>Model recognition is a research target, not a support claim. No phone/firmware/host combination is hardware verified yet.</span></section>
          <div className="model-grid">{models.map(model => <section className="card model-card" key={model.model}><div className="model-heading"><Smartphone size={23} /><span className="subtle-badge">{label(model.family)}</span></div><h3>{model.model}</h3><p>{model.variants.join(' · ')}</p><span className="research-status"><span className="dot amber" /> Awaiting hardware validation</span></section>)}</div>
          <section className="card capability-card"><div className="section-heading"><h3>Operation availability</h3><span className="subtle-badge">{report ? label(report.host) : 'Loading'}</span></div><div className="table-scroll"><table><thead><tr><th>Operation</th><th>Status</th><th>Availability</th></tr></thead><tbody>{report?.capabilities.map(c => <tr key={c.operation}><td><strong>{label(c.operation)}</strong></td><td><span className={`status-badge ${c.executable ? 'experimental' : 'blocked'}`}>{label(c.status)}</span></td><td>{c.reason}</td></tr>)}</tbody></table></div></section>
        </>}

        {page === 'activity' && <section className="card activity-card"><div className="section-heading"><h3><Terminal size={18} /> Session activity</h3><button className="secondary-button compact" disabled={activity.length === 0} onClick={() => backend.download(new Blob([JSON.stringify(activity, null, 2)], { type: 'application/json' }), 'wpinternals-session.json')}><ArrowDownToLine size={15} /> Export log</button></div>{activity.length === 0 ? <div className="big-empty"><Terminal size={35} /><h3>A fresh session.</h3><p>Connect a phone or open an image to get started.</p></div> : <ul className="activity-list">{activity.map((item, i) => <li key={`${item.time}-${i}`}><span className={`activity-symbol ${item.kind}`}>{item.kind === 'success' ? <Check size={15} /> : <Info size={15} />}</span><time>{item.time}</time><span>{item.message}</span></li>)}</ul>}</section>}
        <footer className="page-footer"><span>WPInternals Rust <span className="footer-dot">·</span> Open source. Local by design.</span><span><Monitor size={14} /> {backend.desktop ? 'Desktop workspace' : 'Browser workspace'}</span></footer>
      </main>
    </div>
    {imagePicker}
    {help && <div className="modal-backdrop" onClick={() => setHelp(false)}><section className="modal" role="dialog" aria-modal="true" aria-labelledby="guide-title" onClick={e => e.stopPropagation()}><button className="modal-close icon-button" aria-label="Close guide" onClick={() => setHelp(false)}><X size={20} /></button><Usb size={28} /><h2 id="guide-title">Connect your Lumia</h2><ol><li>Use a USB data cable. Charging-only cables cannot communicate with the phone.</li><li>In the browser, use Chrome or Edge over HTTPS or localhost, then click “Connect a device” to grant USB access.</li><li>On Windows, vendor-specific interfaces need a compatible WinUSB binding. Old x86/x64 drivers do not work on Windows ARM64.</li><li>On Linux, configure the device-specific USB permission rules included in the project.</li><li>Read-only information queries work in normal mode through vendor interface 3, or through the flash interface. Grant access again if the phone reconnects. Emergency mode is enumeration-only.</li></ol><p className="info-note">For raw storage access and unsupported browser features, use the desktop build. These features still require implementation and validation.</p><button className="primary-button" onClick={() => setHelp(false)}>Got it</button></section></div>}
  </div>;
}
function DeviceDetails({ device }: { device: DeviceIdentity }) {
  return <div className="device-details"><div className="selected-device"><span className="selected-device-icon"><Smartphone size={28} /></span><div><h4>{device.model ?? device.product ?? 'Lumia USB interface'}</h4><span><span className="dot" /> {label(device.mode)}</span></div></div><dl className="details-list"><dt>USB identity</dt><dd className="mono">{hexId(device.vendor_id)}:{hexId(device.product_id)}</dd><dt>Hardware variant</dt><dd>{device.variant ?? 'Not yet established'}</dd><dt>Bootloader family</dt><dd>{label(device.family)}</dd><dt>Platform</dt><dd>{device.platform_id ?? (device.mode === 'normal' ? 'Not queried in normal mode' : 'Run read-only probe')}</dd><dt>Firmware</dt><dd>{device.firmware ?? 'Not yet established'}</dd></dl></div>;
}
function Stat({ label: name, value }: { label: string; value: string }) { return <section className="card stat"><span>{name}</span><strong>{value}</strong></section>; }
