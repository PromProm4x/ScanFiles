import { useEffect, useMemo, useState, type ChangeEvent, type ReactNode } from 'react';
import { QueryClient, QueryClientProvider, useQueryClient } from '@tanstack/react-query';
import { Link, Route, Switch, Router as WouterRouter, useLocation } from 'wouter';
import {
  Activity, AlertTriangle, ArrowDownToLine, ArrowRight, BadgeCheck, Ban,
  ChevronRight, Clock3, FileArchive, FileCode2,
  FileSearch, FileText, Fingerprint, Globe2, HardDrive, History, LayoutDashboard,
  Link2, LoaderCircle, LockKeyhole, Menu, Plus, RefreshCw, Search, Settings2,
  Shield, ShieldAlert, ShieldCheck, Trash2, Upload, X,
} from 'lucide-react';
import {
  getGetScamShieldDashboardQueryKey, getGetScamShieldScansQueryKey,
  getGetScamShieldScanQueryKey, getGetVirusTotalStatusQueryKey,
  useCheckVirusTotalHash, useCreateScamShieldScan, useDeleteScamShieldScan,
  useGetScamShieldDashboard, useGetScamShieldScan, useGetScamShieldScans,
  useGetVirusTotalStatus,
} from '@workspace/api-client-react';
import type { ScanInput, ScanRecord, VirusTotalReputation } from '@workspace/api-client-react';
import NotFound from '@/pages/not-found';
import { ErrorBoundary } from '@/components/error-boundary';
import { Toaster } from '@/components/ui/toaster';
import { TooltipProvider } from '@/components/ui/tooltip';
import { inspectFile, normalizeScanLimit, safeURLAnalysis, type LocalAnalysis } from '@/lib/scanner';

const queryClient = new QueryClient();
const reportsEnabled = () => localStorage.getItem('scamshield-save-reports') !== 'off';
const getMaxScanMb = () => normalizeScanLimit(localStorage.getItem('scamshield-max-scan-mb'));
function formatFileSize(bytes: number) {
  if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
  if (bytes >= 1024 ** 2) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}
function formatScanLimit(maxScanMb: number) {
  return maxScanMb >= 1024 ? `${maxScanMb / 1024} GB` : `${maxScanMb} MB`;
}
const nav = [
  { href: '/', label: 'Overview', icon: LayoutDashboard },
  { href: '/scanner', label: 'File scanner', icon: FileSearch },
  { href: '/urls', label: 'URL check', icon: Link2 },
  { href: '/threats', label: 'Threat review', icon: ShieldAlert },
  { href: '/quarantine', label: 'Quarantine', icon: FileArchive },
  { href: '/history', label: 'History', icon: History },
  { href: '/reports', label: 'Reports', icon: FileText },
  { href: '/settings', label: 'Settings', icon: Settings2 },
];

function Shell({ children }: { children: ReactNode }) {
  const [path] = useLocation();
  const [menuOpen, setMenuOpen] = useState(false);
  const active = nav.find((item) => item.href === path)?.label ?? 'Overview';
  return (
    <div className="min-h-[100dvh] bg-background text-foreground md:flex">
      <aside className="hidden w-[248px] shrink-0 flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground md:flex">
        <Link href="/" className="flex h-[82px] items-center gap-3 border-b border-sidebar-border px-7" data-testid="link-brand">
          <span className="grid size-9 place-items-center rounded-xl bg-sidebar-primary text-sidebar-primary-foreground"><Shield size={19} strokeWidth={2.4} /></span>
          <span><b className="block text-[15px] tracking-tight">ScamShield</b><span className="mono text-[9px] uppercase tracking-[.19em] text-sidebar-foreground/55">Personal security</span></span>
        </Link>
        <div className="px-5 pb-2 pt-7 text-[9px] font-extrabold uppercase tracking-[.2em] text-sidebar-foreground/40">Workspace</div>
        <nav className="space-y-1 px-3" aria-label="Main navigation">
          {nav.map(({ href, label, icon: Icon }) => <Link key={href} href={href} data-testid={`link-nav-${label.toLowerCase().replaceAll(' ', '-')}`} className={`flex items-center gap-3 rounded-lg px-3 py-2.5 text-[12px] font-semibold transition-colors ${path === href ? 'bg-sidebar-accent text-sidebar-accent-foreground' : 'text-sidebar-foreground/65 hover:bg-sidebar-accent/70 hover:text-sidebar-foreground'}`}>
            <Icon size={16} strokeWidth={1.8} /><span>{label}</span>{path === href && <span className="ml-auto size-1.5 rounded-full bg-sidebar-primary" />}
          </Link>)}
        </nav>
        <div className="mt-auto p-4">
          <div className="rounded-xl border border-sidebar-border bg-sidebar-accent/55 p-3.5">
            <div className="mb-2 flex items-center gap-2"><span className="size-1.5 rounded-full bg-sidebar-primary" /><span className="mono text-[9px] uppercase tracking-widest text-sidebar-foreground/80">Local-first mode</span></div>
            <p className="text-[10px] leading-relaxed text-sidebar-foreground/55">Files stay in this browser. Only report metadata is saved.</p>
          </div>
          <div className="mt-4 flex items-center gap-2 px-1 text-[9px] text-sidebar-foreground/35"><LockKeyhole size={12} /> Privacy is the default</div>
        </div>
      </aside>
      <div className="min-w-0 flex-1">
        <header className="sticky top-0 z-20 flex h-[66px] items-center justify-between border-b border-border bg-background/95 px-4 backdrop-blur-md md:px-8">
          <div className="flex items-center gap-3">
            <button className="grid size-9 place-items-center rounded-lg border border-border md:hidden" aria-label="Open navigation" data-testid="button-open-menu" onClick={() => setMenuOpen((v) => !v)}>{menuOpen ? <X size={17} /> : <Menu size={17} />}</button>
            <div className="hidden items-center gap-2 text-[11px] text-muted-foreground sm:flex"><span>Workspace</span><ChevronRight size={13} /><span className="font-bold text-foreground">{active}</span></div>
            <span className="text-sm font-bold sm:hidden">{active}</span>
          </div>
          <div className="flex items-center gap-2.5">
            <span className="hidden items-center gap-1.5 rounded-full border border-border bg-card px-2.5 py-1.5 text-[9px] font-bold uppercase tracking-wide text-muted-foreground sm:flex"><span className="size-1.5 rounded-full bg-primary" /> Browser analysis</span>
            <Link href="/settings" aria-label="Settings" data-testid="link-quick-settings" className="grid size-9 place-items-center rounded-lg border border-border text-muted-foreground hover:bg-muted"><Settings2 size={16} /></Link>
          </div>
        </header>
        {menuOpen && <nav className="absolute z-30 w-full border-b border-border bg-card px-4 py-3 shadow-lg md:hidden">{nav.map((item) => <Link key={item.href} href={item.href} onClick={() => setMenuOpen(false)} className="flex items-center gap-3 rounded-lg px-3 py-3 text-sm font-semibold hover:bg-muted"><item.icon size={17} />{item.label}</Link>)}</nav>}
        <main className="mx-auto max-w-[1440px] px-4 py-7 md:px-8 md:py-9">{children}</main>
      </div>
    </div>
  );
}

function PageHead({ eyebrow, title, detail, action }: { eyebrow: string; title: string; detail: string; action?: ReactNode }) {
  return <div className="mb-7 flex flex-wrap items-end justify-between gap-4 rise-in"><div><div className="mono mb-2 text-[9px] font-medium uppercase tracking-[.2em] text-primary">{eyebrow}</div><h1 className="text-[27px] font-extrabold tracking-[-.045em] md:text-[32px]">{title}</h1><p className="mt-1.5 max-w-2xl text-[12px] leading-relaxed text-muted-foreground">{detail}</p></div>{action}</div>;
}

function Button({ children, onClick, variant = 'primary', disabled, type = 'button', testId }: { children: ReactNode; onClick?: () => void; variant?: 'primary' | 'outline' | 'quiet' | 'danger'; disabled?: boolean; type?: 'button' | 'submit'; testId?: string }) {
  const styles = { primary: 'bg-primary text-primary-foreground hover:brightness-95', outline: 'border border-border bg-card hover:bg-muted', quiet: 'text-muted-foreground hover:bg-muted', danger: 'border border-destructive/25 text-destructive hover:bg-destructive/10' };
  return <button type={type} onClick={onClick} disabled={disabled} data-testid={testId} className={`inline-flex min-h-9 items-center justify-center gap-2 rounded-lg px-3.5 text-[11px] font-bold transition-all disabled:cursor-not-allowed disabled:opacity-50 ${styles[variant]}`}>{children}</button>;
}

function Panel({ children, className = '' }: { children: ReactNode; className?: string }) { return <section className={`rounded-xl border border-card-border bg-card ${className}`}>{children}</section>; }
function SectionTitle({ title, caption, right }: { title: string; caption?: string; right?: ReactNode }) { return <div className="mb-4 flex items-center justify-between gap-3"><div><h2 className="text-[13px] font-extrabold tracking-tight">{title}</h2>{caption && <p className="mt-1 text-[10px] text-muted-foreground">{caption}</p>}</div>{right}</div>; }
function LoadingRows() { return <div className="space-y-3 p-5" aria-label="Loading"><div className="h-4 w-1/3 animate-pulse rounded bg-muted" /><div className="h-10 animate-pulse rounded bg-muted/70" /><div className="h-10 animate-pulse rounded bg-muted/70" /><div className="h-10 animate-pulse rounded bg-muted/70" /></div>; }
function ErrorBox({ onRetry, message = 'Could not retrieve saved scan data.' }: { onRetry: () => void; message?: string }) { return <div className="flex items-center justify-between gap-4 rounded-xl border border-destructive/25 bg-destructive/5 p-4 text-[11px]"><div className="flex items-center gap-2 text-destructive"><AlertTriangle size={16} />{message}</div><Button variant="outline" onClick={onRetry}><RefreshCw size={13} /> Retry</Button></div>; }
function verdictTone(verdict: string) { return verdict === 'malicious' ? 'red' : verdict === 'suspicious' ? 'amber' : 'green'; }
function Verdict({ verdict }: { verdict: string }) {
  const tone = verdictTone(verdict);
  const Icon = tone === 'red' ? Ban : tone === 'amber' ? AlertTriangle : BadgeCheck;
  return <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[9px] font-extrabold uppercase tracking-[.08em] ${tone === 'red' ? 'bg-destructive/10 text-destructive' : tone === 'amber' ? 'bg-amber-500/10 text-amber-700 dark:text-amber-300' : 'bg-primary/10 text-primary'}`}><Icon size={11} />{verdict}</span>;
}
function formatDate(value: string) { const date = new Date(value); return Number.isNaN(date.getTime()) ? value : date.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }); }
function shortHash(value: string | null) { return value ? `${value.slice(0, 12)}…${value.slice(-8)}` : 'Not available'; }
function EmptyState({ icon: Icon, title, detail, action }: { icon: typeof Shield; title: string; detail: string; action?: ReactNode }) { return <div className="grid min-h-[220px] place-items-center p-8 text-center"><div><div className="mx-auto mb-3 grid size-11 place-items-center rounded-xl bg-muted text-muted-foreground"><Icon size={20} /></div><h3 className="text-sm font-extrabold">{title}</h3><p className="mx-auto mt-1 max-w-sm text-[11px] leading-relaxed text-muted-foreground">{detail}</p>{action && <div className="mt-4">{action}</div>}</div></div>; }

function useReports() {
  const query = useGetScamShieldScans(undefined, { query: { queryKey: getGetScamShieldScansQueryKey(), refetchOnMount: true } });
  return query;
}

function ReportRow({ scan, onOpen, onDelete }: { scan: ScanRecord; onOpen: (id: string) => void; onDelete?: (id: string) => void }) {
  return <div className="grid gap-3 border-b border-border/70 px-4 py-3.5 last:border-0 md:grid-cols-[minmax(180px,1.5fr)_100px_minmax(160px,1fr)_145px_auto] md:items-center md:px-5">
    <button onClick={() => onOpen(scan.id)} data-testid={`button-open-report-${scan.id}`} className="flex min-w-0 items-center gap-3 text-left">
      <span className={`grid size-8 shrink-0 place-items-center rounded-lg ${scan.kind === 'file' ? 'bg-secondary text-muted-foreground' : 'bg-accent text-primary'}`}>{scan.kind === 'file' ? <FileCode2 size={15} /> : <Globe2 size={15} />}</span>
      <span className="min-w-0"><span className="block truncate text-[11px] font-bold">{scan.fileName ?? scan.target}</span><span className="mono block truncate pt-1 text-[9px] text-muted-foreground">{scan.kind === 'file' ? shortHash(scan.sha256) : scan.target}</span></span>
    </button>
    <div className="flex items-center gap-2"><Verdict verdict={scan.verdict} /></div>
    <div className="flex flex-wrap gap-1.5">{scan.indicators.slice(0, 2).map((indicator, i) => <span key={i} className="rounded-md border border-border bg-background px-2 py-1 text-[9px] text-muted-foreground">{indicator}</span>)}{!scan.indicators.length && <span className="text-[10px] text-muted-foreground">No indicators flagged</span>}</div>
    <div className="text-[10px] text-muted-foreground md:text-right">{formatDate(scan.scannedAt)}</div>
    {onDelete && <button onClick={() => onDelete(scan.id)} aria-label="Delete report" data-testid={`button-delete-report-${scan.id}`} className="justify-self-end rounded-md p-2 text-muted-foreground hover:bg-destructive/10 hover:text-destructive"><Trash2 size={14} /></button>}
  </div>;
}

function ScanDetail({ id, onClose }: { id: string; onClose: () => void }) {
  const query = useGetScamShieldScan(id, { query: { queryKey: getGetScamShieldScanQueryKey(id), enabled: !!id } });
  return <div className="fixed inset-0 z-50 flex items-end justify-center bg-foreground/35 p-0 backdrop-blur-sm sm:items-center sm:p-5" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
    <div className="max-h-[90dvh] w-full max-w-xl overflow-y-auto rounded-t-2xl border border-border bg-card p-5 shadow-2xl sm:rounded-2xl sm:p-7">
      <div className="mb-5 flex items-start justify-between"><div><div className="mono text-[9px] uppercase tracking-widest text-primary">Saved analysis</div><h2 className="mt-1 text-lg font-extrabold">Report detail</h2></div><button onClick={onClose} aria-label="Close detail" className="rounded-lg p-2 text-muted-foreground hover:bg-muted"><X size={17} /></button></div>
      {query.isLoading ? <LoadingRows /> : query.isError ? <ErrorBox message="Unable to load this report." onRetry={() => void query.refetch()} /> : query.data && <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl bg-muted/70 p-4"><div className="min-w-0"><div className="truncate text-sm font-bold">{query.data.fileName ?? query.data.target}</div><div className="mt-1 text-[10px] text-muted-foreground">{formatDate(query.data.scannedAt)} · {query.data.detectionSource}{query.data.fileType ? ` · ${query.data.fileType}` : ''}</div></div><Verdict verdict={query.data.verdict} /></div>
        <div className="space-y-2"><p className="mono text-[9px] uppercase tracking-widest text-muted-foreground">Indicators</p>{query.data.indicators.length ? query.data.indicators.map((x, i) => <div key={i} className="flex gap-2 rounded-lg border border-border p-3 text-[11px]"><AlertTriangle size={14} className="shrink-0 text-amber-600" />{x}</div>) : <p className="text-[11px] text-muted-foreground">No local indicators recorded. This is not proof of safety.</p>}</div>
        <div className="grid gap-2 rounded-xl border border-border p-4 text-[10px]"><span><b>SHA-256</b><span className="mono ml-2 break-all text-muted-foreground">{query.data.sha256 ?? 'Unavailable'}</span></span><span><b>SHA-1</b><span className="mono ml-2 break-all text-muted-foreground">{query.data.sha1 ?? 'Unavailable'}</span></span></div>
        <p className="text-[10px] leading-relaxed text-muted-foreground">Analysis is limited to local heuristics and available reputation data. A clean result cannot guarantee a file or link is safe.</p>
      </div>}
    </div>
  </div>;
}

function Overview() {
  const dashboard = useGetScamShieldDashboard({ query: { queryKey: getGetScamShieldDashboardQueryKey(), refetchOnMount: true } });
  const reports = useReports();
  const [detail, setDetail] = useState<string | null>(null);
  const metrics: { label: string; value: number | undefined; icon: typeof Activity; tone: string }[] = [
    { label: 'Total inspected', value: dashboard.data?.totalScans, icon: Activity, tone: 'text-primary bg-primary/10' },
    { label: 'Needs review', value: dashboard.data?.suspiciousCount, icon: AlertTriangle, tone: 'text-amber-700 bg-amber-500/10 dark:text-amber-300' },
    { label: 'Threats found', value: dashboard.data?.maliciousCount, icon: ShieldAlert, tone: 'text-destructive bg-destructive/10' },
    { label: 'Today', value: dashboard.data?.scannedToday, icon: Clock3, tone: 'text-sky-700 bg-sky-500/10 dark:text-sky-300' },
  ];
  return <>
    <PageHead eyebrow="Security workspace / 01" title="Your scan overview" detail="A clear view of what you have inspected. Files are analyzed in this browser; they are never uploaded or opened." action={<Link href="/scanner" data-testid="link-start-file-scan" className="inline-flex min-h-10 items-center gap-2 rounded-lg bg-primary px-4 text-[11px] font-bold text-primary-foreground"><Plus size={15} /> New scan</Link>} />
    {dashboard.isError && <div className="mb-5"><ErrorBox onRetry={() => void dashboard.refetch()} /></div>}
    <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">{metrics.map(({ label, value, icon: Icon, tone }, index) => <Panel key={label} className={`p-4 rise-in [animation-delay:${index * 60}ms]`}><div className="flex items-center justify-between"><span className="text-[10px] font-semibold text-muted-foreground">{label}</span><span className={`grid size-8 place-items-center rounded-lg ${tone}`}><Icon size={16} /></span></div><div className="mt-3 text-[26px] font-extrabold tracking-[-.05em]">{dashboard.isLoading ? <span className="inline-block h-7 w-12 animate-pulse rounded bg-muted" /> : value ?? '—'}</div><div className="mono mt-1 text-[8px] uppercase tracking-[.16em] text-muted-foreground/75">Saved reports</div></Panel>)}</div>
    <div className="grid gap-5 xl:grid-cols-[1.55fr_1fr]">
      <Panel className="overflow-hidden"><div className="flex items-center justify-between border-b border-border px-5 py-4"><div><h2 className="text-[13px] font-extrabold">Recent activity</h2><p className="mt-1 text-[10px] text-muted-foreground">Latest browser-side inspections</p></div><Link href="/history" className="inline-flex items-center gap-1 text-[10px] font-bold text-primary">All history <ArrowRight size={13} /></Link></div>
        {dashboard.isLoading ? <LoadingRows /> : dashboard.data?.recentScans?.length ? dashboard.data.recentScans.slice(0, 6).map((scan) => <ReportRow key={scan.id} scan={scan} onOpen={setDetail} />) : <EmptyState icon={FileSearch} title="No scans saved yet" detail="Inspect a file or paste a URL to create your first report." action={<Link href="/scanner" className="text-[11px] font-bold text-primary">Start with a file</Link>} />}
      </Panel>
      <div className="space-y-5">
        <Panel className="scan-grid relative overflow-hidden p-5"><div className="relative z-10"><span className="mono text-[9px] uppercase tracking-[.18em] text-primary">Inspection modes</span><h2 className="mt-2 max-w-[270px] text-[20px] font-extrabold leading-tight tracking-[-.04em]">Look closer.<br />Keep control.</h2><p className="mt-2 max-w-[270px] text-[10px] leading-relaxed text-muted-foreground">Static checks help spot warning signs without executing files or visiting links.</p><div className="mt-5 flex flex-wrap gap-2"><Link href="/scanner" className="rounded-lg bg-primary px-3 py-2 text-[10px] font-bold text-primary-foreground">Inspect a file</Link><Link href="/urls" className="rounded-lg border border-border bg-card px-3 py-2 text-[10px] font-bold">Check a URL</Link></div></div><div className="absolute -right-3 bottom-2 opacity-[.075]"><Fingerprint size={150} strokeWidth={.7} /></div></Panel>
        <Panel className="p-5"><SectionTitle title="Report mix" caption="Based on saved scan reports" right={<span className="mono text-[9px] text-muted-foreground">{dashboard.data?.totalScans ?? '—'} total</span>} />
          {dashboard.isLoading ? <div className="h-3 animate-pulse rounded-full bg-muted" /> : <div className="space-y-4">{[
            { name: 'Clean', value: dashboard.data?.cleanCount ?? 0, color: 'bg-primary' },
            { name: 'Suspicious', value: dashboard.data?.suspiciousCount ?? 0, color: 'bg-amber-500' },
            { name: 'Malicious', value: dashboard.data?.maliciousCount ?? 0, color: 'bg-destructive' },
          ].map((item) => <div key={item.name}><div className="mb-1.5 flex justify-between text-[10px]"><span className="font-semibold">{item.name}</span><span className="mono text-muted-foreground">{item.value}</span></div><div className="h-1.5 overflow-hidden rounded-full bg-muted"><div className={`h-full rounded-full ${item.color}`} style={{ width: `${dashboard.data?.totalScans ? Math.min(100, item.value / dashboard.data.totalScans * 100) : 0}%` }} /></div></div>)}</div>}
        </Panel>
        <div className="flex items-start gap-2 rounded-xl border border-primary/20 bg-primary/[.045] p-3.5 text-[10px] leading-relaxed text-muted-foreground"><LockKeyhole size={14} className="mt-0.5 shrink-0 text-primary" /><span><b className="text-foreground">Privacy note.</b> File bytes remain on your device. Reports store hashes and analysis metadata only.</span></div>
      </div>
    </div>
    {reports.isError && <div className="mt-5"><ErrorBox message="Searchable reports could not be loaded." onRetry={() => void reports.refetch()} /></div>}
    {detail && <ScanDetail id={detail} onClose={() => setDetail(null)} />}
  </>;
}

function Scanner() {
  const [files, setFiles] = useState<File[]>([]);
  const [results, setResults] = useState<Array<{ file: File; result: LocalAnalysis }>>([]);
  const [running, setRunning] = useState(false);
  const [scanProgress, setScanProgress] = useState<{ fileName: string; processedBytes: number; totalBytes: number } | null>(null);
  const [error, setError] = useState('');
  const create = useCreateScamShieldScan();
  const client = useQueryClient();
  const selectFiles = (e: ChangeEvent<HTMLInputElement>) => {
    const incoming = Array.from(e.target.files ?? []);
    const limit = getMaxScanMb() * 1024 * 1024;
    const accepted = incoming.filter((file) => file.size <= limit);
    const skipped = incoming.length - accepted.length;
    setFiles((old) => [...old, ...accepted]);
    e.target.value = '';
        setError(skipped ? `${skipped} file${skipped === 1 ? '' : 's'} skipped: the current limit is ${formatScanLimit(getMaxScanMb())} per file.` : '');
  };
  const runScan = async () => {
    if (!files.length || running) return;
    setRunning(true); setError(''); setResults([]);
    try {
      const analyzed: Array<{ file: File; result: LocalAnalysis }> = [];
      for (const file of files) {
        const result = await inspectFile(file, getMaxScanMb(), (processedBytes, totalBytes) => {
          setScanProgress({ fileName: file.name, processedBytes, totalBytes });
        });
        analyzed.push({ file, result });
      }
      setScanProgress(null);
      setResults(analyzed);
      if (reportsEnabled()) for (const { file, result } of analyzed) {
        const input: ScanInput = { kind: 'file', fileName: file.name, fileType: result.fileType, target: file.name, sizeBytes: file.size, sha256: result.sha256, sha1: result.sha1, verdict: result.verdict, indicators: result.indicators, detectionSource: 'Browser-local static checks' };
        await create.mutateAsync({ data: input });
      }
      setFiles([]);
      if (reportsEnabled()) await Promise.all([client.invalidateQueries({ queryKey: getGetScamShieldScansQueryKey() }), client.invalidateQueries({ queryKey: getGetScamShieldDashboardQueryKey() })]);
    } catch (error) {
      setError(error instanceof Error && error.message.includes('scan limit')
        ? error.message
        : 'Local analysis completed, but a report could not be saved. Your file was not uploaded. Retry after checking your connection.');
    }
    finally { setRunning(false); setScanProgress(null); }
  };
  return <>
    <PageHead eyebrow="Browser analysis / 02" title="Inspect files locally" detail="Static inspection only. Files are hashed in small local chunks and checked for signature clues; nothing is uploaded, executed, or opened." />
    <div className="grid gap-5 xl:grid-cols-[1.2fr_.8fr]">
      <Panel className="p-5 md:p-7">
        <SectionTitle title="Select files" caption={`Multiple files supported · ${formatScanLimit(getMaxScanMb())} maximum per file`} />
        <label className="scan-grid flex min-h-[220px] cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed border-border bg-background/70 px-5 text-center transition-colors hover:border-primary/50 hover:bg-primary/[.025]">
          <span className="mb-3 grid size-12 place-items-center rounded-xl bg-primary/10 text-primary"><Upload size={21} /></span><span className="text-[13px] font-extrabold">Drop files here or browse</span><span className="mt-1.5 text-[10px] text-muted-foreground">Your device reads file bytes locally only</span>
          <input type="file" multiple className="sr-only" onChange={selectFiles} data-testid="input-file-select" />
        </label>
        {files.length > 0 && <div className="mt-4 space-y-2">{files.map((file, i) => <div key={`${file.name}-${i}`} className="flex items-center gap-3 rounded-lg border border-border px-3 py-2.5"><FileCode2 size={15} className="text-primary" /><span className="min-w-0 flex-1 truncate text-[10px] font-bold">{file.name}</span><span className="mono text-[9px] text-muted-foreground">{formatFileSize(file.size)}</span><button aria-label={`Remove ${file.name}`} onClick={() => setFiles((list) => list.filter((_, idx) => idx !== i))} className="p-1 text-muted-foreground hover:text-destructive"><X size={14} /></button></div>)}</div>}
        {error && <div className="mt-4 text-[10px] text-destructive" role="alert">{error}</div>}
        {running && scanProgress && <div className="mt-4 rounded-lg border border-border bg-background/60 p-3" aria-live="polite"><div className="mb-2 flex items-center justify-between gap-3 text-[10px]"><span className="min-w-0 truncate font-semibold">Hashing {scanProgress.fileName}</span><span className="mono shrink-0 text-muted-foreground">{formatFileSize(scanProgress.processedBytes)} / {formatFileSize(scanProgress.totalBytes)}</span></div><div className="h-1.5 overflow-hidden rounded-full bg-muted" role="progressbar" aria-label={`Hashing ${scanProgress.fileName}`} aria-valuemin={0} aria-valuemax={scanProgress.totalBytes} aria-valuenow={scanProgress.processedBytes}><div className="h-full rounded-full bg-primary transition-[width]" style={{ width: `${scanProgress.totalBytes ? scanProgress.processedBytes / scanProgress.totalBytes * 100 : 100}%` }} /></div></div>}
        <div className="mt-5 flex flex-wrap items-center justify-between gap-3"><span className="flex items-center gap-1.5 text-[9px] text-muted-foreground"><LockKeyhole size={12} /> No upload. No execution. No file opening.</span><Button onClick={() => void runScan()} disabled={!files.length || running || create.isPending} testId="button-run-file-scan">{running || create.isPending ? <><LoaderCircle size={14} className="animate-spin" /> Inspecting locally…</> : <><FileSearch size={14} /> Inspect {files.length || ''} {files.length === 1 ? 'file' : 'files'}</>}</Button></div>
      </Panel>
      <Panel className="p-5"><SectionTitle title="What this scan checks" caption="Cautious indicators, not a malware verdict from a full antivirus engine" />
        <div className="space-y-4">{[
          { icon: Fingerprint, name: 'File fingerprints', desc: 'SHA-256 and SHA-1 hashes calculated locally in 4 MB chunks.' },
          { icon: FileCode2, name: 'File signature clues', desc: 'Recognizable header bytes and filename patterns that may warrant a closer look.' },
          { icon: Globe2, name: 'Visible text clues', desc: 'A short header sample checked for embedded URL text.' },
        ].map(({ icon: Icon, name, desc }) => <div key={name} className="flex gap-3"><span className="grid size-8 shrink-0 place-items-center rounded-lg bg-muted text-primary"><Icon size={15} /></span><div><b className="text-[10px]">{name}</b><p className="mt-1 text-[10px] leading-relaxed text-muted-foreground">{desc}</p></div></div>)}</div>
        <div className="mt-5 rounded-lg border border-amber-500/25 bg-amber-500/[.06] p-3 text-[10px] leading-relaxed text-muted-foreground"><b className="text-foreground">Important:</b> a clean label only means these checks found no common warning signs. It does not establish that a file is safe.</div>
      </Panel>
    </div>
    {results.length > 0 && <Panel className="mt-5 overflow-hidden"><div className="border-b border-border p-4"><h2 className="text-[13px] font-extrabold">Inspection complete</h2><p className="mt-1 text-[10px] text-muted-foreground">{reportsEnabled() ? 'Scan metadata saved. File contents were never sent to a server.' : 'Local inspection only. Report saving is disabled in your preferences.'}</p></div>{results.map(({ file, result }, i) => <div key={i} className="grid gap-3 border-b border-border p-4 last:border-0 sm:grid-cols-[1fr_auto] sm:items-center"><div className="min-w-0"><b className="block truncate text-[11px]">{file.name}</b><p className="mt-1 text-[10px] text-muted-foreground">Detected type · {result.fileType}</p><div className="mono mt-1 break-all text-[9px] text-muted-foreground">SHA-256 · {result.sha256 ?? 'Unavailable in this browser'}</div><div className="mt-2 space-y-1">{result.indicators.map((x, idx) => <p key={idx} className="text-[10px] text-amber-700 dark:text-amber-300">{x}</p>)}</div></div><Verdict verdict={result.verdict} /></div>)}</Panel>}
  </>;
}

function URLCheck() {
  const [text, setText] = useState('');
  const [result, setResult] = useState<ReturnType<typeof safeURLAnalysis> | null>(null);
  const [error, setError] = useState('');
  const create = useCreateScamShieldScan();
  const client = useQueryClient();
  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    const parsed = safeURLAnalysis(text);
    if (!parsed.target) { setError('Paste a URL or domain to inspect.'); return; }
    setError(''); setResult(parsed);
    try {
      if (reportsEnabled()) {
        await create.mutateAsync({ data: { kind: 'url', fileName: null, fileType: null, target: parsed.target, sizeBytes: null, sha256: null, sha1: null, verdict: parsed.verdict, indicators: parsed.indicators, detectionSource: 'Local URL text checks' } });
        await Promise.all([client.invalidateQueries({ queryKey: getGetScamShieldScansQueryKey() }), client.invalidateQueries({ queryKey: getGetScamShieldDashboardQueryKey() })]);
      }
    } catch { setError('Local checks completed, but the report could not be saved.'); }
  };
  return <>
    <PageHead eyebrow="Text-only inspection / 03" title="Check a suspicious URL" detail="We parse the text you paste. ScamShield does not request, navigate to, or resolve the destination URL." />
    <div className="grid gap-5 xl:grid-cols-[1.15fr_.85fr]">
      <Panel className="p-5 md:p-7"><form onSubmit={(e) => void submit(e)}><label htmlFor="url-text" className="mb-2 block text-[11px] font-bold">URL text</label><div className="flex items-center gap-2 rounded-xl border border-input bg-background px-3 focus-within:ring-2 focus-within:ring-ring/30"><Link2 size={16} className="shrink-0 text-muted-foreground" /><input id="url-text" value={text} onChange={(e) => setText(e.target.value)} maxLength={2048} placeholder="Paste a link or domain — nothing will open" className="h-12 min-w-0 flex-1 bg-transparent text-[11px] outline-none placeholder:text-muted-foreground/60" data-testid="input-url-text" /><span className="mono hidden text-[8px] text-muted-foreground sm:block">{text.length}/2048</span></div>
        <div className="mt-3 flex items-start gap-2 text-[10px] leading-relaxed text-muted-foreground"><LockKeyhole size={13} className="mt-0.5 shrink-0 text-primary" />This is a local text analysis. No DNS lookup, HTTP request, or link navigation occurs.</div>
        {error && <p role="alert" className="mt-3 text-[10px] text-destructive">{error}</p>}
        <div className="mt-5 flex justify-end"><Button type="submit" disabled={!text.trim() || create.isPending} testId="button-check-url">{create.isPending ? <><LoaderCircle size={14} className="animate-spin" /> Saving…</> : <><Search size={14} /> Inspect text</>}</Button></div></form></Panel>
      <Panel className="p-5"><SectionTitle title="Local checks" caption="Common persuasion and address-format signals" /><div className="space-y-3">{['Connection scheme and HTTPS presence', 'Embedded credentials in the URL', 'Raw IP and unusually deep subdomains', 'Encoded characters and unusually long text', 'Internationalized domain encoding'].map((item, i) => <div key={item} className="flex items-center gap-2.5 text-[10px]"><span className="mono text-[9px] text-primary">0{i + 1}</span><span>{item}</span></div>)}</div><p className="mt-5 rounded-lg bg-muted/70 p-3 text-[10px] leading-relaxed text-muted-foreground">A well-formed URL can still be malicious. Do not treat the absence of these signs as verification.</p></Panel>
    </div>
    {result && <Panel className="mt-5 p-5"><div className="flex flex-wrap items-start justify-between gap-3"><div><div className="mono text-[9px] uppercase tracking-widest text-primary">Text inspection result</div><p className="mono mt-2 break-all text-[11px] font-medium">{result.target}</p></div><Verdict verdict={result.verdict} /></div><div className="mt-4 space-y-2">{result.indicators.map((item, i) => <div key={i} className="flex gap-2 rounded-lg bg-muted/50 p-3 text-[10px]"><span className="mt-1 size-1.5 shrink-0 rounded-full bg-amber-500" />{item}</div>)}</div></Panel>}
  </>;
}

function Threats() {
  const reports = useReports();
  const status = useGetVirusTotalStatus({ query: { queryKey: getGetVirusTotalStatusQueryKey(), refetchOnMount: true } });
  const check = useCheckVirusTotalHash();
  const [selected, setSelected] = useState<ScanRecord | null>(null);
  const [reputation, setReputation] = useState<VirusTotalReputation | null>(null);
  const [message, setMessage] = useState('');
  const client = useQueryClient();
  const request = async (scan: ScanRecord) => {
    if (!scan.sha256) { setMessage('This report has no SHA-256 hash to check.'); return; }
    setSelected(scan); setReputation(null); setMessage('');
    try {
      const value = await check.mutateAsync({ sha256: scan.sha256 });
      setReputation(value);
      await client.invalidateQueries({ queryKey: getGetVirusTotalStatusQueryKey() });
    } catch { setMessage('The reputation request failed. No file bytes were sent; only the SHA-256 hash is checked.'); }
  };
  const candidates = (reports.data ?? []).filter((x) => x.verdict !== 'clean' || x.kind === 'file');
  return <>
    <PageHead eyebrow="Reputation review / 04" title="Threat review" detail="Review local indicators and optionally request a VirusTotal reputation check using a file hash only." />
    <Panel className="mb-5 flex flex-wrap items-center justify-between gap-4 p-4"><div className="flex items-center gap-3"><span className={`grid size-10 place-items-center rounded-xl ${status.data?.configured ? 'bg-primary/10 text-primary' : 'bg-muted text-muted-foreground'}`}><ShieldCheck size={19} /></span><div><div className="text-[11px] font-extrabold">VirusTotal hash reputation</div><div className="mt-1 text-[10px] text-muted-foreground">{status.isLoading ? 'Checking connection status…' : status.isError ? 'Connection status unavailable' : status.data?.configured ? 'Connected · checks send only SHA-256 hashes' : 'Not configured · local checks still work'}</div></div></div><span className={`rounded-full px-2.5 py-1 text-[9px] font-bold ${status.data?.configured ? 'bg-primary/10 text-primary' : 'bg-muted text-muted-foreground'}`}>{status.isLoading ? 'CHECKING' : status.data?.configured ? 'AVAILABLE' : 'OFFLINE'}</span></Panel>
    {status.isError && <div className="mb-5"><ErrorBox message="Could not read VirusTotal connection status." onRetry={() => void status.refetch()} /></div>}
    {reports.isError && <ErrorBox onRetry={() => void reports.refetch()} />}
    <Panel className="overflow-hidden"><div className="border-b border-border p-4"><h2 className="text-[13px] font-extrabold">Saved file reports</h2><p className="mt-1 text-[10px] text-muted-foreground">Hash lookups never upload the file itself.</p></div>
      {reports.isLoading ? <LoadingRows /> : candidates.length ? candidates.map((scan) => <div key={scan.id} className="flex flex-wrap items-center justify-between gap-3 border-b border-border p-4 last:border-0"><div className="flex min-w-0 items-center gap-3"><span className="grid size-8 place-items-center rounded-lg bg-muted"><FileCode2 size={15} /></span><div className="min-w-0"><p className="truncate text-[11px] font-bold">{scan.fileName ?? scan.target}</p><p className="mono mt-1 truncate text-[9px] text-muted-foreground">{shortHash(scan.sha256)} · {formatDate(scan.scannedAt)}</p></div></div><div className="flex items-center gap-2"><Verdict verdict={scan.verdict} /><Button variant="outline" disabled={!scan.sha256 || check.isPending} onClick={() => void request(scan)} testId={`button-check-reputation-${scan.id}`}>{check.isPending && selected?.id === scan.id ? <LoaderCircle size={13} className="animate-spin" /> : <Search size={13} />}Check hash</Button></div></div>) : <EmptyState icon={ShieldCheck} title="No saved file reports" detail="Inspect a file first. URL reports do not have file hashes for reputation lookup." action={<Link href="/scanner" className="text-[11px] font-bold text-primary">Go to file scanner</Link>} />}
    </Panel>
    {message && <div role="alert" className="mt-4 rounded-lg border border-amber-500/20 bg-amber-500/[.06] p-3 text-[10px] text-amber-800 dark:text-amber-200">{message}</div>}
    {reputation && selected && <Panel className="mt-5 p-5"><div className="flex flex-wrap items-start justify-between gap-3"><div><div className="mono text-[9px] uppercase tracking-widest text-primary">VirusTotal hash result</div><h3 className="mt-1 text-[13px] font-extrabold">{selected.fileName ?? selected.target}</h3><p className="mono mt-1 break-all text-[9px] text-muted-foreground">{reputation.sha256}</p></div><span className={`rounded-full px-2.5 py-1 text-[9px] font-extrabold ${reputation.malicious || reputation.suspicious ? 'bg-destructive/10 text-destructive' : 'bg-primary/10 text-primary'}`}>{reputation.found ? 'MATCH FOUND' : 'NO MATCH'}</span></div>
      {reputation.found ? <><div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-4">{[['Malicious', reputation.malicious, 'text-destructive'], ['Suspicious', reputation.suspicious, 'text-amber-700 dark:text-amber-300'], ['Harmless', reputation.harmless, 'text-primary'], ['Undetected', reputation.undetected, 'text-muted-foreground']].map(([label, value, color]) => <div key={String(label)} className="rounded-lg bg-muted/60 p-3"><div className={`text-xl font-extrabold ${color}`}>{value}</div><div className="mt-1 text-[9px] text-muted-foreground">{label}</div></div>)}</div><p className="mt-3 text-[9px] text-muted-foreground">{reputation.lastAnalysisAt ? `Last analysis ${formatDate(reputation.lastAnalysisAt)}` : 'Analysis timestamp not provided'}{reputation.engines.length ? ` · ${reputation.engines.length} engines reported` : ''}</p></> : <p className="mt-4 text-[10px] text-muted-foreground">No reputation record was returned for this hash. That is not proof of safety.</p>}
    </Panel>}
  </>;
}

type QuarantineEntry = { key: string; name: string; size: number; addedAt: string };
const DB_NAME = 'scamshield-local-quarantine';
function openQuarantineDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (!('indexedDB' in window)) { reject(new Error('IndexedDB is unavailable')); return; }
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => { if (!request.result.objectStoreNames.contains('copies')) request.result.createObjectStore('copies', { keyPath: 'key' }); };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
async function listQuarantine(): Promise<QuarantineEntry[]> {
  const db = await openQuarantineDb();
  return new Promise((resolve, reject) => {
    const req = db.transaction('copies', 'readonly').objectStore('copies').getAll();
    req.onsuccess = () => resolve((req.result as Array<{ key: string; name: string; blob: Blob; addedAt: string }>).map(({ key, name, blob, addedAt }) => ({ key, name, size: blob.size, addedAt })));
    req.onerror = () => reject(req.error);
  });
}
async function putQuarantine(file: File) {
  const db = await openQuarantineDb();
  return new Promise<void>((resolve, reject) => {
    const tx = db.transaction('copies', 'readwrite');
    tx.objectStore('copies').put({ key: `${Date.now()}-${crypto.randomUUID()}`, name: file.name, blob: file.slice(0, file.size, file.type), addedAt: new Date().toISOString() });
    tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error);
  });
}
async function removeQuarantine(key: string) {
  const db = await openQuarantineDb();
  return new Promise<void>((resolve, reject) => {
    const tx = db.transaction('copies', 'readwrite'); tx.objectStore('copies').delete(key);
    tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error);
  });
}
async function retrieveQuarantine(key: string) {
  const db = await openQuarantineDb();
  return new Promise<{ name: string; blob: Blob }>((resolve, reject) => {
    const req = db.transaction('copies', 'readonly').objectStore('copies').get(key);
    req.onsuccess = () => req.result ? resolve({ name: req.result.name, blob: req.result.blob }) : reject(new Error('Copy not found'));
    req.onerror = () => reject(req.error);
  });
}
function Quarantine() {
  const [items, setItems] = useState<QuarantineEntry[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const reload = async () => { try { setItems(await listQuarantine()); setError(''); } catch { setError('Browser-local storage is unavailable. Check browser privacy settings or available storage.'); } };
  useEffect(() => { void reload(); }, []);
  const addCopy = async (e: ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files ?? []); e.target.value = '';
    if (!files.length) return;
    if (files.some((file) => file.size > 100 * 1024 * 1024)) {
      setError('Quarantine copies are limited to 100 MB per file to protect browser storage.');
      return;
    }
    setBusy(true);
    try { for (const file of files) await putQuarantine(file); await reload(); } catch { setError('Could not save a local copy. Check available browser storage.'); }
    finally { setBusy(false); }
  };
  const download = async (key: string) => {
    if (!window.confirm('Save a copy to your computer? The file may be unsafe.')) return;
    try { const item = await retrieveQuarantine(key); const url = URL.createObjectURL(item.blob); const anchor = document.createElement('a'); anchor.href = url; anchor.download = item.name; anchor.click(); window.setTimeout(() => URL.revokeObjectURL(url), 1000); } catch { setError('Could not retrieve this local copy.'); }
  };
  const remove = async (key: string) => { if (!window.confirm('Permanently remove this browser-local copy? The original file is not affected.')) return; try { await removeQuarantine(key); await reload(); } catch { setError('Could not remove this copy.'); } };
  return <>
    <PageHead eyebrow="Browser storage / 05" title="Quarantine copies" detail="Store and remove copies in this browser's IndexedDB. ScamShield never claims to move, lock, or alter the original file." action={<label className={`inline-flex min-h-9 cursor-pointer items-center gap-2 rounded-lg bg-primary px-3.5 text-[11px] font-bold text-primary-foreground ${busy ? 'opacity-50' : ''}`}><Plus size={14} /> Add a copy<input type="file" multiple disabled={busy} className="sr-only" onChange={(e) => void addCopy(e)} data-testid="input-quarantine-add" /></label>} />
    <div className="mb-5 flex gap-3 rounded-xl border border-amber-500/25 bg-amber-500/[.055] p-4"><AlertTriangle size={17} className="mt-0.5 shrink-0 text-amber-700 dark:text-amber-300" /><p className="text-[10px] leading-relaxed text-muted-foreground"><b className="text-foreground">A local copy only.</b> This feature does not isolate, delete, or change the original file. Copies live in this browser profile and may be removed when browser data is cleared.</p></div>
    {error && <div role="alert" className="mb-4"><ErrorBox message={error} onRetry={() => void reload()} /></div>}
    <Panel className="overflow-hidden"><div className="border-b border-border px-5 py-4"><h2 className="text-[13px] font-extrabold">Stored copies</h2><p className="mt-1 text-[10px] text-muted-foreground">{items.length} items in browser storage</p></div>{busy ? <LoadingRows /> : items.length ? items.map((item) => <div key={item.key} className="flex flex-wrap items-center justify-between gap-3 border-b border-border p-4 last:border-0"><div className="flex min-w-0 items-center gap-3"><span className="grid size-9 place-items-center rounded-lg bg-muted text-primary"><HardDrive size={16} /></span><div className="min-w-0"><p className="truncate text-[11px] font-bold">{item.name}</p><p className="mt-1 text-[9px] text-muted-foreground">{(item.size / 1024).toFixed(1)} KB · Added {formatDate(item.addedAt)}</p></div></div><div className="flex gap-2"><Button variant="outline" onClick={() => void download(item.key)}><ArrowDownToLine size={13} /> Save copy</Button><Button variant="danger" onClick={() => void remove(item.key)}><Trash2 size={13} /> Remove copy</Button></div></div>) : <EmptyState icon={FileArchive} title="No local copies stored" detail="Choose a file to store a separate copy in this browser. The original file stays where it is." />}
    </Panel>
  </>;
}

function HistoryPage() {
  const [search, setSearch] = useState('');
  const [verdict, setVerdict] = useState('');
  const [kind, setKind] = useState('');
  const [detail, setDetail] = useState<string | null>(null);
  const client = useQueryClient();
  const deleteScan = useDeleteScamShieldScan();
  const params = useMemo(() => ({ ...(search.trim() ? { search: search.trim() } : {}), ...(verdict ? { verdict: verdict as 'clean' | 'suspicious' | 'malicious' } : {}), ...(kind ? { kind: kind as 'file' | 'url' } : {}) }), [search, verdict, kind]);
  const reports = useGetScamShieldScans(params, { query: { queryKey: getGetScamShieldScansQueryKey(params), refetchOnMount: true } });
  const remove = async (id: string) => { if (!window.confirm('Delete this saved report? This does not affect any file.')) return; try { await deleteScan.mutateAsync({ scanId: id }); await Promise.all([client.invalidateQueries({ queryKey: getGetScamShieldScansQueryKey() }), client.invalidateQueries({ queryKey: getGetScamShieldDashboardQueryKey() })]); } catch { window.alert('Could not delete this report. Try again.'); } };
  return <>
    <PageHead eyebrow="Saved report archive / 06" title="Scan history" detail="Search and filter saved scan metadata. Deleting a report never changes the original file." />
    <Panel className="mb-4 p-3"><div className="grid gap-2 sm:grid-cols-[1fr_150px_130px]"><label className="flex items-center gap-2 rounded-lg border border-input bg-background px-3"><Search size={14} className="text-muted-foreground" /><input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search names, URLs, or hashes" className="h-9 min-w-0 flex-1 bg-transparent text-[10px] outline-none" data-testid="input-history-search" /></label><select value={verdict} onChange={(e) => setVerdict(e.target.value)} className="h-9 rounded-lg border border-input bg-background px-3 text-[10px]" aria-label="Filter by verdict" data-testid="select-history-verdict"><option value="">All verdicts</option><option value="clean">Clean</option><option value="suspicious">Suspicious</option><option value="malicious">Malicious</option></select><select value={kind} onChange={(e) => setKind(e.target.value)} className="h-9 rounded-lg border border-input bg-background px-3 text-[10px]" aria-label="Filter by type" data-testid="select-history-kind"><option value="">All types</option><option value="file">Files</option><option value="url">URLs</option></select></div></Panel>
    {reports.isError ? <ErrorBox onRetry={() => void reports.refetch()} /> : <Panel className="overflow-hidden"><div className="hidden grid-cols-[minmax(180px,1.5fr)_100px_minmax(160px,1fr)_145px_auto] border-b border-border bg-muted/40 px-5 py-2.5 text-[8px] font-extrabold uppercase tracking-widest text-muted-foreground md:grid"><span>Target</span><span>Verdict</span><span>Indicators</span><span className="text-right">Scanned</span><span /></div>{reports.isLoading ? <LoadingRows /> : reports.data?.length ? reports.data.map((scan) => <ReportRow key={scan.id} scan={scan} onOpen={setDetail} onDelete={remove} />) : <EmptyState icon={History} title="No matching reports" detail="Adjust your search or filters, or inspect a file or URL to create a report." action={<Link href="/scanner" className="text-[11px] font-bold text-primary">Start a scan</Link>} />}</Panel>}
    {deleteScan.isPending && <p className="mt-2 text-[10px] text-muted-foreground">Removing saved report…</p>}
    {detail && <ScanDetail id={detail} onClose={() => setDetail(null)} />}
  </>;
}

function ReportsPage() {
  const reports = useReports();
  const [selected, setSelected] = useState<string[]>([]);
  useEffect(() => { if (reports.data) setSelected((current) => current.filter((id) => reports.data?.some((r) => r.id === id))); }, [reports.data]);
  const items = useMemo(() => (reports.data ?? []).filter((r) => selected.includes(r.id)), [reports.data, selected]);
  const exportText = () => {
    if (!items.length) return;
    const contents = items.map((r) => [`SCAMSHIELD SCAN REPORT`, `Scanned: ${formatDate(r.scannedAt)}`, `Type: ${r.kind}`, `Target: ${r.fileName ?? r.target}`, `Detected file type: ${r.fileType ?? 'Not available'}`, `Verdict: ${r.verdict}`, `Detection source: ${r.detectionSource}`, `Size: ${r.sizeBytes ?? 'Not applicable'}`, `SHA-256: ${r.sha256 ?? 'Not available'}`, `SHA-1: ${r.sha1 ?? 'Not available'}`, `Indicators:`, ...(r.indicators.length ? r.indicators.map((v) => `- ${v}`) : ['- None recorded']), '', `This report is not proof of safety.`].join('\n')).join('\n\n------------------------------\n\n');
    const blob = new Blob([contents], { type: 'text/plain;charset=utf-8' }); const url = URL.createObjectURL(blob); const anchor = document.createElement('a'); anchor.href = url; anchor.download = `scamshield-reports-${new Date().toISOString().slice(0, 10)}.txt`; anchor.click(); URL.revokeObjectURL(url);
  };
  return <>
    <PageHead eyebrow="Portable records / 07" title="Export reports" detail="Download selected saved reports as plain text, or prepare a clean print view you can save as PDF." />
    <div className="mb-4 flex flex-wrap items-center justify-between gap-3"><span className="text-[10px] text-muted-foreground">{selected.length} of {reports.data?.length ?? 0} reports selected</span><div className="flex gap-2"><Button variant="outline" disabled={!items.length} onClick={() => window.print()} testId="button-export-pdf"><FileText size={13} /> Print / save PDF</Button><Button disabled={!items.length} onClick={exportText} testId="button-export-txt"><ArrowDownToLine size={13} /> Download TXT</Button></div></div>
    {reports.isError ? <ErrorBox onRetry={() => void reports.refetch()} /> : <Panel className="overflow-hidden">{reports.isLoading ? <LoadingRows /> : reports.data?.length ? <><div className="flex items-center gap-3 border-b border-border bg-muted/30 px-4 py-3 text-[10px] font-bold"><input type="checkbox" checked={selected.length === reports.data.length && reports.data.length > 0} onChange={(e) => setSelected(e.target.checked ? reports.data?.map((r) => r.id) ?? [] : [])} aria-label="Select all reports" data-testid="checkbox-select-all-reports" />Select all reports</div>{reports.data.map((report) => <label key={report.id} className="flex cursor-pointer items-center gap-3 border-b border-border px-4 py-3.5 last:border-0 hover:bg-muted/30"><input type="checkbox" checked={selected.includes(report.id)} onChange={(e) => setSelected((old) => e.target.checked ? [...old, report.id] : old.filter((x) => x !== report.id))} aria-label={`Select ${report.fileName ?? report.target}`} data-testid={`checkbox-report-${report.id}`} /><span className="grid size-8 shrink-0 place-items-center rounded-lg bg-muted"><FileText size={14} /></span><span className="min-w-0 flex-1"><span className="block truncate text-[10px] font-bold">{report.fileName ?? report.target}</span><span className="mt-1 block text-[9px] text-muted-foreground">{formatDate(report.scannedAt)} · {report.kind}</span></span><Verdict verdict={report.verdict} /></label>)}</> : <EmptyState icon={FileText} title="Nothing to export" detail="Saved reports appear here after you inspect a file or URL." />}</Panel>}
    {!!items.length && <div className="print:block hidden">{items.map((r) => <article key={r.id} className="report-print-page"><div className="mono text-xs">SCAMSHIELD / SCAN REPORT</div><h2>{r.fileName ?? r.target}</h2><p>{formatDate(r.scannedAt)} · {r.kind} · {r.verdict.toUpperCase()}</p><hr /><p>Detection source: {r.detectionSource}</p><p>Detected file type: {r.fileType ?? 'Not available'}</p><p>SHA-256: {r.sha256 ?? 'Not available'}</p><p>SHA-1: {r.sha1 ?? 'Not available'}</p><h3>Indicators</h3>{r.indicators.length ? <ul>{r.indicators.map((x, i) => <li key={i}>{x}</li>)}</ul> : <p>None recorded</p>}<p className="report-disclaimer">A clean result does not guarantee that a file or link is safe.</p></article>)}</div>}
  </>;
}

function SettingsPage() {
  const status = useGetVirusTotalStatus({ query: { queryKey: getGetVirusTotalStatusQueryKey(), refetchOnMount: true } });
  const [saveReports, setSaveReports] = useState(() => localStorage.getItem('scamshield-save-reports') !== 'off');
  const [maxFileMb, setMaxFileMb] = useState(() => getMaxScanMb());
  const [saved, setSaved] = useState(false);
  const save = () => { localStorage.setItem('scamshield-max-scan-mb', String(maxFileMb)); localStorage.setItem('scamshield-save-reports', saveReports ? 'on' : 'off'); setSaved(true); window.setTimeout(() => setSaved(false), 1800); };
  const Toggle = ({ checked, onChange, title, text, testId }: { checked: boolean; onChange: (v: boolean) => void; title: string; text: string; testId: string }) => <label className="flex cursor-pointer items-center justify-between gap-4 border-b border-border py-4 last:border-0"><span><span className="block text-[11px] font-bold">{title}</span><span className="mt-1 block text-[10px] leading-relaxed text-muted-foreground">{text}</span></span><input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} className="size-4 accent-primary" data-testid={testId} /></label>;
  return <>
    <PageHead eyebrow="Preferences / 08" title="Privacy & settings" detail="Your choices affect what is stored in this browser and how external hash reputation checks are used." />
    <div className="grid gap-5 xl:grid-cols-[1.1fr_.9fr]">
      <Panel className="p-5"><SectionTitle title="Scan preferences" caption="Saved on this device" />
        <label className="flex items-center justify-between gap-4 border-b border-border py-4"><span><span className="block text-[11px] font-bold">Maximum file size</span><span className="mt-1 block text-[10px] leading-relaxed text-muted-foreground">Files are hashed in 4 MB chunks to keep memory use bounded.</span></span><select value={maxFileMb} onChange={(e) => setMaxFileMb(Number(e.target.value))} className="rounded-lg border border-input bg-background px-3 py-2 text-[11px]" aria-label="Maximum file size" data-testid="select-max-file-size">{[10, 25, 50, 100, 250, 500, 1024].map((size) => <option key={size} value={size}>{size === 1024 ? '1 GB' : `${size} MB`}</option>)}</select></label>
        <Toggle checked={saveReports} onChange={setSaveReports} title="Save scan reports" text="When off, the app avoids saving report metadata after future inspections." testId="toggle-save-reports" />
        <div className="mt-4 flex justify-end"><Button onClick={save} testId="button-save-settings">{saved ? <><BadgeCheck size={14} /> Saved</> : 'Save preferences'}</Button></div>
      </Panel>
      <div className="space-y-5">
        <Panel className="p-5"><SectionTitle title="VirusTotal connection" caption="Server-side status only; credentials are never shown here." />
          {status.isLoading ? <div className="h-14 animate-pulse rounded-lg bg-muted" /> : status.isError ? <ErrorBox message="Connection status could not be loaded." onRetry={() => void status.refetch()} /> : <div className="flex items-center gap-3 rounded-xl border border-border p-4"><span className={`grid size-9 place-items-center rounded-lg ${status.data?.configured ? 'bg-primary/10 text-primary' : 'bg-muted text-muted-foreground'}`}><Activity size={16} /></span><div><p className="text-[11px] font-extrabold">{status.data?.configured ? 'Connected' : 'Not configured'}</p><p className="mt-1 text-[9px] text-muted-foreground">{status.data?.configured ? 'Hash reputation checks are available in Threat review.' : 'Add VIRUSTOTAL_API_KEY to Replit Secrets for the API server. The key stays server-side.'}</p></div></div>}
          <p className="mt-3 text-[10px] leading-relaxed text-muted-foreground">VirusTotal checks send only a SHA-256 hash. File contents are not uploaded. A missing match is not a safety guarantee.</p>
        </Panel>
        <Panel className="p-5"><SectionTitle title="Data boundaries" /><div className="space-y-3">{[
          ['File bytes', 'Read in 4 MB browser-local chunks for hashing and signature clues.'],
          ['Saved reports', 'Metadata and hashes are sent to the ScamShield report service.'],
          ['URL checks', 'Pasted text is assessed locally; the destination is never visited.'],
          ['Quarantine copies', 'Stored in IndexedDB in this browser profile only.'],
        ].map(([name, text]) => <div key={name} className="flex gap-3 border-b border-border pb-3 last:border-0 last:pb-0"><LockKeyhole size={13} className="mt-0.5 shrink-0 text-primary" /><p className="text-[10px] leading-relaxed"><b>{name}.</b> <span className="text-muted-foreground">{text}</span></p></div>)}</div></Panel>
      </div>
    </div>
  </>;
}

function Router() {
  const [location] = useLocation();
  return <ErrorBoundary resetKey={location}><Shell><Switch>
    <Route path="/" component={Overview} />
    <Route path="/scanner" component={Scanner} />
    <Route path="/urls" component={URLCheck} />
    <Route path="/threats" component={Threats} />
    <Route path="/quarantine" component={Quarantine} />
    <Route path="/history" component={HistoryPage} />
    <Route path="/reports" component={ReportsPage} />
    <Route path="/settings" component={SettingsPage} />
    <Route component={NotFound} />
  </Switch></Shell></ErrorBoundary>;
}

function App() {
  return <div className="dark min-h-screen"><QueryClientProvider client={queryClient}><TooltipProvider><WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, '')}><Router /></WouterRouter><Toaster /></TooltipProvider></QueryClientProvider></div>;
}

export default App;
