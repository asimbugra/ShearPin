/**
 * Counterparty scanner — the user-facing interface for the AI-security flow.
 * scan an address before paying: verdict + reasons + live off-chain signals,
 * the on-chain report history, and a staked report form.
 */
import { useState, useCallback, useEffect, useRef, useMemo } from 'react';
import {
  Radar, Loader2, ShieldCheck, AlertTriangle, Ban,
  FileWarning, Search, ChevronDown, ChevronUp, ExternalLink,
} from 'lucide-react';

const API_BASE = '/api';

interface Signal {
  name: string;
  value: string;
  risk: boolean;
  reason?: string;
}

interface ReportRow {
  reporter: string;
  category: string;
  evidence: string;
  block_height: number;
}

interface CheckResult {
  address: string;
  policy: string;
  verdict?: 'allow' | 'warn' | 'block';
  reasons: string[];
  signals?: Signal[];
  reports: ReportRow[];
}

interface ScanState {
  phase: 'idle' | 'scanning' | 'done' | 'error';
  result?: CheckResult;
  error?: string;
}

const VERDICT_STYLES = {
  allow: {
    label: 'ALLOW', icon: ShieldCheck,
    text: 'text-[var(--color-green)]', border: 'border-[var(--color-green)]',
    glow: 'shadow-[0_0_40px_-8px_var(--color-green-glow)]',
    bg: 'bg-[var(--color-green)]/5',
  },
  warn: {
    label: 'WARN', icon: AlertTriangle,
    text: 'text-[var(--color-amber)]', border: 'border-[var(--color-amber)]',
    glow: 'shadow-[0_0_40px_-8px_var(--color-amber-glow)]',
    bg: 'bg-[var(--color-amber)]/5',
  },
  block: {
    label: 'BLOCK', icon: Ban,
    text: 'text-[var(--color-red)]', border: 'border-[var(--color-red)]',
    glow: 'shadow-[0_0_40px_-8px_var(--color-red-glow)]',
    bg: 'bg-[var(--color-red)]/5',
  },
} as const;

const SIGNAL_LABELS: Record<string, string> = {
  'account-age': 'ACCOUNT AGE / ACTIVITY',
  'contract': 'CONTRACT / CODE',
  'prior-interactions': 'PRIOR INTERACTIONS',
};

const CATEGORIES = ['drainer', 'phishing', 'fake_vendor', 'impersonation', 'other'];

function Scanline() {
  return (
    <div className="relative overflow-hidden h-1 my-2" aria-hidden="true">
      <div className="absolute inset-0 bg-[var(--color-panel)] rounded-full" />
      <div className="scanline-beam absolute top-0 h-full w-1/4 rounded-full bg-[var(--color-blue-glow)] opacity-80" />
    </div>
  );
}

function VerdictLamp({ verdict }: { verdict: 'allow' | 'warn' | 'block' }) {
  const cfg = VERDICT_STYLES[verdict];
  const Icon = cfg.icon;
  return (
    <div
      className={`flex items-center justify-between gap-4 rounded-lg border-2 ${cfg.border} ${cfg.bg} ${cfg.glow} px-5 py-4 scan-reveal`}
      role="status"
      aria-label={`Verdict: ${cfg.label}`}
    >
      <div className="flex items-center gap-3">
        <Icon className={`w-8 h-8 ${cfg.text}`} aria-hidden="true" />
        <span className={`mono text-3xl font-bold tracking-widest ${cfg.text}`}>{cfg.label}</span>
      </div>
      <span className={`led ${verdict === 'allow' ? 'led-green led-pulse' : verdict === 'warn' ? 'led-amber led-pulse' : 'led-red led-pulse'}`} aria-hidden="true" />
    </div>
  );
}

function SignalRow({ signal }: { signal: Signal }) {
  const [open, setOpen] = useState(false);
  const hasReason = Boolean(signal.reason);
  return (
    <div className="panel-elevated px-3 py-2">
      <button
        className="w-full flex items-center gap-3 text-left"
        onClick={() => hasReason && setOpen((o) => !o)}
        aria-expanded={open}
      >
        <span className={`badge ${signal.risk ? 'badge-red' : 'badge-gray'} flex-shrink-0`}>
          {signal.risk ? 'RISK' : 'OK'}
        </span>
        <span className="mono text-xs text-[var(--color-text-secondary)] uppercase tracking-wide flex-shrink-0 w-44">
          {SIGNAL_LABELS[signal.name] ?? signal.name}
        </span>
        <span className="mono text-xs text-[var(--color-text-primary)] truncate flex-1">
          {signal.value}
        </span>
        {hasReason && (open ? <ChevronUp className="w-4 h-4 text-[var(--color-text-muted)]" /> : <ChevronDown className="w-4 h-4 text-[var(--color-text-muted)]" />)}
      </button>
      {open && hasReason && (
        <p className="mono text-xs text-[var(--color-text-secondary)] mt-2 pl-[4.7rem] break-words">{signal.reason}</p>
      )}
    </div>
  );
}

export default function CounterpartyScanner({ policies }: { policies: string[] }) {
  const [address, setAddress] = useState('');
  const [policy, setPolicy] = useState(policies[0] ?? 'sat1');
  const [scan, setScan] = useState<ScanState>({ phase: 'idle' });
  const [showReportForm, setShowReportForm] = useState(false);
  const [reportCategory, setReportCategory] = useState(CATEGORIES[0]);
  const [reportEvidence, setReportEvidence] = useState('');
  const [reportState, setReportState] = useState<'idle' | 'sending' | 'sent' | 'error'>('idle');
  const [reportError, setReportError] = useState('');
  const resultsRef = useRef<HTMLDivElement>(null);

  const validAddress = useMemo(() => /^0x[0-9a-fA-F]{40}$/.test(address.trim()), [address]);

  const runScan = useCallback(async (mode: 'check' | 'enrich') => {
    const addr = address.trim();
    if (!/^0x[0-9a-fA-F]{40}$/.test(addr)) return;
    setScan({ phase: 'scanning' });
    try {
      const res = await fetch(`${API_BASE}/counterparty/${mode}?address=${encodeURIComponent(addr)}&policy=${encodeURIComponent(policy)}`);
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
      setScan({ phase: 'done', result: body as CheckResult });
    } catch (e) {
      setScan({ phase: 'error', error: String(e).slice(0, 200) });
    }
  }, [address, policy]);

  const submitReport = useCallback(async () => {
    if (!validAddress || !reportEvidence.trim()) return;
    setReportState('sending');
    setReportError('');
    try {
      const res = await fetch(`${API_BASE}/counterparty/report`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ address: address.trim(), category: reportCategory, evidence: reportEvidence.trim() }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
      setReportState('sent');
      setReportEvidence('');
      // refresh the on-chain report list after the tx lands
      setTimeout(() => void runScan(scan.result?.signals ? 'enrich' : 'check'), 2500);
    } catch (e) {
      setReportState('error');
      setReportError(String(e).slice(0, 200));
    }
  }, [address, validAddress, reportCategory, reportEvidence, runScan, scan.result?.signals]);

  // scroll verdict into view when a scan completes
  useEffect(() => {
    if (scan.phase === 'done') resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }, [scan.phase]);

  const result = scan.result;
  const verdict = result?.verdict;

  return (
    <section className="panel p-4" aria-label="Counterparty scanner">
      <header className="flex items-center justify-between mb-4">
        <h2 className="flex items-center gap-2 font-semibold">
          <Radar className="w-5 h-5 text-[var(--color-blue)]" aria-hidden="true" />
          COUNTERPARTY SCANNER
        </h2>
        <span className="mono text-xs text-[var(--color-text-muted)]">blocklist + signals — ask before you pay</span>
      </header>

      {/* scan input */}
      <div className="flex flex-col sm:flex-row gap-2 mb-1">
        <input
          className="mono input flex-1 min-w-0"
          placeholder="0x — recipient address to vet"
          value={address}
          onChange={(e) => setAddress(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter' && validAddress) void runScan('enrich'); }}
          spellCheck={false}
          aria-label="Recipient address"
        />
        {policies.length > 1 ? (
          <select
            className="mono input sm:w-32"
            value={policy}
            onChange={(e) => setPolicy(e.target.value)}
            aria-label="Policy"
          >
            {policies.map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
        ) : (
          <span className="badge badge-gray mono sm:self-center">policy: {policy}</span>
        )}
        <button
          className="btn btn-primary sm:w-28"
          onClick={() => void runScan('enrich')}
          disabled={!validAddress || scan.phase === 'scanning'}
          aria-label="Scan address"
        >
          {scan.phase === 'scanning'
            ? <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" />
            : <Search className="w-4 h-4" aria-hidden="true" />}
          SCAN
        </button>
      </div>
      <p className="mono text-[11px] text-[var(--color-text-muted)] mb-2">
        blocklist verdict on-chain · signals live from an Etherscan-compatible API · block ≥2 evidence-backed reports
      </p>
      {scan.phase === 'scanning' && <Scanline />}
      {scan.phase === 'error' && (
        <p className="mono text-xs text-[var(--color-red)] panel-elevated p-3 mt-2" role="alert">{scan.error}</p>
      )}

      {/* results */}
      {scan.phase === 'done' && result && (
        <div ref={resultsRef} className="mt-3 space-y-3">
          {verdict && <VerdictLamp verdict={verdict} />}

          {result.reasons?.length > 0 && (
            <ul className="space-y-1" aria-label="Reasons">
              {result.reasons.map((r, i) => (
                <li key={i} className="mono text-xs text-[var(--color-text-secondary)] panel-elevated px-3 py-2 break-words">
                  {r}
                </li>
              ))}
            </ul>
          )}

          {result.signals && result.signals.length > 0 && (
            <div className="space-y-2" aria-label="Off-chain signals">
              <p className="mono text-[11px] uppercase tracking-wide text-[var(--color-text-muted)]">off-chain signals</p>
              {result.signals.map((s) => <SignalRow key={s.name} signal={s} />)}
            </div>
          )}

          {/* on-chain reports */}
          <div className="space-y-2" aria-label="On-chain reports">
            <p className="mono text-[11px] uppercase tracking-wide text-[var(--color-text-muted)]">
              on-chain reports ({result.reports?.length ?? 0})
            </p>
            {(result.reports ?? []).length === 0 ? (
              <p className="mono text-xs text-[var(--color-text-muted)] panel-elevated p-3">no reports on the shared blocklist</p>
            ) : (
              result.reports!.map((rep, i) => (
                <div key={i} className="panel-elevated px-3 py-2 flex items-start gap-2 flex-wrap">
                  <FileWarning className="w-4 h-4 text-[var(--color-amber)] mt-0.5 flex-shrink-0" aria-hidden="true" />
                  <span className="badge badge-red mono text-[11px]">{rep.category}</span>
                  <span className="mono text-xs text-[var(--color-text-secondary)] break-all flex-1">{rep.evidence}</span>
                  <span className="mono text-[11px] text-[var(--color-text-muted)] w-full sm:w-auto">{rep.reporter}</span>
                </div>
              ))
            )}
          </div>

          {/* report form */}
          <div className="panel-elevated p-3">
            <button
              className="btn btn-sm btn-warning"
              onClick={() => setShowReportForm((s) => !s)}
              aria-expanded={showReportForm}
            >
              <FileWarning className="w-4 h-4" aria-hidden="true" />
              REPORT THIS ADDRESS
            </button>
            {showReportForm && (
              <div className="mt-3 space-y-2">
                <p className="mono text-[11px] text-[var(--color-amber)]">
                  reporting attaches a 0.01 NEAR anti-Sybil stake (kept, no refunds) — signed by the backend owner key
                </p>
                <div className="flex flex-col sm:flex-row gap-2">
                  <select
                    className="mono input sm:w-44"
                    value={reportCategory}
                    onChange={(e) => setReportCategory(e.target.value)}
                    aria-label="Report category"
                  >
                    {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
                  </select>
                  <input
                    className="mono input flex-1 min-w-0"
                    placeholder="evidence — URL or tx hash (required)"
                    value={reportEvidence}
                    onChange={(e) => setReportEvidence(e.target.value)}
                    spellCheck={false}
                    aria-label="Evidence"
                  />
                  <button
                    className="btn btn-sm btn-danger sm:w-24"
                    onClick={() => void submitReport()}
                    disabled={reportState === 'sending' || !reportEvidence.trim()}
                  >
                    {reportState === 'sending' ? <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" /> : null}
                    SUBMIT
                  </button>
                </div>
                {reportState === 'sent' && (
                  <p className="mono text-xs text-[var(--color-green)]">✓ report submitted to the shared blocklist</p>
                )}
                {reportState === 'error' && (
                  <p className="mono text-xs text-[var(--color-red)]" role="alert">{reportError}</p>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      <footer className="mono text-[11px] text-[var(--color-text-muted)] mt-3 flex items-center gap-1">
        <ExternalLink className="w-3 h-3" aria-hidden="true" />
        verdict source: check_counterparty view call — free, no signature, no tx
      </footer>
    </section>
  );
}
