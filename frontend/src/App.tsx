import { useState, useEffect, useCallback, useRef } from 'react';
import { 
  Zap, Shield, Loader2, 
  Pause, Play, 
  AlertTriangle, CheckCircle, XCircle, Info,
  Github, Link2
} from 'lucide-react';
import {
  PolicyView, SpendRequest, DemoState, INITIAL_DEMO_STATE,
  createScenarioRunner, formatNearShort, getProgressPercent,
  getProgressClass, getStatusConfig, NEAR_EXPLORER_TX,
  Scenario
} from './demo';

const API_BASE = '/api';

interface BackendPolicy {
  id: string;
  owner: string;
  agent_label: string;
  max_tx: string;
  daily_limit: string;
  cooldown_blocks: number;
  rate_limit_per_day: number;
  spent_today: string;
  requests_today: number;
  tripped: number;
  frozen: number;
  status: string;
}

interface BackendRequest {
  id: number;
  policy_id: string;
  amount: string;
  verdict: 'allow' | 'deny';
  reason: string | null;
  near_tx: string | null;
  target_chain_tx: string | null;
  ts: string;
}

function backendToPolicy(p: BackendPolicy): PolicyView {
  // Map backend status "ok" -> "live" for UI
  let status: PolicyView['status'] = p.status as PolicyView['status'];
  if (status === 'ok') status = 'live';
  
  return {
    id: p.id,
    owner: p.owner,
    agent_label: p.agent_label,
    max_tx: p.max_tx,
    daily_limit: p.daily_limit,
    cooldown_blocks: p.cooldown_blocks,
    rate_limit_per_day: p.rate_limit_per_day,
    spent_today: p.spent_today,
    requests_today: p.requests_today,
    tripped: p.tripped,
    frozen: p.frozen,
    status,
  };
}

function backendToRequest(r: BackendRequest): SpendRequest {
  return {
    id: r.id,
    policy_id: r.policy_id,
    amount: r.amount,
    verdict: r.verdict,
    reason: r.reason,
    near_tx: r.near_tx,
    target_chain_tx: r.target_chain_tx,
    ts: r.ts,
  };
}

// --- Components ---

function ShearPinLogo({ className = '' }: { className?: string }) {
  return (
    <svg 
      width="32" height="32" viewBox="0 0 32 32" fill="none" 
      className={className}
      aria-hidden="true"
    >
      <rect x="14" y="4" width="4" height="24" rx="2" fill="currentColor" opacity="0.3" />
      {/* Shear pin break point */}
      <circle cx="16" cy="16" r="3" fill="currentColor" />
      <path d="M16 13V10M16 19V22" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      {/* Broken pieces */}
      <path d="M11 16 L13 14 M11 16 L13 18" stroke="currentColor" strokeWidth="2" strokeLinecap="round" opacity="0.6" />
      <path d="M21 16 L19 14 M21 16 L19 18" stroke="currentColor" strokeWidth="2" strokeLinecap="round" opacity="0.6" />
    </svg>
  );
}

function StatusLED({ status }: { status: 'connecting' | 'online' | 'offline' | 'demo' }) {
  const configs = {
    online: { class: 'led-green led-pulse', label: 'CANLI' },
    connecting: { class: 'led-amber led-pulse', label: 'CONNECTING...' },
    offline: { class: 'led-red', label: 'OFFLINE' },
    demo: { class: 'led-amber led-pulse', label: 'DEMO MODU' },
  };
  const config = configs[status];
  return (
    <span className="flex items-center gap-2" aria-label={`Backend durumu: ${config.label}`}>
      <span className={`led ${config.class}`} aria-hidden="true" />
      <span className="mono text-xs uppercase tracking-wide">{config.label}</span>
    </span>
  );
}

function PolicyCard({ 
  policy, 
  onFreeze, 
  onUnfreeze, 
  onReset, 
  isDemo,
  loadingAction 
}: { 
  policy: PolicyView;
  onFreeze: (id: string) => void;
  onUnfreeze: (id: string) => void;
  onReset: (id: string) => void;
  isDemo: boolean;
  loadingAction: string | null;
}) {
  const progress = getProgressPercent(policy.spent_today, policy.daily_limit);
  const progressClass = getProgressClass(progress);
  const statusConfig = getStatusConfig(policy.status);
  const ratePercent = policy.rate_limit_per_day > 0 
    ? Math.min(100, Math.floor((policy.requests_today * 100) / policy.rate_limit_per_day))
    : 0;

  const isLoading = loadingAction === policy.id;

  return (
    <article className={`panel p-4 ${policy.status === 'tripped' ? 'shake border-red-500/50' : ''}`} data-policy-id={policy.id}>
      <div className="flex items-start justify-between gap-4 mb-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 mb-2">
            <span className={`led ${statusConfig.led}`} aria-hidden="true" />
            <h3 className="text-lg font-semibold truncate">{policy.agent_label}</h3>
            <span className={`badge ${statusConfig.badge} ml-auto flex-shrink-0`}>{statusConfig.label}</span>
          </div>
          <p className="mono text-xs text-[var(--color-text-muted)] truncate">{policy.owner}</p>
        </div>
      </div>

      {/* Limits */}
      <div className="space-y-3 mb-4">
        <div>
          <div className="flex justify-between text-xs mb-1">
            <span className="text-[var(--color-text-secondary)]">Daily Limit</span>
            <span className="mono text-[var(--color-text-primary)]">
              {formatNearShort(policy.spent_today)} / {formatNearShort(policy.daily_limit)} ({progress}%)
            </span>
          </div>
          <div className="progress-bar" role="progressbar" aria-valuenow={progress} aria-valuemin={0} aria-valuemax={100} aria-label={`Daily limit usage ${progress}%`}>
            <div className={`progress-fill ${progressClass}`} style={{ width: `${progress}%` }} />
          </div>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div className="panel-elevated p-3">
            <p className="text-xs text-[var(--color-text-muted)] uppercase tracking-wide">Per-Tx Cap</p>
            <p className="mono text-base font-medium">{formatNearShort(policy.max_tx)}</p>
          </div>
          <div className="panel-elevated p-3">
            <p className="text-xs text-[var(--color-text-muted)] uppercase tracking-wide">Rate Usage</p>
            <p className="mono text-base font-medium">{policy.requests_today} / {policy.rate_limit_per_day} ({ratePercent}%)</p>
          </div>
        </div>
      </div>

      {/* Actions */}
      <div className="flex items-center gap-2 flex-wrap">
        <button
          className={`btn btn-sm ${policy.frozen ? 'btn-primary' : 'btn-danger'}`}
          onClick={() => policy.frozen ? onUnfreeze(policy.id) : onFreeze(policy.id)}
          disabled={isLoading || isDemo}
          aria-label={policy.frozen ? `Unfreeze ${policy.agent_label}` : `Freeze ${policy.agent_label}`}
        >
          {isLoading && <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" />}
          {policy.frozen ? 'UNFREEZE' : 'FREEZE'}
        </button>
        <button
          className="btn btn-sm btn-warning"
          onClick={() => onReset(policy.id)}
          disabled={isLoading || isDemo}
          aria-label={`Reset pin for ${policy.agent_label}`}
        >
          {isLoading && <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" />}
          RESET PIN
        </button>
        {isDemo && (
          <span className="ml-auto badge badge-gray">DEMO</span>
        )}
      </div>
    </article>
  );
}

function LiveFeed({ requests, isDemo }: { requests: SpendRequest[]; isDemo: boolean }) {
  return (
    <section className="panel h-full flex flex-col" aria-label="Live transaction feed">
      <header className="flex items-center justify-between p-4 border-b border-[var(--color-border)]">
        <h2 className="flex items-center gap-2 font-semibold">
          <Zap className="w-5 h-5 text-[var(--color-amber)]" aria-hidden="true" />
          LIVE FEED
        </h2>
        {isDemo && <span className="demo-badge mono text-xs">DEMO DATA</span>}
      </header>
      <div className="flex-1 overflow-y-auto scrollbar-thin p-4 space-y-2" role="log" aria-live="polite" aria-label="Transaction history">
        {requests.length === 0 ? (
          <p className="text-[var(--color-text-muted)] text-center py-8 mono text-sm">No transactions yet — waiting...</p>
        ) : (
          requests
            .slice()
            .reverse()
            .map((req, idx) => {
              const isAllow = req.verdict === 'allow';
              const policyShort = req.policy_id.slice(0, 8);
              return (
                <div 
                  key={req.id} 
                  className={`flex items-start gap-3 p-3 panel-elevated slide-in ${isAllow ? 'border-l-4 border-[var(--color-green)]' : 'border-l-4 border-[var(--color-red)]'}`}
                  style={{ animationDelay: `${idx * 30}ms` }}
                >
                  <div className="flex-shrink-0 w-6 h-6 flex items-center justify-center">
                    {isAllow ? (
                      <CheckCircle className="w-5 h-5 text-[var(--color-green)]" aria-hidden="true" />
                    ) : (
                      <XCircle className="w-5 h-5 text-[var(--color-red)]" aria-hidden="true" />
                    )}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap text-xs">
                      <span className={`mono font-medium ${isAllow ? 'text-[var(--color-green)]' : 'text-[var(--color-red)]'}`}>
                        {isAllow ? '✓ ALLOW' : '✗ DENY'}
                      </span>
                      <span className="text-[var(--color-text-muted)] mono">{formatNearShort(req.amount)}</span>
                      <span className="text-[var(--color-text-muted)]">{policyShort}</span>
                      <time className="text-[var(--color-text-muted)]" dateTime={req.ts}>
                        {new Date(req.ts).toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </time>
                    </div>
                    {req.reason && (
                      <p className="mt-1 mono text-xs text-[var(--color-red)] break-all">{req.reason}</p>
                    )}
                    {req.near_tx && (
                      <a 
                        href={`${NEAR_EXPLORER_TX}${req.near_tx}`} 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="tx-link mono text-xs inline-flex items-center gap-1 mt-1"
                      >
                        <Link2 className="w-3 h-3" aria-hidden="true" />
                        {req.near_tx.slice(0, 16)}...
                      </a>
                    )}
                  </div>
                </div>
              );
            })
        )}
      </div>
    </section>
  );
}

function DemoControls({ 
  isDemo, 
  isPlaying, 
  currentScenario,
  onPlayScenario,
  onStopScenario,
  onSingleStep
}: {
  isDemo: boolean;
  isPlaying: boolean;
  currentScenario: Scenario | null;
  onPlayScenario: (scenario: Scenario) => void;
  onStopScenario: () => void;
  onSingleStep: (scenario: Scenario) => void;
}) {
  if (!isDemo) return null;

  const scenarios: { id: Scenario; label: string; description: string }[] = [
    { id: 'S1', label: 'S1: Normal', description: 'SAT-1 in-policy spend, green flow' },
    { id: 'S2', label: 'S2: Overflow', description: 'Over-limit → pin SNAPS (red LED + shake)' },
    { id: 'S3', label: 'S3: Reset', description: 'Owner resets → card turns green, agent spends again' },
  ];

  return (
    <section className="panel p-4" aria-label="Demo kontrolleri">
      <header className="flex items-center justify-between mb-4">
        <h2 className="flex items-center gap-2 font-semibold">
          <Play className="w-5 h-5" aria-hidden="true" />
          DEMO SENARYOLARI
        </h2>
        <span className="demo-badge mono text-xs">DEMO MODU</span>
      </header>
      
      <div className="space-y-3">
        {scenarios.map(s => (
          <div key={s.id} className="panel-elevated p-3">
            <div className="flex items-start justify-between gap-3 mb-2">
              <div>
                <p className="font-medium mono text-sm">{s.label}</p>
                <p className="text-xs text-[var(--color-text-muted)]">{s.description}</p>
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                <button
                  className="btn btn-sm btn-primary"
                  onClick={() => onSingleStep(s.id)}
                  disabled={isPlaying}
                  aria-label={`${s.label} run single step`}
                >
                  <Play className="w-3 h-3" aria-hidden="true" /> RUN
                </button>
              </div>
            </div>
          </div>
        ))}
        
        <div className="pt-2 border-t border-[var(--color-border)]">
          <button
            className="btn btn-primary w-full"
            onClick={() => onPlayScenario('S1')}
            disabled={isPlaying}
          >
            {isPlaying ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" />
                RUNNING: {currentScenario}...
              </>
            ) : (
              <>
                <Play className="w-4 h-4" aria-hidden="true" />
                PLAY ALL SCENARIOS IN ORDER (S1 → S2 → S3)
              </>
            )}
          </button>
          {isPlaying && (
            <button
              className="btn btn-danger w-full mt-2"
              onClick={onStopScenario}
            >
              <Pause className="w-4 h-4" aria-hidden="true" />
              DURDUR
            </button>
          )}
        </div>
      </div>
    </section>
  );
}

function Header({ 
  backendStatus, 
  isDemo 
}: { 
  backendStatus: 'connecting' | 'online' | 'offline' | 'demo';
  isDemo: boolean;
}) {
  return (
    <header className="panel p-4 mb-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-4">
          <div className="p-2 bg-[var(--color-bg)] rounded-lg border border-[var(--color-border)]">
            <ShearPinLogo className="text-[var(--color-amber)]" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight">ShearPin</h1>
            <p className="text-sm text-[var(--color-text-secondary)]">A circuit breaker for every agent wallet</p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <StatusLED status={backendStatus} />
          {isDemo && (
            <span className="demo-badge mono text-sm px-3 py-1 rounded border border-[var(--color-amber)]">
              DEMO MODU
            </span>
          )}
        </div>
      </div>
    </header>
  );
}

function Footer() {
  return (
    <footer className="mt-8 pt-6 border-t border-[var(--color-border)]">
      <div className="flex items-center justify-between flex-wrap gap-4 text-sm text-[var(--color-text-muted)]">
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1">
            <Info className="w-4 h-4" aria-hidden="true" />
            NEAR Chain Signatures + Testnet
          </span>
        </div>
        <div className="flex items-center gap-4">
          <a href="https://github.com" target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 hover:text-[var(--color-text-primary)] transition-colors">
            <Github className="w-4 h-4" aria-hidden="true" />
            <span className="mono">Repo</span>
          </a>
        </div>
      </div>
    </footer>
  );
}

// --- Main App ---

export default function App() {
  const [policies, setPolicies] = useState<PolicyView[]>([]);
  const [requests, setRequests] = useState<SpendRequest[]>([]);
  const [backendStatus, setBackendStatus] = useState<'connecting' | 'online' | 'offline' | 'demo'>('connecting');
  const [isDemo, setIsDemo] = useState(false);
  const [loadingAction, setLoadingAction] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  
  // Demo state
  const [demoState, setDemoState] = useState<DemoState>(INITIAL_DEMO_STATE);
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentScenario, setCurrentScenario] = useState<Scenario | null>(null);
  const scenarioTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const scenarioQueueRef = useRef<{ scenario: Scenario; stepIndex: number }[]>([]);

  // Poll interval refs
  const pollIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const healthCheckIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // --- Backend API calls ---
  const fetchPolicies = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/policies`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: BackendPolicy[] = await res.json();
      setPolicies(data.map(backendToPolicy));
      setError(null);
    } catch (e) {
      console.error('[fetchPolicies]', e);
      throw e;
    }
  }, []);

  const fetchRequests = useCallback(async (sinceId: number) => {
    try {
      const res = await fetch(`${API_BASE}/requests?since=${sinceId}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: BackendRequest[] = await res.json();
      if (data.length > 0) {
        setRequests(prev => {
          const newReqs = data.map(backendToRequest);
          const combined = [...prev, ...newReqs].slice(-500);
          return combined;
        });
      }
    } catch (e) {
      console.error('[fetchRequests]', e);
    }
  }, []);

  const postAction = useCallback(async (endpoint: string, policyId: string) => {
    setLoadingAction(policyId);
    try {
      const res = await fetch(`${API_BASE}${endpoint}`, { method: 'POST' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      await fetchPolicies();
    } catch (e) {
      console.error(`[postAction ${endpoint}]`, e);
      setError(`Action failed: ${e instanceof Error ? e.message : 'Unknown error'}`);
    } finally {
      setLoadingAction(null);
    }
  }, [fetchPolicies]);

  const freezePolicy = useCallback((id: string) => postAction(`/policies/${id}/freeze`, id), [postAction]);
  const unfreezePolicy = useCallback((id: string) => postAction(`/policies/${id}/unfreeze`, id), [postAction]);
  const resetPolicy = useCallback((id: string) => postAction(`/policies/${id}/reset`, id), [postAction]);

  // --- Health check ---
  const checkBackendHealth = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(3000) });
      if (res.ok) {
        const data = await res.json();
        if (data.ok && data.contract) {
          setBackendStatus('online');
          setIsDemo(false);
          return true;
        }
      }
    } catch {}
    return false;
  }, []);

  // --- Polling ---
  const startPolling = useCallback(() => {
    if (pollIntervalRef.current) return;
    let sinceId = requests.length > 0 ? Math.max(...requests.map(r => r.id)) : 0;
    
    const poll = async () => {
      await fetchRequests(sinceId);
      sinceId = requests.length > 0 ? Math.max(...requests.map(r => r.id)) : sinceId;
    };
    
    pollIntervalRef.current = setInterval(poll, 2000);
    poll(); // Initial
  }, [fetchRequests, requests.length]);

  const stopPolling = useCallback(() => {
    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current);
      pollIntervalRef.current = null;
    }
  }, []);

  const startHealthCheck = useCallback(() => {
    if (healthCheckIntervalRef.current) return;
    const check = async () => {
      const healthy = await checkBackendHealth();
      if (healthy) {
        stopHealthCheck();
        startPolling();
        // If we were in demo mode, switch to live data
        if (isDemo) {
          setIsDemo(false);
          await fetchPolicies();
          // Reset requests to live data
          const res = await fetch(`${API_BASE}/requests?since=0`);
          if (res.ok) {
            const data: BackendRequest[] = await res.json();
            setRequests(data.map(backendToRequest));
          }
        }
      }
    };
    healthCheckIntervalRef.current = setInterval(check, 5000);
    check(); // Initial
  }, [checkBackendHealth, isDemo, fetchPolicies, startPolling]);

  const stopHealthCheck = useCallback(() => {
    if (healthCheckIntervalRef.current) {
      clearInterval(healthCheckIntervalRef.current);
      healthCheckIntervalRef.current = null;
    }
  }, []);

  // --- Initialization ---
  useEffect(() => {
    const init = async () => {
      setBackendStatus('connecting');
      const healthy = await checkBackendHealth();
      if (healthy) {
        setBackendStatus('online');
        setIsDemo(false);
        await fetchPolicies();
        const res = await fetch(`${API_BASE}/requests?since=0`);
        if (res.ok) {
          const data: BackendRequest[] = await res.json();
          setRequests(data.map(backendToRequest));
        }
        startPolling();
      } else {
        setBackendStatus('demo');
        setIsDemo(true);
        // Load demo data
        setPolicies(INITIAL_DEMO_STATE.policies);
        setRequests(INITIAL_DEMO_STATE.requests);
        setDemoState(INITIAL_DEMO_STATE);
        startHealthCheck(); // Keep checking for backend
      }
    };
    init();
    return () => {
      stopPolling();
      stopHealthCheck();
      if (scenarioTimeoutRef.current) clearTimeout(scenarioTimeoutRef.current);
    };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // --- Demo scenario runner ---
  const scenarioRunner = createScenarioRunner();

  const runScenarioStep = useCallback((scenario: Scenario, stepIndex: number) => {
    const steps = scenarioRunner[scenario];
    if (stepIndex >= steps.length) {
      // Scenario complete
      if (scenarioQueueRef.current.length > 0) {
        const next = scenarioQueueRef.current.shift()!;
        setCurrentScenario(next.scenario);
        runScenarioStep(next.scenario, 0);
      } else {
        setIsPlaying(false);
        setCurrentScenario(null);
      }
      return;
    }

    const step = steps[stepIndex];
    step.action(setDemoState);
    
    scenarioTimeoutRef.current = setTimeout(() => {
      runScenarioStep(scenario, stepIndex + 1);
    }, step.delayMs);
  }, [scenarioRunner]);

  const playScenario = useCallback((scenario: Scenario) => {
    if (isPlaying) return;
    
    if (scenario === 'S1') {
      // Play all scenarios in sequence
      setIsPlaying(true);
      scenarioQueueRef.current = [
        { scenario: 'S2', stepIndex: 0 },
        { scenario: 'S3', stepIndex: 0 },
      ];
      setCurrentScenario('S1');
      runScenarioStep('S1', 0);
    } else {
      // Play single scenario
      setIsPlaying(true);
      setCurrentScenario(scenario);
      scenarioQueueRef.current = [];
      runScenarioStep(scenario, 0);
    }
  }, [isPlaying, runScenarioStep]);

  const stopScenario = useCallback(() => {
    if (scenarioTimeoutRef.current) {
      clearTimeout(scenarioTimeoutRef.current);
      scenarioTimeoutRef.current = null;
    }
    scenarioQueueRef.current = [];
    setIsPlaying(false);
    setCurrentScenario(null);
  }, []);

  const singleStep = useCallback((scenario: Scenario) => {
    if (isPlaying) return;
    const steps = scenarioRunner[scenario];
    if (steps.length > 0) {
      steps[0].action(setDemoState);
    }
  }, [isPlaying, scenarioRunner]);

  // Sync demo state to UI
  useEffect(() => {
    if (isDemo) {
      setPolicies(demoState.policies);
      setRequests(demoState.requests);
    }
  }, [isDemo, demoState.policies, demoState.requests]);

  // --- Render ---
  const displayPolicies = isDemo ? demoState.policies : policies;
  const displayRequests = isDemo ? demoState.requests : requests;

  return (
    <div className="min-h-screen bg-[var(--color-bg)] text-[var(--color-text-primary)]">
      <main className="max-w-6xl mx-auto px-4 py-6">
        <Header backendStatus={backendStatus} isDemo={isDemo} />
        
        {error && (
          <div className="panel border-[var(--color-red)] p-4 mb-6 flex items-center justify-between" role="alert">
            <AlertTriangle className="w-5 h-5 text-[var(--color-red)] flex-shrink-0" aria-hidden="true" />
            <span className="text-sm text-[var(--color-red)] mono">{error}</span>
            <button onClick={() => setError(null)} className="text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]" aria-label="Kapat">
              ×
            </button>
          </div>
        )}

        <div className="grid lg:grid-cols-12 gap-6">
          {/* Policy Cards */}
          <section className="lg:col-span-7 space-y-4" aria-label="Policy cards">
            {displayPolicies.length === 0 ? (
              <div className="panel p-8 text-center">
                <Shield className="w-12 h-12 mx-auto mb-4 text-[var(--color-text-muted)]" aria-hidden="true" />
                <p className="text-[var(--color-text-secondary)]">No policies yet</p>
                {isDemo && <p className="text-xs text-[var(--color-text-muted)] mt-1">Loading seed data in demo mode...</p>}
              </div>
            ) : (
              displayPolicies.map(policy => (
                <PolicyCard
                  key={policy.id}
                  policy={policy}
                  onFreeze={freezePolicy}
                  onUnfreeze={unfreezePolicy}
                  onReset={resetPolicy}
                  isDemo={isDemo}
                  loadingAction={loadingAction}
                />
              ))
            )}
          </section>

          {/* Right Column: Live Feed + Demo Controls */}
          <aside className="lg:col-span-5 space-y-4" aria-label="Yan panel">
            <LiveFeed requests={displayRequests} isDemo={isDemo} />
            <DemoControls
              isDemo={isDemo}
              isPlaying={isPlaying}
              currentScenario={currentScenario}
              onPlayScenario={playScenario}
              onStopScenario={stopScenario}
              onSingleStep={singleStep}
            />
          </aside>
        </div>

        <Footer />
      </main>
    </div>
  );
}