/** Demo data for ShearPin frontend — 2 policies, 3 scenarios */

export interface PolicyView {
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
  status: 'live' | 'cooldown' | 'tripped' | 'frozen' | 'ok';
}

export interface SpendRequest {
  id: number;
  policy_id: string;
  amount: string;
  verdict: 'allow' | 'deny';
  reason: string | null;
  near_tx: string | null;
  target_chain_tx: string | null;
  ts: string;
}

export type Scenario = 'S1' | 'S2' | 'S3';

export interface DemoState {
  policies: PolicyView[];
  requests: SpendRequest[];
  sinceId: number;
  isPlaying: boolean;
  currentScenario: Scenario | null;
}

// Format helpers - amounts are in NEAR (not yoctoNEAR) based on API response
export function formatNear(near: string): string {
  const num = parseFloat(near);
  if (num >= 1) return `${num.toFixed(4)} NEAR`;
  if (num >= 0.001) return `${num.toFixed(4)} NEAR`;
  return `${(num * 1000).toFixed(2)} mNEAR`;
}

export function formatNearShort(near: string): string {
  const num = parseFloat(near);
  if (num >= 1) return `${num.toFixed(2)} NEAR`;
  if (num >= 0.01) return `${num.toFixed(3)} NEAR`;
  if (num >= 0.001) return `${(num * 1000).toFixed(1)} mNEAR`;
  return `${(num * 1e6).toFixed(0)} µNEAR`;
}

export function formatNearCompact(near: string): string {
  const num = parseFloat(near);
  if (num >= 1000) return `${(num / 1000).toFixed(1)}k NEAR`;
  if (num >= 1) return `${num.toFixed(2)} NEAR`;
  if (num >= 0.001) return `${(num * 1000).toFixed(1)} mNEAR`;
  return `${(num * 1e6).toFixed(0)} µNEAR`;
}

export function getProgressPercent(spent: string, limit: string): number {
  const spentNum = parseFloat(spent);
  const limitNum = parseFloat(limit);
  if (limitNum === 0) return 0;
  return Math.min(100, Math.floor((spentNum / limitNum) * 100));
}

export function getProgressClass(percent: number): string {
  if (percent >= 100) return 'progress-red';
  if (percent >= 80) return 'progress-amber';
  return 'progress-green';
}

export function getStatusConfig(status: PolicyView['status']) {
  switch (status) {
    case 'live':
    case 'ok':
      return { led: 'led-green led-pulse', badge: 'badge-green', label: 'LIVE' };
    case 'cooldown':
      return { led: 'led-amber', badge: 'badge-amber', label: 'COOLDOWN' };
    case 'tripped':
      return { led: 'led-red', badge: 'badge-red', label: 'TRIPPED' };
    case 'frozen':
      return { led: 'led-blue', badge: 'badge-blue', label: 'FROZEN' };
    default:
      return { led: 'led-gray', badge: 'badge-gray', label: String(status).toUpperCase() };
  }
}

export const NEAR_EXPLORER_TX = 'https://explorer.testnet.near.org/transactions/';

// Initial demo policies - amounts in NEAR (matching API response format)
export const DEMO_POLICIES: PolicyView[] = [
  {
    id: 'sat1',
    owner: 'shearpin-owner-1.testnet',
    agent_label: 'SAT-1 Procurement',
    max_tx: '10',      // 10 NEAR per tx
    daily_limit: '50',  // 50 NEAR daily
    cooldown_blocks: 2,
    rate_limit_per_day: 20,
    spent_today: '0',
    requests_today: 0,
    tripped: 0,
    frozen: 0,
    status: 'ok',
  },
  {
    id: 'nav1',
    owner: 'shearpin-owner-2.testnet',
    agent_label: 'NAV-1 Research',
    max_tx: '5',       // 5 NEAR per tx
    daily_limit: '20',  // 20 NEAR daily
    cooldown_blocks: 5,
    rate_limit_per_day: 15,
    spent_today: '0',
    requests_today: 0,
    tripped: 0,
    frozen: 0,
    status: 'ok',
  },
];

export const DEMO_REQUESTS: SpendRequest[] = [
  { id: 1, policy_id: 'sat1', amount: '5', verdict: 'allow', reason: null, near_tx: 'AbCd123...', target_chain_tx: null, ts: new Date(Date.now() - 300000).toISOString() },
  { id: 2, policy_id: 'sat1', amount: '3', verdict: 'allow', reason: null, near_tx: 'EfGh456...', target_chain_tx: null, ts: new Date(Date.now() - 240000).toISOString() },
  { id: 3, policy_id: 'nav1', amount: '2', verdict: 'allow', reason: null, near_tx: 'IjKl789...', target_chain_tx: null, ts: new Date(Date.now() - 180000).toISOString() },
  { id: 4, policy_id: 'sat1', amount: '4', verdict: 'allow', reason: null, near_tx: 'MnOp012...', target_chain_tx: null, ts: new Date(Date.now() - 120000).toISOString() },
  { id: 5, policy_id: 'sat1', amount: '15', verdict: 'deny', reason: 'SHEARPIN_OVER_TX: pin snapped', near_tx: null, target_chain_tx: null, ts: new Date(Date.now() - 60000).toISOString() },
];

export interface ScenarioStep {
  delayMs: number;
  action: (setState: React.Dispatch<React.SetStateAction<DemoState>>) => void;
}

export function createScenarioRunner(): Record<Scenario, ScenarioStep[]> {
  return {
    S1: [
      { delayMs: 500, action: () => {} }, // Normal state - just show initial
    ],
    S2: [
      { delayMs: 500, action: () => {} },
      {
        delayMs: 1000,
        action: (setState) => {
          setState(prev => {
            const newRequests = [
              ...prev.requests,
              {
                id: prev.requests.length + 1,
                policy_id: 'sat1',
                amount: '15', // Exceeds max_tx (10)
                verdict: 'deny' as const,
                reason: 'SHEARPIN_OVER_TX: pin snapped',
                near_tx: null,
                target_chain_tx: null,
                ts: new Date().toISOString(),
              },
            ];
            
            const newPolicies = prev.policies.map(p => 
              p.id === 'sat1' 
                ? { ...p, tripped: 1, status: 'tripped' as const, spent_today: '12', requests_today: p.requests_today + 1 }
                : p
            );
            
            return { ...prev, policies: newPolicies, requests: newRequests };
          });
        },
      },
    ],
    S3: [
      { delayMs: 500, action: () => {} },
      {
        delayMs: 1000,
        action: (setState) => {
          setState(prev => {
            const newRequests = [
              ...prev.requests,
              {
                id: prev.requests.length + 1,
                policy_id: 'sat1',
                amount: '5',
                verdict: 'allow' as const,
                reason: null,
                near_tx: 'QrSt345...',
                target_chain_tx: null,
                ts: new Date().toISOString(),
              },
            ];
            
            const newPolicies = prev.policies.map(p => 
              p.id === 'sat1' 
                ? { ...p, tripped: 0, frozen: 0, status: 'ok' as const, spent_today: '5', requests_today: 0 }
                : p
            );
            
            return { ...prev, policies: newPolicies, requests: newRequests };
          });
        },
      },
    ],
  };
}

// Initial demo state
export const INITIAL_DEMO_STATE: DemoState = {
  policies: DEMO_POLICIES,
  requests: DEMO_REQUESTS,
  sinceId: DEMO_REQUESTS.length,
  isPlaying: false,
  currentScenario: null,
};