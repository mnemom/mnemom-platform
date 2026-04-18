interface Env {
  STATUSPAGE_API_KEY: string;
  SUPABASE_URL: string;
  SUPABASE_SECRET_KEY: string;
  MONITOR_SECRET: string;
  // CF AI Gateway monitoring (Step 42)
  CLOUDFLARE_API_TOKEN?: string;
  CLOUDFLARE_ACCOUNT_ID?: string;
  AI_GATEWAY_ID?: string;
  AI_GATEWAY_LOG_LIMIT?: string; // default: 100000
}

const PAGE_ID = '2vbfqw4638pl';

// Statuspage component IDs
const COMPONENTS = {
  api: 'nfr1q6w6bqrk',
  gateway: '9l6r013yjnv6',
  website: 'qvh22g24gb9f',
  database: 'fghczssw9ld0',
  observer: 'fmzk98pybm5y',
  ai_gateway: 'ryd50fzp7cmz',
  anthropic: '8pkylry0mk8m',
  auth: 'vzqcg8mm4pl5',
} as const;

type Status = 'operational' | 'degraded_performance' | 'partial_outage' | 'major_outage';

async function checkEndpoint(url: string, timeoutMs = 10000): Promise<{ ok: boolean; ms: number }> {
  const start = Date.now();
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
    return { ok: res.ok, ms: Date.now() - start };
  } catch {
    return { ok: false, ms: Date.now() - start };
  }
}

async function checkApi(): Promise<Status> {
  const { ok, ms } = await checkEndpoint('https://api.mnemom.ai/health');
  if (!ok) return 'major_outage';
  if (ms > 5000) return 'degraded_performance';
  return 'operational';
}

async function checkGateway(): Promise<Status> {
  const { ok, ms } = await checkEndpoint('https://gateway.mnemom.ai/health');
  if (!ok) return 'major_outage';
  if (ms > 5000) return 'degraded_performance';
  return 'operational';
}

async function checkWebsite(): Promise<Status> {
  const { ok, ms } = await checkEndpoint('https://www.mnemom.ai/');
  if (!ok) return 'major_outage';
  if (ms > 8000) return 'degraded_performance';
  return 'operational';
}

async function checkDatabase(env: Env): Promise<Status> {
  const start = Date.now();
  try {
    const res = await fetch(`${env.SUPABASE_URL}/rest/v1/agents?select=id&limit=1`, {
      headers: {
        'apikey': env.SUPABASE_SECRET_KEY,
        'Authorization': `Bearer ${env.SUPABASE_SECRET_KEY}`,
      },
      signal: AbortSignal.timeout(10000),
    });
    const ms = Date.now() - start;
    if (!res.ok) return 'major_outage';
    if (ms > 5000) return 'degraded_performance';
    return 'operational';
  } catch {
    return 'major_outage';
  }
}

async function checkObserver(env: Env): Promise<Status> {
  // Check data freshness: if the agent is active, checkpoints should be recent.
  // If no activity for a while, that's normal (agent offline) — not an outage.
  try {
    // Check the most recent trace or checkpoint to see if the agent is active
    const [cpRes, traceRes] = await Promise.all([
      fetch(
        `${env.SUPABASE_URL}/rest/v1/integrity_checkpoints?select=timestamp&order=timestamp.desc&limit=1`,
        {
          headers: { 'apikey': env.SUPABASE_SECRET_KEY, 'Authorization': `Bearer ${env.SUPABASE_SECRET_KEY}` },
          signal: AbortSignal.timeout(10000),
        },
      ),
      fetch(
        `${env.SUPABASE_URL}/rest/v1/traces?select=timestamp&order=timestamp.desc&limit=1`,
        {
          headers: { 'apikey': env.SUPABASE_SECRET_KEY, 'Authorization': `Bearer ${env.SUPABASE_SECRET_KEY}` },
          signal: AbortSignal.timeout(10000),
        },
      ),
    ]);
    if (!cpRes.ok) return 'degraded_performance';
    const cpRows = await cpRes.json() as { timestamp: string }[];
    const traceRows = traceRes.ok ? await traceRes.json() as { timestamp: string }[] : [];

    // If no data at all, observer is fine (nothing to process)
    if (cpRows.length === 0 && traceRows.length === 0) return 'operational';

    // Find the most recent activity across both tables
    const latestTrace = traceRows.length > 0 ? new Date(traceRows[0].timestamp).getTime() : 0;
    const latestCp = cpRows.length > 0 ? new Date(cpRows[0].timestamp).getTime() : 0;
    const latestActivity = Math.max(latestTrace, latestCp);
    const activityAge = Date.now() - latestActivity;

    const thirtyMin = 30 * 60 * 1000;
    // If no recent agent activity, the observer has nothing to do — that's fine
    if (activityAge > thirtyMin) return 'operational';

    // Agent is active: observer should be producing checkpoints
    // Check if checkpoints are keeping up with traces
    if (latestTrace > 0 && latestCp > 0) {
      const lag = latestTrace - latestCp;
      const fifteenMin = 15 * 60 * 1000;
      if (lag > fifteenMin) return 'degraded_performance';
    }

    return 'operational';
  } catch {
    return 'degraded_performance';
  }
}

async function checkAiGateway(): Promise<Status> {
  // Check Cloudflare's status page for AI Gateway component
  try {
    const res = await fetch('https://www.cloudflarestatus.com/api/v2/components/0311l882p558.json', {
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return 'operational'; // can't check, assume ok
    const data = await res.json() as { component: { status: string } };
    const s = data.component.status;
    if (s === 'operational') return 'operational';
    if (s === 'degraded_performance') return 'degraded_performance';
    if (s === 'partial_outage') return 'partial_outage';
    return 'major_outage';
  } catch {
    return 'operational'; // can't reach CF status, don't false-alarm
  }
}

async function checkAnthropic(): Promise<Status> {
  try {
    const res = await fetch('https://status.anthropic.com/api/v2/status.json', {
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return 'operational';
    const data = await res.json() as { status: { indicator: string } };
    const ind = data.status.indicator;
    if (ind === 'none') return 'operational';
    if (ind === 'minor') return 'degraded_performance';
    if (ind === 'major') return 'partial_outage';
    return 'major_outage'; // critical
  } catch {
    return 'operational';
  }
}

// Step 42: CF AI Gateway log usage monitoring
async function checkAiGatewayLogUsage(env: Env): Promise<{ status: Status; logCount?: number; limit?: number }> {
  if (!env.CLOUDFLARE_API_TOKEN || !env.CLOUDFLARE_ACCOUNT_ID || !env.AI_GATEWAY_ID) {
    return { status: 'operational' }; // not configured, skip
  }

  const limit = parseInt(env.AI_GATEWAY_LOG_LIMIT || '100000', 10);

  try {
    const res = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${env.CLOUDFLARE_ACCOUNT_ID}/ai-gateway/gateways/${env.AI_GATEWAY_ID}/logs?per_page=1`,
      {
        headers: { Authorization: `Bearer ${env.CLOUDFLARE_API_TOKEN}` },
        signal: AbortSignal.timeout(10000),
      },
    );
    if (!res.ok) return { status: 'operational' }; // can't check, don't false-alarm

    const data = await res.json() as { result_info?: { total_count?: number } };
    const logCount = data.result_info?.total_count ?? 0;
    const ratio = logCount / limit;

    console.log(JSON.stringify({ ai_gateway_logs: { count: logCount, limit, ratio: ratio.toFixed(3) } }));

    if (ratio >= 0.9) return { status: 'partial_outage', logCount, limit };
    if (ratio >= 0.7) return { status: 'degraded_performance', logCount, limit };
    return { status: 'operational', logCount, limit };
  } catch {
    return { status: 'operational' }; // can't reach CF API, don't false-alarm
  }
}

async function checkAuth(env: Env): Promise<Status> {
  const start = Date.now();
  try {
    // Supabase Auth health check
    const res = await fetch(`${env.SUPABASE_URL}/auth/v1/health`, {
      headers: { 'apikey': env.SUPABASE_SECRET_KEY },
      signal: AbortSignal.timeout(10000),
    });
    const ms = Date.now() - start;
    if (!res.ok) return 'major_outage';
    if (ms > 5000) return 'degraded_performance';
    return 'operational';
  } catch {
    return 'major_outage';
  }
}

async function updateComponent(apiKey: string, componentId: string, status: Status): Promise<void> {
  await fetch(
    `https://api.statuspage.io/v1/pages/${PAGE_ID}/components/${componentId}`,
    {
      method: 'PATCH',
      headers: {
        'Authorization': `OAuth ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ component: { status } }),
    },
  );
}

export default {
  async scheduled(_event: ScheduledEvent, env: Env, _ctx: ExecutionContext): Promise<void> {
    const checks: [string, Promise<Status>][] = [
      [COMPONENTS.api, checkApi()],
      [COMPONENTS.gateway, checkGateway()],
      [COMPONENTS.website, checkWebsite()],
      [COMPONENTS.database, checkDatabase(env)],
      [COMPONENTS.observer, checkObserver(env)],
      [COMPONENTS.ai_gateway, checkAiGateway()],
      [COMPONENTS.anthropic, checkAnthropic()],
      [COMPONENTS.auth, checkAuth(env)],
    ];

    const results = await Promise.allSettled(checks.map(([, p]) => p));

    const updates: Promise<void>[] = [];
    for (let i = 0; i < checks.length; i++) {
      const [componentId] = checks[i];
      const result = results[i];
      const status: Status = result.status === 'fulfilled' ? result.value : 'major_outage';
      updates.push(updateComponent(env.STATUSPAGE_API_KEY, componentId, status));
    }

    // Step 42: AI Gateway log usage check (updates the ai_gateway component)
    const logUsage = await checkAiGatewayLogUsage(env);
    if (logUsage.status !== 'operational') {
      updates.push(updateComponent(env.STATUSPAGE_API_KEY, COMPONENTS.ai_gateway, logUsage.status));
      console.warn(`[monitor] AI Gateway log usage alert: ${logUsage.logCount}/${logUsage.limit} (${logUsage.status})`);
    }

    await Promise.allSettled(updates);
  },

  async fetch(_request: Request, env: Env): Promise<Response> {
    // Authenticate: require X-Monitor-Secret header
    const secret = _request.headers.get('X-Monitor-Secret');
    if (!secret || secret !== env.MONITOR_SECRET) {
      return new Response('Unauthorized', { status: 401 });
    }

    // Manual trigger via HTTP for testing
    await this.scheduled({} as ScheduledEvent, env, {} as ExecutionContext);
    return new Response(JSON.stringify({ ok: true, checked: Object.keys(COMPONENTS) }), {
      headers: { 'Content-Type': 'application/json' },
    });
  },
};
