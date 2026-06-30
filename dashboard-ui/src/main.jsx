import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';

const RISK_CLASS = {
  Critical: 'critical',
  High: 'high',
  Medium: 'medium',
  Low: 'low',
};

const PROTOCOL_ORDER = ['all', 'http', 'mqtt', 'rtsp', 'ssh'];

// Each protocol gets its own colour in the traffic trend instead of all-white.
const PROTOCOL_COLORS = {
  http: '#3b82f6', // blue
  ssh: '#22c55e',  // green
  rtsp: '#a855f7', // purple
  mqtt: '#f59e0b', // amber
};
const TREND_PROTOCOLS = ['http', 'ssh', 'rtsp', 'mqtt'];

// Time ranges for the traffic trend chart.
const TREND_RANGES = [
  { key: '1h', label: '1 Hour', ms: 60 * 60 * 1000, buckets: 12, fmt: (d) => d.toISOString().slice(11, 16) },
  { key: '6h', label: '6 Hours', ms: 6 * 60 * 60 * 1000, buckets: 12, fmt: (d) => d.toISOString().slice(11, 16) },
  { key: '24h', label: '24 Hours', ms: 24 * 60 * 60 * 1000, buckets: 24, fmt: (d) => d.toISOString().slice(11, 16) },
];

// Left-nav sections (icon + scroll-to target id).
const NAV_ITEMS = [
  { id: 'overview', icon: '▦', label: 'Overview' },
  { id: 'attack-map', icon: '◉', label: 'Attack Map' },
  { id: 'traffic-trend', icon: '📈', label: 'Trend' },
  { id: 'live-feed', icon: '≣', label: 'Live Feed' },
  { id: 'paths', icon: '⌗', label: 'Paths' },
];

function formatNumber(value) {
  return Number(value || 0).toLocaleString();
}

function percent(value, total) {
  const denominator = Number(total || 0);
  if (!denominator) return 0;
  return Math.max(0, Math.min(100, (Number(value || 0) / denominator) * 100));
}

function formatPercent(value, total) {
  return `${percent(value, total).toFixed(1)}%`;
}

function riskClass(value) {
  return RISK_CLASS[value] || String(value || 'unknown').toLowerCase();
}

function statusLabel(status) {
  if (status === 'websocket-live') return 'Live';
  if (status === 'http-live') return 'Connected';
  if (status === 'fallback-polling') return 'Auto-updating';
  if (status === 'websocket-error') return 'Reconnecting…';
  if (status === 'offline') return 'Offline';
  return 'Connecting…';
}

function protocolLabel(protocol) {
  if (protocol === 'all') return 'Mixed';
  return String(protocol || 'unknown').toUpperCase();
}

function rowMatchesProtocol(row, selectedProtocol) {
  if (selectedProtocol === 'all') return true;
  return String(row?.protocol || '').toLowerCase() === selectedProtocol;
}

function mapRowMatchesProtocol(row, selectedProtocol) {
  if (selectedProtocol === 'all') return true;
  return (row?.protocols || []).map((item) => String(item).toLowerCase()).includes(selectedProtocol);
}

function buildHeatmap(rows = []) {
  const now = new Date();
  now.setMinutes(0, 0, 0);
  const buckets = Array.from({ length: 24 }).map((_, index) => {
    const date = new Date(now.getTime() - (23 - index) * 60 * 60 * 1000);
    return {
      hour: date.toISOString(),
      label: date.toISOString().slice(11, 16),
      total: 0,
      intensity: 0,
    };
  });
  const byHour = new Map(buckets.map((bucket) => [bucket.hour.slice(0, 13), bucket]));

  rows.forEach((row) => {
    const date = new Date(row.timestamp_utc || '');
    if (Number.isNaN(date.getTime())) return;
    const key = date.toISOString().slice(0, 13);
    if (byHour.has(key)) byHour.get(key).total += 1;
  });

  const max = Math.max(1, ...buckets.map((bucket) => bucket.total));
  return buckets.map((bucket) => ({ ...bucket, intensity: bucket.total / max }));
}

// Buckets recent packets into the chosen time range, counting each protocol
// separately so every bucket can be drawn as a stacked, per-protocol bar.
function buildTrend(rows = [], rangeKey = '24h') {
  const range = TREND_RANGES.find((item) => item.key === rangeKey) || TREND_RANGES[2];
  const bucketMs = range.ms / range.buckets;
  const now = Date.now();
  const start = now - range.ms;
  const buckets = Array.from({ length: range.buckets }).map((_, index) => {
    const bucketStart = start + index * bucketMs;
    return {
      label: range.fmt(new Date(bucketStart)),
      counts: { http: 0, ssh: 0, rtsp: 0, mqtt: 0 },
      total: 0,
    };
  });

  rows.forEach((row) => {
    const time = new Date(row.timestamp_utc || '').getTime();
    if (Number.isNaN(time) || time < start || time > now) return;
    const index = Math.min(buckets.length - 1, Math.floor((time - start) / bucketMs));
    const protocol = String(row.protocol || '').toLowerCase();
    if (buckets[index].counts[protocol] === undefined) return;
    buckets[index].counts[protocol] += 1;
    buckets[index].total += 1;
  });

  const max = Math.max(1, ...buckets.map((bucket) => bucket.total));
  return { buckets, max };
}

function wsUrl() {
  const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws';
  return `${scheme}://${window.location.host}/ws/events`;
}

let _authToken = localStorage.getItem('dashboard_token') || '';
let _onAuthFail = null;

function setAuthToken(token) {
  _authToken = token;
  if (token) localStorage.setItem('dashboard_token', token);
  else localStorage.removeItem('dashboard_token');
}

async function api(path, options) {
  const headers = { 'Content-Type': 'application/json', ...(options?.headers || {}) };
  if (_authToken) headers['Authorization'] = `Bearer ${_authToken}`;
  const response = await fetch(path, { ...options, headers });
  if (response.status === 401) {
    setAuthToken('');
    _onAuthFail?.();
    throw new Error('Unauthorized');
  }
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json();
}

function useDashboardData() {
  const [data, setData] = useState(null);
  const [status, setStatus] = useState('connecting');
  const [error, setError] = useState(null);

  useEffect(() => {
    let alive = true;
    let socket;
    let fallbackTimer;

    const loadSnapshot = async () => {
      try {
        const snapshot = await api('/api/summary');
        if (alive) {
          setData(snapshot);
          setStatus('http-live');
          setError(null);
        }
      } catch (err) {
        if (alive) {
          setError(err.message);
          setStatus('offline');
        }
      }
    };

    const connect = () => {
      socket = new WebSocket(wsUrl());
      socket.onopen = () => {
        if (alive) setStatus('websocket-live');
      };
      socket.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          if (message.type === 'snapshot' && alive) {
            setData(message.payload);
            setError(null);
          }
        } catch (err) {
          if (alive) setError(err.message);
        }
      };
      socket.onerror = () => {
        if (alive) setStatus('websocket-error');
      };
      socket.onclose = () => {
        if (!alive) return;
        setStatus('fallback-polling');
        fallbackTimer = setInterval(loadSnapshot, 15000);
        loadSnapshot();
      };
    };

    connect();
    loadSnapshot();

    return () => {
      alive = false;
      if (socket) socket.close();
      if (fallbackTimer) clearInterval(fallbackTimer);
    };
  }, []);

  return { data, status, error };
}

function useNightMode() {
  const [nightMode, setNightMode] = useState(() => {
    return window.localStorage.getItem('iot-dashboard-theme') !== 'control';
  });

  useEffect(() => {
    document.body.classList.toggle('theme-night', nightMode);
    document.body.classList.toggle('theme-control', !nightMode);
    window.localStorage.setItem('iot-dashboard-theme', nightMode ? 'night' : 'control');
  }, [nightMode]);

  return [nightMode, setNightMode];
}

function StatCard({ label, value, hint, tone }) {
  return (
    <section className={`stat-card ${tone || ''}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{hint}</small>
    </section>
  );
}

function ProtocolSelector({ rows = [], selected, onSelect }) {
  const byProtocol = new Map(rows.map((row) => [row.protocol, row]));
  const ordered = PROTOCOL_ORDER.map((protocol) => (
    byProtocol.get(protocol) || {
      protocol,
      label: protocolLabel(protocol),
      total_packets: 0,
      attacked_packets: 0,
      normal_packets: 0,
      attack_rate: 0,
      router_station_events: 0,
      source_events: 0,
      honeypot_events: 0,
      real_events: 0,
    }
  ));

  return (
    <section className="protocol-selector">
      {ordered.map((row) => (
        <button
          className={`protocol-card ${selected === row.protocol ? 'active' : ''}`}
          key={row.protocol}
          onClick={() => onSelect(row.protocol)}
        >
          <span className="protocol-name">
            <span className="protocol-dot" style={{ background: PROTOCOL_COLORS[row.protocol] || 'var(--muted)' }} />
            {row.label}
          </span>
          <strong>{formatNumber(row.total_packets)}</strong>
          <small>{formatNumber(row.attacked_packets)} attacked · {formatNumber(row.normal_packets)} normal</small>
          <small>{formatNumber(row.honeypot_events || 0)} honeypot · {formatNumber(row.real_events || 0)} allowed</small>
          <div className="mini-meter" aria-hidden="true">
            <span className="mini-meter-attack" style={{ width: `${percent(row.attacked_packets, row.total_packets)}%` }} />
            <span className="mini-meter-normal" style={{ width: `${percent(row.normal_packets, row.total_packets)}%` }} />
          </div>
        </button>
      ))}
    </section>
  );
}

function AttackSplit({ dashboard }) {
  const attacked = dashboard?.attacked_packets || 0;
  const normal = dashboard?.normal_packets || 0;
  const total = Math.max(1, dashboard?.total_packets || 0);

  return (
    <div className="attack-split">
      <div className="split-bar" aria-label="Attacked versus normal packets">
        <span className="split-attack" style={{ width: `${(attacked / total) * 100}%` }} />
        <span className="split-normal" style={{ width: `${(normal / total) * 100}%` }} />
      </div>
      <div className="split-legend">
        <b>{formatNumber(attacked)} attacked · {formatPercent(attacked, total)}</b>
        <b>{formatNumber(normal)} normal · {formatPercent(normal, total)}</b>
      </div>
    </div>
  );
}

function WholeProjectTotals({ summary = {} }) {
  const total = summary.window_packets || summary.packets_loaded || 0;
  const normal = summary.normal_packets || 0;
  const attacked = summary.attacked_packets || 0;
  const systemTotal = summary.total_packets_system || total;
  const systemNormal = summary.total_normal_packets_system || normal;
  const systemAttacked = summary.total_attacked_packets_system || attacked;
  const windowLimit = summary.window_packet_limit || 5000;
  const eventsFromStart = summary.total_events_from_start || summary.total_events_system || summary.events_loaded || 0;
  const rawEventsFromStart = summary.total_raw_events_from_start || eventsFromStart;

  return (
    <section className="whole-project">
      <div>
        <span className="eyebrow">Overview</span>
        <h2>Traffic Summary</h2>
        <p>Showing the latest {formatNumber(total)} packets. {formatNumber(systemTotal)} total packets have been captured since the system started.</p>
      </div>
      <div className="whole-grid">
        <article className="event-total">
          <span>Total Captured</span>
          <strong>{formatNumber(rawEventsFromStart)}</strong>
          <small>{formatNumber(eventsFromStart)} events after processing</small>
        </article>
        <article>
          <span>All Packets</span>
          <strong>{formatNumber(systemTotal)}</strong>
          <small>{formatNumber(systemAttacked)} flagged · {formatNumber(systemNormal)} safe</small>
        </article>
        <article>
          <span>Currently Visible</span>
          <strong>{formatNumber(total)}</strong>
          <small>out of {formatNumber(summary.total_events_system || summary.events_loaded)} total events</small>
        </article>
        <article>
          <span>Safe Traffic</span>
          <strong>{formatNumber(normal)}</strong>
          <small>{formatPercent(normal, total)} passed or low-risk</small>
          <div className="metric-bar"><span className="normal-fill" style={{ width: `${percent(normal, total)}%` }} /></div>
        </article>
        <article className="danger-total">
          <span>Threats Found</span>
          <strong>{formatNumber(attacked)}</strong>
          <small>{formatPercent(attacked, total)} suspicious or honeypot traffic</small>
          <div className="metric-bar"><span className="attack-fill" style={{ width: `${percent(attacked, total)}%` }} /></div>
        </article>
      </div>
    </section>
  );
}

function ProtocolRiskGraph({ rows = [] }) {
  const protocols = rows.filter((row) => row.protocol !== 'all');
  const maxTotal = Math.max(1, ...protocols.map((row) => Number(row.total_packets || 0)));

  return (
    <div className="protocol-risk-graph">
      {protocols.map((row) => {
        const total = Number(row.total_packets || 0);
        const attackValue = Number(row.attacked_packets || 0);
        const normalValue = Number(row.normal_packets || 0);
        const scaleWidth = percent(total, maxTotal);

        return (
          <article className="risk-graph-row" key={row.protocol}>
            <div className="risk-graph-label">
              <b>
                <span className="protocol-dot" style={{ background: PROTOCOL_COLORS[row.protocol] || 'var(--muted)' }} />
                {row.label}
              </b>
              <small>{formatNumber(total)} packets · {formatPercent(attackValue, total)} attacks · {formatPercent(normalValue, total)} safe</small>
            </div>
            <div className="risk-graph-track">
              <div className="risk-graph-scale" style={{ width: `${scaleWidth}%` }}>
                <span className="attack-fill" style={{ width: `${percent(attackValue, total)}%` }} />
                <span className="normal-fill" style={{ width: `${percent(normalValue, total)}%` }} />
              </div>
            </div>
            <strong>{formatNumber(attackValue)}</strong>
          </article>
        );
      })}
    </div>
  );
}

function PercentRows({ title, rows = [], tone = 'attack' }) {
  const total = rows.reduce((sum, row) => sum + Number(row.value || 0), 0);

  return (
    <section className="percent-card">
      <div className="panel-title compact">
        <div>
          <h2>{title}</h2>
        </div>
      </div>
      <div className="percent-list">
        {rows.map((row) => (
          <article className="percent-row" key={row.name}>
            <div>
              <b>{row.name}</b>
              <small>{formatNumber(row.value)} packets</small>
            </div>
            <strong>{formatPercent(row.value, total)}</strong>
            <div className="metric-bar">
              <span className={tone === 'normal' ? 'normal-fill' : 'attack-fill'} style={{ width: `${percent(row.value, total)}%` }} />
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}

function OutcomePercentDashboard({ dashboard, attackBreakdown = [] }) {
  const total = dashboard?.total_packets || 0;
  const outcomeRows = [
    { name: 'Attack behavior', value: dashboard?.attacked_packets || 0 },
    { name: 'Normal behavior', value: dashboard?.normal_packets || 0 },
  ];
  const attackRows = attackBreakdown.filter((row) => String(row.name).toLowerCase() !== 'normal');

  return (
    <section className="percent-dashboard">
      <section className="percent-card hero-percent">
        <span className="eyebrow">{dashboard?.label || 'All Protocols'} Traffic</span>
        <h2>{formatPercent(dashboard?.attacked_packets, total)} attack / {formatPercent(dashboard?.normal_packets, total)} normal</h2>
        <AttackSplit dashboard={dashboard} />
      </section>
      <PercentRows title="Traffic Breakdown" rows={outcomeRows} />
      <PercentRows title="Attack Types" rows={attackRows.slice(0, 7)} />
    </section>
  );
}

function LeftNav({ open, onToggle }) {
  const goTo = (id) => {
    const target = document.getElementById(id);
    if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };
  return (
    <aside className={`left-nav ${open ? 'open' : 'closed'}`}>
      <button className="left-nav-toggle" onClick={onToggle} title={open ? 'Hide menu' : 'Show menu'}>
        {open ? '×' : '☰'}
      </button>
      {open && (
        <nav className="left-nav-items">
          {NAV_ITEMS.map((item) => (
            <button key={item.id} className="left-nav-btn" title={item.label} onClick={() => goTo(item.id)}>
              <span className="left-nav-icon">{item.icon}</span>
              <span className="left-nav-label">{item.label}</span>
            </button>
          ))}
        </nav>
      )}
    </aside>
  );
}

function TrafficTrend({ rows = [] }) {
  const [range, setRange] = useState('24h');
  const { buckets, max } = useMemo(() => buildTrend(rows, range), [rows, range]);
  return (
    <div className="trend">
      <div className="trend-controls">
        {TREND_RANGES.map((item) => (
          <button
            key={item.key}
            className={`trend-range ${range === item.key ? 'active' : ''}`}
            onClick={() => setRange(item.key)}
          >
            {item.label}
          </button>
        ))}
      </div>
      <div className="trend-chart">
        {buckets.map((bucket, index) => (
          <div
            className="trend-col"
            key={index}
            title={`${bucket.label}: ${bucket.total} packets — HTTP ${bucket.counts.http} · SSH ${bucket.counts.ssh} · RTSP ${bucket.counts.rtsp} · MQTT ${bucket.counts.mqtt}`}
          >
            <div className="trend-bar" style={{ height: `${(bucket.total / max) * 100}%` }}>
              {TREND_PROTOCOLS.map((protocol) => (
                bucket.counts[protocol] > 0 ? (
                  <span
                    key={protocol}
                    className="trend-seg"
                    style={{ flexGrow: bucket.counts[protocol], background: PROTOCOL_COLORS[protocol] }}
                  />
                ) : null
              ))}
            </div>
            <span className="trend-label">{bucket.label}</span>
          </div>
        ))}
      </div>
      <div className="trend-legend">
        {TREND_PROTOCOLS.map((protocol) => (
          <span key={protocol} className="trend-legend-item">
            <i style={{ background: PROTOCOL_COLORS[protocol] }} />
            {protocol.toUpperCase()}
          </span>
        ))}
      </div>
    </div>
  );
}

function Heatmap({ rows = [] }) {
  return (
    <div className="heatmap">
      {rows.map((row) => (
        <div
          className="heat-cell"
          key={row.hour}
          style={{ '--heat': row.intensity || 0 }}
          title={`${row.label}: ${row.total} events`}
        >
          <span>{row.label}</span>
          <strong>{row.total}</strong>
        </div>
      ))}
    </div>
  );
}

function AttackMap({ rows = [], onSelectIp }) {
  return (
    <div className="map-panel">
      <svg viewBox="0 0 960 420" role="img" aria-label="Attack map">
        <defs>
          <radialGradient id="pulse" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#f97316" stopOpacity="0.95" />
            <stop offset="100%" stopColor="#f97316" stopOpacity="0" />
          </radialGradient>
        </defs>
        <rect width="960" height="420" rx="24" className="map-bg" />
        {Array.from({ length: 8 }).map((_, i) => <line key={`v-${i}`} x1={80 + i * 110} x2={80 + i * 110} y1="40" y2="380" className="map-grid" />)}
        {Array.from({ length: 5 }).map((_, i) => <line key={`h-${i}`} x1="50" x2="910" y1={70 + i * 70} y2={70 + i * 70} className="map-grid" />)}
        <path className="land" d="M120 135 C170 95 260 110 290 155 C330 210 260 245 190 230 C135 218 88 180 120 135Z" />
        <path className="land" d="M395 115 C470 70 595 94 626 155 C663 229 558 270 464 245 C390 225 335 158 395 115Z" />
        <path className="land" d="M650 175 C745 125 860 150 890 220 C918 286 810 330 700 304 C628 287 585 214 650 175Z" />
        {rows.map((row) => {
          const x = ((row.lon + 180) / 360) * 860 + 50;
          const y = ((90 - row.lat) / 180) * 340 + 40;
          const size = Math.min(30, 7 + Math.sqrt(row.count || 1) * 4);
          const hasAttack = Number(row.attack_count || 0) > 0;
          return (
            <g key={row.source_ip} onClick={() => onSelectIp(row.source_ip)} className="map-point">
              <circle cx={x} cy={y} r={size * 1.8} fill="url(#pulse)" opacity={hasAttack ? (row.risk_level === 'Critical' ? 0.85 : 0.55) : 0.08} />
              <circle cx={x} cy={y} r={size} className={`point ${hasAttack ? riskClass(row.risk_level) : 'normal-user'}`} />
              <text x={x + size + 4} y={y + 4}>{row.source_ip}</text>
              <title>{`${row.source_ip}: ${row.attack_count || 0} attacks, ${row.normal_count || 0} normal, ${row.count || 0} packets`}</title>
            </g>
          );
        })}
      </svg>
      <div className="map-legend">
        <span><i className="legend-dot attack" /> attack source</span>
        <span><i className="legend-dot normal" /> normal user/source</span>
      </div>
      <p className="map-note">Map shows approximate source locations from the latest visible window. Locations are estimated.</p>
    </div>
  );
}

function AlertPanel({ alerts = [], onSelectIp }) {
  return (
    <section className="panel alerts">
      <div className="panel-title">
        <div>
          <span className="eyebrow">Alerts</span>
          <h2>High Risk Events</h2>
        </div>
        <b>{alerts.length}</b>
      </div>
      <div className="alert-list">
        {alerts.slice(0, 20).map((alert) => (
          <article className="alert-card" key={`${alert.timestamp_utc}-${alert.source_ip}-${alert.decision_id || alert.event_type}`}>
            <button className="ip-link" onClick={() => onSelectIp(alert.source_ip)}>{alert.source_ip}</button>
            <span className={`risk-pill ${riskClass(alert.risk_level)}`}>{alert.risk_level}</span>
            <p>{alert.predicted_attack} via {alert.protocol}</p>
            <small>{alert.timestamp_utc || 'unknown time'} · {alert.route_decision === 'honeypot' ? 'sent to honeypot' : alert.route_decision || 'monitored'}</small>
          </article>
        ))}
      </div>
    </section>
  );
}

function LiveFeed({ events = [], onSelectIp }) {
  return (
    <section className="panel live-feed">
      <div className="panel-title">
        <div>
          <span className="eyebrow">Live</span>
          <h2>Recent Activity</h2>
        </div>
      </div>
      <div className="event-list">
        {events.slice(0, 45).map((event, index) => (
          <button className="event-row" key={`${event.timestamp_utc}-${event.source_ip}-${event.decision_id || event.event_type}-${index}`} onClick={() => onSelectIp(event.source_ip)}>
            <span className={`risk-dot ${riskClass(event.risk_level)}`} />
            <b>{event.source_ip}</b>
            <em>{event.protocol}</em>
            <span>{event.event_type}</span>
            <small>{event.timestamp_utc}</small>
          </button>
        ))}
      </div>
    </section>
  );
}

function IpDrilldown({ ip, onClose }) {
  const [details, setDetails] = useState(null);
  const [detailError, setDetailError] = useState(null);

  useEffect(() => {
    if (!ip) return;
    let alive = true;

    const loadDetails = async (initial = false) => {
      if (initial) {
        setDetails(null);
        setDetailError(null);
      }
      try {
        const nextDetails = await api(`/api/ip/${encodeURIComponent(ip)}`);
        if (alive) {
          setDetails(nextDetails);
          setDetailError(null);
        }
      } catch {
        if (alive) setDetailError('Failed to refresh IP details');
      }
    };

    loadDetails(true);
    const timer = setInterval(() => loadDetails(false), 15000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [ip]);

  if (!ip) return null;

  return (
    <aside className="drilldown">
      <button className="close" onClick={onClose}>Close ×</button>
      {!details ? (
        <p>Loading {ip}...</p>
      ) : (
        <>
          <span className="eyebrow">IP Details</span>
          <h2>{details.source_ip}</h2>
          {detailError ? <p className="inline-warning">{detailError}. Showing last loaded details.</p> : null}
          <div className="drill-actions">
            <a className="pdf-link" href={`/api/export/session/${encodeURIComponent(details.source_ip)}`}>Export Full PDF Summary</a>
          </div>
          <div className="detail-grid">
            <span>Risk Level</span><b>{details.summary.risk_level}</b>
            <span>Threat Type</span><b>{details.summary.predicted_attack}</b>
            <span>Total Events</span><b>{details.summary.event_count}</b>
            <span>Decisions Made</span><b>{details.summary.route_count}</b>
            <span>Last Action</span><b>{details.summary.last_route_decision || 'n/a'}{details.summary.last_routed_to ? ` → ${details.summary.last_routed_to}` : ''}</b>
            <span>Action Time</span><b>{details.summary.last_route_at || 'n/a'}</b>
            <span>Latest Activity</span><b>{details.summary.last_event_type || 'n/a'}</b>
            <span>Activity Time</span><b>{details.summary.last_event_at || 'n/a'}</b>
            <span>Protocols Used</span><b>{(details.summary.protocols || []).join(', ') || 'n/a'}</b>
          </div>
          <h3>Decision History <small>PDF includes {details.summary.routes_returned || 0} rows</small></h3>
          <div className="mini-list">
            {(details.routes || []).slice(0, 15).map((route) => (
              <div key={route.decision_id || `${route.timestamp_utc}-${route.score}`}>
                <b>{route.route_decision}</b>
                <span>{route.protocol} · {route.routed_to || 'n/a'} · score {route.score} · {route.timestamp_utc}</span>
                <small>{Array.isArray(route.reason) ? route.reason.join(', ') : route.reason}</small>
              </div>
            ))}
          </div>
          <h3>Activity Log <small>PDF includes {details.summary.events_returned || 0} rows</small></h3>
          <div className="mini-list">
            {(details.events || []).slice(0, 15).map((event, index) => (
              <div key={`${event.timestamp_utc}-${index}`}>
                <b>{event.event_type}</b>
                <span>{event.protocol} · {event.route_decision || 'n/a'} · {event.timestamp_utc}</span>
                <small>{event.path || event.topic || event.payload || 'no payload'}</small>
              </div>
            ))}
          </div>
        </>
      )}
    </aside>
  );
}

function LoginScreen({ onLogin }) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const res = await fetch('/api/auth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      if (!res.ok) { setError('Invalid password.'); setLoading(false); return; }
      const data = await res.json();
      setAuthToken(data.token);
      onLogin();
    } catch {
      setError('Connection error.');
      setLoading(false);
    }
  };

  return (
    <main className="login-screen">
      <section className="login-card">
        <span className="eyebrow">IoT Honeypot</span>
        <h1>Network Security Dashboard</h1>
        <form onSubmit={submit}>
          <input
            type="password"
            placeholder="Dashboard password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoFocus
          />
          {error && <p className="login-error">{error}</p>}
          <button type="submit" disabled={loading || !password}>
            {loading ? 'Checking…' : 'Sign In'}
          </button>
        </form>
      </section>
    </main>
  );
}

function PathExplorer({ onSelectIp }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [sortBy, setSortBy] = useState('hits');

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const result = await api('/api/paths?limit=200');
        if (alive) { setData(result); setLoading(false); }
      } catch {
        if (alive) setLoading(false);
      }
    };
    load();
    return () => { alive = false; };
  }, []);

  const rows = useMemo(() => {
    const list = data?.paths || [];
    return [...list].sort((a, b) => {
      if (sortBy === 'hits') return b.hits - a.hits;
      if (sortBy === 'honeypot_pct') return b.honeypot_pct - a.honeypot_pct;
      if (sortBy === 'score') return b.top_score - a.top_score;
      return 0;
    });
  }, [data, sortBy]);

  return (
    <section className="panel path-explorer">
      <div className="panel-title">
        <div>
          <span className="eyebrow">HTTP Intelligence</span>
          <h2>Path Explorer</h2>
          <p className="panel-desc">Every URL path seen at the router — hit counts, honeypot routing rate, and matched rules.</p>
        </div>
        <div className="sort-controls">
          <span>Sort by</span>
          {[['hits', 'Total Hits'], ['honeypot_pct', 'Honeypot %'], ['score', 'Top Score']].map(([key, label]) => (
            <button key={key} className={`sort-btn${sortBy === key ? ' active' : ''}`} onClick={() => setSortBy(key)}>{label}</button>
          ))}
        </div>
      </div>
      {loading ? <p className="panel-loading">Loading paths…</p> : (
        <div className="path-table-wrap">
          <table className="path-table">
            <thead>
              <tr>
                <th>Path</th>
                <th>Hits</th>
                <th>Honeypot %</th>
                <th>Top Score</th>
                <th>Top Rules Matched</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.path} className={row.honeypot_pct > 80 ? 'row-danger' : row.honeypot_pct > 40 ? 'row-warn' : ''}>
                  <td className="path-cell" title={row.path}>{row.path}</td>
                  <td>{row.hits.toLocaleString()}</td>
                  <td>
                    <span className={row.honeypot_pct > 80 ? 'pct-high' : row.honeypot_pct > 40 ? 'pct-mid' : 'pct-low'}>
                      {row.honeypot_pct}%
                    </span>
                  </td>
                  <td>{row.top_score}</td>
                  <td className="reasons-cell">{(row.top_reasons || []).join(' · ') || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {data?.total_paths > rows.length && (
            <p className="table-footer">Showing {rows.length} of {data.total_paths} unique paths.</p>
          )}
        </div>
      )}
    </section>
  );
}

function HoneypotResponses({ onSelectIp }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const result = await api('/api/honeypot/responses?limit=50');
        if (alive) { setData(result); setLoading(false); }
      } catch {
        if (alive) setLoading(false);
      }
    };
    load();
    const timer = setInterval(load, 30000);
    return () => { alive = false; clearInterval(timer); };
  }, []);

  const responses = data?.responses || [];

  return (
    <section className="panel honeypot-viewer">
      <div className="panel-title">
        <div>
          <span className="eyebrow">Honeypot Activity</span>
          <h2>Bot Interactions</h2>
          <p className="panel-desc">What attackers sent to the honeypot and what it returned. Click an IP to drill down.</p>
        </div>
        {data?.total != null && (
          <span className="honeypot-count">{data.total.toLocaleString()} total interactions</span>
        )}
      </div>
      {loading ? <p className="panel-loading">Loading interactions…</p> : responses.length === 0 ? (
        <p className="panel-loading">No honeypot interactions recorded yet.</p>
      ) : (
        <div className="honeypot-list">
          {responses.map((row, index) => (
            <article className="honeypot-card" key={`${row.timestamp_utc}-${row.ip}-${index}`}>
              <div className="honeypot-meta">
                <button className="ip-link" onClick={() => onSelectIp(row.ip)}>{row.ip}</button>
                <span className={`status-badge s${row.response_status}`}>{row.response_status}</span>
                <b>{row.method}</b>
                <code className="path-code">{row.path}</code>
                <small>{row.timestamp_utc}</small>
              </div>
              {row.user_agent && <div className="honeypot-ua">UA: {row.user_agent}</div>}
              {row.body_preview && (
                <pre className="honeypot-body">{row.body_preview}</pre>
              )}
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

function App() {
  const { data, status, error } = useDashboardData();
  const [selectedIp, setSelectedIp] = useState(null);
  const [selectedProtocol, setSelectedProtocol] = useState('all');
  const [nightMode, setNightMode] = useNightMode();
  const [showLogin, setShowLogin] = useState(false);
  const [navOpen, setNavOpen] = useState(true);

  useEffect(() => {
    _onAuthFail = () => setShowLogin(true);
    return () => { _onAuthFail = null; };
  }, []);

  if (showLogin) {
    return <LoginScreen onLogin={() => setShowLogin(false)} />;
  }

  const summary = data?.summary || {};
  const protocolDashboards = data?.protocol_dashboards || [];
  const selectedDashboard = protocolDashboards.find((row) => row.protocol === selectedProtocol) || {
    protocol: selectedProtocol,
    label: protocolLabel(selectedProtocol),
    total_packets: 0,
    attacked_packets: 0,
    normal_packets: 0,
    attack_rate: 0,
    router_station_events: 0,
    source_events: 0,
    honeypot_events: 0,
    real_events: 0,
  };
  const packetRows = data?.recent_packets || data?.recent_events || [];
  const filteredPackets = packetRows.filter((row) => rowMatchesProtocol(row, selectedProtocol));
  const filteredAlerts = (data?.alerts || []).filter((row) => rowMatchesProtocol(row, selectedProtocol));
  const filteredMap = (data?.attack_map || []).filter((row) => mapRowMatchesProtocol(row, selectedProtocol));
  const attackLabel = useMemo(() => {
    const top = data?.attack_breakdown?.[0];
    return top ? `${top.name} dominant` : 'No attack data';
  }, [data]);

  return (
    <div className={`app-shell ${navOpen ? 'nav-open' : 'nav-closed'}`}>
      <LeftNav open={navOpen} onToggle={() => setNavOpen((value) => !value)} />
    <main>
      <header className="hero">
        <div>
          <span className="eyebrow">IoT Honeypot</span>
          <h1>Network Security Dashboard</h1>
          <p>Monitoring HTTP, MQTT, RTSP, and SSH traffic in real time. Shows the latest 5,000 packets plus total counters since the system started.</p>
        </div>
        <div className="status-card">
          <span className={`status-light ${status.includes('live') ? 'online' : ''}`} />
          <b>{statusLabel(status)}</b>
          <small>{error || (data?.generated_at ? `Updated ${data.generated_at}` : 'Waiting for data…')}</small>
          <button className="theme-toggle" onClick={() => setNightMode((value) => !value)}>
            {nightMode ? 'Dark Mode' : 'Light Mode'}
          </button>
        </div>
      </header>

      <WholeProjectTotals summary={summary} />
      <ProtocolSelector rows={protocolDashboards} selected={selectedProtocol} onSelect={setSelectedProtocol} />
      <OutcomePercentDashboard dashboard={selectedDashboard} attackBreakdown={data?.attack_breakdown || []} />

      <section className="stats" id="overview">
        <StatCard label={`${selectedDashboard.label} Packets`} value={formatNumber(selectedDashboard.total_packets)} hint={`${formatNumber(summary.events_loaded)} raw normalized logs`} />
        <StatCard label="Attacked Packets" value={formatNumber(selectedDashboard.attacked_packets)} hint={`${selectedDashboard.attack_rate || 0}% attack rate`} tone="danger" />
        <StatCard label="Normal Packets" value={formatNumber(selectedDashboard.normal_packets)} hint={`${formatPercent(selectedDashboard.normal_packets, selectedDashboard.total_packets)} router allowed or low risk`} />
        <StatCard label="High Alerts" value={formatNumber(selectedProtocol === 'all' ? summary.high_alerts : filteredAlerts.length)} hint={selectedProtocol === 'all' ? attackLabel : `${selectedDashboard.label} selected`} tone="warm" />
      </section>

      <section className="grid-main" id="attack-map">
        <section className="panel map-shell">
          <div className="panel-title">
            <div>
              <span className="eyebrow">Attack Map</span>
              <h2>Source Map</h2>
            </div>
          </div>
          <AttackMap rows={filteredMap} onSelectIp={setSelectedIp} />
        </section>
        <AlertPanel alerts={filteredAlerts} onSelectIp={setSelectedIp} />
      </section>

      <section className="grid-secondary" id="traffic-trend">
        <section className="panel">
          <div className="panel-title">
            <div>
              <span className="eyebrow">Traffic Trend</span>
              <h2>Packets by Protocol</h2>
            </div>
          </div>
          <TrafficTrend rows={packetRows} />
        </section>
        <section className="panel">
          <div className="panel-title">
            <div>
              <span className="eyebrow">Risk by Protocol</span>
              <h2>Attack Rate Comparison</h2>
            </div>
          </div>
          <ProtocolRiskGraph rows={protocolDashboards} />
          <AttackSplit dashboard={selectedDashboard} />
        </section>
      </section>

      <div id="live-feed">
        <LiveFeed events={filteredPackets} onSelectIp={setSelectedIp} />
      </div>
      <div id="paths">
        <PathExplorer onSelectIp={setSelectedIp} />
      </div>
      <HoneypotResponses onSelectIp={setSelectedIp} />
      <IpDrilldown ip={selectedIp} onClose={() => setSelectedIp(null)} />
    </main>
    </div>
  );
}

createRoot(document.getElementById('root')).render(<App />);
