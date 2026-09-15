import { useState } from "react";

type Risk = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
type Status = "BLOCKED" | "RESOLVED" | "ACTIVE";

interface Finding {
  id: string;
  type: string;
  file: string;
  line: number;
  risk: Risk;
  confidence: number;
  entropy: number;
  signals: string[];
  firstSeen: string;
  lastSeen: string;
  status: Status;
  commit: string;
  fingerprint: string;
}

interface ScanEvent {
  id: string;
  timestamp: string;
  trigger: "pre-commit" | "pre-push" | "manual" | "workspace";
  filesScanned: number;
  findings: number;
  blocked: boolean;
  duration: number;
}

const RISK_COLOR: Record<Risk, string> = {
  CRITICAL: "#ff3b3b",
  HIGH: "#ff8c00",
  MEDIUM: "#e8b800",
  LOW: "#00e5b0",
};

const RISK_BG: Record<Risk, string> = {
  CRITICAL: "rgba(255,59,59,0.08)",
  HIGH: "rgba(255,140,0,0.08)",
  MEDIUM: "rgba(232,184,0,0.08)",
  LOW: "rgba(0,229,176,0.08)",
};

const findings: Finding[] = [
  {
    id: "f001",
    type: "AWS Access Key",
    file: "config/aws.env",
    line: 3,
    risk: "CRITICAL",
    confidence: 97,
    entropy: 5.21,
    signals: ["Known credential format", "High entropy", "Sensitive variable name", "Production config file"],
    firstSeen: "2026-09-14 09:12:44",
    lastSeen: "2026-09-14 09:12:44",
    status: "BLOCKED",
    commit: "a3f8c12",
    fingerprint: "hmac:e9b2f4a1d3c7e8b2",
  },
  {
    id: "f002",
    type: "API Credential",
    file: "src/services/stripe.ts",
    line: 7,
    risk: "CRITICAL",
    confidence: 94,
    entropy: 4.87,
    signals: ["Pattern match", "High entropy", "Sensitive variable name", "Authorization header"],
    firstSeen: "2026-09-13 14:31:07",
    lastSeen: "2026-09-13 14:31:07",
    status: "RESOLVED",
    commit: "b1e4d99",
    fingerprint: "hmac:d2a9c5b8e1f3a7d2",
  },
  {
    id: "f003",
    type: "Database Password",
    file: "docker-compose.yml",
    line: 22,
    risk: "HIGH",
    confidence: 88,
    entropy: 4.43,
    signals: ["Pattern match", "Sensitive variable name", "Configuration file"],
    firstSeen: "2026-09-12 16:55:20",
    lastSeen: "2026-09-14 11:08:33",
    status: "ACTIVE",
    commit: "c7f2a55",
    fingerprint: "hmac:b5f1e8a4c9d2b5f1",
  },
  {
    id: "f004",
    type: "GitHub Token",
    file: ".env.production",
    line: 11,
    risk: "CRITICAL",
    confidence: 99,
    entropy: 5.64,
    signals: ["Known credential format (ghp_)", "High entropy", "Production environment", "Sensitive filename"],
    firstSeen: "2026-09-10 08:20:11",
    lastSeen: "2026-09-10 08:20:11",
    status: "RESOLVED",
    commit: "d9a4b88",
    fingerprint: "hmac:c8e3f6a2d4c8e3f6",
  },
  {
    id: "f005",
    type: "JWT Secret",
    file: "src/auth/jwt.config.ts",
    line: 4,
    risk: "HIGH",
    confidence: 81,
    entropy: 4.12,
    signals: ["Pattern match", "Sensitive variable name", "Authentication context"],
    firstSeen: "2026-09-09 17:44:58",
    lastSeen: "2026-09-09 17:44:58",
    status: "RESOLVED",
    commit: "e2c7f11",
    fingerprint: "hmac:a1d6e9b3c5a1d6e9",
  },
  {
    id: "f006",
    type: "Connection String",
    file: "config/database.json",
    line: 8,
    risk: "HIGH",
    confidence: 76,
    entropy: 3.98,
    signals: ["Pattern match", "Connection string format", "Credential in URL"],
    firstSeen: "2026-09-08 12:03:29",
    lastSeen: "2026-09-08 12:03:29",
    status: "RESOLVED",
    commit: "f5b3e44",
    fingerprint: "hmac:f4b7d2e6a8f4b7d2",
  },
];

const scanHistory: ScanEvent[] = [
  { id: "s001", timestamp: "2026-09-15 14:30:22", trigger: "pre-commit", filesScanned: 18, findings: 0, blocked: false, duration: 312 },
  { id: "s002", timestamp: "2026-09-14 09:12:41", trigger: "pre-commit", filesScanned: 14, findings: 1, blocked: true, duration: 289 },
  { id: "s003", timestamp: "2026-09-13 14:31:04", trigger: "pre-push", filesScanned: 31, findings: 1, blocked: true, duration: 544 },
  { id: "s004", timestamp: "2026-09-13 11:22:18", trigger: "manual", filesScanned: 47, findings: 0, blocked: false, duration: 891 },
  { id: "s005", timestamp: "2026-09-12 16:55:17", trigger: "workspace", filesScanned: 52, findings: 1, blocked: false, duration: 1204 },
  { id: "s006", timestamp: "2026-09-11 09:44:33", trigger: "pre-commit", filesScanned: 11, findings: 0, blocked: false, duration: 201 },
  { id: "s007", timestamp: "2026-09-10 08:20:08", trigger: "pre-commit", filesScanned: 9, findings: 1, blocked: true, duration: 178 },
  { id: "s008", timestamp: "2026-09-09 17:44:55", trigger: "pre-push", filesScanned: 28, findings: 1, blocked: true, duration: 467 },
];

function RiskBadge({ risk }: { risk: Risk }) {
  return (
    <span
      className="font-mono text-xs font-semibold px-2 py-0.5 rounded-sm"
      style={{ color: RISK_COLOR[risk], background: RISK_BG[risk], border: `1px solid ${RISK_COLOR[risk]}22` }}
    >
      {risk}
    </span>
  );
}

function StatusBadge({ status }: { status: Status }) {
  const map = {
    BLOCKED: { color: "#ff3b3b", bg: "rgba(255,59,59,0.08)", label: "BLOCKED" },
    RESOLVED: { color: "#00e5b0", bg: "rgba(0,229,176,0.08)", label: "RESOLVED" },
    ACTIVE: { color: "#ff8c00", bg: "rgba(255,140,0,0.08)", label: "ACTIVE" },
  };
  const s = map[status];
  return (
    <span
      className="font-mono text-xs font-semibold px-2 py-0.5 rounded-sm"
      style={{ color: s.color, background: s.bg, border: `1px solid ${s.color}22` }}
    >
      {s.label}
    </span>
  );
}

function EntropyBar({ value }: { value: number }) {
  const pct = Math.min((value / 6) * 100, 100);
  const color = value >= 5 ? "#ff3b3b" : value >= 4 ? "#ff8c00" : value >= 3 ? "#e8b800" : "#00e5b0";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1 rounded-full" style={{ background: "#1a2535" }}>
        <div className="h-1 rounded-full transition-all" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="font-mono text-xs" style={{ color, minWidth: 32 }}>{value.toFixed(2)}</span>
    </div>
  );
}

function StatCard({ label, value, sub, accent }: { label: string; value: string | number; sub?: string; accent?: string }) {
  return (
    <div className="rounded p-4 flex flex-col gap-1" style={{ background: "#0d1117", border: "1px solid #1a2535" }}>
      <div className="font-mono text-xs" style={{ color: "#5a6a7a" }}>{label}</div>
      <div className="font-mono text-2xl font-bold" style={{ color: accent || "#c8d3dc" }}>{value}</div>
      {sub && <div className="font-mono text-xs" style={{ color: "#3a4a5a" }}>{sub}</div>}
    </div>
  );
}

function MiniBar({ label, value, max, color }: { label: string; value: number; max: number; color: string }) {
  return (
    <div className="flex items-center gap-3">
      <span className="font-mono text-xs w-16" style={{ color: "#5a6a7a" }}>{label}</span>
      <div className="flex-1 h-1.5 rounded-full" style={{ background: "#1a2535" }}>
        <div className="h-1.5 rounded-full" style={{ width: `${(value / max) * 100}%`, background: color }} />
      </div>
      <span className="font-mono text-xs w-4 text-right" style={{ color }}>{value}</span>
    </div>
  );
}

type Tab = "overview" | "findings" | "history" | "settings";

export default function App() {
  const [tab, setTab] = useState<Tab>("overview");
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [filterRisk, setFilterRisk] = useState<Risk | "ALL">("ALL");

  const totalScans = scanHistory.length;
  const blockedCommits = scanHistory.filter((s) => s.blocked).length;
  const activeFindings = findings.filter((f) => f.status === "ACTIVE").length;
  const resolvedFindings = findings.filter((f) => f.status === "RESOLVED").length;
  const criticalCount = findings.filter((f) => f.risk === "CRITICAL").length;
  const highCount = findings.filter((f) => f.risk === "HIGH").length;
  const complianceScore = Math.round(((totalScans - blockedCommits + resolvedFindings) / (totalScans + findings.length)) * 100);

  const filteredFindings = filterRisk === "ALL" ? findings : findings.filter((f) => f.risk === filterRisk);

  const tabs: { id: Tab; label: string }[] = [
    { id: "overview", label: "OVERVIEW" },
    { id: "findings", label: "FINDINGS" },
    { id: "history", label: "SCAN HISTORY" },
    { id: "settings", label: "CONFIG" },
  ];

  return (
    <div className="min-h-screen" style={{ background: "#080c10", color: "#c8d3dc" }}>
      {/* Header */}
      <header style={{ borderBottom: "1px solid #1a2535", background: "#0a0e14" }}>
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5">
              <div className="w-2 h-2 rounded-full" style={{ background: "#00e5b0", boxShadow: "0 0 6px #00e5b0" }} />
              <span className="font-mono text-xs font-semibold" style={{ color: "#00e5b0" }}>PROTECTED</span>
            </div>
            <div style={{ width: 1, height: 16, background: "#1a2535" }} />
            <span className="font-mono font-bold text-sm tracking-widest" style={{ color: "#c8d3dc" }}>SECRET LEAK DETECTOR</span>
          </div>
          <div className="flex items-center gap-6">
            <div className="font-mono text-xs" style={{ color: "#3a4a5a" }}>
              Last scan: <span style={{ color: "#5a6a7a" }}>2026-09-15 14:30:22</span>
            </div>
            <div
              className="font-mono text-xs font-semibold px-3 py-1 rounded-sm"
              style={{ background: "rgba(0,229,176,0.08)", color: "#00e5b0", border: "1px solid #00e5b022" }}
            >
              v2.4.1
            </div>
          </div>
        </div>
        {/* Tabs */}
        <div className="max-w-7xl mx-auto px-6 flex gap-0">
          {tabs.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className="font-mono text-xs font-semibold px-4 py-3 transition-all"
              style={{
                color: tab === t.id ? "#00e5b0" : "#3a4a5a",
                borderBottom: tab === t.id ? "2px solid #00e5b0" : "2px solid transparent",
                background: "transparent",
                cursor: "pointer",
                letterSpacing: "0.08em",
              }}
            >
              {t.label}
            </button>
          ))}
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-6 py-8">
        {/* OVERVIEW */}
        {tab === "overview" && (
          <div className="flex flex-col gap-8">
            {/* Stats row */}
            <div className="grid gap-4" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))" }}>
              <StatCard label="COMPLIANCE SCORE" value={`${complianceScore}%`} sub="workspace" accent="#00e5b0" />
              <StatCard label="TOTAL SCANS" value={totalScans} sub="all triggers" />
              <StatCard label="BLOCKED COMMITS" value={blockedCommits} sub="prevented leaks" accent="#ff3b3b" />
              <StatCard label="ACTIVE FINDINGS" value={activeFindings} sub="needs attention" accent="#ff8c00" />
              <StatCard label="RESOLVED" value={resolvedFindings} sub="remediated" accent="#00e5b0" />
              <StatCard label="FILES SCANNED" value={scanHistory.reduce((a, s) => a + s.filesScanned, 0)} sub="all-time" />
            </div>

            {/* Main grid */}
            <div className="grid gap-6" style={{ gridTemplateColumns: "1fr 340px" }}>
              {/* Recent findings */}
              <div className="rounded" style={{ background: "#0d1117", border: "1px solid #1a2535" }}>
                <div className="flex items-center justify-between px-5 py-4" style={{ borderBottom: "1px solid #1a2535" }}>
                  <span className="font-mono text-xs font-semibold tracking-widest" style={{ color: "#5a6a7a" }}>RECENT FINDINGS</span>
                  <button onClick={() => setTab("findings")} className="font-mono text-xs" style={{ color: "#00e5b0", cursor: "pointer", background: "none", border: "none" }}>
                    VIEW ALL →
                  </button>
                </div>
                <div>
                  {findings.slice(0, 4).map((f, i) => (
                    <div
                      key={f.id}
                      className="flex items-center gap-4 px-5 py-3.5 cursor-pointer transition-all"
                      style={{
                        borderBottom: i < 3 ? "1px solid #111820" : "none",
                      }}
                      onMouseEnter={(e) => (e.currentTarget.style.background = "#111820")}
                      onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                      onClick={() => { setSelectedFinding(f); setTab("findings"); }}
                    >
                      <div className="w-1 h-8 rounded-full flex-shrink-0" style={{ background: RISK_COLOR[f.risk] }} />
                      <div className="flex-1 min-w-0">
                        <div className="font-mono text-sm font-semibold" style={{ color: "#c8d3dc" }}>{f.type}</div>
                        <div className="font-mono text-xs" style={{ color: "#3a4a5a" }}>{f.file}:{f.line}</div>
                      </div>
                      <div className="flex items-center gap-3">
                        <RiskBadge risk={f.risk} />
                        <StatusBadge status={f.status} />
                        <span className="font-mono text-xs" style={{ color: "#3a4a5a", minWidth: 60 }}>
                          {f.confidence}% conf
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Right column */}
              <div className="flex flex-col gap-4">
                {/* Risk breakdown */}
                <div className="rounded p-5" style={{ background: "#0d1117", border: "1px solid #1a2535" }}>
                  <div className="font-mono text-xs font-semibold tracking-widest mb-4" style={{ color: "#5a6a7a" }}>RISK DISTRIBUTION</div>
                  <div className="flex flex-col gap-3">
                    <MiniBar label="CRITICAL" value={criticalCount} max={6} color="#ff3b3b" />
                    <MiniBar label="HIGH" value={highCount} max={6} color="#ff8c00" />
                    <MiniBar label="MEDIUM" value={findings.filter((f) => f.risk === "MEDIUM").length} max={6} color="#e8b800" />
                    <MiniBar label="LOW" value={findings.filter((f) => f.risk === "LOW").length} max={6} color="#00e5b0" />
                  </div>
                </div>

                {/* Type breakdown */}
                <div className="rounded p-5" style={{ background: "#0d1117", border: "1px solid #1a2535" }}>
                  <div className="font-mono text-xs font-semibold tracking-widest mb-4" style={{ color: "#5a6a7a" }}>SECRET TYPES</div>
                  <div className="flex flex-col gap-2">
                    {["AWS Access Key", "API Credential", "Database Password", "GitHub Token", "JWT Secret", "Connection String"].map((type) => {
                      const count = findings.filter((f) => f.type === type).length;
                      return (
                        <div key={type} className="flex items-center justify-between">
                          <span className="font-mono text-xs" style={{ color: "#5a6a7a" }}>{type}</span>
                          <span className="font-mono text-xs font-semibold" style={{ color: "#c8d3dc" }}>{count}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Scan trigger breakdown */}
                <div className="rounded p-5" style={{ background: "#0d1117", border: "1px solid #1a2535" }}>
                  <div className="font-mono text-xs font-semibold tracking-widest mb-4" style={{ color: "#5a6a7a" }}>TRIGGER BREAKDOWN</div>
                  <div className="flex flex-col gap-2">
                    {(["pre-commit", "pre-push", "manual", "workspace"] as const).map((trigger) => {
                      const count = scanHistory.filter((s) => s.trigger === trigger).length;
                      return (
                        <div key={trigger} className="flex items-center justify-between">
                          <span className="font-mono text-xs" style={{ color: "#5a6a7a" }}>{trigger}</span>
                          <span className="font-mono text-xs font-semibold" style={{ color: "#c8d3dc" }}>{count}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            </div>

            {/* Terminal output preview */}
            <div className="rounded" style={{ background: "#060a0e", border: "1px solid #1a2535" }}>
              <div className="flex items-center gap-2 px-5 py-3" style={{ borderBottom: "1px solid #1a2535" }}>
                <div className="w-2 h-2 rounded-full" style={{ background: "#ff3b3b" }} />
                <div className="w-2 h-2 rounded-full" style={{ background: "#ff8c00" }} />
                <div className="w-2 h-2 rounded-full" style={{ background: "#00e5b0" }} />
                <span className="font-mono text-xs ml-3" style={{ color: "#3a4a5a" }}>terminal — pre-commit hook output</span>
              </div>
              <div className="px-6 py-5 font-mono text-xs leading-relaxed" style={{ color: "#c8d3dc" }}>
                <div style={{ color: "#3a4a5a" }}>$ git commit -m "add configuration"</div>
                <div className="mt-3 mb-1" style={{ color: "#5a6a7a" }}>╔════════════════════════════════════════════╗</div>
                <div style={{ color: "#5a6a7a" }}>║       SECRET LEAK DETECTOR v2.4.1          ║</div>
                <div style={{ color: "#5a6a7a" }}>╚════════════════════════════════════════════╝</div>
                <div className="mt-2" style={{ color: "#ff3b3b" }}>✖ COMMIT BLOCKED</div>
                <div className="mt-2">Potential secret detected.</div>
                <div className="mt-2">
                  <span style={{ color: "#5a6a7a" }}>File:       </span>config/aws.env
                </div>
                <div>
                  <span style={{ color: "#5a6a7a" }}>Line:       </span>3
                </div>
                <div>
                  <span style={{ color: "#5a6a7a" }}>Type:       </span>AWS Access Key
                </div>
                <div>
                  <span style={{ color: "#5a6a7a" }}>Risk:       </span><span style={{ color: "#ff3b3b" }}>CRITICAL</span>
                </div>
                <div>
                  <span style={{ color: "#5a6a7a" }}>Confidence: </span>97%
                </div>
                <div>
                  <span style={{ color: "#5a6a7a" }}>Entropy:    </span>5.21
                </div>
                <div>
                  <span style={{ color: "#5a6a7a" }}>Value:      </span>[REDACTED]
                </div>
                <div className="mt-2">
                  <div style={{ color: "#5a6a7a" }}>Signals:</div>
                  <div>  <span style={{ color: "#00e5b0" }}>✓</span> Known credential format (AKIA...)</div>
                  <div>  <span style={{ color: "#00e5b0" }}>✓</span> High entropy (5.21 bits/char)</div>
                  <div>  <span style={{ color: "#00e5b0" }}>✓</span> Sensitive variable name</div>
                  <div>  <span style={{ color: "#00e5b0" }}>✓</span> Production configuration file</div>
                </div>
                <div className="mt-2" style={{ color: "#ff3b3b" }}>Commit aborted. Remove or replace the secret before committing.</div>
              </div>
            </div>
          </div>
        )}

        {/* FINDINGS */}
        {tab === "findings" && (
          <div className="flex gap-6">
            {/* Findings list */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-3 mb-5">
                <span className="font-mono text-xs font-semibold tracking-widest" style={{ color: "#5a6a7a" }}>FILTER:</span>
                {(["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((r) => (
                  <button
                    key={r}
                    onClick={() => setFilterRisk(r)}
                    className="font-mono text-xs font-semibold px-3 py-1 rounded-sm transition-all"
                    style={{
                      background: filterRisk === r ? (r === "ALL" ? "rgba(0,229,176,0.12)" : RISK_BG[r as Risk] || "rgba(0,229,176,0.12)") : "transparent",
                      color: filterRisk === r ? (r === "ALL" ? "#00e5b0" : RISK_COLOR[r as Risk] || "#00e5b0") : "#3a4a5a",
                      border: `1px solid ${filterRisk === r ? (r === "ALL" ? "#00e5b022" : (RISK_COLOR[r as Risk] || "#00e5b0") + "22") : "#1a2535"}`,
                      cursor: "pointer",
                    }}
                  >
                    {r}
                  </button>
                ))}
              </div>

              <div className="rounded overflow-hidden" style={{ border: "1px solid #1a2535" }}>
                {/* Table header */}
                <div
                  className="grid font-mono text-xs font-semibold px-5 py-3"
                  style={{
                    gridTemplateColumns: "1fr 180px 80px 100px 80px 90px",
                    background: "#0a0e14",
                    color: "#3a4a5a",
                    borderBottom: "1px solid #1a2535",
                    letterSpacing: "0.06em",
                  }}
                >
                  <span>TYPE / FILE</span>
                  <span>FINGERPRINT</span>
                  <span>ENTROPY</span>
                  <span>RISK</span>
                  <span>CONF</span>
                  <span>STATUS</span>
                </div>
                {filteredFindings.map((f, i) => (
                  <div
                    key={f.id}
                    className="grid items-center px-5 py-4 cursor-pointer transition-all"
                    style={{
                      gridTemplateColumns: "1fr 180px 80px 100px 80px 90px",
                      borderBottom: i < filteredFindings.length - 1 ? "1px solid #0f1419" : "none",
                      background: selectedFinding?.id === f.id ? "#111820" : "transparent",
                    }}
                    onMouseEnter={(e) => { if (selectedFinding?.id !== f.id) e.currentTarget.style.background = "#0d1117"; }}
                    onMouseLeave={(e) => { if (selectedFinding?.id !== f.id) e.currentTarget.style.background = "transparent"; }}
                    onClick={() => setSelectedFinding(selectedFinding?.id === f.id ? null : f)}
                  >
                    <div>
                      <div className="font-mono text-sm font-semibold" style={{ color: "#c8d3dc" }}>{f.type}</div>
                      <div className="font-mono text-xs mt-0.5" style={{ color: "#3a4a5a" }}>{f.file}:{f.line}</div>
                    </div>
                    <div className="font-mono text-xs" style={{ color: "#3a4a5a" }}>{f.fingerprint}</div>
                    <EntropyBar value={f.entropy} />
                    <RiskBadge risk={f.risk} />
                    <span className="font-mono text-xs" style={{ color: "#5a6a7a" }}>{f.confidence}%</span>
                    <StatusBadge status={f.status} />
                  </div>
                ))}
              </div>
            </div>

            {/* Detail panel */}
            {selectedFinding && (
              <div
                className="w-80 flex-shrink-0 rounded self-start sticky top-6"
                style={{ background: "#0d1117", border: "1px solid #1a2535" }}
              >
                <div className="flex items-center justify-between px-5 py-4" style={{ borderBottom: "1px solid #1a2535" }}>
                  <span className="font-mono text-xs font-semibold tracking-widest" style={{ color: "#5a6a7a" }}>FINDING DETAIL</span>
                  <button
                    onClick={() => setSelectedFinding(null)}
                    className="font-mono text-xs"
                    style={{ color: "#3a4a5a", cursor: "pointer", background: "none", border: "none" }}
                  >
                    ✕
                  </button>
                </div>
                <div className="px-5 py-4 flex flex-col gap-4">
                  <div>
                    <div className="font-mono text-base font-bold" style={{ color: "#c8d3dc" }}>{selectedFinding.type}</div>
                    <div className="font-mono text-xs mt-1" style={{ color: "#3a4a5a" }}>
                      {selectedFinding.file}:{selectedFinding.line}
                    </div>
                  </div>

                  <div className="flex gap-2 flex-wrap">
                    <RiskBadge risk={selectedFinding.risk} />
                    <StatusBadge status={selectedFinding.status} />
                  </div>

                  <div className="flex flex-col gap-2.5" style={{ borderTop: "1px solid #111820", paddingTop: 16 }}>
                    {[
                      ["Confidence", `${selectedFinding.confidence}%`],
                      ["Entropy", selectedFinding.entropy.toFixed(2)],
                      ["Commit", selectedFinding.commit],
                      ["First Seen", selectedFinding.firstSeen],
                      ["Last Seen", selectedFinding.lastSeen],
                      ["Fingerprint", selectedFinding.fingerprint],
                    ].map(([k, v]) => (
                      <div key={k} className="flex flex-col gap-0.5">
                        <span className="font-mono text-xs" style={{ color: "#3a4a5a" }}>{k}</span>
                        <span className="font-mono text-xs" style={{ color: "#c8d3dc", wordBreak: "break-all" }}>{v}</span>
                      </div>
                    ))}
                  </div>

                  <div style={{ borderTop: "1px solid #111820", paddingTop: 16 }}>
                    <div className="font-mono text-xs mb-2" style={{ color: "#3a4a5a" }}>Detection Signals</div>
                    <div className="flex flex-col gap-1.5">
                      {selectedFinding.signals.map((s) => (
                        <div key={s} className="flex items-start gap-2">
                          <span style={{ color: "#00e5b0" }}>✓</span>
                          <span className="font-mono text-xs" style={{ color: "#8b9aaa" }}>{s}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div style={{ borderTop: "1px solid #111820", paddingTop: 16 }}>
                    <div className="font-mono text-xs mb-2" style={{ color: "#3a4a5a" }}>Value</div>
                    <div
                      className="font-mono text-xs px-3 py-2 rounded-sm"
                      style={{ background: "#060a0e", color: "#3a4a5a", border: "1px solid #1a2535" }}
                    >
                      [REDACTED — never stored]
                    </div>
                  </div>

                  <div style={{ borderTop: "1px solid #111820", paddingTop: 16 }}>
                    <div className="font-mono text-xs mb-2" style={{ color: "#3a4a5a" }}>Remediation</div>
                    <div className="font-mono text-xs flex flex-col gap-1.5" style={{ color: "#8b9aaa" }}>
                      <div>1. Remove the hard-coded credential</div>
                      <div>2. Replace with environment variable</div>
                      <div>3. Add sensitive file to .gitignore</div>
                      <div>4. Rotate the credential if exposed</div>
                      <div>5. Re-run scanner to confirm clean</div>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* SCAN HISTORY */}
        {tab === "history" && (
          <div>
            <div className="rounded overflow-hidden" style={{ border: "1px solid #1a2535" }}>
              <div
                className="grid font-mono text-xs font-semibold px-5 py-3"
                style={{
                  gridTemplateColumns: "200px 120px 100px 80px 80px 100px",
                  background: "#0a0e14",
                  color: "#3a4a5a",
                  borderBottom: "1px solid #1a2535",
                  letterSpacing: "0.06em",
                }}
              >
                <span>TIMESTAMP</span>
                <span>TRIGGER</span>
                <span>FILES</span>
                <span>FINDINGS</span>
                <span>DURATION</span>
                <span>RESULT</span>
              </div>
              {scanHistory.map((s, i) => (
                <div
                  key={s.id}
                  className="grid items-center px-5 py-3.5"
                  style={{
                    gridTemplateColumns: "200px 120px 100px 80px 80px 100px",
                    borderBottom: i < scanHistory.length - 1 ? "1px solid #0f1419" : "none",
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = "#0d1117")}
                  onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                >
                  <span className="font-mono text-xs" style={{ color: "#8b9aaa" }}>{s.timestamp}</span>
                  <span
                    className="font-mono text-xs"
                    style={{
                      color: s.trigger === "pre-commit" ? "#00b4e0" : s.trigger === "pre-push" ? "#8b5cf6" : "#5a6a7a",
                    }}
                  >
                    {s.trigger}
                  </span>
                  <span className="font-mono text-xs" style={{ color: "#5a6a7a" }}>{s.filesScanned}</span>
                  <span className="font-mono text-xs font-semibold" style={{ color: s.findings > 0 ? "#ff3b3b" : "#5a6a7a" }}>
                    {s.findings}
                  </span>
                  <span className="font-mono text-xs" style={{ color: "#3a4a5a" }}>{s.duration}ms</span>
                  <span>
                    {s.blocked ? (
                      <span className="font-mono text-xs font-semibold" style={{ color: "#ff3b3b" }}>✖ BLOCKED</span>
                    ) : (
                      <span className="font-mono text-xs font-semibold" style={{ color: "#00e5b0" }}>✓ CLEAN</span>
                    )}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* CONFIG */}
        {tab === "settings" && (
          <div className="grid gap-6" style={{ gridTemplateColumns: "1fr 1fr" }}>
            {[
              {
                title: "SCANNER",
                fields: [
                  { key: "entropy_threshold", value: "4.0", desc: "Minimum entropy to flag a string" },
                  { key: "minimum_secret_length", value: "12", desc: "Minimum length of candidate secret" },
                  { key: "block_threshold", value: "60", desc: "Risk score threshold for blocking (0–100)" },
                ],
              },
              {
                title: "GIT HOOKS",
                fields: [
                  { key: "pre_commit", value: "enabled", desc: "Block commits containing secrets" },
                  { key: "pre_push", value: "enabled", desc: "Block pushes containing secrets" },
                  { key: "scan_history", value: "optional", desc: "Scan Git history for past leaks" },
                ],
              },
              {
                title: "SECURITY",
                fields: [
                  { key: "store_raw_secrets", value: "false — immutable", desc: "Raw secrets are never persisted" },
                  { key: "send_secrets_to_ai", value: "false — immutable", desc: "AI never receives raw secret values" },
                  { key: "telemetry", value: "disabled", desc: "No usage data sent to external services" },
                  { key: "external_verification", value: "disabled", desc: "No credential verification against provider APIs" },
                ],
              },
              {
                title: "BLOCKING POLICY",
                fields: [
                  { key: "LOW (0–29)", value: "ALLOW", desc: "Commit and push proceed" },
                  { key: "MEDIUM (30–59)", value: "WARN", desc: "Warning shown, commit allowed" },
                  { key: "HIGH (60–79)", value: "BLOCK", desc: "Commit and push prevented" },
                  { key: "CRITICAL (80–100)", value: "BLOCK", desc: "Commit and push prevented" },
                ],
              },
            ].map((section) => (
              <div key={section.title} className="rounded" style={{ background: "#0d1117", border: "1px solid #1a2535" }}>
                <div className="px-5 py-4" style={{ borderBottom: "1px solid #1a2535" }}>
                  <span className="font-mono text-xs font-semibold tracking-widest" style={{ color: "#5a6a7a" }}>{section.title}</span>
                </div>
                <div className="px-5 py-4 flex flex-col gap-4">
                  {section.fields.map((f) => (
                    <div key={f.key} className="flex items-start justify-between gap-4">
                      <div>
                        <div className="font-mono text-xs font-semibold" style={{ color: "#8b9aaa" }}>{f.key}</div>
                        <div className="font-mono text-xs mt-0.5" style={{ color: "#3a4a5a" }}>{f.desc}</div>
                      </div>
                      <div
                        className="font-mono text-xs font-semibold px-2 py-0.5 rounded-sm flex-shrink-0"
                        style={{
                          color: f.value.includes("false") || f.value.includes("disabled") ? "#3a4a5a"
                            : f.value === "BLOCK" ? "#ff3b3b"
                            : f.value === "WARN" ? "#e8b800"
                            : f.value === "ALLOW" || f.value === "enabled" ? "#00e5b0"
                            : "#8b9aaa",
                          background: "#060a0e",
                          border: "1px solid #1a2535",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {f.value}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}

            {/* Commands reference */}
            <div className="rounded col-span-2" style={{ background: "#060a0e", border: "1px solid #1a2535" }}>
              <div className="px-5 py-4" style={{ borderBottom: "1px solid #1a2535" }}>
                <span className="font-mono text-xs font-semibold tracking-widest" style={{ color: "#5a6a7a" }}>VS CODE COMMANDS</span>
              </div>
              <div className="px-5 py-4 grid gap-2" style={{ gridTemplateColumns: "1fr 1fr" }}>
                {[
                  "Secret Leak Detector: Scan Workspace",
                  "Secret Leak Detector: Scan Staged Files",
                  "Secret Leak Detector: Scan Git History",
                  "Secret Leak Detector: Install Git Hooks",
                  "Secret Leak Detector: Uninstall Git Hooks",
                  "Secret Leak Detector: Open Security Dashboard",
                  "Secret Leak Detector: Show Last Scan",
                  "Secret Leak Detector: Rescan",
                ].map((cmd) => (
                  <div key={cmd} className="flex items-center gap-2">
                    <span style={{ color: "#00e5b0" }}>›</span>
                    <span className="font-mono text-xs" style={{ color: "#5a6a7a" }}>{cmd}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
