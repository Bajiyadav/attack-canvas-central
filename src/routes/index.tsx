import { createFileRoute } from "@tanstack/react-router";
import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { Activity, AlertTriangle, ArrowDownRight, ArrowRight, Bot, Check, ChevronDown, CircleDot, Cloud, Crosshair, Database, Folder, KeyRound, LockKeyhole, MessageSquare, Network, Play, RotateCcw, Search, Send, Shield, ShieldAlert, ShieldCheck, Terminal, X, Zap } from "lucide-react";
import { Button } from "@/components/ui/button";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "AegisGraph | Incident Command Center" },
      { name: "description", content: "Live cloud incident response, attack-path visibility, and blast-radius containment." },
      { property: "og:title", content: "AegisGraph | Incident Command Center" },
      { property: "og:description", content: "Live cloud incident response, attack-path visibility, and blast-radius containment." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: CommandCenter,
});

type NodeType = "Pod" | "IAM Role" | "S3 Bucket" | "Database" | "Vulnerability";
type GraphNode = { id: string; label: string; name: string; status?: string; type?: NodeType; properties?: Record<string, unknown>; x?: number; y?: number };
type GraphEdge = { id: string; source: string; target: string; type: string; properties?: Record<string, unknown> };
type Trace = { step: number; phase: string; query?: string; action?: string; detail?: string; ms?: number };

const initialNodes: GraphNode[] = [
  { id: "pod-ingress-7b4d", label: "Pod", name: "pod-ingress-7b4d", status: "compromised", type: "Pod", x: 110, y: 276, properties: { namespace: "production", image: "nginx:1.24.0", vulnerability: "CVE-2026-9912", exposure: "Public ingress" } },
  { id: "cve-2026-9912", label: "Vulnerability", name: "CVE-2026-9912", status: "critical", type: "Vulnerability", x: 110, y: 102, properties: { cvss: 9.8, severity: "Critical", patched: false } },
  { id: "pod-api-65c2", label: "Pod", name: "pod-api-65c2", status: "healthy", type: "Pod", x: 316, y: 276, properties: { namespace: "production", image: "api:4.18.2", replicas: 3 } },
  { id: "iam-prod-reader", label: "IAM Role", name: "iam-prod-reader", status: "exposed", type: "IAM Role", x: 500, y: 276, properties: { permissions: "s3:GetObject · rds:Connect", trust: "service-account" } },
  { id: "s3-customer-export", label: "S3 Bucket", name: "s3-customer-export", status: "healthy", type: "S3 Bucket", x: 500, y: 482, properties: { encryption: "AES-256", access: "Private", objects: 18420 } },
  { id: "rds-customer-prod", label: "Database", name: "rds-customer-prod", status: "crown-jewel", type: "Database", x: 714, y: 276, properties: { classification: "Restricted · PII", records: "2,400,000", encryption: "At rest" } },
  { id: "vault-prod-secrets", label: "S3 Bucket", name: "vault-prod-secrets", status: "healthy", type: "S3 Bucket", x: 316, y: 482, properties: { classification: "Confidential", access: "IAM only" } },
  { id: "pod-worker-8a19", label: "Pod", name: "pod-worker-8a19", status: "healthy", type: "Pod", x: 714, y: 482, properties: { namespace: "jobs", image: "worker:2.1.0", replicas: 2 } },
];
const initialEdges: GraphEdge[] = [
  { id: "e1", source: "pod-ingress-7b4d", target: "cve-2026-9912", type: "EXPOSES" },
  { id: "e2", source: "pod-ingress-7b4d", target: "pod-api-65c2", type: "ROUTES_TO" },
  { id: "e3", source: "pod-api-65c2", target: "iam-prod-reader", type: "ASSUMES_ROLE" },
  { id: "e4", source: "iam-prod-reader", target: "vault-prod-secrets", type: "CAN_READ" },
  { id: "e5", source: "iam-prod-reader", target: "rds-customer-prod", type: "UNLOCKS_DATABASE" },
  { id: "e6", source: "vault-prod-secrets", target: "pod-worker-8a19", type: "EXPOSES_SECRET" },
  { id: "e7", source: "pod-worker-8a19", target: "rds-customer-prod", type: "CAN_READ" },
  { id: "e8", source: "pod-api-65c2", target: "vault-prod-secrets", type: "CAN_READ" },
];
const chain = ["pod-ingress-7b4d", "pod-api-65c2", "iam-prod-reader", "rds-customer-prod"];
const edgeChain = ["e2", "e3", "e5"];
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const nodePosition: Record<string, { x: number; y: number }> = Object.fromEntries(initialNodes.map((node) => [node.id, { x: node.x ?? 0, y: node.y ?? 0 }]));
const typeIcon = (type?: string) => type === "Pod" ? Cloud : type === "IAM Role" ? KeyRound : type === "Database" ? Database : type === "Vulnerability" ? ShieldAlert : Folder;

async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, { ...options, headers: { "Content-Type": "application/json", ...options?.headers } });
  if (!response.ok) throw new Error(`Request failed (${response.status})`);
  return response.json() as Promise<T>;
}

function CommandCenter() {
  const [nodes, setNodes] = useState(initialNodes);
  const [edges, setEdges] = useState(initialEdges);
  const [selectedId, setSelectedId] = useState(initialNodes[0].id);
  const [status, setStatus] = useState<"breach" | "investigating" | "contained">("breach");
  const [assetQuery, setAssetQuery] = useState("");
  const [breachTarget, setBreachTarget] = useState(initialNodes[0].id);
  const [trace, setTrace] = useState<Trace[]>([]);
  const [isAssistantOpen, setIsAssistantOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<"log" | "inspector">("log");
  const [messages, setMessages] = useState<{ from: "operator" | "agent"; text: string }[]>([{ from: "agent", text: "Incident copilot online. Ask about attack paths, affected assets, or containment." }]);
  const [chatInput, setChatInput] = useState("");
  const [backendConnected, setBackendConnected] = useState(false);
  const selected = nodes.find((node) => node.id === selectedId) ?? nodes[0];
  const visibleNodes = useMemo(() => nodes.filter((node) => `${node.name} ${node.label}`.toLowerCase().includes(assetQuery.toLowerCase())), [nodes, assetQuery]);
  const isCompromised = status !== "contained";
  const reachableCount = isCompromised ? 4 : 0;

  useEffect(() => {
    let alive = true;
    Promise.all([api<{ nodes: GraphNode[]; edges: GraphEdge[] }>("/api/graph"), api<GraphNode[]>("/api/nodes")]).then(([graph, available]) => {
      if (!alive || !graph.nodes?.length) return;
      setNodes(graph.nodes.map((node) => ({ ...node, type: node.type ?? node.label as NodeType, ...nodePosition[node.id] })));
      setEdges(graph.edges ?? []);
      setBackendConnected(true);
      if (available?.length) setBreachTarget(available[0].id);
    }).catch(() => { if (alive) setBackendConnected(false); });
    return () => { alive = false; };
  }, []);

  const investigate = useCallback(async () => {
    if (status === "investigating") return;
    setStatus("investigating");
    setActiveTab("log");
    const fallback: Trace[] = [
      { step: 1, phase: "INGRESS DETECTED", query: "MATCH (p:Pod {id:'pod-ingress-7b4d'})-[:EXPOSES]->(v:Vulnerability)", detail: "CVE-2026-9912 confirmed · CVSS 9.8 · public-facing pod", ms: 12 },
      { step: 2, phase: "ATTACK PATH TRAVERSED", query: "MATCH path = (p:Pod)-[*1..5]->(d:Database) RETURN path", detail: "4-hop chain found · 2,400,000 PII records within blast radius", ms: 38 },
      { step: 3, phase: "TOXIC PERMISSION SEVERED", action: "DELETE relationship (iam-prod-reader)-[:UNLOCKS_DATABASE]->(rds-customer-prod)", detail: "IAM trust edge revoked · lateral movement contained", ms: 64 },
      { step: 4, phase: "ZERO-TRUST VERIFIED", query: "MATCH path = (p:Pod)-[*1..5]->(d:Database) RETURN count(path)", detail: "Reachable paths: 0 · containment verified", ms: 83 },
    ];
    setTrace(fallback.slice(0, 1));
    try {
      const result = await api<{ trace?: Trace[]; status?: string; final_summary?: string; post_remediation?: unknown }>("/api/investigate", { method: "POST", body: JSON.stringify({ node_id: breachTarget }) });
      const actual = result.trace?.length ? result.trace : fallback;
      for (let i = 1; i <= actual.length; i++) {
        await new Promise((resolve) => window.setTimeout(resolve, 450));
        setTrace(actual.slice(0, i));
      }
      setBackendConnected(true);
    } catch {
      for (let i = 1; i <= fallback.length; i++) {
        await new Promise((resolve) => window.setTimeout(resolve, 450));
        setTrace(fallback.slice(0, i));
      }
    }
    setEdges((current) => current.filter((edge) => edge.id !== "e5"));
    setNodes((current) => current.map((node) => node.id === "pod-ingress-7b4d" ? { ...node, status: "quarantined" } : node));
    setStatus("contained");
  }, [breachTarget, status]);

  const reset = async () => {
    try { await api("/api/reset-graph", { method: "POST" }); setBackendConnected(true); } catch { setBackendConnected(false); }
    setNodes(initialNodes);
    setEdges(initialEdges);
    setTrace([]);
    setStatus("breach");
    setSelectedId("pod-ingress-7b4d");
  };

  const simulateBreach = async () => {
    try { await api("/api/simulate-breach", { method: "POST", body: JSON.stringify({ node_id: breachTarget }) }); setBackendConnected(true); } catch { setBackendConnected(false); }
    setNodes((current) => current.map((node) => node.id === breachTarget ? { ...node, status: "compromised" } : node));
    setSelectedId(breachTarget);
    setTrace([]);
    setEdges(initialEdges);
    setStatus("breach");
  };

  const sendMessage = async (event: FormEvent) => {
    event.preventDefault();
    const question = chatInput.trim();
    if (!question) return;
    setMessages((current) => [...current, { from: "operator", text: question }]);
    setChatInput("");
    try {
      const result = await api<{ response: string }>("/api/chat", { method: "POST", body: JSON.stringify({ message: question, asset_id: selected?.id }) });
      setMessages((current) => [...current, { from: "agent", text: result.response }]);
      setBackendConnected(true);
    } catch {
      const reply = question.toLowerCase().includes("shortest") || question.toLowerCase().includes("path")
        ? isCompromised ? "Shortest path: pod-ingress-7b4d → pod-api-65c2 → iam-prod-reader → rds-customer-prod. Three trust edges expose 2.4M customer records." : "No active path. The IAM-to-database trust edge was severed and zero reachable paths were verified."
        : question.toLowerCase().includes("why") ? "The IAM role carried an unrestricted database trust path from a compromised public ingress. Severing that edge stopped lateral movement while preserving the role's other access." : "I found the active ingress-to-database chain through iam-prod-reader. The exposed trust edge was removed; zero paths to the customer database remain. Select an asset to inspect its current properties.";
      setMessages((current) => [...current, { from: "agent", text: reply }]);
    }
  };

  return (
    <main className="command-shell">
      <header className="topbar">
        <a className="brand-lockup" href="#main" aria-label="AegisGraph home"><span className="brand-mark"><Shield size={20} /><span className="radar-pulse" /></span><span><strong>Aegis<span>Graph</span></strong><small>INCIDENT COMMAND</small></span></a>
        <div className="system-status"><span className="system-chip"><span className={`status-led ${backendConnected ? "led-green" : "led-amber"}`} />GRAPH ENGINE <b>{backendConnected ? "FALKORDB · ONLINE" : "MOCK GRAPH · READY"}</b></span><span className="system-chip reasoning"><span className="status-led led-cyan" />REASONING <b>GEMINI</b></span><span className="track-label">TRACK 01 <i>·</i> AGENTS THAT ACT ON CONNECTED DATA</span></div>
        <div className={`breach-pill ${status === "contained" ? "contained" : ""}`}><span className="breach-dot" />{status === "contained" ? "CONTAINED · 0.0 SECURE" : status === "investigating" ? "AUTONOMOUS RESPONSE ACTIVE" : "BREACH DETECTED · CVE-2026-9912"}<small>{status === "contained" ? "VERIFIED" : "CVSS 9.8 · CRITICAL"}</small></div>
        <div className="top-actions"><Button onClick={investigate} disabled={status === "investigating"} className="action-primary"><Zap size={15} />{status === "investigating" ? "INVESTIGATING…" : status === "contained" ? "RE-INVESTIGATE" : "AUTONOMOUS RESPONSE"}</Button><Button variant="outline" onClick={reset} className="action-reset" aria-label="Reset topology" title="Reset topology"><RotateCcw size={15} /><span>RESET</span></Button><Button variant="outline" onClick={() => setIsAssistantOpen((open) => !open)} className="action-assistant"><MessageSquare size={15} /><span>AI COPILOT</span></Button></div>
      </header>

      <div className="incident-strip"><div><span className="live-indicator"><span /> LIVE INCIDENT</span><span className="strip-divider" /><span className="mono">INC-2026-1042</span><span className="strip-divider" /><span>PRODUCTION / US-EAST-1</span></div><span className="incident-time"><span className="status-led led-green" /> TELEMETRY STREAMING <i>·</i> 00:04:32</span></div>

      <div className="workspace" id="main">
        <aside className="left-rail">
          <section className="rail-section overview-section"><div className="section-eyebrow"><span>INCIDENT OVERVIEW</span><span className="eyebrow-code">01 / 04</span></div><div className="risk-heading"><div><span className="metric-label">BLAST RADIUS</span><strong className={status === "contained" ? "metric-contained" : ""}>{reachableCount}<small> assets</small></strong></div><div className={`risk-donut ${status === "contained" ? "donut-safe" : ""}`}><span>{status === "contained" ? "0.0" : "9.8"}</span><small>RISK</small></div></div><div className="risk-meter"><span style={{ width: status === "contained" ? "2%" : "94%" }} /></div><div className="metric-foot"><span>{status === "contained" ? "THREAT NEUTRALIZED" : "CRITICAL EXPOSURE"}</span><span className="mono">CVSS {status === "contained" ? "0.0" : "9.8"}</span></div><div className="pii-exposure"><div className="pii-icon"><Database size={16} /></div><div><span>PII RECORDS AT RISK</span><strong>{status === "contained" ? "0" : "2,400,000"}</strong></div><span className="pii-unit">RECORDS</span></div></section>

          <section className="rail-section asset-section"><div className="section-eyebrow"><span>ASSET INVENTORY</span><span className="count-tag">{nodes.length.toString().padStart(2, "0")}</span></div><label className="asset-search"><Search size={14} /><input value={assetQuery} onChange={(event) => setAssetQuery(event.target.value)} placeholder="Filter assets…" /><kbd>/</kbd></label><div className="asset-list">{visibleNodes.map((node) => { const Icon = typeIcon(node.type); return <button key={node.id} className={`asset-row ${selectedId === node.id ? "asset-selected" : ""}`} onClick={() => { setSelectedId(node.id); setActiveTab("inspector"); }}><span className={`asset-icon type-${(node.type ?? "pod").toLowerCase().replace(" ", "-")}`}><Icon size={14} /></span><span className="asset-copy"><strong>{node.name}</strong><small>{node.label.toUpperCase()}</small></span><span className={`asset-health health-${node.status ?? "healthy"}`} /></button>; })}{visibleNodes.length === 0 && <div className="empty-assets">No matching assets</div>}</div></section>

          <section className="rail-section simulate-section"><div className="section-eyebrow"><span>BREACH SIMULATOR</span><span className="sim-ready"><CircleDot size={11} /> READY</span></div><label className="select-wrap"><select value={breachTarget} onChange={(event) => setBreachTarget(event.target.value)}>{nodes.map((node) => <option key={node.id} value={node.id}>{node.name}</option>)}</select><ChevronDown size={14} /></label><Button variant="outline" className="simulate-button" onClick={simulateBreach}><Play size={13} /> SIMULATE BREACH</Button></section>

          <div className="left-footer"><span><LockKeyhole size={12} /> ZERO-TRUST ENFORCED</span><span className="mono">AEGIS v2.6.1</span></div>
        </aside>

        <section className="graph-panel" aria-label="Interactive attack graph"><div className="graph-toolbar"><div className="graph-title"><Network size={15} /><span>ATTACK SURFACE</span><span className="graph-subtitle">· LIVE TOPOLOGY</span></div><div className="graph-tools"><span className="node-count">{nodes.length} NODES <i>/</i> {edges.length} EDGES</span><Button variant="ghost" size="icon" className="icon-action" onClick={() => setSelectedId("pod-ingress-7b4d")} title="Focus ingress" aria-label="Focus ingress"><Crosshair size={15} /></Button></div></div>
          <div className="graph-canvas"><div className="canvas-grid" /><div className="zone-label zone-edge">EXTERNAL EDGE <span>UNTRUSTED</span></div><div className="zone-label zone-workload">COMPUTE LAYER <span>PRODUCTION</span></div><div className="zone-label zone-data">DATA PLANE <span>RESTRICTED</span></div><div className="graph-vignette" />
            <svg className="topology-svg" viewBox="0 0 820 590" role="img" aria-label="Cloud asset attack path topology" preserveAspectRatio="xMidYMid meet"><defs><marker id="arrow-dim" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0 0 L8 4 L0 8" className="arrow-dim" /></marker><marker id="arrow-threat" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto"><path d="M0 0 L9 4.5 L0 9" className="arrow-threat" /></marker><marker id="arrow-safe" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0 0 L8 4 L0 8" className="arrow-safe" /></marker></defs>
              {edges.map((edge) => { const from = nodePosition[edge.source]; const to = nodePosition[edge.target]; if (!from || !to) return null; const hot = isCompromised && edgeChain.includes(edge.id); const severed = status === "contained" && edge.id === "e5"; const path = `M ${from.x + 46} ${from.y + 30} C ${(from.x + to.x) / 2 + 20} ${from.y + 30}, ${(from.x + to.x) / 2 - 20} ${to.y + 30}, ${to.x + 46} ${to.y + 30}`; return <g key={edge.id} className={severed ? "edge-severed" : ""}><path d={path} className={`graph-edge ${hot ? "edge-hot" : ""} ${status === "contained" && !severed ? "edge-secure" : ""}`} markerEnd={hot ? "url(#arrow-threat)" : status === "contained" ? "url(#arrow-safe)" : "url(#arrow-dim)"} /><text className={`edge-label ${hot ? "edge-label-hot" : ""}`} x={(from.x + to.x) / 2 + 44} y={(from.y + to.y) / 2 + 19}>{edge.type}</text>{hot && status !== "contained" && <circle className="edge-particle" r="3"><animateMotion dur="1.7s" repeatCount="indefinite" path={path} /></circle>}</g>; })}
              {nodes.map((node) => { const pos = nodePosition[node.id]; if (!pos) return null; const Icon = typeIcon(node.type); const isSelected = selectedId === node.id; const compromised = node.status === "compromised" && isCompromised; const quarantined = node.status === "quarantined" || (node.id === "pod-ingress-7b4d" && status === "contained"); const jewel = node.status === "crown-jewel"; const vulnerability = node.type === "Vulnerability"; return <g key={node.id} className={`graph-node ${isSelected ? "node-selected" : ""} ${compromised ? "node-compromised" : ""} ${quarantined ? "node-quarantined" : ""} ${jewel ? "node-jewel" : ""} ${vulnerability ? "node-vulnerability" : ""}`} transform={`translate(${pos.x},${pos.y})`} onClick={() => { setSelectedId(node.id); setActiveTab("inspector"); }} tabIndex={0} role="button" aria-label={`Inspect ${node.name}`} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { setSelectedId(node.id); setActiveTab("inspector"); } }}><rect className="node-halo" x="-5" y="-5" width="102" height="72" rx="5" /><rect className="node-box" width="92" height="62" rx="3" /><foreignObject x="10" y="11" width="20" height="20"><div className="node-icon-wrap"><Icon size={15} /></div></foreignObject><text className="node-kind" x="36" y="20">{node.type?.toUpperCase()}</text><text className="node-name" x="10" y="43">{node.name.length > 15 ? `${node.name.slice(0, 14)}…` : node.name}</text><circle className="node-status-dot" cx="81" cy="15" r="3" /></g>; })}
            </svg><div className="graph-legend"><span><i className="legend-red" />COMPROMISED</span><span><i className="legend-cyan" />TRUST PATH</span><span><i className="legend-green" />SECURE</span></div><div className="graph-scale">TOPOLOGY: CLOUD / US-EAST-1 <span>·</span> UPDATED JUST NOW</div>
          </div>
          <div className="path-ribbon"><div className="path-ribbon-title"><AlertTriangle size={13} /><span>{status === "contained" ? "ATTACK PATH CONTAINED" : "PRIMARY ATTACK CHAIN"}</span><span className="chain-count">{status === "contained" ? "SEVERED" : "3 EDGES · 4 HOPS"}</span></div><div className="chain-flow">{chain.map((id, index) => { const node = nodes.find((item) => item.id === id) ?? initialNodes.find((item) => item.id === id); return <span className={`chain-node ${status === "contained" && index > 2 ? "chain-safe" : ""}`} key={id} onClick={() => setSelectedId(id)}>{node?.name}<ArrowRight size={12} /></span>; })}<span className="chain-target">CUSTOMER PII</span></div></div>
        </section>

        <aside className="right-rail"><div className="copilot-head"><div><span className="copilot-icon"><Bot size={17} /></span><div><strong>COMMAND COPILOT</strong><small><span className="status-led led-green" /> AUTONOMOUS AGENT</small></div></div><Button variant="ghost" size="icon" className="icon-action mobile-copilot-toggle" onClick={() => setIsAssistantOpen((open) => !open)} aria-label="Toggle assistant"><MessageSquare size={15} /></Button></div>
          <div className="right-tabs"><button className={activeTab === "log" ? "tab-active" : ""} onClick={() => setActiveTab("log")}><Activity size={13} /> ACTION LOG<span className="tab-count">{trace.length || "04"}</span></button><button className={activeTab === "inspector" ? "tab-active" : ""} onClick={() => setActiveTab("inspector")}><Crosshair size={13} /> INSPECTOR</button></div>
          <div className="right-content">{activeTab === "log" ? <div className="timeline-wrap"><div className="timeline-status"><span className={`status-led ${status === "contained" ? "led-green" : status === "investigating" ? "led-amber" : "led-red"}`} />{status === "contained" ? "REMEDIATION COMPLETE" : status === "investigating" ? "INVESTIGATION IN PROGRESS" : "AWAITING RESPONSE"}<span className="mono">{status === "contained" ? "83 ms" : "LIVE"}</span></div>{(trace.length ? trace : [{ step: 1, phase: "INGRESS POD DETECTED", detail: "Critical vulnerability surfaced on a public-facing workload.", ms: 12 }, { step: 2, phase: "MULTI-HOP TRAVERSAL", query: "MATCH path = (p:Pod)-[*1..5]->(d:Database)", detail: "Tracing identity edges and downstream data access.", ms: 38 }, { step: 3, phase: "TOXIC IAM EDGE", action: "iam-prod-reader → rds-customer-prod", detail: "High-risk trust relationship identified for containment.", ms: 64 }, { step: 4, phase: "ZERO-TRUST VERIFY", detail: "Awaiting autonomous containment and path verification.", ms: 83 }]).map((step, index) => <article className={`trace-step ${index < trace.length && trace.length > 0 ? "trace-complete" : ""}`} key={`${step.step}-${step.phase}`}><div className="trace-marker"><span>{status === "contained" && index < trace.length ? <Check size={10} /> : String(step.step).padStart(2, "0")}</span></div><div className="trace-body"><div className="trace-heading"><strong>{step.phase}</strong><time>{step.ms ? `${step.ms} ms` : "READY"}</time></div>{step.query && <code>{step.query}</code>}{step.action && <code className="trace-action">{step.action}</code>}<p>{step.detail}</p></div></article>)}<div className="trace-footer"><Terminal size={13} /><span>AGENT REASONING TRACE</span><span className="mono">LATENCY 83ms</span></div></div> : <div className="inspector-pane"><div className="inspector-asset"><span className={`asset-icon type-${(selected?.type ?? "pod").toLowerCase().replace(" ", "-")}`}>{(() => { const Icon = typeIcon(selected?.type); return <Icon size={17} />; })()}</span><div><small>{selected?.type?.toUpperCase() ?? "ASSET"}</small><strong>{selected?.name}</strong></div></div><div className="inspector-risk"><span>RISK STATE</span><strong className={`health-text-${selected?.status ?? "healthy"}`}><span className={`asset-health health-${selected?.status ?? "healthy"}`} />{(selected?.status ?? "healthy").replace("-", " ").toUpperCase()}</strong></div><div className="property-list">{Object.entries(selected?.properties ?? {}).map(([key, value]) => <div key={key}><span>{key.replaceAll("_", " ").toUpperCase()}</span><strong>{String(value)}</strong></div>)}</div><div className="inspector-connections"><div className="mini-heading">CONNECTED RELATIONSHIPS <span>{edges.filter((edge) => edge.source === selected?.id || edge.target === selected?.id).length}</span></div>{edges.filter((edge) => edge.source === selected?.id || edge.target === selected?.id).map((edge) => <div className="relation-row" key={edge.id}><ArrowDownRight size={12} /><span>{edge.source === selected?.id ? edge.target : edge.source}</span><small>{edge.type}</small></div>)}</div></div>}</div>
          <div className={`assistant-terminal ${isAssistantOpen ? "assistant-expanded" : ""}`}><div className="terminal-title"><span><Terminal size={13} /> AI SECOPS TERMINAL</span><span className="terminal-live"><i /> READY</span></div><div className="chat-messages" aria-live="polite">{messages.map((message, index) => <div key={`${index}-${message.from}`} className={`chat-message ${message.from === "operator" ? "chat-operator" : "chat-agent"}`}><span>{message.from === "operator" ? "OPERATOR" : "AGENT"}</span><p>{message.text}</p></div>)}</div><form className="chat-form" onSubmit={sendMessage}><input value={chatInput} onChange={(event) => setChatInput(event.target.value)} placeholder="Ask about this incident…" aria-label="Ask the SecOps assistant" /><Button variant="ghost" size="icon" className="send-button" type="submit" aria-label="Send message"><Send size={14} /></Button></form><div className="terminal-hint">{selected?.name ?? "GLOBAL"} <span>·</span> CONTEXT ATTACHED</div></div>
        </aside>
      </div>
      <footer className="bottom-status"><span><span className="status-led led-green" /> ALL SYSTEMS OPERATIONAL</span><span className="bottom-center">AEGISGRAPH <i>·</i> AUTONOMOUS INCIDENT COMMANDER</span><span>SECURE CHANNEL <LockKeyhole size={11} /></span></footer>
    </main>
  );
}
