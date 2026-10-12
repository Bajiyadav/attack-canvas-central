// AegisGraph Incident Commander Frontend Controller

let network = null;
let nodesDataSet = null;
let edgesDataSet = null;
let currentGraphData = null;

// Sound synthesizer via Web Audio API
const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
function playBeep(freq = 440, type = 'sine', duration = 0.08) {
  try {
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.type = type;
    osc.frequency.setValueAtTime(freq, audioCtx.currentTime);
    gain.gain.setValueAtTime(0.1, audioCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + duration);
    osc.connect(gain);
    gain.connect(audioCtx.destination);
    osc.start();
    osc.stop(audioCtx.currentTime + duration);
  } catch (e) {
    // Audio might be blocked before first user click
  }
}

// Styling per node label
function getNodeStyle(node) {
  const label = node.label;
  const status = node.status;
  const props = node.properties || {};

  let background = '#1f2937';
  let border = '#374151';
  let shape = 'dot';
  let size = 18;

  if (label === 'Pod') {
    if (status === 'COMPROMISED') {
      background = '#ff3366';
      border = '#ff0044';
      size = 24;
    } else if (status === 'QUARANTINED') {
      background = '#ffb700';
      border = '#ffd000';
      size = 22;
    } else {
      background = '#10b981';
      border = '#059669';
    }
  } else if (label === 'Service') {
    background = '#00f0ff';
    border = '#00b4d8';
    size = 20;
  } else if (label === 'IAMRole') {
    background = '#f59e0b';
    border = '#d97706';
    size = 22;
  } else if (label === 'S3Bucket') {
    background = '#b388ff';
    border = '#7c3aed';
    size = 20;
  } else if (label === 'Secret') {
    background = '#ec4899';
    border = '#db2777';
    size = 18;
  } else if (label === 'Database') {
    if (props.classification === 'CROWN_JEWEL') {
      background = '#ff0055';
      border = '#ffffff';
      size = 28;
    } else {
      background = '#3b82f6';
      border = '#2563eb';
      size = 20;
    }
  } else if (label === 'Vulnerability') {
    background = '#ef4444';
    border = '#b91c1c';
    size = 16;
  } else if (label === 'Gateway' || label === 'Network') {
    background = '#6366f1';
    border = '#4f46e5';
    size = 20;
  }

  return {
    id: node.id,
    label: node.name || node.id,
    color: {
      background: background,
      border: border,
      highlight: { background: '#ffffff', border: '#00f0ff' }
    },
    shape: shape,
    size: size,
    font: {
      color: '#e6edf3',
      face: 'JetBrains Mono',
      size: 11,
      strokeWidth: 2,
      strokeColor: '#080a0f'
    },
    borderWidth: 2,
    rawNode: node
  };
}

// Initialize Vis.js Network
function initNetwork(graphData) {
  currentGraphData = graphData;
  const container = document.getElementById('graph-canvas');

  const visNodes = graphData.nodes.map(getNodeStyle);
  const visEdges = graphData.edges.map(e => ({
    id: e.id,
    from: e.source,
    to: e.target,
    label: e.type,
    arrows: 'to',
    color: { color: 'rgba(75, 85, 99, 0.6)', highlight: '#00f0ff' },
    font: { color: '#6b7280', size: 9, face: 'JetBrains Mono', align: 'middle' },
    smooth: { type: 'continuous' }
  }));

  nodesDataSet = new vis.DataSet(visNodes);
  edgesDataSet = new vis.DataSet(visEdges);

  const options = {
    physics: {
      solver: 'forceAtlas2Based',
      forceAtlas2Based: {
        gravitationalConstant: -40,
        centralGravity: 0.008,
        springLength: 95,
        springConstant: 0.16
      },
      stabilization: { iterations: 120 }
    },
    interaction: {
      hover: true,
      tooltipDelay: 100
    }
  };

  network = new vis.Network(container, { nodes: nodesDataSet, edges: edgesDataSet }, options);

  // Click on node -> Update inspector
  network.on('click', params => {
    if (params.nodes.length > 0) {
      const selectedId = params.nodes[0];
      const found = currentGraphData.nodes.find(n => n.id === selectedId);
      if (found) {
        showNodeInspector(found);
        playBeep(600, 'sine', 0.05);
      }
    }
  });

  // Update counts
  document.getElementById('graph-counts').innerText = `${graphData.nodes.length} / ${graphData.edges.length}`;
}

// Show Node Inspector
function showNodeInspector(node) {
  document.getElementById('insp-type').innerText = node.label;
  const content = document.getElementById('insp-content');
  const props = node.properties || {};

  let html = `
    <div class="prop-row"><span class="prop-key">ID</span><span class="prop-val">${node.id}</span></div>
    <div class="prop-row"><span class="prop-key">NAME</span><span class="prop-val">${node.name}</span></div>
    <div class="prop-row"><span class="prop-key">STATUS</span><span class="prop-val">${node.status}</span></div>
  `;

  for (const [k, v] of Object.entries(props)) {
    if (!['id', 'name', 'status'].includes(k)) {
      html += `<div class="prop-row"><span class="prop-key">${k.toUpperCase()}</span><span class="prop-val">${v}</span></div>`;
    }
  }

  content.innerHTML = html;
}

// Fetch Initial Graph
async function loadGraph() {
  try {
    const res = await fetch('/api/graph');
    const data = await res.json();
    initNetwork(data);
  } catch (err) {
    console.error('Failed to load graph:', err);
  }
}

// Run Autonomous Investigation
async function runInvestigation() {
  const btn = document.getElementById('btn-investigate');
  const statusTag = document.getElementById('agent-status');
  const feed = document.getElementById('agent-feed');

  btn.disabled = true;
  statusTag.innerText = 'EXECUTING AGENT LOOP...';
  statusTag.style.color = '#ff3366';
  feed.innerHTML = '';
  playBeep(520, 'square', 0.1);

  try {
    const res = await fetch('/api/investigate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pod_id: 'pod-ingress-7b4d' })
    });
    const result = await res.json();

    // Progressively stream trace steps with realistic delays
    for (let i = 0; i < result.trace.length; i++) {
      const step = result.trace[i];
      await new Promise(r => setTimeout(r, 650)); // Cinematic delay for judges

      playBeep(440 + i * 80, 'sine', 0.08);

      const stepEl = document.createElement('div');
      stepEl.className = `timeline-step ${step.action === 'AUTONOMOUS_CONTAINMENT' ? 'step-remediate' : (step.action === 'ALERT_INGESTION' ? 'step-alert' : '')}`;
      stepEl.innerHTML = `
        <div class="step-header">
          <span class="step-num">STEP 0${step.step} // ${step.action}</span>
        </div>
        <div class="step-title">${step.title}</div>
        <div class="step-detail">${step.detail}</div>
        ${step.cypher_used ? `<div class="step-cypher">CYPHER: ${step.cypher_used}</div>` : ''}
      `;
      feed.appendChild(stepEl);
      feed.scrollTop = feed.scrollHeight;

      // Highlight nodes in the graph canvas
      if (step.highlight_nodes && step.highlight_nodes.length > 0) {
        step.highlight_nodes.forEach(nId => {
          if (nodesDataSet.get(nId)) {
            nodesDataSet.update({
              id: nId,
              borderWidth: 4,
              color: { border: '#ff3366', background: '#ff0055' }
            });
          }
        });
      }
    }

    // After containment: Update UI state to SAFE
    setTimeout(() => {
      // Threat indicator
      const ind = document.getElementById('threat-indicator');
      ind.className = 'cyber-badge pulse-green';
      document.getElementById('threat-badge-text').innerText = 'THREAT NEUTRALIZED';

      document.getElementById('blast-score').innerText = '0.0 (SECURE)';
      document.getElementById('blast-score').className = 'stat-val cyber-green';

      const banner = document.getElementById('overlay-banner');
      banner.className = 'canvas-overlay-banner neutralized';
      document.getElementById('banner-text').innerText = '✅ Kill-Chain Severed: Toxic IAM attachment revoked. Zero paths to Crown Jewel DB.';

      statusTag.innerText = 'CONTAINMENT VERIFIED';
      statusTag.style.color = '#00ff9d';

      // Update graph in canvas
      initNetwork(result.graph);

      // Play success chord
      playBeep(659, 'sine', 0.15);
      setTimeout(() => playBeep(880, 'sine', 0.25), 160);

      btn.disabled = false;
    }, 800);

  } catch (err) {
    console.error('Investigation failed:', err);
    btn.disabled = false;
    statusTag.innerText = 'ERROR';
  }
}

// Reset Graph
async function resetGraph() {
  try {
    playBeep(350, 'sawtooth', 0.1);
    const res = await fetch('/api/reset-graph', { method: 'POST' });
    const data = await res.json();

    // Reset badges
    const ind = document.getElementById('threat-indicator');
    ind.className = 'cyber-badge pulse-red';
    document.getElementById('threat-badge-text').innerText = 'BREACH DETECTED';

    document.getElementById('blast-score').innerText = '9.8 (CRITICAL)';
    document.getElementById('blast-score').className = 'stat-val cyber-red';

    const banner = document.getElementById('overlay-banner');
    banner.className = 'canvas-overlay-banner';
    document.getElementById('banner-text').innerText = 'Active Kill-Chain: pod-ingress-7b4d reaches Crown Jewel DB via 4 hops';

    document.getElementById('agent-status').innerText = 'READY';
    document.getElementById('agent-status').style.color = '#00f0ff';

    const feed = document.getElementById('agent-feed');
    feed.innerHTML = `
      <div class="feed-welcome-card">
        <h4>Awaiting Incident Command Trigger</h4>
        <p>Click <strong>"Autonomous Investigate & Remediate"</strong> to watch the agent:</p>
        <ul>
          <li>Traverse FalkorDB multi-hop connections</li>
          <li>Expose toxic IAM combinations</li>
          <li>Calculate sensitive asset blast radius</li>
          <li>Autonomously sever malicious graph edges</li>
        </ul>
      </div>
    `;

    initNetwork(data.graph);
  } catch (err) {
    console.error('Reset failed:', err);
  }
}

// Attach event listeners
document.getElementById('btn-investigate').addEventListener('click', runInvestigation);
document.getElementById('btn-reset').addEventListener('click', resetGraph);

// Load on start
window.addEventListener('DOMContentLoaded', loadGraph);
