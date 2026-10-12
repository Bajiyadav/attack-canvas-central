// AegisGraph Incident Commander Frontend Controller

let network = null;
let nodesDataSet = null;
let edgesDataSet = null;
let currentGraphData = null;

// Safe Sound synthesizer via Web Audio API (lazy initialized on user interaction)
let audioCtx = null;
function playBeep(freq = 440, type = 'sine', duration = 0.08) {
  try {
    if (!audioCtx) {
      audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    }
    if (audioCtx.state === 'suspended') {
      audioCtx.resume();
    }
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.type = type;
    osc.frequency.setValueAtTime(freq, audioCtx.currentTime);
    gain.gain.setValueAtTime(0.08, audioCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + duration);
    osc.connect(gain);
    gain.connect(audioCtx.destination);
    osc.start();
    osc.stop(audioCtx.currentTime + duration);
  } catch (e) {
    // Non-blocking fallback
  }
}

// Styling per node label
function getNodeStyle(node) {
  const label = node.label || 'Node';
  const status = node.status || 'Normal';
  const props = node.properties || {};

  let background = '#1f2937';
  let border = '#374151';
  let size = 20;

  if (label === 'Pod') {
    if (status === 'COMPROMISED') {
      background = '#ff3366';
      border = '#ff0044';
      size = 26;
    } else if (status === 'QUARANTINED') {
      background = '#ffb700';
      border = '#ffd000';
      size = 24;
    } else {
      background = '#10b981';
      border = '#059669';
    }
  } else if (label === 'Service') {
    background = '#00f0ff';
    border = '#00b4d8';
    size = 22;
  } else if (label === 'IAMRole') {
    background = '#f59e0b';
    border = '#d97706';
    size = 24;
  } else if (label === 'S3Bucket') {
    background = '#b388ff';
    border = '#7c3aed';
    size = 22;
  } else if (label === 'Secret') {
    background = '#ec4899';
    border = '#db2777';
    size = 20;
  } else if (label === 'Database') {
    if (props.classification === 'CROWN_JEWEL') {
      background = '#ff0055';
      border = '#ffffff';
      size = 30;
    } else {
      background = '#3b82f6';
      border = '#2563eb';
      size = 22;
    }
  } else if (label === 'Vulnerability') {
    background = '#ef4444';
    border = '#b91c1c';
    size = 18;
  } else if (label === 'Gateway' || label === 'Network') {
    background = '#6366f1';
    border = '#4f46e5';
    size = 22;
  }

  return {
    id: String(node.id),
    label: String(node.name || node.id),
    color: {
      background: background,
      border: border,
      highlight: { background: '#ffffff', border: '#00f0ff' }
    },
    shape: 'dot',
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
  if (!container) return;

  if (network) {
    try {
      network.destroy();
    } catch(e) {}
    network = null;
  }

  const visNodes = graphData.nodes.map(getNodeStyle);
  const visEdges = graphData.edges.map(e => ({
    id: e.id,
    from: String(e.source),
    to: String(e.target),
    label: e.type,
    arrows: 'to',
    color: { color: 'rgba(75, 85, 99, 0.7)', highlight: '#00f0ff' },
    font: { color: '#8b949e', size: 9, face: 'JetBrains Mono', align: 'middle' },
    smooth: { type: 'continuous' }
  }));

  nodesDataSet = new vis.DataSet(visNodes);
  edgesDataSet = new vis.DataSet(visEdges);

  const options = {
    physics: {
      solver: 'forceAtlas2Based',
      forceAtlas2Based: {
        gravitationalConstant: -45,
        centralGravity: 0.01,
        springLength: 100,
        springConstant: 0.18,
        damping: 0.4
      },
      stabilization: { iterations: 100 }
    },
    interaction: {
      hover: true,
      tooltipDelay: 100,
      zoomView: true,
      dragView: true
    }
  };

  network = new vis.Network(container, { nodes: nodesDataSet, edges: edgesDataSet }, options);

  // Click on node -> Update inspector
  network.on('click', params => {
    if (params.nodes && params.nodes.length > 0) {
      const selectedId = String(params.nodes[0]);
      const found = currentGraphData.nodes.find(n => String(n.id) === selectedId);
      if (found) {
        showNodeInspector(found);
        playBeep(600, 'sine', 0.05);
      }
    }
  });

  // Update counts in header
  const countsEl = document.getElementById('graph-counts');
  if (countsEl) {
    countsEl.innerText = `${graphData.nodes.length} / ${graphData.edges.length}`;
  }
}

// Show Node Inspector
function showNodeInspector(node) {
  const typeEl = document.getElementById('insp-type');
  if (typeEl) typeEl.innerText = node.label || 'Node';

  const content = document.getElementById('insp-content');
  if (!content) return;

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
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    initNetwork(data);
  } catch (err) {
    console.error('Failed to load graph:', err);
    const canvas = document.getElementById('graph-canvas');
    if (canvas) {
      canvas.innerHTML = `<div style="padding: 40px; color: #ff3366; font-family: monospace;">⚠️ Failed to load graph: ${err.message}. Ensure FalkorDB container is running on port 6379.</div>`;
    }
  }
}

// Run Autonomous Investigation
async function runInvestigation() {
  const btn = document.getElementById('btn-investigate');
  const statusTag = document.getElementById('agent-status');
  const feed = document.getElementById('agent-feed');

  if (btn) btn.disabled = true;
  if (statusTag) {
    statusTag.innerText = 'EXECUTING AGENT LOOP...';
    statusTag.style.color = '#ff3366';
  }
  if (feed) feed.innerHTML = '';
  playBeep(520, 'square', 0.1);

  try {
    const res = await fetch('/api/investigate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pod_id: 'pod-ingress-7b4d' })
    });
    if (!res.ok) throw new Error(`API error HTTP ${res.status}`);
    const result = await res.json();

    // Progressively stream trace steps with realistic delays
    if (result.trace && result.trace.length > 0) {
      for (let i = 0; i < result.trace.length; i++) {
        const step = result.trace[i];
        await new Promise(r => setTimeout(r, 600)); // Cinematic delay

        playBeep(440 + i * 80, 'sine', 0.08);

        if (feed) {
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
        }

        // Highlight nodes in the graph canvas
        if (step.highlight_nodes && step.highlight_nodes.length > 0 && nodesDataSet) {
          step.highlight_nodes.forEach(nId => {
            const idStr = String(nId);
            if (nodesDataSet.get(idStr)) {
              nodesDataSet.update({
                id: idStr,
                borderWidth: 4,
                color: { border: '#ff3366', background: '#ff0055' }
              });
            }
          });
        }
      }
    }

    // After containment: Update UI state to SAFE
    setTimeout(() => {
      const ind = document.getElementById('threat-indicator');
      if (ind) ind.className = 'cyber-badge pulse-green';

      const threatText = document.getElementById('threat-badge-text');
      if (threatText) threatText.innerText = 'THREAT NEUTRALIZED';

      const blastScore = document.getElementById('blast-score');
      if (blastScore) {
        blastScore.innerText = '0.0 (SECURE)';
        blastScore.className = 'stat-val cyber-green';
      }

      const banner = document.getElementById('overlay-banner');
      if (banner) banner.className = 'canvas-overlay-banner neutralized';

      const bannerText = document.getElementById('banner-text');
      if (bannerText) bannerText.innerText = '✅ Kill-Chain Severed: Toxic IAM attachment revoked. Zero paths to Crown Jewel DB.';

      if (statusTag) {
        statusTag.innerText = 'CONTAINMENT VERIFIED';
        statusTag.style.color = '#00ff9d';
      }

      // Re-render graph canvas with updated severed topology
      if (result.graph) {
        initNetwork(result.graph);
      }

      // Play success chord
      playBeep(659, 'sine', 0.15);
      setTimeout(() => playBeep(880, 'sine', 0.25), 160);

      if (btn) btn.disabled = false;
    }, 800);

  } catch (err) {
    console.error('Investigation failed:', err);
    if (btn) btn.disabled = false;
    if (statusTag) {
      statusTag.innerText = 'ERROR: ' + err.message;
    }
  }
}

// Reset Graph
async function resetGraph() {
  try {
    playBeep(350, 'sawtooth', 0.1);
    const res = await fetch('/api/reset-graph', { method: 'POST' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    const ind = document.getElementById('threat-indicator');
    if (ind) ind.className = 'cyber-badge pulse-red';

    const threatText = document.getElementById('threat-badge-text');
    if (threatText) threatText.innerText = 'BREACH DETECTED';

    const blastScore = document.getElementById('blast-score');
    if (blastScore) {
      blastScore.innerText = '9.8 (CRITICAL)';
      blastScore.className = 'stat-val cyber-red';
    }

    const banner = document.getElementById('overlay-banner');
    if (banner) banner.className = 'canvas-overlay-banner';

    const bannerText = document.getElementById('banner-text');
    if (bannerText) bannerText.innerText = 'Active Kill-Chain: pod-ingress-7b4d reaches Crown Jewel DB via 4 hops';

    const statusTag = document.getElementById('agent-status');
    if (statusTag) {
      statusTag.innerText = 'READY';
      statusTag.style.color = '#00f0ff';
    }

    const feed = document.getElementById('agent-feed');
    if (feed) {
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
    }

    if (data.graph) {
      initNetwork(data.graph);
    }
  } catch (err) {
    console.error('Reset failed:', err);
  }
}

// Attach event listeners
document.addEventListener('DOMContentLoaded', () => {
  const btnInv = document.getElementById('btn-investigate');
  if (btnInv) btnInv.addEventListener('click', runInvestigation);

  const btnReset = document.getElementById('btn-reset');
  if (btnReset) btnReset.addEventListener('click', resetGraph);

  loadGraph();
});
