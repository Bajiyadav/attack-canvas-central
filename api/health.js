export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.status(200).json({
    status: "healthy",
    service: "AegisGraph SecOps Engine",
    engine: "FalkorDB",
    graph: "aegis_secops",
    version: "2.0.0"
  });
}
