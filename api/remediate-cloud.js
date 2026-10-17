export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  res.status(200).json({
    status: "success",
    cloud_actions: [
      { service: "AWS IAM", action: "DetachRolePolicy", target: "iam-prod-reader", status: "DETACHED", latency_ms: 142 },
      { service: "Kubernetes", action: "ApplyNetworkPolicy", target: "pod-ingress-7b4d", status: "ENFORCED", latency_ms: 98 },
      { service: "Terraform", action: "CreatePullRequest", target: "repo/infrastructure", status: "PR_OPENED", pr_number: 4092, latency_ms: 180 }
    ],
    total_latency_ms: 240,
    records_secured: 2400000
  });
}
