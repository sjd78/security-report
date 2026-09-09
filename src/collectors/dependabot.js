export async function fetchDependabotAlerts(options = {}) {
  const { org, name, githubToken, githubApiUrl = 'https://api.github.com' } = options;

  if (!org || !name) {
    return [];
  }

  if (!githubToken) {
    return [];
  }

  const endpoint = `${githubApiUrl.replace(/\/+$/, '')}/repos/${org}/${name}/dependabot/alerts?state=open&per_page=100`;

  try {
    const res = await fetch(endpoint, {
      headers: {
        Accept: 'application/vnd.github+json',
        Authorization: `Bearer ${githubToken}`,
        'X-GitHub-Api-Version': '2022-11-28',
      },
    });

    if (res.status === 404) {
      // Dependabot alerts not enabled or repo not found
      return [];
    }

    if (!res.ok) {
      console.warn(`[Dependabot] GitHub API returned HTTP ${res.status}: ${res.statusText}`);
      return [];
    }

    const data = await res.json();
    return parseDependabotAlerts(data);
  } catch (err) {
    console.warn(`[Dependabot] Error fetching Dependabot alerts: ${err.message}`);
    return [];
  }
}

export function parseDependabotAlerts(data) {
  if (!Array.isArray(data)) return [];
  const alerts = [];

  for (const item of data) {
    const advisory = item.security_advisory || {};
    const vuln = item.security_vulnerability || {};
    const dep = item.dependency || {};

    const ghsaId = advisory.ghsa_id || null;
    const cve = advisory.cve_id || null;
    const packageName = dep.package?.name || vuln.package?.name || null;
    const ecosystem = dep.package?.ecosystem || vuln.package?.ecosystem || 'npm';

    if (ecosystem !== 'npm') continue;

    alerts.push({
      alertNumber: item.number,
      url: item.html_url,
      state: item.state,
      packageName,
      ecosystem,
      ghsaId,
      cve,
      summary: advisory.summary || `${packageName} vulnerability`,
      severity: (vuln.severity || advisory.severity || 'moderate').toLowerCase(),
      vulnerableVersionRange: vuln.vulnerable_version_range || null,
      targetSafeVersion: vuln.first_patched_version?.identifier || null,
      manifestPath: dep.manifest_path || 'package.json',
    });
  }

  return alerts;
}
