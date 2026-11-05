import { groupPackageFindings } from './collection.js';

export function groupDependabotAlertsByBranch(alerts = [], branches = ['main'], defaultBranch = 'main', repository = null) {
  const selectedBranches = [...new Set(branches)];
  if (!selectedBranches.includes(defaultBranch)) selectedBranches.push(defaultBranch);

  return {
    repository,
    defaultBranch,
    branches: selectedBranches.map((branch) => {
      const isDefaultBranch = branch === defaultBranch;
      return {
        branch,
        isDefaultBranch,
        alertCount: isDefaultBranch ? alerts.length : 0,
        packages: groupPackageFindings(isDefaultBranch ? alerts : []),
        ...(!isDefaultBranch && {
          note: `GitHub Dependabot alerts natively track the repository default branch (${defaultBranch}).`,
        }),
      };
    }),
    totalAlerts: alerts.length,
  };
}

export async function fetchDependabotAlerts(options = {}) {
  const {
    org,
    name,
    githubToken,
    githubApiUrl = 'https://api.github.com',
    branches = ['main'],
  } = options;
  let defaultBranch = typeof options.defaultBranch === 'string' && options.defaultBranch.trim()
    ? options.defaultBranch.trim()
    : null;
  const repository = options.repository || (org && name ? { org, name, fullName: `${org}/${name}` } : null);

  if (!org || !name || !githubToken) {
    return groupDependabotAlertsByBranch([], branches, defaultBranch || 'main', repository);
  }

  const repositoryEndpoint = `${githubApiUrl.replace(/\/+$/, '')}/repos/${org}/${name}`;
  const headers = {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${githubToken}`,
    'X-GitHub-Api-Version': '2022-11-28',
  };
  let defaultBranchNote = null;

  if (!defaultBranch) {
    try {
      const res = await fetch(repositoryEndpoint, { headers });
      if (!res.ok) throw new Error(`GitHub repository API returned HTTP ${res.status}`);
      const metadata = await res.json();
      if (typeof metadata.default_branch !== 'string' || !metadata.default_branch.trim()) {
        throw new Error('GitHub repository metadata did not include a default branch');
      }
      defaultBranch = metadata.default_branch.trim();
    } catch (err) {
      defaultBranch = 'main';
      defaultBranchNote = `Unable to determine the repository default branch: ${err.message}. Falling back to main; requested branches are not assumed to be the default.`;
    }
  }

  let rawAlerts = [];

  try {
    const res = await fetch(`${repositoryEndpoint}/dependabot/alerts?state=open&per_page=100`, { headers });

    if (!res.ok && res.status !== 404) {
      console.warn(`[Dependabot] GitHub API returned HTTP ${res.status}: ${res.statusText}`);
    } else if (res.ok) {
      rawAlerts = parseDependabotAlerts(await res.json());
    }
  } catch (err) {
    console.warn(`[Dependabot] Error fetching Dependabot alerts: ${err.message}`);
  }

  const collection = groupDependabotAlertsByBranch(rawAlerts, branches, defaultBranch, repository);
  if (defaultBranchNote) collection.note = defaultBranchNote;
  return collection;
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
      affectedVersions: [{
        vulnerableRange: vuln.vulnerable_version_range || null,
        firstPatchedVersion: vuln.first_patched_version?.identifier || null,
      }],
      targetSafeVersion: vuln.first_patched_version?.identifier || null,
      manifestPath: dep.manifest_path || 'package.json',
    });
  }

  return alerts;
}
