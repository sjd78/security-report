import semver from 'semver';

export function extractGhsaId(text) {
  if (!text) return null;
  const match = text.match(/GHSA-[2-9a-km-z]{4}-[2-9a-km-z]{4}-[2-9a-km-z]{4}/i) || text.match(/GHSA-[a-zA-Z0-9_-]{4,25}/i);
  return match ? match[0].toUpperCase() : null;
}

export function extractCveId(text) {
  if (!text) return null;
  const match = text.match(/CVE-\d{4}-\d{4,8}/i);
  return match ? match[0].toUpperCase() : null;
}

function sortedVersions(versions) {
  return [...new Set(versions.filter(Boolean))].sort((left, right) => {
    const a = semver.valid(left);
    const b = semver.valid(right);
    if (a && b) return semver.compare(a, b);
    return String(left).localeCompare(String(right));
  });
}

function npmPackageCandidates(rows, packageName, packageField) {
  const npmRows = rows.filter((row) => !row?.[packageField]?.ecosystem || row[packageField].ecosystem.toLowerCase() === 'npm');
  const matching = packageName
    ? npmRows.filter((row) => row?.[packageField]?.name === packageName)
    : npmRows;
  const names = new Set(matching.map((row) => row?.[packageField]?.name).filter(Boolean));
  if (packageName && names.size === 0) return [];
  if (!packageName && names.size > 1) return null;
  return matching;
}

function osvAffectedIntervals(affected) {
  const intervals = [];
  for (const range of affected?.ranges || []) {
    if (String(range.type || '').toUpperCase() !== 'SEMVER' || !Array.isArray(range.events)) continue;
    let introduced = null;
    for (const event of range.events) {
      if (typeof event.introduced === 'string') {
        introduced = event.introduced === '0' ? '0.0.0' : semver.valid(event.introduced);
        continue;
      }
      if (typeof event.fixed === 'string') {
        const fixed = semver.valid(event.fixed);
        if (fixed) {
          intervals.push({
            vulnerableRange: introduced ? `>=${introduced} <${fixed}` : `<${fixed}`,
            firstPatchedVersion: fixed,
          });
        }
        introduced = null;
        continue;
      }
      if (typeof event.last_affected === 'string') {
        const last = semver.valid(event.last_affected);
        if (last) intervals.push({ vulnerableRange: introduced ? `>=${introduced} <=${last}` : `<=${last}`, firstPatchedVersion: null });
        introduced = null;
      }
    }
    if (introduced) intervals.push({ vulnerableRange: `>=${introduced}`, firstPatchedVersion: null });
  }
  return intervals;
}

export async function fetchAdvisoryDetails(advisoryRef, options = {}) {
  const { githubToken, githubApiUrl = 'https://api.github.com', packageName = null } = options;
  const ghsaId = extractGhsaId(advisoryRef);
  const cveId = extractCveId(advisoryRef);
  const identifier = ghsaId || cveId || advisoryRef;
  if (!identifier) return null;

  if (ghsaId) {
    try {
      const headers = { Accept: 'application/vnd.github+json', 'User-Agent': 'security-report' };
      if (githubToken) headers.Authorization = `Bearer ${githubToken}`;
      const cleanApi = githubApiUrl.replace(/\/+$/, '');
      const response = await fetch(`${cleanApi}/advisories/${ghsaId}`, { headers });
      if (response.ok) {
        const data = await response.json();
        const vulnerabilities = npmPackageCandidates(data.vulnerabilities || [], packageName, 'package');
        if (vulnerabilities === null) return null;
        if (vulnerabilities.length) {
          const affectedVersions = vulnerabilities.map((item) => ({
            vulnerableRange: item.vulnerable_version_range || null,
            firstPatchedVersion: typeof item.first_patched_version === 'string' ? item.first_patched_version : null,
          })).filter((item) => item.vulnerableRange || item.firstPatchedVersion);
          const patchedVersions = sortedVersions(affectedVersions.map((item) => item.firstPatchedVersion));
          return {
            id: extractGhsaId(data.ghsa_id) || ghsaId,
            ghsaId: extractGhsaId(data.ghsa_id) || ghsaId,
            cve: extractCveId(data.cve_id) || cveId || null,
            packageName: vulnerabilities[0]?.package?.name || packageName || null,
            ecosystem: 'npm',
            severity: (data.severity || 'moderate').toLowerCase(),
            vulnerableVersionRange: affectedVersions[0]?.vulnerableRange || null,
            affectedVersions,
            targetSafeVersion: patchedVersions[0] || null,
            patchedVersions,
            targetSafeVersions: patchedVersions,
            title: data.summary || null,
            url: data.html_url || `https://github.com/advisories/${ghsaId}`,
            source: 'github-advisory',
          };
        }
      }
    } catch {
      // Fall through to OSV.
    }
  }

  try {
    const response = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(identifier)}`);
    if (response.ok) {
      const data = await response.json();
      const affected = npmPackageCandidates(data.affected || [], packageName, 'package');
      if (affected === null) return null;
      if (affected.length) {
        const affectedVersions = affected.flatMap(osvAffectedIntervals);
        const patchedVersions = sortedVersions(affectedVersions.map((item) => item.firstPatchedVersion));
        const foundCve = (data.aliases || []).map(extractCveId).find(Boolean) || cveId || null;
        const foundGhsa = (data.aliases || []).map(extractGhsaId).find(Boolean) || ghsaId || null;
        return {
          id: foundGhsa || extractGhsaId(data.id) || extractCveId(data.id) || data.id,
          ghsaId: foundGhsa || extractGhsaId(data.id) || null,
          cve: foundCve,
          packageName: affected[0]?.package?.name || packageName || null,
          ecosystem: 'npm',
          severity: 'moderate',
          vulnerableVersionRange: affectedVersions[0]?.vulnerableRange || null,
          affectedVersions,
          targetSafeVersion: patchedVersions[0] || null,
          patchedVersions,
          targetSafeVersions: patchedVersions,
          title: data.summary || null,
          url: data.references?.find((item) => item.url?.includes('github.com/advisories'))?.url
            || `https://github.com/advisories/${foundGhsa || identifier}`,
          source: 'osv',
        };
      }
    }
  } catch {
    // Advisory lookup is best-effort; collectors preserve their original evidence.
  }
  return null;
}
