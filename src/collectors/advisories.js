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

export async function fetchAdvisoryDetails(advisoryRef, options = {}) {
  const { githubToken, githubApiUrl = 'https://api.github.com' } = options;
  const ghsaId = extractGhsaId(advisoryRef);
  const cveId = extractCveId(advisoryRef);

  const identifier = ghsaId || cveId || advisoryRef;
  if (!identifier) return null;

  // 1. Try GitHub Advisories API if GHSA is present
  if (ghsaId) {
    try {
      const headers = {
        Accept: 'application/vnd.github+json',
        'User-Agent': 'security-report',
      };
      if (githubToken) {
        headers.Authorization = `Bearer ${githubToken}`;
      }

      const cleanApi = githubApiUrl.replace(/\/+$/, '');
      const ghUrl = `${cleanApi}/advisories/${ghsaId}`;
      const res = await fetch(ghUrl, { headers });

      if (res.ok) {
        const data = await res.json();
        const vuln = Array.isArray(data.vulnerabilities) ? data.vulnerabilities.find((v) => v.package?.ecosystem === 'npm') || data.vulnerabilities[0] : null;

        return {
          id: data.ghsa_id || ghsaId,
          ghsaId: data.ghsa_id || ghsaId,
          cve: data.cve_id || cveId || null,
          packageName: vuln?.package?.name || null,
          ecosystem: vuln?.package?.ecosystem || 'npm',
          severity: (data.severity || 'moderate').toLowerCase(),
          vulnerableVersionRange: vuln?.vulnerable_version_range || null,
          targetSafeVersion: vuln?.first_patched_version || null,
          title: data.summary || null,
          url: data.html_url || `https://github.com/advisories/${ghsaId}`,
          source: 'github-advisory',
        };
      }
    } catch (err) {
      // Fall through to OSV
    }
  }

  // 2. Fallback to OSV API (Open Source Vulnerabilities database)
  try {
    const osvUrl = `https://api.osv.dev/v1/vulns/${encodeURIComponent(identifier)}`;
    const res = await fetch(osvUrl);

    if (res.ok) {
      const data = await res.json();
      const npmAffected = Array.isArray(data.affected)
        ? data.affected.find((a) => a.package?.ecosystem?.toLowerCase() === 'npm') || data.affected[0]
        : null;

      let firstPatchedVersion = null;
      let vulnerableVersionRange = null;

      if (npmAffected && Array.isArray(npmAffected.ranges)) {
        for (const range of npmAffected.ranges) {
          if (Array.isArray(range.events)) {
            const fixedEvent = range.events.find((e) => e.fixed);
            if (fixedEvent && fixedEvent.fixed) {
              firstPatchedVersion = fixedEvent.fixed;
            }
          }
        }
      }

      const foundCve = data.aliases?.find((a) => a.startsWith('CVE-')) || cveId || null;
      const foundGhsa = data.aliases?.find((a) => a.startsWith('GHSA-')) || ghsaId || null;

      return {
        id: foundGhsa || data.id,
        ghsaId: foundGhsa || (data.id?.startsWith('GHSA-') ? data.id : null),
        cve: foundCve,
        packageName: npmAffected?.package?.name || null,
        ecosystem: npmAffected?.package?.ecosystem || 'npm',
        severity: 'moderate',
        vulnerableVersionRange,
        targetSafeVersion: firstPatchedVersion,
        title: data.summary || null,
        url: data.references?.find((r) => r.url?.includes('github.com/advisories'))?.url || `https://github.com/advisories/${foundGhsa || identifier}`,
        source: 'osv',
      };
    }
  } catch (err) {
    // ignore
  }

  return null;
}
