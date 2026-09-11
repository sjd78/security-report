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
        const npmVulns = Array.isArray(data.vulnerabilities)
          ? data.vulnerabilities.filter((v) => !v.package?.ecosystem || v.package.ecosystem.toLowerCase() === 'npm')
          : [];
        const primaryVuln = npmVulns[0] || (Array.isArray(data.vulnerabilities) ? data.vulnerabilities[0] : null);

        const patchedVersions = [];
        const seenPatched = new Set();
        const targetVulnList = npmVulns.length > 0 ? npmVulns : (Array.isArray(data.vulnerabilities) ? data.vulnerabilities : []);

        for (const v of targetVulnList) {
          const fpv = v.first_patched_version;
          if (fpv && typeof fpv === 'string') {
            const clean = semver.clean(fpv) || fpv.trim();
            if (clean && !seenPatched.has(clean)) {
              seenPatched.add(clean);
              patchedVersions.push(clean);
            }
          }
        }
        patchedVersions.sort((a, b) => {
          const vA = semver.valid(a);
          const vB = semver.valid(b);
          if (vA && vB) return semver.compare(vA, vB);
          return a.localeCompare(b);
        });

        return {
          id: data.ghsa_id || ghsaId,
          ghsaId: data.ghsa_id || ghsaId,
          cve: data.cve_id || cveId || null,
          packageName: primaryVuln?.package?.name || null,
          ecosystem: primaryVuln?.package?.ecosystem || 'npm',
          severity: (data.severity || 'moderate').toLowerCase(),
          vulnerableVersionRange: primaryVuln?.vulnerable_version_range || null,
          targetSafeVersion: patchedVersions[0] || primaryVuln?.first_patched_version || null,
          patchedVersions,
          targetSafeVersions: patchedVersions,
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
        ? data.affected.filter((a) => !a.package?.ecosystem || a.package.ecosystem.toLowerCase() === 'npm')
        : [];
      const primaryAffected = npmAffected[0] || (Array.isArray(data.affected) ? data.affected[0] : null);

      const patchedVersions = [];
      const seenPatched = new Set();
      const targetAffectedList = npmAffected.length > 0 ? npmAffected : (Array.isArray(data.affected) ? data.affected : []);

      for (const aff of targetAffectedList) {
        if (Array.isArray(aff.ranges)) {
          for (const range of aff.ranges) {
            if (Array.isArray(range.events)) {
              for (const event of range.events) {
                if (event.fixed && typeof event.fixed === 'string') {
                  const clean = semver.clean(event.fixed) || event.fixed.trim();
                  if (clean && !seenPatched.has(clean)) {
                    seenPatched.add(clean);
                    patchedVersions.push(clean);
                  }
                }
              }
            }
          }
        }
      }
      patchedVersions.sort((a, b) => {
        const vA = semver.valid(a);
        const vB = semver.valid(b);
        if (vA && vB) return semver.compare(vA, vB);
        return a.localeCompare(b);
      });

      let firstPatchedVersion = patchedVersions[0] || null;
      let vulnerableVersionRange = null;

      const foundCve = data.aliases?.find((a) => a.startsWith('CVE-')) || cveId || null;
      const foundGhsa = data.aliases?.find((a) => a.startsWith('GHSA-')) || ghsaId || null;

      return {
        id: foundGhsa || data.id,
        ghsaId: foundGhsa || (data.id?.startsWith('GHSA-') ? data.id : null),
        cve: foundCve,
        packageName: primaryAffected?.package?.name || null,
        ecosystem: primaryAffected?.package?.ecosystem || 'npm',
        severity: 'moderate',
        vulnerableVersionRange,
        targetSafeVersion: firstPatchedVersion,
        patchedVersions,
        targetSafeVersions: patchedVersions,
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
