import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import semver from 'semver';
import {
  readPackageJson,
  readPackageLock,
  getDirectDependencies,
  extractDependencyChains,
  findDirectRoots,
} from '../core/dependency-graph.js';

const execFileAsync = promisify(execFile);

export async function runNpmAuditRaw(cwd) {
  try {
    const { stdout } = await execFileAsync('npm', ['audit', '--json'], {
      cwd,
      maxBuffer: 30 * 1024 * 1024,
    });
    return JSON.parse(stdout);
  } catch (err) {
    if (err.stdout) {
      try {
        return JSON.parse(err.stdout);
      } catch {
        // failed to parse JSON stdout
      }
    }
    throw new Error(`npm audit failed in ${cwd}: ${err.stderr || err.message}`);
  }
}

export function extractCveFromText(text) {
  if (!text) return null;
  const match = text.match(/CVE-\d{4}-\d{4,8}/i);
  return match ? match[0].toUpperCase() : null;
}

export function determineSafeVersion(vulnerableRange, currentVersion, fixAvailable) {
  if (fixAvailable && typeof fixAvailable === 'object' && fixAvailable.version) {
    return fixAvailable.version;
  }

  // Attempt to parse minimum non-vulnerable version from range (e.g. "< 2.1.4" -> "2.1.4")
  if (vulnerableRange) {
    const match = vulnerableRange.match(/<=\s*([0-9]+\.[0-9]+\.[0-9]+[^ ]*)/);
    if (match && semver.valid(match[1])) {
      return semver.inc(match[1], 'patch') || match[1];
    }
    const matchLt = vulnerableRange.match(/<\s*([0-9]+\.[0-9]+\.[0-9]+[^ ]*)/);
    if (matchLt && semver.valid(matchLt[1])) {
      return matchLt[1];
    }
  }

  return null;
}

export function buildRemediationSuggestion(vuln, directRoots, pkgJson) {
  const isDirect = vuln.isDirect;
  const fix = vuln.fixAvailable;
  const safeVersion = vuln.targetSafeVersion;

  if (isDirect) {
    const directInfo = directRoots.find((r) => r.name === vuln.packageName);
    const currentRange = directInfo?.currentRange || `^${vuln.currentVersion}`;
    const prefix = currentRange.startsWith('~') ? '~' : currentRange.startsWith('^') ? '^' : '';
    const targetRange = safeVersion ? `${prefix}${safeVersion}` : (fix?.version ? `${prefix}${fix.version}` : null);

    return {
      strategy: 'bump-direct',
      targetPackage: vuln.packageName,
      targetVersion: safeVersion || fix?.version || null,
      packageJsonChanges: targetRange
        ? [
            {
              package: vuln.packageName,
              section: directInfo?.section || 'dependencies',
              from: currentRange,
              to: targetRange,
            },
          ]
        : [],
      lockfileActions: targetRange
        ? [`npm install ${vuln.packageName}@${targetRange} --package-lock-only`]
        : [`npm update ${vuln.packageName} --package-lock-only`],
    };
  }

  // Indirect / Transitive vulnerability
  if (fix && typeof fix === 'object' && fix.name && fix.version) {
    const directInfo = directRoots.find((r) => r.name === fix.name);
    const currentRange = directInfo?.currentRange || `^${fix.version}`;
    const prefix = currentRange.startsWith('~') ? '~' : currentRange.startsWith('^') ? '^' : '';
    const targetRange = `${prefix}${fix.version}`;

    return {
      strategy: 'bump-direct-parent',
      targetPackage: fix.name,
      targetVersion: fix.version,
      isSemVerMajor: Boolean(fix.isSemVerMajor),
      packageJsonChanges: [
        {
          package: fix.name,
          section: directInfo?.section || 'dependencies',
          from: currentRange,
          to: targetRange,
        },
      ],
      lockfileActions: [`npm install ${fix.name}@${targetRange} --package-lock-only`],
    };
  }

  // Indirect with no direct parent fix available -> override
  if (safeVersion) {
    return {
      strategy: 'package-override',
      targetPackage: vuln.packageName,
      targetVersion: safeVersion,
      packageJsonChanges: [
        {
          package: vuln.packageName,
          section: 'overrides',
          from: null,
          to: safeVersion,
        },
      ],
      lockfileActions: ['npm install --package-lock-only'],
    };
  }

  return {
    strategy: 'lockfile-update',
    targetPackage: vuln.packageName,
    targetVersion: null,
    packageJsonChanges: [],
    lockfileActions: [`npm update ${vuln.packageName} --package-lock-only`],
  };
}

export async function collectNpmAudit(worktreeDir, branchName = 'main') {
  const auditJson = await runNpmAuditRaw(worktreeDir);
  const pkgJson = readPackageJson(worktreeDir);
  const pkgLock = readPackageLock(worktreeDir);
  const directDeps = getDirectDependencies(pkgJson);

  const vulnerabilities = [];
  const rawVulns = auditJson.vulnerabilities || {};

  for (const [pkgName, vulnData] of Object.entries(rawVulns)) {
    const isDirect = Boolean(vulnData.isDirect);
    const rawVias = vulnData.via || [];

    // Extract primary advisory info
    let advisoryId = null;
    let cve = null;
    let title = `${vulnData.name} vulnerability`;
    let url = null;
    let cwe = [];
    let cvss = null;
    const viaAdvisories = [];

    for (const item of rawVias) {
      if (typeof item === 'object' && item !== null) {
        viaAdvisories.push(item);
        if (!advisoryId && item.source) advisoryId = String(item.source);
        if (!url && item.url) url = item.url;
        if (!title || title === `${vulnData.name} vulnerability`) title = item.title || title;
        if (item.cwe && Array.isArray(item.cwe)) cwe = item.cwe;
        if (item.cvss) cvss = item.cvss;

        // Check if CVE is mentioned in url, title, or cve fields
        const foundCve = extractCveFromText(item.url) || extractCveFromText(item.title) || (item.cve ? item.cve : null);
        if (foundCve && !cve) cve = foundCve;
      }
    }

    if (!advisoryId) {
      advisoryId = `AUDIT-${pkgName}-${vulnData.severity || 'vuln'}`;
    }

    const chains = extractDependencyChains(vulnData, pkgLock, directDeps);
    const directRoots = findDirectRoots(chains, directDeps);

    // Format dependency path strings
    const dependencyPaths = chains.map((chain) => chain.map((c) => c.specifier).join(' -> '));

    // Get current version from chains or package-lock
    const currentVersion = chains[0]?.slice(-1)[0]?.version || vulnData.range || 'unknown';
    const targetSafeVersion = determineSafeVersion(vulnData.range, currentVersion, vulnData.fixAvailable);

    const vulnRecord = {
      id: advisoryId,
      cve,
      packageName: pkgName,
      severity: vulnData.severity || 'moderate',
      title,
      url,
      cwe,
      cvss,
      isDirect,
      vulnerableVersionRange: vulnData.range || null,
      currentVersion,
      targetSafeVersion,
      fixAvailable: vulnData.fixAvailable || false,
      dependencyPaths,
      dependencyChains: chains,
      directRoots,
      sources: {
        npmAudit: {
          advisoryId,
          url,
          severity: vulnData.severity,
        },
      },
    };

    vulnRecord.remediation = buildRemediationSuggestion(vulnRecord, directRoots, pkgJson);
    vulnerabilities.push(vulnRecord);
  }

  // Sort vulnerabilities by severity
  const severityRank = { critical: 4, high: 3, moderate: 2, low: 1, info: 0 };
  vulnerabilities.sort((a, b) => (severityRank[b.severity] || 0) - (severityRank[a.severity] || 0));

  const summary = auditJson.metadata?.vulnerabilities || {
    critical: vulnerabilities.filter((v) => v.severity === 'critical').length,
    high: vulnerabilities.filter((v) => v.severity === 'high').length,
    moderate: vulnerabilities.filter((v) => v.severity === 'moderate').length,
    low: vulnerabilities.filter((v) => v.severity === 'low').length,
    total: vulnerabilities.length,
  };

  return {
    branch: branchName,
    summary,
    vulnerabilities,
  };
}
