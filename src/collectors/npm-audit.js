import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import semver from 'semver';
import {
  readPackageJson,
  readPackageLock,
  getDirectDependencies,
  extractDependencyChains,
  findDirectRoots,
  lookupPackageInstalledInfo,
  runNpmLs,
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

export function canBeResolvedInLockfile(safeVersion, chains = []) {
  if (!safeVersion || chains.length === 0) return false;

  const validSafe = semver.valid(safeVersion);
  if (!validSafe) return false;

  let anyParentHasRange = false;

  for (const chain of chains) {
    if (chain.length < 2) continue;
    const immediateParent = chain[chain.length - 2];
    const targetLink = chain[chain.length - 1];

    if (targetLink.requiredRange) {
      anyParentHasRange = true;
      if (!semver.satisfies(validSafe, targetLink.requiredRange)) {
        return false;
      }
    } else if (immediateParent.requiredRange) {
      anyParentHasRange = true;
      if (!semver.satisfies(validSafe, immediateParent.requiredRange)) {
        return false;
      }
    }
  }

  return anyParentHasRange;
}

export function buildRemediationSuggestion(vuln, directRoots, pkgJson, chains = [], directInfo = null, worktreeDir = null) {
  const isDirect = vuln.isDirect;
  const isIndirect = vuln.isIndirect;
  const dependencyType = vuln.dependencyType;
  const fix = vuln.fixAvailable;
  const safeVersion = vuln.targetSafeVersion;

  // Resolve all direct declarations (root + workspaces)
  const resolvedDirectInfo = directInfo || directRoots.find((r) => r.name === vuln.packageName) || getDirectDependencies(pkgJson, worktreeDir).get(vuln.packageName);
  const declarations = vuln.workspaceDeclarations || resolvedDirectInfo?.declarations || (resolvedDirectInfo ? [resolvedDirectInfo] : []);

  // 1. Direct Dependency (Pure Direct OR Dual Direct & Indirect, like js-yaml)
  if (isDirect || dependencyType === 'Direct & Indirect' || declarations.length > 0) {
    const packageJsonChanges = [];

    for (const decl of declarations) {
      const currentRange = decl.range || `^${String(vuln.currentVersion || '').split(',')[0].trim()}`;
      const prefix = currentRange.startsWith('~') ? '~' : currentRange.startsWith('^') ? '^' : '';
      const targetRange = safeVersion ? `${prefix}${safeVersion}` : (fix?.version ? `${prefix}${fix.version}` : null);

      if (targetRange) {
        packageJsonChanges.push({
          package: vuln.packageName,
          section: decl.section || 'dependencies',
          from: currentRange,
          to: targetRange,
          packageJsonPath: decl.packageJsonPath || 'package.json',
          workspace: decl.workspace || null,
        });
      }
    }

    const primaryPrefix = packageJsonChanges[0]?.to?.startsWith('~') ? '~' : '^';
    const lockfileTarget = safeVersion ? `${primaryPrefix}${safeVersion}` : (fix?.version ? `${primaryPrefix}${fix.version}` : vuln.packageName);

    const isDual = isIndirect || dependencyType === 'Direct & Indirect';

    return {
      strategy: isDual ? 'bump-direct-and-lockfile' : 'bump-direct',
      targetPackage: vuln.packageName,
      targetVersion: safeVersion || fix?.version || null,
      workspaceDeclarations: declarations,
      packageJsonChanges,
      lockfileActions: safeVersion || fix?.version
        ? [`npm install ${vuln.packageName}@${lockfileTarget} --package-lock-only`]
        : [`npm update ${vuln.packageName} --package-lock-only`],
      note: isDual
        ? 'Package is both a direct dependency and required transitively. Resolution updates package.json semver and synchronizes lockfile for all instances.'
        : undefined,
    };
  }

  // 2. Direct Root Parent Fix Available (npm audit identified parent fix)
  if (fix && typeof fix === 'object' && fix.name && fix.version) {
    const parentDirectInfo = directRoots.find((r) => r.name === fix.name) || getDirectDependencies(pkgJson, worktreeDir).get(fix.name);
    const parentDecls = parentDirectInfo?.declarations || (parentDirectInfo ? [parentDirectInfo] : []);

    const packageJsonChanges = [];
    for (const decl of parentDecls) {
      const currentRange = decl.range || `^${fix.version}`;
      const prefix = currentRange.startsWith('~') ? '~' : currentRange.startsWith('^') ? '^' : '';
      const targetRange = `${prefix}${fix.version}`;

      packageJsonChanges.push({
        package: fix.name,
        section: decl.section || 'dependencies',
        from: currentRange,
        to: targetRange,
        packageJsonPath: decl.packageJsonPath || 'package.json',
        workspace: decl.workspace || null,
      });
    }

    return {
      strategy: 'bump-direct-parent',
      targetPackage: fix.name,
      targetVersion: fix.version,
      isSemVerMajor: Boolean(fix.isSemVerMajor),
      directRoot: parentDirectInfo?.name || fix.name,
      packageJsonChanges,
      lockfileActions: [`npm install ${fix.name}@^${fix.version} --package-lock-only`],
    };
  }

  // 3. In-Range Transitive Lockfile Bump (parent range allows safe version)
  if (safeVersion && canBeResolvedInLockfile(safeVersion, chains)) {
    return {
      strategy: 'lockfile-update',
      targetPackage: vuln.packageName,
      targetVersion: safeVersion,
      directRoot: directRoots[0]?.name || null,
      packageJsonChanges: [],
      lockfileActions: [
        `npm install ${vuln.packageName}@${safeVersion} --package-lock-only`,
        `npm update ${vuln.packageName} --package-lock-only`,
      ],
      note: 'Transitive safe version is permitted within parent declared semver ranges. Can be updated directly in lockfile.',
    };
  }

  // 4. Transitive with identified Direct Root Parent (e.g. msw)
  if (directRoots.length > 0) {
    const primaryRoot = directRoots[0];
    return {
      strategy: 'bump-direct-parent',
      targetPackage: primaryRoot.name,
      targetVersion: null,
      directRoot: primaryRoot.name,
      packageJsonChanges: [],
      lockfileActions: [
        `npm update ${primaryRoot.name} --package-lock-only`,
        `npm install ${vuln.packageName}@${safeVersion || 'latest'} --package-lock-only`,
      ],
      note: `Introduced via direct root "${primaryRoot.name}". Check for newer release of ${primaryRoot.name} or lockfile update.`,
    };
  }

  // 5. Fallback: Package Override
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
          packageJsonPath: 'package.json',
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
  const [auditJson, npmLsData] = await Promise.all([
    runNpmAuditRaw(worktreeDir),
    runNpmLs(worktreeDir),
  ]);

  const pkgJson = readPackageJson(worktreeDir);
  const pkgLock = readPackageLock(worktreeDir);
  const directDeps = getDirectDependencies(pkgJson, worktreeDir);

  const vulnerabilities = [];
  const rawVulns = auditJson.vulnerabilities || {};

  for (const [pkgName, vulnData] of Object.entries(rawVulns)) {
    const pkgInfo = lookupPackageInstalledInfo(pkgName, pkgJson, pkgLock, npmLsData, worktreeDir);
    const isDirect = pkgInfo.isDirect || Boolean(vulnData.isDirect);
    const isIndirect = pkgInfo.isIndirect || !isDirect;
    const dependencyType = pkgInfo.dependencyType !== 'Unknown' ? pkgInfo.dependencyType : (isDirect ? 'Direct' : 'Indirect (Transitive)');

    const rawVias = vulnData.via || [];

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

        const foundCve = extractCveFromText(item.url) || extractCveFromText(item.title) || (item.cve ? item.cve : null);
        if (foundCve && !cve) cve = foundCve;
      }
    }

    if (!advisoryId) {
      advisoryId = `AUDIT-${pkgName}-${vulnData.severity || 'vuln'}`;
    }

    const chains = pkgInfo.chains.length > 0
      ? pkgInfo.chains
      : extractDependencyChains(vulnData, pkgLock, directDeps, npmLsData);

    const directRoots = pkgInfo.directRoots.length > 0
      ? pkgInfo.directRoots
      : findDirectRoots(chains, directDeps);

    const dependencyPaths = chains.map((chain) => chain.map((c) => c.specifier).join(' -> '));

    const currentVersion = pkgInfo.currentVersion !== 'unknown'
      ? pkgInfo.currentVersion
      : (chains[0]?.slice(-1)[0]?.version || vulnData.range || 'unknown');

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
      isIndirect,
      dependencyType,
      workspaceDeclarations: pkgInfo.workspaceDeclarations,
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

    vulnRecord.remediation = buildRemediationSuggestion(
      vulnRecord,
      directRoots,
      pkgJson,
      chains,
      pkgInfo.directInfo,
      worktreeDir
    );
    vulnerabilities.push(vulnRecord);
  }

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
