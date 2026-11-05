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
  getPackageInstances,
} from '../core/dependency-graph.js';
import { sortVulnerabilities, pickHighestSafeVersion, selectBestRemediationVersion } from '../core/blender.js';
import { extractGhsaId, extractCveId, fetchAdvisoryDetails } from './advisories.js';
import { normalizePlanFindings } from '../core/advisory-evidence.js';
const execFileAsync = promisify(execFile);

export async function runNpmAuditRaw(cwd) {
  let stdout;
  try {
    ({ stdout } = await execFileAsync('npm', ['audit', '--json'], {
      cwd,
      maxBuffer: 30 * 1024 * 1024,
    }));
  } catch (err) {
    if (!err.stdout) {
      throw new Error(`npm audit failed in ${cwd}: ${err.stderr || err.message}`);
    }
    stdout = err.stdout;
  }

  try {
    const audit = JSON.parse(stdout);
    if (!audit || typeof audit !== 'object' || Array.isArray(audit)) {
      throw new Error('Invalid npm audit payload');
    }
    if (audit.error) {
      const detail = typeof audit.error === 'string'
        ? audit.error
        : [audit.error.code, audit.error.summary, audit.error.detail].filter(Boolean).join(': ');
      throw new Error(detail || 'npm returned an audit error');
    }
    if (!audit.vulnerabilities || typeof audit.vulnerabilities !== 'object'
      || Array.isArray(audit.vulnerabilities)
      || Object.values(audit.vulnerabilities).some((v) => !v || typeof v !== 'object' || Array.isArray(v))) {
      throw new Error('Missing or invalid vulnerabilities in npm audit payload');
    }
    return audit;
  } catch (err) {
    throw new Error(`npm audit failed in ${cwd}: ${err.message}`);
  }
}

export function extractCveFromText(text) {
  if (!text) return null;
  const match = text.match(/CVE-\d{4}-\d{4,8}/i);
  return match ? match[0].toUpperCase() : null;
}

export function determinePatchedVersions(vulnerableRange, fixAvailable = null, targetPkgName = null) {
  const versions = [];
  const seen = new Set();
  const add = (v) => {
    if (!v || typeof v !== 'string') return;
    const clean = semver.clean(v) || v.trim();
    if (clean && semver.valid(clean) && !seen.has(clean)) {
      seen.add(clean);
      versions.push(clean);
    }
  };

  if (fixAvailable && typeof fixAvailable === 'object' && fixAvailable.version) {
    if (!targetPkgName || !fixAvailable.name || fixAvailable.name === targetPkgName) {
      add(fixAvailable.version);
    }
  }

  if (vulnerableRange && typeof vulnerableRange === 'string' && vulnerableRange !== '*') {
    const matches = Array.from(vulnerableRange.matchAll(/(?:<=|<)\s*([0-9]+\.[0-9]+\.[0-9]+[a-zA-Z0-9_.-]*)/g));
    for (const m of matches) {
      if (m[1] && semver.valid(m[1])) {
        if (m[0].trim().startsWith('<=')) {
          add(semver.inc(m[1], 'patch') || m[1]);
        } else {
          add(m[1]);
        }
      }
    }
  }

  versions.sort((a, b) => {
    const vA = semver.valid(a);
    const vB = semver.valid(b);
    if (vA && vB) return semver.compare(vA, vB);
    return a.localeCompare(b);
  });

  return versions;
}

export function determineSafeVersion(vulnerableRange, currentVersion, fixAvailable, targetPkgName = null) {
  const allPatched = determinePatchedVersions(vulnerableRange, fixAvailable, targetPkgName);
  if (allPatched.length === 0) return null;
  return selectBestRemediationVersion(currentVersion, allPatched);
}

export function isBreakingChange(fromRangeOrVer, toRangeOrVer) {
  if (!fromRangeOrVer || !toRangeOrVer) return false;
  try {
    const cleanFromStr = String(fromRangeOrVer).replace(/^[~^<>= ]+/, '').trim().split(',')[0].trim();
    const cleanToStr = String(toRangeOrVer).replace(/^[~^<>= ]+/, '').trim().split(',')[0].trim();
    const vFrom = semver.coerce(cleanFromStr);
    const vTo = semver.coerce(cleanToStr);
    if (!vFrom || !vTo) return false;

    return vTo.major > vFrom.major;
  } catch {
    return false;
  }
}

export function isOutOfRangeChange(currentRangeOrVer, targetVersion) {
  if (!currentRangeOrVer || !targetVersion) return false;
  try {
    const range = String(currentRangeOrVer).trim().split(',')[0].trim();
    const cleanVer = semver.clean(String(targetVersion).replace(/^[~^]/, '')) || semver.coerce(targetVersion)?.version;
    if (!cleanVer) return false;
    if (semver.validRange(range) && !semver.satisfies(cleanVer, range)) {
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

export function canBeResolvedInLockfile(safeVersion, targetPkgOrChains, arboristTree = null, chains = []) {
  if (!safeVersion) return false;
  const validSafe = semver.valid(safeVersion);
  if (!validSafe) return false;

  let targetPkgName = null;
  let tree = null;
  let evalChains = [];

  if (Array.isArray(targetPkgOrChains)) {
    evalChains = targetPkgOrChains;
  } else if (typeof targetPkgOrChains === 'string') {
    targetPkgName = targetPkgOrChains;
    if (arboristTree && arboristTree.inventory) {
      tree = arboristTree;
    } else if (Array.isArray(arboristTree)) {
      evalChains = arboristTree;
    }
    if (Array.isArray(chains) && chains.length > 0) {
      evalChains = chains;
    }
  }

  if (tree && targetPkgName) {
    const nodes = Array.from(tree.inventory.query('name', targetPkgName));
    if (nodes.length > 0) {
      let anyEdge = false;
      for (const node of nodes) {
        for (const edge of node.edgesIn || []) {
          if (!edge.spec) continue;
          anyEdge = true;
          if (!semver.satisfies(validSafe, edge.spec)) {
            return false;
          }
        }
      }
      if (anyEdge) return true;
    }
  }

  // Fallback to evaluating chains
  if (evalChains.length === 0) return false;

  let anyParentHasRange = false;
  for (const chain of evalChains) {
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

/**
 * Lockfile remediation is expressed as a list of package names to re-resolve with
 * `npm update <pkg> --package-lock-only`. `npm install <pkg>@<version>` is deliberately
 * not used: it also writes the package to the root package.json, which would silently
 * promote a transitive dependency to a direct one. Pinning a version that no parent
 * range allows is the job of the `package-override` strategy.
 */
export function formatLockfileUpdate(packageName) {
  return `npm update ${packageName} --package-lock-only`;
}

function parentUpgradeIsForward(targetVersion, declaration, parentRoots, parentInstances, chains, parentName) {
  if (!semver.valid(targetVersion)) return false;
  const currentRange = declaration.range || declaration.currentRange;
  if (typeof currentRange !== 'string' || !semver.validRange(currentRange)) return false;
  const minimum = semver.minVersion(currentRange);
  if (!minimum || !semver.gt(targetVersion, minimum)) return false;

  const file = declaration.packageJsonPath || 'package.json';
  const section = declaration.section || 'dependencies';
  const versions = parentInstances.filter((instance) => instance.origins.some((origin) =>
    origin.packageJsonPath === file && origin.section === section && origin.chain.length === 1))
    .map((instance) => instance.installedVersion);
  for (const root of parentRoots) {
    if ((root.packageJsonPath || 'package.json') === file && (root.section || 'dependencies') === section
      && root.installedVersion) versions.push(root.installedVersion);
  }
  // Unlocated saved chains can rule out an upgrade, but cannot prove which
  // installed version belongs to a particular workspace declaration.
  for (const chain of chains) {
    const anchor = chain.find((link) => link.isRoot || link.isWorkspace);
    const originFile = anchor?.packageJsonPath || (anchor?.isRoot ? 'package.json'
      : anchor?.isWorkspace && anchor.location ? `${anchor.location}/package.json` : null);
    for (const link of chain) {
      if (link.name !== parentName || !link.version) continue;
      if (!semver.valid(link.version) || !semver.gt(targetVersion, link.version)) return false;
      if (originFile === file) versions.push(link.version);
    }
  }
  if (versions.length) {
    return versions.every((version) => semver.valid(version) && semver.gt(targetVersion, version));
  }
  // Without installed evidence, a range's minimum is not an installed version.
  // Only a target above the entire declared range can be proven an upgrade.
  return semver.gtr(targetVersion, currentRange);
}

export function buildRemediationSuggestion(vuln, directRoots, pkgJson, chains = [], directInfo = null, worktreeDir = null, arboristTree = null) {
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
    let isBreaking = false;

    for (const decl of declarations) {
      const currentRange = decl.range || `^${String(vuln.currentVersion || '').split(',')[0].trim()}`;
      const prefix = currentRange.startsWith('~') ? '~' : currentRange.startsWith('^') ? '^' : '';
      const targetRange = safeVersion ? `${prefix}${safeVersion}` : (fix?.version ? `${prefix}${fix.version}` : null);

      if (targetRange) {
        const changeIsBreaking = isBreakingChange(currentRange, targetRange);
        if (changeIsBreaking) isBreaking = true;

        packageJsonChanges.push({
          package: vuln.packageName,
          section: decl.section || 'dependencies',
          from: currentRange,
          to: targetRange,
          packageJsonPath: decl.packageJsonPath || 'package.json',
          workspace: decl.workspace || null,
          isOutOfRange: changeIsBreaking,
          isSemVerMajor: changeIsBreaking,
          isBreaking: changeIsBreaking,
        });
      }
    }

    const isDual = isIndirect || dependencyType === 'Direct & Indirect';
    const isDirectLockOnly = !isDual && packageJsonChanges.length === 0 && (safeVersion || fix?.version);
    const strategy = isDirectLockOnly
      ? 'lockfile-update'
      : (isDual ? 'bump-direct-and-lockfile' : 'bump-direct');
    const strategyLabel = isDirectLockOnly
      ? 'lockfile-update (direct)'
      : (isDual ? 'bump-direct-and-lockfile (direct + transitive pin)' : 'bump-direct');

    return {
      strategy,
      strategyLabel,
      targetPackage: vuln.packageName,
      targetVersion: safeVersion || fix?.version || null,
      workspaceDeclarations: declarations,
      packageJsonChanges,
      isOutOfRange: isBreaking,
      isSemVerMajor: isBreaking,
      isBreaking,
      transientOverrides: isDual && safeVersion ? [{ package: vuln.packageName, to: `^${safeVersion}` }] : [],
      lockfileUpdates: isDual || isDirectLockOnly ? [vuln.packageName] : [],
      note: isDual
        ? 'Package is both a direct dependency and required transitively. Resolution updates package.json semver and synchronizes lockfile for all instances.'
        : (isDirectLockOnly ? 'Direct dependency declared range already permits the safe version. Update lockfile directly without package.json changes.' : undefined),
    };
  }

  // 2. In-Range Transitive Lockfile Bump (parent range allows safe version)
  const canResolveInLock = canBeResolvedInLockfile(safeVersion, vuln.packageName, arboristTree, chains);
  if (safeVersion && canResolveInLock) {
    return {
      strategy: 'lockfile-update',
      strategyLabel: 'lockfile-update (transitive pin)',
      targetPackage: vuln.packageName,
      targetVersion: safeVersion,
      directRoot: directRoots[0]?.name || null,
      packageJsonChanges: [],
      transientOverrides: [
        {
          package: vuln.packageName,
          to: `^${safeVersion}`,
        },
      ],
      isOutOfRange: false,
      isSemVerMajor: false,
      isBreaking: false,
      lockfileUpdates: [vuln.packageName],
      note: 'Transitive safe version is permitted within parent declared semver ranges. Can be updated directly in lockfile via transient pin.',
    };
  }

  // 3. Direct Root Parent Fix Available (npm audit identified parent fix)
  if (fix && typeof fix === 'object' && fix.name && fix.version) {
    const parentRoots = directRoots.filter((root) => root.name === fix.name);
    const manifestInfo = getDirectDependencies(pkgJson, worktreeDir).get(fix.name);
    const parentDirectInfo = parentRoots[0] || manifestInfo;
    const declarationsByOrigin = new Map();
    for (const info of [manifestInfo, ...parentRoots].filter(Boolean)) {
      for (const declaration of info.declarations?.length ? info.declarations : [info]) {
        const key = JSON.stringify([declaration.packageJsonPath || 'package.json', declaration.section || 'dependencies']);
        if (!declarationsByOrigin.has(key)) declarationsByOrigin.set(key, declaration);
      }
    }
    const parentDecls = [...declarationsByOrigin.values()];
    const parentInstances = arboristTree ? getPackageInstances(fix.name, { arboristTree }) : [];
    const isForwardUpgrade = parentDecls.length > 0 && parentDecls.every((declaration) =>
      parentUpgradeIsForward(fix.version, declaration, parentRoots, parentInstances, chains, fix.name));

    let isBreaking = Boolean(fix.isSemVerMajor);
    let isOutOfRange = false;
    const packageJsonChanges = [];
    for (const decl of isForwardUpgrade ? parentDecls : []) {
      const currentRange = decl.range || decl.currentRange;
      const prefix = currentRange.startsWith('~') ? '~' : currentRange.startsWith('^') ? '^' : '';
      const targetRange = `${prefix}${fix.version}`;
      const changeIsBreaking = isBreaking || isBreakingChange(currentRange, targetRange);
      if (changeIsBreaking) isBreaking = true;
      const changeOutOfRange = isOutOfRangeChange(currentRange, targetRange);
      if (changeOutOfRange) isOutOfRange = true;

      // Only add to packageJsonChanges if it represents an actual version change!
      if (currentRange !== targetRange && (!semver.validRange(currentRange) || !semver.satisfies(fix.version, currentRange))) {
        packageJsonChanges.push({
          package: fix.name,
          section: decl.section || 'dependencies',
          from: currentRange,
          to: targetRange,
          packageJsonPath: decl.packageJsonPath || 'package.json',
          workspace: decl.workspace || null,
          isOutOfRange: changeOutOfRange,
          isSemVerMajor: changeIsBreaking,
          isBreaking: changeIsBreaking,
        });
      }
    }

    if (packageJsonChanges.length > 0) {
      return {
        strategy: 'bump-direct-parent',
        strategyLabel: 'bump-direct-parent',
        targetPackage: fix.name,
        targetVersion: fix.version,
        isOutOfRange,
        isSemVerMajor: isBreaking,
        isBreaking,
        directRoot: parentDirectInfo?.name || fix.name,
        packageJsonChanges,
        lockfileUpdates: [vuln.packageName],
      };
    }
  }

  // 4. Transitive requiring overrides (parent range forbids safeVersion, no parent update available)
  if (safeVersion) {
    let workspaceScope = vuln.workspaceScope || null;
    let forbiddingParentName = vuln.parentPackage || null;

    if (!workspaceScope && chains.length > 0) {
      const wsNames = new Set();
      for (const chain of chains) {
        for (const link of chain) {
          if (link.isWorkspace && link.name) {
            wsNames.add(link.name);
          } else if (link.workspace) {
            wsNames.add(link.workspace);
          }
        }
      }
      if (wsNames.size === 1) {
        workspaceScope = Array.from(wsNames)[0];
      }
    }

    if (!forbiddingParentName && chains.length > 0) {
      for (const chain of chains) {
        if (chain.length >= 2) {
          const immParent = chain[chain.length - 2];
          const target = chain[chain.length - 1];
          const range = target.requiredRange || immParent.requiredRange;
          if (range && !semver.satisfies(safeVersion, range)) {
            forbiddingParentName = immParent.name;
            break;
          }
        }
      }
    }

    const isBreaking = isBreakingChange(vuln.currentVersion, safeVersion);
    const overrideChange = {
      package: vuln.packageName,
      section: 'overrides',
      from: null,
      to: safeVersion,
      packageJsonPath: 'package.json',
      isOutOfRange: true,
      isSemVerMajor: isBreaking,
      isBreaking,
    };
    if (workspaceScope) {
      overrideChange.workspaceScope = workspaceScope;
    }
    if (forbiddingParentName) {
      overrideChange.parentPackage = forbiddingParentName;
    }

    const strategyLabel = workspaceScope
      ? 'package-override (workspace-scoped)'
      : (forbiddingParentName ? 'package-override (parent-scoped)' : 'package-override (root override)');

    return {
      strategy: 'package-override',
      strategyLabel,
      targetPackage: vuln.packageName,
      targetVersion: safeVersion,
      isOutOfRange: true,
      isSemVerMajor: isBreaking,
      isBreaking,
      packageJsonChanges: [overrideChange],
      lockfileUpdates: [],
      note: 'Transitive dependency is forbidden by parent declared ranges. Requires persistent root override.',
    };
  }

  // 5. Transitive without safe version available
  return {
    strategy: 'none',
    strategyLabel: 'none',
    targetPackage: vuln.packageName,
    targetVersion: null,
    packageJsonChanges: [],
    lockfileUpdates: [],
    note: `No known patched version is currently available for ${vuln.packageName}. Upstream maintainers have not released a fix; investigate alternative packages or runtime mitigations.`,
  };
}

export async function resolveAuditAdvisories(vulnerabilities = [], options = {}) {
  const { githubToken, githubApiUrl, advisoryCache = new Map() } = options;

  await Promise.all(vulnerabilities.map(async (v) => {
    const lookupRefs = new Set();
    if (v.sources?.npmAudit?.url) lookupRefs.add(v.sources.npmAudit.url);
    for (const url of v.sources?.npmAudit?.urls || []) if (url) lookupRefs.add(url);
    for (const advisory of v.advisories || []) {
      if (advisory.url) lookupRefs.add(advisory.url);
      if (advisory.ghsaId) lookupRefs.add(advisory.ghsaId);
      if (advisory.id) lookupRefs.add(advisory.id);
    }
    if (v.url) lookupRefs.add(v.url);
    if (v.id) lookupRefs.add(v.id);

    for (const ref of lookupRefs) {
      const ghsaId = extractGhsaId(ref);
      const cveId = extractCveId(ref);
      const lookup = ghsaId || cveId;
      if (!lookup) continue;
      const cacheKey = JSON.stringify([lookup, v.packageName || null]);
      if (!advisoryCache.has(cacheKey)) {
        advisoryCache.set(cacheKey, fetchAdvisoryDetails(lookup, {
          githubToken, githubApiUrl, packageName: v.packageName || null,
        }));
      }
      const details = await advisoryCache.get(cacheKey);
      if (!details) continue;

      if (details.cve) {
        v.cves ||= [];
        if (!v.cves.includes(details.cve)) v.cves.push(details.cve);
        if (!v.cve) v.cve = details.cve;
      }
      if (Array.isArray(details.patchedVersions) && details.patchedVersions.length) {
        v.patchedVersions ||= [];
        for (const version of details.patchedVersions) if (version && !v.patchedVersions.includes(version)) v.patchedVersions.push(version);
        v.patchedVersions.sort((left, right) => semver.valid(left) && semver.valid(right) ? semver.compare(left, right) : left.localeCompare(right));
        v.targetSafeVersions = [...v.patchedVersions];
        v.targetSafeVersion = selectBestRemediationVersion(v.currentVersion, v.patchedVersions);
      } else if (details.targetSafeVersion) {
        v.patchedVersions ||= [];
        if (!v.patchedVersions.includes(details.targetSafeVersion)) v.patchedVersions.push(details.targetSafeVersion);
        v.targetSafeVersions = [...v.patchedVersions];
        v.targetSafeVersion = selectBestRemediationVersion(v.currentVersion, v.patchedVersions);
      }
      if (details.url) {
        if (!v.url) v.url = details.url;
        if (v.sources?.npmAudit) {
          v.sources.npmAudit.url ||= details.url;
          v.sources.npmAudit.urls ||= [];
          if (!v.sources.npmAudit.urls.includes(details.url)) v.sources.npmAudit.urls.push(details.url);
        }
      }

      v.advisories ||= [];
      const matches = v.advisories.filter((advisory) => {
        const ids = [advisory.ghsaId, advisory.id, advisory.url].filter(Boolean);
        return ids.some((id) => (ghsaId && extractGhsaId(id) === ghsaId) || (cveId && extractCveId(id) === cveId));
      });
      const affectedVersions = Array.isArray(details.affectedVersions) ? details.affectedVersions : [];
      if (!matches.length) {
        matches.push({
          id: details.ghsaId || details.cve || lookup,
          ghsaId: details.ghsaId || ghsaId || null,
          cve: details.cve || cveId || null,
          title: details.title || v.title,
          severity: details.severity || v.severity,
          url: details.url || null,
          vulnerableVersionRange: details.vulnerableVersionRange || null,
        });
        v.advisories.push(matches[0]);
      }
      for (const advisory of matches) {
        if (details.cve && !advisory.cve) advisory.cve = details.cve;
        if (affectedVersions.length) {
          advisory.affectedVersions = [...new Map([
            ...(advisory.affectedVersions || []), ...affectedVersions,
          ].map((item) => [JSON.stringify(item), item])).values()];
        }
        if (details.vulnerableVersionRange && !advisory.vulnerableVersionRange) {
          advisory.vulnerableVersionRange = details.vulnerableVersionRange;
        }
        if (Array.isArray(details.patchedVersions) && details.patchedVersions.length) {
          advisory.patchedVersions = [...new Set([...(advisory.patchedVersions || []), ...details.patchedVersions])];
          advisory.targetSafeVersions = [...advisory.patchedVersions];
        }
        if (details.targetSafeVersion && !advisory.targetSafeVersion) advisory.targetSafeVersion = details.targetSafeVersion;
        if (details.url && !advisory.url) advisory.url = details.url;
      }
    }

    if (v.targetSafeVersion && v.remediation) {
      v.remediation.targetVersion = v.targetSafeVersion;
      for (const change of v.remediation.packageJsonChanges || []) {
        if (change.package === v.packageName) {
          const prefix = change.from?.startsWith('~') ? '~' : change.from?.startsWith('^') ? '^' : '';
          change.to = `${prefix}${v.targetSafeVersion}`;
        }
      }
    }
  }));
  return vulnerabilities;
}

export async function parseAuditVulnerabilities(auditJson, pkgJson, pkgLock, npmLsData = null, worktreeDir = null, branchName = 'main', options = {}) {
  const directDeps = getDirectDependencies(pkgJson, worktreeDir);
  const vulnerabilities = [];
  const rawVulns = auditJson?.vulnerabilities || {};

  for (const [pkgName, vulnData] of Object.entries(rawVulns)) {
    const rawVias = Array.isArray(vulnData.via) ? vulnData.via : [];

    // Filter out purely intermediate packages in dependency chains (they only contain string references to vulnerable packages)
    const hasAdvisory = rawVias.some((item) => typeof item === 'object' && item !== null);
    if (rawVias.length > 0 && !hasAdvisory) {
      continue;
    }

    const pkgInfo = lookupPackageInstalledInfo(pkgName, pkgJson, pkgLock, npmLsData, worktreeDir, options.arboristTree);
    const isDirect = pkgInfo.isDirect || Boolean(vulnData.isDirect);
    const isIndirect = pkgInfo.isIndirect || !isDirect;
    const dependencyType = pkgInfo.dependencyType !== 'Unknown' ? pkgInfo.dependencyType : (isDirect ? 'Direct' : 'Indirect (Transitive)');

    let advisoryId = null;
    let cve = null;
    let title = `${vulnData.name || pkgName} vulnerability`;
    let url = null;
    let cwe = [];
    let cvss = null;
    const viaAdvisories = [];
    const cves = [];
    const urls = [];

    for (const item of rawVias) {
      if (typeof item === 'object' && item !== null) {
        viaAdvisories.push(item);
        if (!advisoryId && item.source) advisoryId = String(item.source);
        if (item.url) {
          if (!url) url = item.url;
          if (!urls.includes(item.url)) urls.push(item.url);
        }
        if (!title || title === `${vulnData.name || pkgName} vulnerability`) title = item.title || title;
        if (item.cwe && Array.isArray(item.cwe)) cwe = item.cwe;
        if (item.cvss) cvss = item.cvss;

        const foundCve = extractCveFromText(item.url) || extractCveFromText(item.title) || (item.cve ? item.cve : null);
        if (foundCve) {
          if (!cve) cve = foundCve;
          if (!cves.includes(foundCve)) cves.push(foundCve);
        }
      }
    }

    if (!advisoryId) {
      advisoryId = `AUDIT-${pkgName}-${vulnData.severity || 'vuln'}`;
    }

    const parsedAdvisories = viaAdvisories.map((a) => {
      const advGhsa = extractGhsaId(a.url) || extractGhsaId(String(a.source)) || extractGhsaId(a.title);
      const advCve = extractCveId(a.url) || extractCveId(a.title) || extractCveFromText(a.url) || extractCveFromText(a.title) || (a.cve ? a.cve : null);
      const advUrl = a.url || (advGhsa ? `https://github.com/advisories/${advGhsa}` : null);
      return {
        id: advGhsa || (a.source ? String(a.source) : advisoryId),
        ghsaId: advGhsa,
        cve: advCve,
        title: a.title || title,
        severity: a.severity || vulnData.severity || 'moderate',
        url: advUrl,
        vulnerableVersionRange: a.range || vulnData.range || null,
        targetSafeVersion: null,
        sources: {
          npmAudit: {
            advisoryId: String(a.source || advisoryId),
            url: advUrl,
            severity: a.severity || vulnData.severity,
          },
        },
      };
    });

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

    const patchedVersions = determinePatchedVersions(vulnData.range, vulnData.fixAvailable, pkgName);
    const targetSafeVersion = determineSafeVersion(vulnData.range, currentVersion, vulnData.fixAvailable, pkgName);
    const vulnRecord = {
      id: advisoryId,
      cve,
      cves,
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
      patchedVersions: [...patchedVersions],
      targetSafeVersions: [...patchedVersions],
      fixAvailable: vulnData.fixAvailable || false,
      dependencyPaths,
      dependencyChains: chains,
      directRoots,
      advisories: parsedAdvisories,
      sources: {
        npmAudit: {
          advisoryId,
          url,
          urls,
          advisories: parsedAdvisories,
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
      worktreeDir,
      options.arboristTree
    );
    vulnerabilities.push(vulnRecord);
  }

  // Resolve advisory details (CVE, targetSafeVersion, GitHub Advisory URL) via GitHub / OSV
  await resolveAuditAdvisories(vulnerabilities, options);

  // Re-synchronize remediation after resolving advisories
  for (const v of vulnerabilities) {
    if (v.targetSafeVersion && v.remediation?.strategy !== 'bump-direct' && v.remediation?.strategy !== 'bump-direct-and-lockfile') {
      v.remediation = buildRemediationSuggestion(
        v,
        v.directRoots || [],
        pkgJson,
        v.dependencyChains || [],
        v.directInfo || null,
        worktreeDir,
        options.arboristTree
      );
    }
  }

  for (const v of vulnerabilities) {
    v.isOutOfRange = Boolean(v.remediation?.isOutOfRange);
    v.isBreaking = Boolean(v.remediation?.isBreaking);
    v.isSemVerMajor = Boolean(v.remediation?.isSemVerMajor);
  }

  vulnerabilities.sort(sortVulnerabilities);

  const summary = {
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

export function groupNpmAuditByBranch(branchReports = [], repository = null) {
  return {
    repository,
    branches: branchReports.map((report) => {
      const packages = new Map();
      for (const row of report.vulnerabilities || []) {
        if (!packages.has(row.packageName)) packages.set(row.packageName, []);
        packages.get(row.packageName).push(row);
      }
      return {
        branch: report.branch,
        ...(report.baseCommit && { baseCommit: report.baseCommit }),
        ...(report.error && { error: report.error }),
        summary: report.summary,
        packages: [...packages].sort(([a], [b]) => a.localeCompare(b)).map(([packageName, rows]) => {
          const instances = getPackageInstances(packageName, report);
          return {
            packageName,
            installedVersions: [...new Set(instances.map((instance) => instance.installedVersion))].sort(semver.compare),
            instances,
            findings: normalizePlanFindings(rows, packageName),
          };
        }),
      };
    }),
  };
}

export async function collectNpmAudit(worktreeDir, branchName = 'main', options = {}) {
  const [auditJson, npmLsData] = await Promise.all([
    runNpmAuditRaw(worktreeDir),
    options.arboristTree ? Promise.resolve(null) : runNpmLs(worktreeDir),
  ]);

  const pkgJson = readPackageJson(worktreeDir);
  const pkgLock = readPackageLock(worktreeDir);

  return parseAuditVulnerabilities(auditJson, pkgJson, pkgLock, npmLsData, worktreeDir, branchName, options);
}
