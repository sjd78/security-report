import fs from 'node:fs';
import path from 'node:path';
import semver from 'semver';
import { normalizePlanFindings, isVersionSafe, selectLatestSafePatch } from './advisory-evidence.js';
import { getPackageInstances, buildDependencyInventory } from './dependency-graph.js';
import { classifyPackageFix } from './remediation-policy.js';
import { findOverrideConflicts } from './override-coverage.js';
const unique = (values) => [...new Set(values.filter((value) => value !== null && value !== undefined && value !== ''))];
const sorted = (values) => unique(values).sort();
const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const validVersion = (value) => typeof value === 'string' ? semver.valid(value) : null;

function jsonValue(value, seen = new Set()) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value !== 'object' || seen.has(value)) return undefined;
  seen.add(value);
  const result = Array.isArray(value) ? [] : {};
  for (const [key, child] of Object.entries(value)) {
    if (['arboristTree', 'worktreeDir', 'pkgJson', 'pkgLock', 'npmLsData'].includes(key)) continue;
    const normalized = jsonValue(child, seen);
    if (normalized !== undefined) {
      if (Array.isArray(result)) result.push(normalized);
      else Object.defineProperty(result, key, { value: normalized, enumerable: true, writable: true, configurable: true });
    }
  }
  seen.delete(value);
  return result;
}

function manifestsFor(branch) {
  const manifests = new Map();
  if (isObject(branch.pkgJson)) manifests.set('package.json', branch.pkgJson);
  for (const workspace of branch.workspaces || []) {
    const file = workspace.relativePath || (workspace.isRoot ? 'package.json' : null);
    if (typeof file === 'string' && isObject(workspace.pkgJson)) manifests.set(file, workspace.pkgJson);
  }
  return manifests;
}


function resolutionInstances(instances) {
  return instances.map(({ installedVersion: _installedVersion, ...instance }) => instance);
}

function currentCatalog(options, branchName, packageName) {
  return options.publishedVersionsByBranch?.get(branchName)?.get(packageName) || null;
}

function evidenceIsComplete(finding) {
  return Array.isArray(finding.constraints) && finding.constraints.length > 0
    && finding.constraints.every((constraint) => (constraint.vulnerableRange && semver.validRange(constraint.vulnerableRange))
      || (constraint.firstPatchedVersion && semver.valid(constraint.firstPatchedVersion)));
}

function safeTargetForKnownEvidence(installedVersion, versions, findings) {
  const known = findings.filter(evidenceIsComplete);
  return known.length ? selectLatestSafePatch(installedVersion, versions, known) : null;
}

function resolutionReasonForMissingPatch(line, findings) {
  const otherLines = unique(findings.flatMap((finding) => finding.constraints.map((constraint) => constraint.firstPatchedVersion))
    .filter(validVersion).filter((version) => `${semver.major(version)}.${semver.minor(version)}` !== line)
    .map((version) => `${semver.major(version)}.${semver.minor(version)}.x`)).sort();
  return `No safe patch is available on ${line}.x${otherLines.length ? `; known fixes on other lines (${otherLines.join(', ')}) do not apply to this installed line` : ''}.`;
}

function planResolutions(packageName, findings, instances, branch, options) {
  const byVersion = new Map();
  for (const instance of instances) {
    if (!byVersion.has(instance.installedVersion)) byVersion.set(instance.installedVersion, []);
    byVersion.get(instance.installedVersion).push(instance);
  }
  return [...byVersion].map(([installedVersion, versionInstances]) => {
    const line = `${semver.major(installedVersion)}.${semver.minor(installedVersion)}`;
    const id = `${packageName}@${installedVersion}`;
    const affected = findings.filter((finding) => isVersionSafe(installedVersion, [finding]) !== true);
    const safety = isVersionSafe(installedVersion, findings);
    const base = {
      id, installedVersion, line,
      status: 'manual-review',
      targetVersion: null,
      strategy: 'none',
      findingIds: sorted(affected.map((finding) => finding.id)),
      reasons: [],
      instances: resolutionInstances(versionInstances),
    };
    if (safety === true) {
      return { ...base, status: 'resolved', targetVersion: installedVersion,
        reasons: ['Already safe against all package findings; no refresh action is planned.'] };
    }
    if (safety === null) {
      const catalog = currentCatalog(options, branch.branch, packageName);
      if (Array.isArray(catalog?.versions)) base.targetVersion = safeTargetForKnownEvidence(installedVersion, catalog.versions, findings);
      base.reasons.push('Advisory evidence is incomplete or invalid; the installed version cannot be proven safe or assigned an executable target.');
      if (catalog?.error) base.reasons.push(`Published release catalog unavailable: ${catalog.error}`);
      return base;
    }
    const catalog = currentCatalog(options, branch.branch, packageName);
    if (!catalog || catalog.error || !Array.isArray(catalog.versions)) {
      base.reasons.push(`Published release catalog is unavailable${catalog?.error ? `: ${catalog.error}` : ''}; the advisory minimum is not treated as the newest published patch.`);
      return base;
    }
    const targetVersion = selectLatestSafePatch(installedVersion, catalog.versions, findings);
    if (!targetVersion) {
      base.status = 'no-fix';
      base.reasons.push(resolutionReasonForMissingPatch(line, findings));
      return base;
    }
    return { ...base, status: 'ready', targetVersion };
  }).sort((left, right) => {
    if (left.status === 'resolved' && right.status !== 'resolved') return 1;
    if (right.status === 'resolved' && left.status !== 'resolved') return -1;
    return semver.compare(left.installedVersion, right.installedVersion);
  });
}

function resolutionSummary(resolutions, actions) {
  const transitions = resolutions.filter((resolution) => resolution.status === 'ready')
    .map((resolution) => `${resolution.installedVersion} → ${resolution.targetVersion} (${resolution.strategy})`);
  const safe = resolutions.filter((resolution) => resolution.status === 'resolved').length;
  const declarations = actions.filter((action) => action.type === 'update-dependency')
    .map((action) => `${action.file} ${action.section}.${action.package}: ${action.expectedRange} → ${action.targetRange}`);
  const lockfiles = actions.filter((action) => action.type === 'update-lockfile').map((action) => `re-resolve ${action.package} in package-lock.json`);
  return [transitions.join('; '), declarations.join('; '), lockfiles.join('; '), safe ? `${safe} installed version(s) already safe; no refresh action` : '']
    .filter(Boolean).join('. ') || 'No executable version transition is planned.';
}

function directOrigins(resolution) {
  return (resolution.instances || []).flatMap((instance) => (instance.origins || [])
    .filter((origin) => origin.chain?.length === 1)
    .map((origin) => ({ instance, origin })));
}

function transitiveOrigins(resolution) {
  return (resolution.instances || []).flatMap((instance) => (instance.origins || [])
    .filter((origin) => origin.chain?.length > 1)
    .map((origin) => ({ instance, origin })));
}

function declarationTargetRange(expectedRange, targetVersion, catalogVersions) {
  if (semver.valid(expectedRange)) return targetVersion;
  if (!semver.validRange(expectedRange)) return null;
  const tilde = `~${targetVersion}`;
  return semver.maxSatisfying(catalogVersions, tilde) === targetVersion ? tilde : targetVersion;
}

function actionMotivation(packageName, resolution, findingIds = resolution.findingIds) {
  return { packageNames: [packageName], findingIds: sorted(findingIds), resolutionIds: [resolution.id] };
}

function existingOverride(rootManifest, scope, childSelector) {
  let container = rootManifest?.overrides;
  for (const key of scope) {
    if (!isObject(container) || !Object.hasOwn(container, key)) return { actionScope: [...scope], package: childSelector, expectedValue: null };
    container = container[key];
  }
  if (!isObject(container) || !Object.hasOwn(container, childSelector)) {
    return { actionScope: [...scope], package: childSelector, expectedValue: null };
  }
  const existing = container[childSelector];
  if (isObject(existing)) {
    const target = Object.hasOwn(existing, '.') ? existing['.'] : null;
    return { actionScope: [...scope, childSelector], package: '.', expectedValue: target };
  }
  return { actionScope: [...scope], package: childSelector, expectedValue: existing };
}

function originScope(origin) {
  return (origin.chain || []).slice(0, -1).map((link) => {
    if (!link.name || !validVersion(link.version)) return null;
    return `${link.name}@${link.version}`;
  });
}

function buildResolutionActions(pkg, resolution, branch, manifests, options, reasons) {
  const packageName = pkg.packageName;
  const catalog = currentCatalog(options, branch.branch, packageName);
  const actions = [];
  let directEdit = false;
  let directNeedsLockfile = false;
  let transitive = false;
  let override = false;
  const direct = directOrigins(resolution);
  const indirect = transitiveOrigins(resolution);
  const directLocations = new Set();
  for (const { instance, origin } of direct) {
    const file = origin.packageJsonPath;
    const declaration = manifests.get(file)?.[origin.section]?.[packageName];
    if (typeof declaration !== 'string' || !validVersion(resolution.targetVersion)) {
      reasons.push(`Direct origin ${file} ${origin.section}.${packageName} is missing or unsupported; the declaration cannot be safely updated.`);
      continue;
    }
    directLocations.add(instance.location);
    if (!semver.validRange(declaration)) {
      reasons.push(`Unsupported direct declaration ${file} ${origin.section}.${packageName}: ${declaration}.`);
      continue;
    }
    const targetRange = declarationTargetRange(declaration, resolution.targetVersion, catalog?.versions || []);
    if (!targetRange) {
      reasons.push(`Cannot derive an exact safe declaration for ${file} ${origin.section}.${packageName}.`);
      continue;
    }
    const rootOverride = branch.pkgJson?.overrides?.[packageName];
    const overrideValue = isObject(rootOverride) ? rootOverride['.'] : rootOverride;
    if (file === 'package.json' && typeof overrideValue === 'string' && overrideValue !== `$${packageName}` && overrideValue !== targetRange) {
      reasons.push(`Existing root override ${packageName}=${overrideValue} conflicts with direct declaration ${targetRange}; reconcile it explicitly.`);
      continue;
    }
    if (declaration !== targetRange) {
      actions.push({ type: 'update-dependency', file, section: origin.section, package: packageName,
        expectedRange: declaration, targetRange, ...actionMotivation(packageName, resolution) });
      directEdit = true;
    } else directNeedsLockfile = true;
  }
  for (const { instance, origin } of indirect) {
    transitive = true;
    const chain = origin.chain || [];
    const parent = chain.at(-2);
    const edge = (instance.incoming || []).find((item) => item.parentLocation === parent?.location
      && item.parentName === parent?.name && item.parentVersion === parent?.version);
    const requestedRange = edge?.requestedRange || chain.at(-1)?.requiredRange;
    const effectiveRange = edge?.effectiveRange || requestedRange;
    if (!parent?.name || !validVersion(parent.version) || !semver.validRange(requestedRange) || !semver.validRange(effectiveRange)) {
      reasons.push(`Transitive origin ${chain.map((link) => link.name || '?').join(' → ')} has an unsupported or missing parent range.`);
      continue;
    }
    const requestedCandidate = semver.maxSatisfying(catalog?.versions || [], requestedRange);
    const effectiveCandidate = semver.maxSatisfying(catalog?.versions || [], effectiveRange);
    const ordinarilyResolvesTarget = requestedCandidate === resolution.targetVersion
      && effectiveCandidate === resolution.targetVersion
      && semver.satisfies(resolution.targetVersion, requestedRange)
      && semver.satisfies(resolution.targetVersion, effectiveRange);
    if (ordinarilyResolvesTarget) continue;
    const scope = originScope(origin);
    if (!scope.length || scope.some((entry) => !entry)) {
      reasons.push(`No complete version-qualified override ancestry is available for ${parent.name} → ${packageName}.`);
      continue;
    }
    if (options.allowOverrides === false) {
      reasons.push('The selected patch line requires a persistent override, but overrides are disabled.');
      continue;
    }
    const childSelector = `${packageName}@${resolution.line}.x`;
    const existing = existingOverride(branch.pkgJson || {}, scope, childSelector);
    if (existing.expectedValue !== null && typeof existing.expectedValue !== 'string') {
      reasons.push(`Existing override path ${[...existing.actionScope, existing.package].join(' > ')} is not a string and requires manual review.`);
      continue;
    }
    actions.push({ type: 'set-override', file: 'package.json', package: existing.package,
      scope: existing.actionScope, expectedValue: existing.expectedValue, targetVersion: resolution.targetVersion,
      ...actionMotivation(packageName, resolution) });
    override = true;
  }
  if (!direct.length && !indirect.length) {
    reasons.push(`No complete physical origin is available for ${packageName}@${resolution.installedVersion}.`);
  }
  if (transitive || directNeedsLockfile || (direct.length && !directEdit)) {
    actions.push({ type: 'update-lockfile', package: packageName, ...actionMotivation(packageName, resolution) });
  }
  const strategies = actions.map((action) => action.type);
  const strategy = override ? 'package-override'
    : strategies.includes('update-dependency') && strategies.includes('update-lockfile') ? 'bump-direct-and-lockfile'
      : strategies.includes('update-dependency') ? 'bump-direct'
        : strategies.includes('update-lockfile') ? 'lockfile-update' : 'none';
  resolution.strategy = strategy;
  return actions;
}

function actionIdentity(action) {
  if (action.type === 'update-dependency') return JSON.stringify([action.type, action.file, action.section, action.package]);
  if (action.type === 'set-override') return JSON.stringify([action.type, action.file, ...action.scope, action.package]);
  return JSON.stringify([action.type, action.package]);
}

function reconcileActions(actions, blockers) {
  const reconciled = new Map();
  for (const action of actions) {
    const key = actionIdentity(action);
    const previous = reconciled.get(key);
    if (!previous) {
      reconciled.set(key, { ...action, ...(action.scope ? { scope: [...action.scope] } : {}),
        packageNames: [...action.packageNames], findingIds: [...action.findingIds], resolutionIds: [...action.resolutionIds] });
      continue;
    }
    const fields = action.type === 'update-dependency' ? ['expectedRange', 'targetRange']
      : action.type === 'set-override' ? ['expectedValue', 'targetVersion'] : [];
    if (fields.some((field) => previous[field] !== action[field])) {
      blockers.push(`Conflicting saved actions for ${action.file || 'package-lock.json'} ${action.section || 'overrides'} ${action.package}; targets and preconditions differ.`);
      continue;
    }
    previous.packageNames = sorted([...previous.packageNames, ...action.packageNames]);
    previous.findingIds = sorted([...previous.findingIds, ...action.findingIds]);
    previous.resolutionIds = sorted([...previous.resolutionIds, ...action.resolutionIds]);
  }
  return [...reconciled.values()].sort((left, right) => actionIdentity(left).localeCompare(actionIdentity(right)));
}

function packagePlan(packageName, rows, branch, options) {
  const findings = normalizePlanFindings(rows, packageName);
  const instances = getPackageInstances(packageName, branch);
  const versions = unique(instances.map((instance) => instance.installedVersion)).filter(validVersion).sort(semver.compare);
  const base = { packageName, installedVersions: versions, status: 'manual-review', summary: '', reasons: [],
    resolutions: [], findings, risk: { fixType: 'unknown', breaking: null, reasons: [] } };
  if (!versions.length) {
    base.status = isObject(branch.pkgLock?.packages) || isObject(branch.pkgLock?.dependencies) ? 'not-installed' : 'manual-review';
    base.reasons.push(base.status === 'not-installed'
      ? 'Package is absent from the scanned installed dependency snapshot.'
      : 'An installed dependency snapshot is required to establish package presence.');
    base.summary = base.reasons[0];
    return base;
  }
  base.resolutions = planResolutions(packageName, findings, instances, branch, options);
  const manifestMap = manifestsFor(branch);
  const proposed = [];
  for (const resolution of base.resolutions) {
    if (resolution.status !== 'ready') continue;
    const resolutionActions = buildResolutionActions(base, resolution, branch, manifestMap, options, resolution.reasons);
    if (resolution.reasons.length) {
      resolution.status = 'manual-review';
      resolution.strategy = 'none';
      base.reasons.push(...resolution.reasons);
      continue;
    }
    proposed.push(...resolutionActions);
  }
  const incomplete = base.resolutions.some((resolution) => ['manual-review', 'no-fix'].includes(resolution.status));
  const ready = base.resolutions.some((resolution) => resolution.status === 'ready');
  base.reasons = sorted([...base.reasons, ...base.resolutions.flatMap((resolution) => resolution.reasons)]);
  if (incomplete) {
    base.status = base.resolutions.some((resolution) => resolution.status === 'manual-review') ? 'manual-review' : 'no-fix';
    if (ready) base.reasons.push('Other ready installed lines are not executable until every version of this package is covered.');
  } else if (ready) base.status = 'ready';
  else base.status = 'resolved';
  base.summary = resolutionSummary(base.resolutions, base.status === 'ready' ? proposed : []);
  if (base.status !== 'ready') return base;
  if (base.resolutions.some((resolution) => resolution.status === 'ready' && resolution.strategy === 'none')) {
    base.status = 'manual-review';
    base.reasons.push('At least one vulnerable installed line has no executable action coverage.');
    return base;
  }
  base.actions = proposed;
  return base;
}

function mergeOverrideConflictReasons(packages, actions, branch) {
  const overrides = actions.filter((action) => action.type === 'set-override');
  if (!overrides.length) return new Set();
  const inventory = buildDependencyInventory(branch);
  const conflicts = findOverrideConflicts(overrides, inventory, branch.pkgJson || {});
  const affected = new Set();
  for (const reason of conflicts) {
    const candidates = overrides.filter((action) => reason.includes(action.package)
      || action.packageNames.some((name) => reason.includes(name)));
    for (const action of candidates.length ? candidates : overrides) {
      for (const name of action.packageNames) affected.add(name);
      const pkg = packages.find((entry) => action.packageNames.includes(entry.packageName));
      if (pkg) {
        pkg.status = 'manual-review';
        pkg.reasons.push(reason);
        for (const resolution of pkg.resolutions.filter((entry) => action.resolutionIds.includes(entry.id))) {
          resolution.status = 'manual-review';
          resolution.strategy = 'none';
          resolution.reasons.push(reason);
        }
      }
    }
  }
  return affected;
}

export function generateRemediationPlan(report, options = {}) {
  const branches = (report.branches || []).map((branch) => {
    const blockers = [];
    const baseCommit = typeof branch.baseCommit === 'string' && branch.baseCommit.trim() ? branch.baseCommit : null;
    if (!baseCommit) blockers.push('Missing scanned base commit SHA; scan this branch again before planning edits.');
    if (branch.error) blockers.push(`Branch scan failed: ${typeof branch.error === 'string' ? branch.error : JSON.stringify(jsonValue(branch.error))}.`);
    const groups = new Map();
    for (const vulnerability of branch.vulnerabilities || []) {
      const name = vulnerability.packageName || 'unknown';
      if (!groups.has(name)) groups.set(name, []);
      groups.get(name).push(vulnerability);
    }
    if (groups.size && !isObject(branch.pkgJson)) blockers.push('Missing scanned package.json snapshot; scan this branch again before planning edits.');
    if (groups.size && (!isObject(branch.pkgLock) || (!isObject(branch.pkgLock.packages) && !isObject(branch.pkgLock.dependencies)))) {
      blockers.push('Missing or invalid scanned package-lock.json snapshot; installed packages cannot be established.');
    }
    const packages = [...groups].map(([name, rows]) => packagePlan(name, rows, branch, options))
      .sort((left, right) => left.packageName.localeCompare(right.packageName));
    const actions = reconcileActions(packages.flatMap((pkg) => pkg.actions || []), blockers);
    const overrideAffected = mergeOverrideConflictReasons(packages, actions, branch);
    const executableNames = new Set(packages.filter((pkg) => pkg.status === 'ready' && !overrideAffected.has(pkg.packageName))
      .map((pkg) => pkg.packageName));
    const canonicalActions = actions.filter((action) => action.packageNames.some((name) => executableNames.has(name)))
      .map((action) => {
        const packageNames = action.packageNames.filter((name) => executableNames.has(name));
        const resolutions = packages.filter((pkg) => packageNames.includes(pkg.packageName));
        const findingIds = new Set(resolutions.flatMap((pkg) => pkg.findings.map((finding) => finding.id)));
        const resolutionIds = new Set(resolutions.flatMap((pkg) => pkg.resolutions.filter((resolution) => resolution.status === 'ready').map((resolution) => resolution.id)));
        return { ...action, packageNames, findingIds: sorted(action.findingIds.filter((id) => findingIds.has(id))),
          resolutionIds: sorted(action.resolutionIds.filter((id) => resolutionIds.has(id))) };
      });
    for (const pkg of packages) {
      delete pkg.actions;
      const pkgActions = canonicalActions.filter((action) => action.packageNames.includes(pkg.packageName));
      if (pkg.status === 'ready' && pkgActions.length) {
        pkg.risk = classifyPackageFix(pkg, pkgActions, branch);
      } else if (pkg.status === 'ready') {
        pkg.status = 'manual-review';
        pkg.reasons.push('No canonical action covers every selected installed resolution.');
      }
      pkg.summary = resolutionSummary(pkg.resolutions, pkgActions);
    }
    const ready = packages.filter((pkg) => pkg.status === 'ready').length;
    const manual = packages.filter((pkg) => pkg.status === 'manual-review').length;
    const noFix = packages.filter((pkg) => pkg.status === 'no-fix').length;
    const resolved = packages.filter((pkg) => pkg.status === 'resolved').length;
    const absent = packages.filter((pkg) => pkg.status === 'not-installed').length;
    const status = blockers.length ? 'blocked' : canonicalActions.length ? 'ready' : 'no-op';
    return {
      branch: branch.branch,
      baseCommit,
      status,
      summary: `${blockers.length ? 'Execution blocked; ' : ''}${ready} package(s) planned for remediation, ${manual} require manual review, ${noFix} have no known fix, ${resolved} are resolved, and ${absent} are not installed.`,
      blockers: sorted(blockers),
      packages,
      actions: blockers.length ? [] : canonicalActions,
    };
  });
  return {
    schemaVersion: '2.0.0',
    kind: 'security-remediation-plan',
    generatedAt: report.generatedAt || null,
    repository: jsonValue(report.repository) || null,
    summary: {
      totalBranches: branches.length,
      readyPackages: branches.reduce((total, branch) => total + (branch.status === 'ready' ? branch.packages.filter((pkg) => pkg.status === 'ready').length : 0), 0),
      unresolvedPackages: branches.reduce((total, branch) => total + branch.packages.filter((pkg) => ['manual-review', 'no-fix'].includes(pkg.status) || (branch.status === 'blocked' && pkg.status === 'ready')).length, 0),
    },
    branches,
  };
}

export function writeRemediationPlan(plan, outputDir, filename = 'security-remediation-plan.json') {
  fs.mkdirSync(outputDir, { recursive: true });
  const targetPath = path.resolve(outputDir, filename);
  fs.writeFileSync(targetPath, JSON.stringify(plan, null, 2) + '\n', 'utf8');
  return targetPath;
}
