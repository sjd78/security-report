import path from 'node:path';
import fs from 'node:fs';
import semver from 'semver';
import { isVulnerabilityResolved, selectBestRemediationVersion } from '../core/blender.js';
import { getDirectDependencies, lookupPackageInstalledInfo } from '../core/dependency-graph.js';
import { canBeResolvedInLockfile } from '../collectors/npm-audit.js';
import { classifyPackageFix } from '../core/remediation-policy.js';

const dependencySections = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
const unique = (values) => [...new Set(values.filter((value) => value !== null && value !== undefined && value !== ''))];
const sorted = (values) => unique(values).sort();
const cleanVersion = (value) => typeof value === 'string' ? semver.valid(value.replace(/^[~^]/, '')) : null;
const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

// Source metadata is copied, never the mutable Arborist/worktree snapshot.
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

function mergeSources(...sources) {
  const result = {};
  for (const source of sources) {
    for (const [key, value] of Object.entries(jsonValue(source) || {})) {
      if (!(key in result) || result[key] === null) result[key] = value;
      else if (Array.isArray(result[key]) || Array.isArray(value)) {
        const values = [...(Array.isArray(result[key]) ? result[key] : [result[key]]), ...(Array.isArray(value) ? value : [value])];
        result[key] = [...new Map(values.map((entry) => [JSON.stringify(entry), entry])).values()];
      } else if (isObject(result[key]) && isObject(value)) result[key] = mergeSources(result[key], value);
      else if (JSON.stringify(result[key]) !== JSON.stringify(value)) result[key] = [result[key], value];
    }
  }
  return result;
}

function normalizeFindings(rows, packageName) {
  const findings = new Map();
  for (const row of rows) {
    const advisories = row.advisories?.length ? [...row.advisories] : [row];
    if (row.advisories?.length && row.vulnerableVersionRange && !advisories.some((advisory) => advisory.vulnerableVersionRange === row.vulnerableVersionRange)) advisories.push(row);
    for (const advisory of advisories) {
      const cves = sorted([advisory.cve, ...(advisory.cves || []), row.cve, ...(row.cves || [])]);
      const finding = {
        id: String(advisory.id || advisory.cve || advisory.url || row.id || `${packageName}:finding-${findings.size + 1}`),
        cve: advisory.cve || cves[0] || null,
        cves,
        title: advisory.title || row.title || `${packageName} vulnerability`,
        severity: advisory.severity || row.severity || 'unknown',
        url: advisory.url || row.url || null,
        vulnerableVersionRange: advisory.vulnerableVersionRange || (!row.advisories?.length ? row.vulnerableVersionRange : null) || null,
        targetSafeVersion: advisory.targetSafeVersion || null,
        patchedVersions: sorted([...(advisory.patchedVersions || []), ...(advisory.targetSafeVersions || []), advisory.targetSafeVersion]),
        sources: mergeSources(row.sources, advisory.sources, row.url && row.url !== advisory.url ? { advisoryUrls: [row.url] } : null),
      };
      const key = JSON.stringify([finding.id, finding.vulnerableVersionRange, finding.targetSafeVersion, finding.patchedVersions]);
      const previous = findings.get(key);
      if (previous) {
        previous.cves = sorted([...previous.cves, ...finding.cves]);
        previous.sources = mergeSources(previous.sources, finding.sources);
        if (finding.url && previous.url !== finding.url) previous.sources = mergeSources(previous.sources, { advisoryUrls: [previous.url, finding.url].filter(Boolean) });
      } else findings.set(key, finding);
    }
  }
  return [...findings.values()].sort((a, b) => a.id.localeCompare(b.id) || JSON.stringify(a).localeCompare(JSON.stringify(b)));
}

function safeForFinding(version, finding) {
  if (!semver.valid(version)) return false;
  if (finding.vulnerableVersionRange) {
    if (!semver.validRange(finding.vulnerableVersionRange)) return false;
    return !semver.satisfies(version, finding.vulnerableVersionRange);
  }
  return isVulnerabilityResolved({ ...finding, installedVersions: [version] });
}

function safeForAll(version, findings) {
  return findings.length > 0 && findings.every((finding) => safeForFinding(version, finding));
}

function safeFile(file) {
  return typeof file === 'string' && file !== '' && !file.includes('\\') && !path.posix.isAbsolute(file)
    && !/^[a-zA-Z]:/.test(file) && file.split('/').every((part) => part !== '' && part !== '.' && part !== '..')
    && path.posix.basename(file) === 'package.json';
}

function snapshotFor(branch, blockers) {
  const manifests = new Map();
  if (!isObject(branch.pkgJson)) blockers.push('Missing scanned package.json snapshot; scan this branch again before planning edits.');
  else manifests.set('package.json', branch.pkgJson);
  if (!isObject(branch.pkgLock) || (!isObject(branch.pkgLock.packages) && !isObject(branch.pkgLock.dependencies))) {
    blockers.push('Missing or invalid scanned package-lock.json snapshot; installed packages cannot be established.');
  }
  for (const workspace of branch.workspaces || []) {
    const file = workspace.relativePath || (workspace.isRoot ? 'package.json' : null);
    if (!safeFile(file) || !isObject(workspace.pkgJson)) {
      blockers.push(`Invalid workspace manifest snapshot ${JSON.stringify(file)}; provide a repository-relative package.json and its contents.`);
      continue;
    }
    if (manifests.has(file) && JSON.stringify(manifests.get(file)) !== JSON.stringify(workspace.pkgJson)) {
      blockers.push(`Conflicting scanned manifest snapshots for ${file}.`);
      continue;
    }
    manifests.set(file, workspace.pkgJson);
  }
  const workspaces = [...manifests].map(([relativePath, pkgJson]) => ({ relativePath, pkgJson, name: pkgJson.name || 'root', isRoot: relativePath === 'package.json' }));
  const arboristTree = typeof branch.arboristTree?.inventory?.query === 'function' ? branch.arboristTree : null;
  return { manifests, workspaces, arboristTree, direct: getDirectDependencies(branch.pkgJson, workspaces) };
}

function installedVersions(packageName, branch, snapshot) {
  const versions = [];
  if (snapshot.arboristTree) {
    for (const node of snapshot.arboristTree.inventory.query('name', packageName)) if (semver.valid(node.version)) versions.push(node.version);
  }
  for (const [location, entry] of Object.entries(branch.pkgLock?.packages || {})) {
    if ((location === `node_modules/${packageName}` || location.endsWith(`/node_modules/${packageName}`)) && semver.valid(entry.version)) versions.push(entry.version);
  }
  if (!branch.pkgLock?.packages) {
    const visit = (dependencies) => {
      for (const [name, entry] of Object.entries(dependencies || {})) {
        if (name === packageName && semver.valid(entry.version)) versions.push(entry.version);
        visit(entry.dependencies);
      }
    };
    visit(branch.pkgLock?.dependencies);
  }
  return unique(versions).sort(semver.compare);
}

function incomingRanges(packageName, rows, branch, snapshot) {
  const edges = [];
  if (snapshot.arboristTree) {
    for (const node of snapshot.arboristTree.inventory.query('name', packageName)) {
      for (const edge of node.edgesIn || []) {
        if (edge.from?.isProjectRoot || edge.from?.isWorkspace) continue;
        edges.push({ parent: edge.from?.packageName || edge.from?.name, version: node.version, range: edge.spec, root: null });
      }
    }
  }
  const chains = rows.flatMap((row) => row.dependencyChains || row.chains || []);
  if (!chains.length && !snapshot.arboristTree && isObject(branch.pkgLock)) {
    const info = lookupPackageInstalledInfo(packageName, branch.pkgJson, branch.pkgLock, branch.npmLsData, snapshot.workspaces);
    chains.push(...info.chains);
  }
  for (const chain of chains) {
    if (!Array.isArray(chain) || chain.length < 2) continue;
    const target = chain[chain.length - 1];
    const parent = chain[chain.length - 2];
    if (target.name && target.name !== packageName) continue;
    if (parent.isRoot || parent.isWorkspace || parent.isWorkspaceRoot || parent.isProjectRoot || parent.isDirectDecl) continue;
    edges.push({ parent: parent.name, version: target.version, range: target.requiredRange || parent.requiredRange, root: chain.find((link) => !link.isRoot && !link.isWorkspace)?.name || null });
  }
  return [...new Map(edges.map((edge) => [JSON.stringify(edge), edge])).values()];
}

function actionKey(action) {
  if (action.type === 'update-dependency') return JSON.stringify([action.type, action.file, action.section, action.package]);
  if (action.type === 'set-override') return JSON.stringify([action.type, action.file, ...action.scope, action.package]);
  return JSON.stringify([action.type, action.package]);
}

function reconcileActions(actions, blockers) {
  const reconciled = new Map();
  for (const action of actions) {
    const key = actionKey(action);
    const previous = reconciled.get(key);
    if (!previous) reconciled.set(key, { ...action, ...(action.scope ? { scope: [...action.scope] } : {}), packageNames: [...action.packageNames], findingIds: [...action.findingIds] });
    else {
      const fields = action.type === 'update-dependency' ? ['expectedRange', 'targetRange'] : action.type === 'set-override' ? ['expectedValue', 'targetVersion'] : [];
      if (fields.some((field) => previous[field] !== action[field])) {
        blockers.push(`Conflicting edits for ${action.file || 'package-lock.json'} ${action.section || 'overrides'} ${action.package}: ${JSON.stringify(previous)} conflicts with ${JSON.stringify(action)}; choose one compatible target and precondition before execution.`);
      } else {
        previous.packageNames = sorted([...previous.packageNames, ...action.packageNames]);
        previous.findingIds = sorted([...previous.findingIds, ...action.findingIds]);
      }
    }
  }
  const result = [...reconciled.values()].sort((a, b) => actionKey(a).localeCompare(actionKey(b)));
  const overrides = result.filter((action) => action.type === 'set-override');
  for (let i = 0; i < overrides.length; i += 1) {
    for (let j = i + 1; j < overrides.length; j += 1) {
      const left = [...overrides[i].scope, overrides[i].package];
      const right = [...overrides[j].scope, overrides[j].package];
      if (left.every((part, index) => part === right[index]) || right.every((part, index) => part === left[index])) {
        blockers.push(`Overlapping override edits at ${left.join(' > ')} and ${right.join(' > ')} would replace shared manifest structure.`);
      }
    }
  }
  for (const override of overrides.filter((action) => action.scope.length === 0)) {
    const direct = result.find((action) => action.type === 'update-dependency' && action.file === 'package.json' && action.package === override.package);
    if (direct && direct.targetRange !== override.targetVersion) blockers.push(`Root override for ${override.package} (${override.targetVersion}) conflicts with its direct declaration (${direct.targetRange}); npm requires matching specs.`);
  }
  return result;
}

function buildPackage(rows, branch, snapshot, options, blockers) {
  const packageName = rows[0].packageName || 'unknown';
  const findings = normalizeFindings(rows, packageName);
  const versions = installedVersions(packageName, branch, snapshot);
  const plan = {
    packageName,
    currentVersion: versions.length ? versions.join(', ') : rows[0].currentVersion || 'unknown',
    installedVersions: versions,
    targetSafeVersion: null,
    status: 'manual-review',
    reasons: [],
    findings,
    dependencyPaths: sorted(rows.flatMap((row) => row.dependencyPaths || [])),
    actions: [],
  };
  const finish = (status, reason) => {
    plan.status = status;
    if (reason) plan.reasons.push(reason);
    if (status !== 'ready') plan.actions = [];
    return plan;
  };
  if (!versions.length) {
    if (isObject(branch.pkgLock?.packages) || isObject(branch.pkgLock?.dependencies)) return finish('not-installed', 'Package is absent from the scanned installed dependency snapshot; report placeholders are not installed versions.');
    return finish('manual-review', 'An installed dependency snapshot is required to establish package presence.');
  }
  const candidates = unique(rows.flatMap((row) => [row.targetSafeVersion, ...(row.patchedVersions || []), ...(row.targetSafeVersions || [])])
    .concat(findings.flatMap((finding) => [finding.targetSafeVersion, ...finding.patchedVersions])))
    .map(cleanVersion).filter(Boolean).filter((version) => safeForAll(version, findings));
  const choose = (current, choices = candidates) => selectBestRemediationVersion(current, choices.filter((version) => !current || !semver.valid(current) || semver.gte(version, current)));
  plan.targetSafeVersion = choose(versions[0]);
  if (versions.every((version) => safeForAll(version, findings))) return finish('resolved', 'Every installed version is safe against every finding; no edits are needed.');
  if (!candidates.length) {
    const knownFix = rows.some((row) => row.targetSafeVersion || row.patchedVersions?.length || row.targetSafeVersions?.length)
      || findings.some((finding) => finding.targetSafeVersion || finding.patchedVersions.length);
    return finish(knownFix ? 'manual-review' : 'no-fix', knownFix
      ? 'No known target can be proven safe against every advisory; resolve the incompatible or incomplete advisory metadata before execution.'
      : 'No known patched version is available; investigate upstream fixes, alternatives, or runtime mitigations.');
  }
  const motivation = { packageNames: [packageName], findingIds: sorted(findings.map((finding) => finding.id)) };
  const remediations = rows.map((row) => row.remediation).filter(Boolean);
  const changes = remediations.flatMap((remediation) => remediation.packageJsonChanges || []);
  const manualReasons = [];
  const dependencyAction = (change, targetRange) => {
    const file = change.packageJsonPath || 'package.json';
    const section = change.section || 'dependencies';
    if (!safeFile(file)) {
      blockers.push(`Unsafe manifest edit path ${JSON.stringify(file)} for ${packageName}; only repository-relative package.json paths without traversal are allowed.`);
      return;
    }
    const manifest = snapshot.manifests.get(file);
    const expectedRange = manifest?.[section]?.[change.package];
    if (!manifest || !dependencySections.includes(section) || typeof expectedRange !== 'string') {
      blockers.push(`Missing scanned declaration ${file} ${section}.${change.package}; rescan before planning this edit.`);
      return;
    }
    if (change.from !== undefined && change.from !== null && change.from !== expectedRange) {
      blockers.push(`Stale edit precondition for ${file} ${section}.${change.package}: expected ${JSON.stringify(change.from)}, snapshot contains ${JSON.stringify(expectedRange)}.`);
      return;
    }
    if (!semver.validRange(targetRange)) {
      manualReasons.push(`Unsupported target range ${JSON.stringify(targetRange)} for ${file} ${change.package}.`);
      return;
    }
    const previousFloor = semver.validRange(expectedRange) ? semver.minVersion(expectedRange)?.version : null;
    const targetFloor = semver.minVersion(targetRange)?.version;
    if (!previousFloor || !targetFloor || semver.lt(targetFloor, previousFloor)) {
      manualReasons.push(`The edit for ${file} ${change.package} has an unsupported source range or would downgrade its declared major; reconcile this declaration manually.`);
      return;
    }
    if (expectedRange !== targetRange) plan.actions.push({ type: 'update-dependency', file, section, package: change.package, expectedRange, targetRange, ...motivation });
  };
  const overrideAction = (scope, targetVersion) => {
    if (options.allowOverrides === false) {
      manualReasons.push('The safe version requires a persistent override, but overrides are disabled.');
      return;
    }
    if (!Array.isArray(scope) || !scope.every((key) => typeof key === 'string' && key !== '' && !['__proto__', 'prototype', 'constructor'].includes(key))) {
      manualReasons.push('The required override scope cannot be represented safely.');
      return;
    }
    let container = branch.pkgJson?.overrides;
    for (const key of scope) {
      if (container !== undefined && container !== null && !isObject(container)) {
        manualReasons.push(`Existing override at ${scope.join(' > ')} is a scalar; adding a nested override requires manual reconciliation.`);
        return;
      }
      container = container?.[key];
    }
    if (container !== undefined && container !== null && !isObject(container)) {
      manualReasons.push(`Existing override scope ${scope.join(' > ')} must be reconciled before adding ${packageName}.`);
      return;
    }
    let overridePackage = packageName;
    let actionScope = scope;
    let expectedValue = container?.[packageName] ?? null;
    if (isObject(expectedValue)) {
      actionScope = [...scope, packageName];
      overridePackage = '.';
      expectedValue = expectedValue['.'] ?? null;
    }
    if (expectedValue !== null && typeof expectedValue !== 'string') {
      manualReasons.push(`Existing override for ${packageName} is not a string or a supported nested override.`);
      return;
    }
    if (expectedValue !== targetVersion) plan.actions.push({ type: 'set-override', file: 'package.json', package: overridePackage, scope: actionScope, expectedValue, targetVersion, ...motivation });
  };
  const lockfileAction = () => plan.actions.push({ type: 'update-lockfile', package: packageName, ...motivation });
  const declarations = snapshot.direct.get(packageName)?.declarations || [];
  const proposedEdits = new Map();
  for (const change of changes) {
    const identity = JSON.stringify([change.packageJsonPath || 'package.json', change.section || 'dependencies', change.scope || change.workspaceScope || change.parentPackage || null, change.package]);
    const previous = proposedEdits.get(identity);
    if (previous && (previous.to !== change.to || previous.from !== change.from)) blockers.push(`Conflicting proposed manifest edits for ${change.package} at ${change.packageJsonPath || 'package.json'}; reconcile targets and expected ranges before execution.`);
    else proposedEdits.set(identity, change);
  }
  for (const declaration of rows.flatMap((row) => row.workspaceDeclarations || [])) {
    const file = declaration.packageJsonPath || 'package.json';
    const actual = snapshot.manifests.get(file)?.[declaration.section || 'dependencies']?.[packageName];
    if (!safeFile(file) || typeof actual !== 'string' || (declaration.range != null && actual !== declaration.range)) blockers.push(`Missing, unsafe, or stale scanned declaration ${JSON.stringify(file)} for ${packageName}; rescan the workspace before execution.`);
  }
  for (const change of changes) {
    if (change.section !== 'overrides') {
      const file = change.packageJsonPath || 'package.json';
      if (!safeFile(file) || !snapshot.manifests.has(file)) {
        blockers.push(`Missing or unsafe scanned manifest ${JSON.stringify(file)} referenced by ${packageName}.`);
      } else if (change.from != null && snapshot.manifests.get(file)?.[change.section || 'dependencies']?.[change.package] !== change.from) {
        blockers.push(`Stale edit precondition for ${file} ${change.section || 'dependencies'}.${change.package}; rescan before execution.`);
      }
    }
  }
  for (const declaration of declarations) {
    const matching = versions.filter((version) => semver.validRange(declaration.range) && semver.satisfies(version, declaration.range));
    if (matching.length && matching.every((version) => safeForAll(version, findings))) continue;
    const baseline = matching.at(-1) || (semver.validRange(declaration.range) ? semver.minVersion(declaration.range)?.version : null);
    if (!baseline) {
      manualReasons.push(`Unsupported declaration ${declaration.packageJsonPath} ${declaration.range}; a registry semver range is required.`);
      continue;
    }
    const target = choose(baseline);
    if (!target) {
      manualReasons.push(`No safe, non-downgrading target is known for ${declaration.packageJsonPath} ${declaration.range}.`);
      continue;
    }
    const prefix = declaration.range.startsWith('~') ? '~' : declaration.range.startsWith('^') ? '^' : '';
    const rootOverride = branch.pkgJson?.overrides?.[packageName];
    const overrideValue = isObject(rootOverride) ? rootOverride['.'] : rootOverride;
    if (overrideValue && overrideValue !== `${prefix}${target}` && overrideValue !== `$${packageName}`) {
      manualReasons.push(`Existing root override ${packageName}=${overrideValue} must match the planned direct declaration ${prefix}${target}; reconcile it explicitly before execution.`);
    }
    dependencyAction({ package: packageName, ...declaration, from: declaration.range }, `${prefix}${target}`);
  }
  const parentRemediations = remediations.filter((remediation) => remediation.strategy === 'bump-direct-parent');
  const updatedParents = new Set();
  for (const remediation of parentRemediations) {
    for (const change of remediation.packageJsonChanges || []) {
      if (change.section === 'overrides' || change.package === packageName) continue;
      const target = cleanVersion(remediation.targetVersion);
      const floor = semver.validRange(change.to) ? semver.minVersion(change.to)?.version : null;
      if (!target || !floor || semver.lt(floor, target)) {
        manualReasons.push(`Parent upgrade for ${change.package} lacks a concrete target matching its remediation strategy.`);
        continue;
      }
      dependencyAction(change, change.to);
      updatedParents.add(change.package);
    }
  }
  const edges = incomingRanges(packageName, rows, branch, snapshot);
  const hasTransitive = edges.length > 0 || rows.some((row) => row.isIndirect || row.dependencyType?.includes('Indirect') || row.dependencyType?.includes('Transitive'))
    || remediations.some((remediation) => ['lockfile-update', 'package-override', 'bump-direct-and-lockfile', 'bump-direct-parent'].includes(remediation.strategy));
  const needsLockfile = !plan.actions.length || hasTransitive;
  if (hasTransitive) {
    if (edges.length) {
      for (const version of versions.filter((installed) => !safeForAll(installed, findings))) {
        if (!edges.some((edge) => cleanVersion(edge.version) === version) && !declarations.some((declaration) => semver.validRange(declaration.range) && semver.satisfies(version, declaration.range))) {
          manualReasons.push(`Incoming ranges do not cover installed vulnerable version ${version}; complete the dependency snapshot before execution.`);
        }
      }
      const requiredOverrides = new Map();
      for (const edge of edges) {
        if (updatedParents.has(edge.root) || updatedParents.has(edge.parent)) continue;
        const current = cleanVersion(edge.version) || (versions.length === 1 ? versions[0] : null);
        if (!current) {
          manualReasons.push(`Incoming dependency from ${edge.parent || 'unknown parent'} lacks its installed version; multiple installed majors cannot be safely reconciled.`);
          continue;
        }
        if (safeForAll(current, findings)) continue;
        const allowed = candidates.filter((version) => canBeResolvedInLockfile(version, [[{ name: edge.parent }, { name: packageName, requiredRange: edge.range }]]));
        const globalOverride = branch.pkgJson?.overrides?.[packageName];
        const parentOverride = branch.pkgJson?.overrides?.[edge.parent]?.[packageName];
        const existingOverride = parentOverride ?? (isObject(globalOverride) ? globalOverride['.'] : globalOverride);
        const permitted = choose(current, allowed);
        if (permitted && (!existingOverride || (semver.validRange(existingOverride) && semver.satisfies(permitted, existingOverride)))) continue;
        const target = choose(current);
        if (!target || !edge.parent) {
          manualReasons.push(`No provably safe target or persistent override scope is known for ${edge.parent || 'unknown parent'} -> ${packageName} (${edge.range || 'missing range'}).`);
          continue;
        }
        const existing = requiredOverrides.get(edge.parent);
        if (existing && existing !== target) manualReasons.push(`Parent ${edge.parent} requires incompatible safe major versions of ${packageName}; version-scoped overrides need manual review.`);
        else requiredOverrides.set(edge.parent, target);
      }
      for (const [parent, target] of requiredOverrides) overrideAction([parent], target);
    } else if (!declarations.length) {
      const explicit = changes.filter((change) => change.section === 'overrides' && change.package === packageName);
      if (explicit.length) {
        const target = choose(versions.at(-1));
        if (!target) manualReasons.push(`No common safe override target avoids downgrading installed versions of ${packageName}.`);
        else for (const change of explicit) {
          const scope = change.scope || (change.workspaceScope ? [change.workspaceScope] : change.parentPackage ? [change.parentPackage] : []);
          if (!Array.isArray(scope) || scope.length) manualReasons.push('Scoped override coverage cannot be proven without incoming dependency paths; provide a complete snapshot or an explicit global override.');
          else overrideAction(scope, target);
        }
      } else manualReasons.push('Incoming dependency ranges are missing from the snapshot; lockfile-only or parent-upgrade safety cannot be proven.');
    } else if (rows.some((row) => row.isIndirect || row.dependencyType === 'Direct & Indirect') || remediations.some((remediation) => remediation.strategy === 'bump-direct-and-lockfile')) {
      manualReasons.push('Transitive instances are reported, but their incoming dependency ranges are missing; a direct edit alone cannot establish safety.');
    }
  }
  if (!declarations.length && !hasTransitive && !updatedParents.size) manualReasons.push('No scanned declaration or supported remediation strategy identifies how this installed package can be updated.');
  if (manualReasons.length) return finish('manual-review', unique(manualReasons).join(' '));
  if (needsLockfile) lockfileAction();
  if (!plan.actions.length) return finish('manual-review', 'No safe executable edit could be derived from the scanned declarations.');
  plan.actions = reconcileActions(plan.actions, blockers);
  return finish('ready', 'Planned edits use known versions safe against every finding; lockfile changes must be verified after execution.');
}

export function generateRemediationPlan(report, options = {}) {
  const branches = (report.branches || []).map((branch) => {
    const blockers = [];
    const baseCommit = typeof branch.baseCommit === 'string' && branch.baseCommit.trim() ? branch.baseCommit : null;
    if (!baseCommit) blockers.push('Missing scanned base commit SHA; scan this branch again before execution.');
    if (branch.error) blockers.push(`Branch scan failed: ${typeof branch.error === 'string' ? branch.error : JSON.stringify(jsonValue(branch.error))}.`);
    const groups = new Map();
    for (const vulnerability of branch.vulnerabilities || []) {
      const name = vulnerability.packageName || 'unknown';
      if (!groups.has(name)) groups.set(name, []);
      groups.get(name).push(vulnerability);
    }
    const snapshot = groups.size ? snapshotFor(branch, blockers) : { manifests: new Map(), workspaces: [], arboristTree: null, direct: new Map() };
    const packages = [...groups.values()].map((rows) => buildPackage(rows, branch, snapshot, options, blockers)).sort((a, b) => a.packageName.localeCompare(b.packageName));
    const actions = reconcileActions(packages.flatMap((pkg) => pkg.actions), blockers);
    for (const pkg of packages) {
      const canonicalActions = blockers.length ? [] : actions.filter((action) => action.packageNames.includes(pkg.packageName));
      pkg.risk = classifyPackageFix(pkg, canonicalActions, branch);
    }
    const ready = packages.filter((pkg) => pkg.status === 'ready').length;
    const manual = packages.filter((pkg) => pkg.status === 'manual-review').length;
    const noFix = packages.filter((pkg) => pkg.status === 'no-fix').length;
    const resolved = packages.filter((pkg) => pkg.status === 'resolved').length;
    const absent = packages.filter((pkg) => pkg.status === 'not-installed').length;
    const status = blockers.length ? 'blocked' : actions.length ? 'ready' : 'no-op';
    return {
      branch: branch.branch,
      baseCommit,
      status,
      summary: `${blockers.length ? 'Execution blocked; ' : ''}${ready} package(s) planned for remediation, ${manual} require manual review, ${noFix} have no known fix, ${resolved} are resolved, and ${absent} are not installed.`,
      blockers: unique(blockers),
      packages,
      actions: blockers.length ? [] : actions,
    };
  });
  return {
    schemaVersion: '1.0.0',
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
  fs.writeFileSync(targetPath, JSON.stringify(plan, null, 2), 'utf8');
  return targetPath;
}
