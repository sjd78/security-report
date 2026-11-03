import path from 'node:path';
import semver from 'semver';

const sections = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
const unique = (values) => [...new Set(values)];
const validVersion = (value) => typeof value === 'string' ? semver.valid(value) : null;
const rawContext = (context) => context.rawBranch && typeof context.rawBranch === 'object' ? context.rawBranch
  : context.branch && typeof context.branch === 'object' ? context.branch : context;

export function isCompatibleUpgrade(beforeVersion, afterVersion) {
  const before = validVersion(beforeVersion);
  const after = validVersion(afterVersion);
  if (!before || !after || semver.lt(after, before)) return false;
  if (semver.eq(before, after)) return true;
  if (semver.prerelease(before) || semver.prerelease(after)) return false;
  return semver.satisfies(after, `^${before}`);
}

function selector(value) {
  if (typeof value !== 'string' || !value || value === '.') return null;
  const separator = value.indexOf('@', value.startsWith('@') ? 1 : 0);
  const name = separator === -1 ? value : value.slice(0, separator);
  const range = separator === -1 ? null : value.slice(separator + 1);
  return name && (!range || semver.validRange(range)) ? { name, range } : null;
}

function matches(node, spec) {
  return node.name === spec.name && (!spec.range || (validVersion(node.version) && semver.satisfies(node.version, spec.range)));
}

function addChainParents(nodes, context) {
  const chains = [...(context.dependencyChains || []), ...(context.vulnerabilities || []).flatMap((row) => row.dependencyChains || row.chains || [])];
  for (const chain of chains) {
    if (!Array.isArray(chain)) continue;
    for (let index = 1; index < chain.length; index += 1) {
      const before = chain[index - 1];
      const after = chain[index];
      const parents = [...nodes.values()].filter((node) => node.name === before.name && node.version === before.version);
      const children = [...nodes.values()].filter((node) => node.name === after.name && node.version === after.version);
      if (parents.length === 1 && children.length === 1) children[0].parents.add(parents[0]);
    }
  }
}

function inventoryFor(context) {
  const nodes = new Map();
  const links = new Map();
  const lock = context.pkgLock;
  const add = (location, entry, name) => nodes.set(location, { location, name: entry.name || name, version: entry.version, entry, parents: new Set() });
  if (lock?.packages && typeof lock.packages === 'object') {
    for (const [location, entry] of Object.entries(lock.packages)) {
      if (!entry || typeof entry !== 'object') continue;
      if (entry.link && typeof entry.resolved === 'string') links.set(location, entry.resolved.replace(/^\.\//, ''));
      else add(location, entry, location.includes('node_modules/') ? location.slice(location.lastIndexOf('node_modules/') + 13) : null);
    }
    if (!nodes.has('')) add('', context.pkgJson || {}, context.pkgJson?.name);
    for (const workspace of context.workspaces || []) {
      if (!workspace.relativePath || !workspace.pkgJson) continue;
      const location = path.posix.dirname(workspace.relativePath);
      const key = location === '.' ? '' : location;
      if (!nodes.has(key)) add(key, workspace.pkgJson, workspace.pkgJson.name);
    }
    for (const node of nodes.values()) {
      const manifest = node.location === '' ? context.pkgJson : (context.workspaces || []).find((workspace) => path.posix.dirname(workspace.relativePath || '') === node.location)?.pkgJson;
      for (const section of sections) {
        for (const name of Object.keys({ ...node.entry[section], ...manifest?.[section] })) {
          const child = resolveInstalled(nodes, links, node.location, name);
          if (child) child.parents.add(node);
        }
      }
    }
    addChainParents(nodes, context);
    return { nodes, links, raw: true, scoped: true };
  }
  if (lock?.dependencies && typeof lock.dependencies === 'object') {
    const visit = (dependencies, parent = '') => {
      for (const [name, entry] of Object.entries(dependencies || {})) {
        if (!entry || typeof entry !== 'object') continue;
        const location = `${parent ? `${parent}/` : ''}node_modules/${name}`;
        add(location, entry, name);
        visit(entry.dependencies, location);
      }
    };
    add('', context.pkgJson || {}, context.pkgJson?.name);
    visit(lock.dependencies);
    for (const node of nodes.values()) {
      for (const name of Object.keys(node.location ? { ...node.entry.requires, ...node.entry.dependencies } : { ...lock.dependencies, ...context.pkgJson?.dependencies })) {
        const child = resolveInstalled(nodes, links, node.location, name);
        if (child) child.parents.add(node);
      }
    }
    addChainParents(nodes, context);
    return { nodes, links, raw: true, scoped: true };
  }
  if (typeof context.arboristTree?.inventory?.values === 'function') {
    for (const node of context.arboristTree.inventory.values()) {
      nodes.set(node, { name: node.packageName || node.name, version: node.version, source: node, parents: new Set() });
    }
    for (const node of nodes.values()) {
      for (const edge of node.source.edgesIn || []) {
        if (nodes.has(edge.from)) node.parents.add(nodes.get(edge.from));
      }
    }
    return { nodes, links, raw: true, scoped: true };
  }
  return { nodes, links, raw: false, scoped: false };
}

function resolveInstalled(nodes, links, location, name) {
  let directory = location || '.';
  while (true) {
    if (path.posix.basename(directory) !== 'node_modules') {
      const candidate = path.posix.join(directory, 'node_modules', name);
      const node = nodes.get(links.get(candidate) || candidate);
      if (node) return node;
    }
    if (directory === '.') return null;
    directory = path.posix.dirname(directory);
  }
}

function versionsFor(name, pkg, inventory) {
  if (inventory.raw) return [...inventory.nodes.values()].filter((node) => node.name === name).map((node) => node.version);
  if (name !== pkg.packageName) return [];
  if (Array.isArray(pkg.installedVersions)) return unique(pkg.installedVersions);
  return typeof pkg.currentVersion === 'string' ? unique(pkg.currentVersion.split(',').map((version) => version.trim())) : [];
}

function versionRisk(versions, target) {
  if (!validVersion(target) || !versions.length) return null;
  const known = versions.filter(validVersion);
  if (known.some((version) => !isCompatibleUpgrade(version, target))) return true;
  return known.length === versions.length ? false : null;
}

function dependencyRisk(action, pkg, inventory) {
  if (!semver.validRange(action.expectedRange) || !semver.validRange(action.targetRange)) return null;
  const beforeFloor = semver.minVersion(action.expectedRange)?.version;
  const target = semver.minVersion(action.targetRange)?.version;
  if (!beforeFloor || !target) return null;
  let baselines;
  if (inventory.raw && typeof action.file === 'string') {
    const location = path.posix.dirname(action.file);
    const node = resolveInstalled(inventory.nodes, inventory.links, location === '.' ? '' : location, action.package);
    baselines = node ? [node.version] : [];
  } else {
    const installed = versionsFor(action.package, pkg, inventory);
    const matching = installed.filter((version) => validVersion(version) && semver.satisfies(version, action.expectedRange));
    if (matching.length > 1) {
      return matching.every((before) => isCompatibleUpgrade(before, target) && semver.subset(action.targetRange, `^${before}`)) ? false : null;
    }
    if (matching.length === 1) baselines = matching;
    else if (installed.length) return null;
    else if (semver.subset(action.expectedRange, `^${beforeFloor}`)) baselines = [beforeFloor];
    else return null;
  }
  if (!baselines.length || baselines.some((version) => !validVersion(version))) return null;
  for (const before of baselines) {
    if (!isCompatibleUpgrade(before, target) || !semver.subset(action.targetRange, `^${before}`)) return true;
  }
  return false;
}

function withinScope(node, scopes) {
  const visited = new Map();
  const visit = (current, index) => {
    if (index < 0) return true;
    if (!visited.has(current)) visited.set(current, new Set());
    if (visited.get(current).has(index)) return false;
    visited.get(current).add(index);
    for (const parent of current.parents) {
      if (visit(parent, matches(parent, scopes[index]) ? index - 1 : index)) return true;
    }
    return false;
  };
  return visit(node, scopes.length - 1);
}

function hasCompleteAncestry(node, seen = new Set()) {
  if (node.location !== undefined && !node.location.includes('node_modules/')) return true;
  if (node.source?.isProjectRoot || node.source?.isWorkspace) return true;
  if (seen.has(node) || !node.parents.size) return false;
  const next = new Set(seen).add(node);
  return [...node.parents].every((parent) => hasCompleteAncestry(parent, next));
}

function overrideRisk(action, pkg, inventory) {
  if (!Array.isArray(action.scope)) return null;
  const keys = [...action.scope];
  const targetKey = action.package === '.' ? keys.pop() : action.package;
  const target = selector(targetKey);
  const scopes = keys.map(selector);
  if (!target || scopes.some((scope) => !scope)) return null;
  const allVersions = versionsFor(target.name, pkg, inventory);
  if (!keys.length && !target.range) return versionRisk(allVersions, action.targetVersion);
  if (inventory.scoped) {
    const candidates = [...inventory.nodes.values()].filter((node) => node.name === target.name);
    const nodes = candidates.filter((node) => matches(node, target) && withinScope(node, scopes));
    const risk = versionRisk(nodes.map((node) => node.version), action.targetVersion);
    if (risk === true) return true;
    const uncertain = candidates.filter((node) => !validVersion(node.version) || (!hasCompleteAncestry(node) && matches(node, target)));
    return uncertain.length && versionRisk(uncertain.map((node) => node.version), action.targetVersion) !== false ? null : risk;
  }
  // Without dependency paths we do not know which installed line a scoped override affects.
  // It is safe only when every possible baseline is compatible, never because one happens to match.
  return versionRisk(allVersions, action.targetVersion) === false ? false : null;
}

function safeForFinding(version, finding) {
  if (finding.vulnerableVersionRange) {
    return Boolean(semver.validRange(finding.vulnerableVersionRange)) && !semver.satisfies(version, finding.vulnerableVersionRange);
  }
  const patches = unique([finding.targetSafeVersion, ...(finding.patchedVersions || []), ...(finding.targetSafeVersions || [])].filter(validVersion));
  return patches.some((patch) => isCompatibleUpgrade(patch, version));
}

function lockfileRisk(action, pkg, inventory) {
  if (action.package !== pkg.packageName) return null;
  const versions = versionsFor(action.package, pkg, inventory);
  if (!versions.length || versions.some((version) => !validVersion(version))) return null;
  const findings = Array.isArray(pkg.findings) && pkg.findings.length ? pkg.findings : [pkg];
  const safe = (version) => findings.every((finding) => safeForFinding(version, finding));
  const candidates = unique([pkg.targetSafeVersion, ...(pkg.patchedVersions || []), ...(pkg.targetSafeVersions || []),
    ...findings.flatMap((finding) => [finding.targetSafeVersion, ...(finding.patchedVersions || []), ...(finding.targetSafeVersions || [])])]
    .filter(validVersion)).filter(safe);
  let unknown = false;
  for (const before of versions) {
    if (safe(before)) continue;
    if (!candidates.length) unknown = true;
    else if (!candidates.some((after) => isCompatibleUpgrade(before, after))) return true;
  }
  return unknown ? null : false;
}

export function classifyPackageFix(pkg, actions = pkg.actions || [], context = {}) {
  if (!Array.isArray(actions) || !actions.length) {
    return { fixType: 'unknown', breaking: null, reasons: ['No canonical remediation action establishes upgrade safety.'] };
  }
  const inventory = inventoryFor(rawContext(context));
  let hasOverride = false;
  let hasParent = false;
  const risks = [];
  const reasons = [];
  for (const action of actions) {
    let breaking = null;
    let description = `Unsupported canonical action ${action?.type || '(missing type)'}`;
    if (action?.type === 'update-dependency') {
      hasParent ||= action.package !== pkg.packageName;
      breaking = dependencyRisk(action, pkg, inventory);
      description = `${action.package === pkg.packageName ? 'Dependency' : 'Parent dependency'} ${action.package}: ${action.expectedRange} -> ${action.targetRange}`;
    } else if (action?.type === 'set-override') {
      hasOverride = true;
      breaking = overrideRisk(action, pkg, inventory);
      description = `Persistent override ${[...(Array.isArray(action.scope) ? action.scope : []), action.package].join(' > ')} -> ${action.targetVersion}`;
    } else if (action?.type === 'update-lockfile') {
      breaking = lockfileRisk(action, pkg, inventory);
      description = `Lockfile update for ${action.package}`;
    }
    risks.push(breaking);
    reasons.push(`${description}: ${breaking === true ? 'incompatible version line, downgrade, prerelease change, or widened target range' : breaking === false ? 'known compatible upgrade' : 'upgrade safety is unknown from the available installed snapshot and canonical action'}.`);
  }
  const breaking = risks.includes(true) ? true : risks.includes(null) ? null : false;
  const fixType = hasOverride ? 'override-required' : breaking === true ? 'breaking-upgrade' : hasParent ? 'parent-upgrade' : breaking === false ? 'safe-fix' : 'unknown';
  return { fixType, breaking, reasons };
}

function actionIdentities(actions) {
  if (!Array.isArray(actions)) return null;
  return actions.map((action) => {
    if (!action || typeof action !== 'object') return null;
    return JSON.stringify(Object.fromEntries(Object.entries(action)
      .filter(([key]) => key !== 'packageNames' && key !== 'findingIds')
      .sort(([left], [right]) => left.localeCompare(right))));
  }).sort();
}

function hasLostOverrideScope(pkg, action) {
  if (action?.type !== 'set-override' || !Array.isArray(action.scope) || !validVersion(action.targetVersion)) return false;
  const scopes = [...action.scope];
  const target = selector(action.package === '.' ? scopes.pop() : action.package);
  if (!target || target.name !== pkg.packageName || scopes.some((key) => !selector(key)) || (!scopes.length && !target.range)) return false;
  const baselines = versionsFor(target.name, pkg, { raw: false });
  return baselines.length > 0 && baselines.every(validVersion);
}

export function reconcilePackageRisk(pkg, actions = pkg.actions || []) {
  const computed = classifyPackageFix(pkg, actions);
  const saved = pkg.risk;
  if (!saved || typeof saved !== 'object') return computed;
  const savedReasons = Array.isArray(saved.reasons) ? saved.reasons.filter((reason) => typeof reason === 'string') : [];
  if (saved.breaking === true) {
    return {
      fixType: actions.some((action) => action?.type === 'set-override') ? 'override-required' : 'breaking-upgrade',
      breaking: true,
      reasons: unique([...computed.reasons, ...savedReasons, 'The saved scanned classification identifies a breaking upgrade; that safety warning is preserved.']),
    };
  }
  if (computed.breaking !== null || saved.breaking !== false) return computed;
  const identity = actionIdentities(actions);
  const originalIdentity = actionIdentities(pkg.actions);
  const unchanged = identity?.length > 0 && identity.every((value) => value !== null)
    && JSON.stringify(identity) === JSON.stringify(originalIdentity);
  const compatibleType = saved.fixType === 'override-required' && computed.fixType === 'override-required';
  const onlyLostScope = actions.every((action) => classifyPackageFix(pkg, [action]).breaking !== null || hasLostOverrideScope(pkg, action));
  if (!unchanged || !compatibleType || !onlyLostScope) return computed;
  return {
    fixType: saved.fixType,
    breaking: false,
    reasons: unique([...computed.reasons, ...savedReasons, 'The unchanged canonical actions retain their saved nonbreaking classification from the scanned dependency snapshot.']),
  };
}
