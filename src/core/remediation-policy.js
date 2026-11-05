import semver from 'semver';
import { buildDependencyInventory } from './dependency-graph.js';
import { getOverrideCoverage, parseOverrideSelector } from './override-coverage.js';
import { isVersionSafe } from './advisory-evidence.js';

const validVersion = (value) => typeof value === 'string' ? semver.valid(value) : null;

export function isCompatibleUpgrade(beforeVersion, afterVersion) {
  const before = validVersion(beforeVersion);
  const after = validVersion(afterVersion);
  if (!before || !after || semver.lt(after, before)) return false;
  if (semver.eq(before, after)) return true;
  if (semver.prerelease(before) || semver.prerelease(after)) return false;
  return semver.satisfies(after, `^${before}`);
}

function planInventory(pkg) {
  const nodes = new Map();
  const getNode = (link) => {
    if (!link || typeof link.location !== 'string') return null;
    if (!nodes.has(link.location)) {
      nodes.set(link.location, {
        location: link.location,
        name: link.name,
        version: link.version,
        isRoot: Boolean(link.isRoot),
        isWorkspace: Boolean(link.isWorkspace),
        parents: new Set(),
        incoming: [],
      });
    } else {
      const node = nodes.get(link.location);
      node.isRoot ||= Boolean(link.isRoot);
      node.isWorkspace ||= Boolean(link.isWorkspace);
    }
    return nodes.get(link.location);
  };
  for (const resolution of pkg.resolutions || []) {
    for (const instance of resolution.instances || []) {
      const origins = instance.origins || [];
      for (const origin of origins) {
        const workspace = Boolean(origin.workspace);
        const anchor = getNode({
          name: workspace ? origin.workspace : '[root]',
          location: workspace ? (origin.packageJsonPath || '').replace(/[/\\]package\.json$/, '') : '',
          isRoot: !workspace,
          isWorkspace: workspace,
        });
        let parent = null;
        for (const [index, link] of (origin.chain || []).entries()) {
          const node = getNode(link);
          if (!node) continue;
          if (index === 0 && (origin.chain || []).length > 1 && anchor && anchor.location !== node.location) {
            const edge = { from: anchor, to: node, rawSpec: link.requiredRange || null, spec: link.requiredRange || null };
            node.incoming.push(edge);
            node.parents.add(anchor);
          }
          if (parent) {
            const edge = {
              from: parent,
              to: node,
              rawSpec: link.requiredRange || null,
              spec: link.requiredRange || null,
            };
            node.incoming.push(edge);
            node.parents.add(parent);
          }
          parent = node;
        }
      }
      for (const edge of instance.incoming || []) {
        const child = getNode({ name: pkg.packageName, version: resolution.installedVersion, location: instance.location });
        const isWorkspace = origins.some((origin) => origin.workspace && origin.packageJsonPath
          && origin.packageJsonPath.replace(/[/\\]package\.json$/, '') === edge.parentLocation);
        const parent = getNode({ name: edge.parentName, version: edge.parentVersion, location: edge.parentLocation,
          isWorkspace, isRoot: edge.parentLocation === '' });
        if (!child || !parent) continue;
        const key = JSON.stringify([parent.location, pkg.packageName, edge.requestedRange]);
        if (!child.incoming.some((entry) => JSON.stringify([entry.from.location, pkg.packageName, entry.rawSpec]) === key)) {
          const incoming = { from: parent, to: child, rawSpec: edge.requestedRange || null, spec: edge.effectiveRange || edge.requestedRange || null };
          child.incoming.push(incoming);
          child.parents.add(parent);
        }
      }
    }
  }
  return { nodes, links: new Map(), raw: true, scoped: true };
}

function linkedActionRisk(action, resolution, packageName, inventory, findings) {
  if (!validVersion(resolution.installedVersion) || !validVersion(resolution.targetVersion)) return null;
  const safe = isVersionSafe(resolution.targetVersion, findings);
  if (safe === false) return true;
  if (safe === null) return null;
  if (action.type === 'update-dependency') {
    if (!semver.validRange(action.targetRange)) return null;
    if (action.package === packageName) {
      if (!semver.satisfies(resolution.targetVersion, action.targetRange)
        || !semver.subset(action.targetRange, `~${resolution.targetVersion}`)) return true;
      return !isCompatibleUpgrade(resolution.installedVersion, resolution.targetVersion);
    }
    const parentOrigins = (resolution.instances || []).flatMap((instance) => instance.origins || [])
      .map((origin) => origin.chain?.[0])
      .filter((parent) => parent?.name === action.package && validVersion(parent.version));
    if (!parentOrigins.length || resolution.strategy !== 'bump-direct-parent' || !semver.validRange(action.expectedRange)) return null;
    if (parentOrigins.some((parent) => !semver.satisfies(parent.version, action.expectedRange))) return null;
    return parentOrigins.every((parent) => semver.subset(action.targetRange, `^${parent.version}`))
      ? false : true;
  }
  if (action.type === 'update-lockfile') {
    if (action.package !== packageName) return null;
    return !isCompatibleUpgrade(resolution.installedVersion, resolution.targetVersion);
  }
  if (action.type === 'set-override') {
    const scopes = [...(action.scope || [])];
    const target = parseOverrideSelector(action.package === '.' ? scopes.pop() : action.package);
    if (!target || target.name !== packageName || action.targetVersion !== resolution.targetVersion) return true;
    const coverage = getOverrideCoverage(action, inventory);
    const expected = new Set((resolution.instances || []).flatMap((instance) => (instance.incoming || [])
      .map((edge) => JSON.stringify([edge.parentLocation, packageName, edge.requestedRange]))));
    if (!expected.size || ![...expected].every((key) => coverage.has(key))) return null;
    return !isCompatibleUpgrade(resolution.installedVersion, resolution.targetVersion);
  }
  return null;
}

export function classifyPackageFix(pkg, actions = [], context = {}) {
  const resolutions = (pkg.resolutions || []).filter((resolution) => resolution.status === 'ready');
  if (!Array.isArray(actions) || !actions.length || !resolutions.length) {
    return { fixType: 'unknown', breaking: null, reasons: ['No canonical action covers a ready dependency resolution.'] };
  }
  const branch = context.rawBranch || context.branch || context;
  const inventory = branch?.pkgLock || branch?.arboristTree
    ? buildDependencyInventory(branch) : planInventory(pkg);
  const risks = [];
  const reasons = [];
  const selectedActions = [];
  for (const resolution of resolutions) {
    const linked = actions.filter((action) => action.resolutionIds?.includes(resolution.id));
    if (!linked.length) {
      risks.push(null);
      reasons.push(`${resolution.id}: no canonical action covers this resolution.`);
      continue;
    }
    for (const action of linked) {
      selectedActions.push(action);
      const breaking = linkedActionRisk(action, resolution, pkg.packageName, inventory, pkg.findings);
      risks.push(breaking);
      reasons.push(`${resolution.id}: ${action.type} is ${breaking === true ? 'incompatible or targets another line' : breaking === false ? 'compatible with the installed line' : 'not proven compatible by the recorded origins'}.`);
    }
  }
  const breaking = risks.includes(true) ? true : risks.includes(null) ? null : false;
  const hasOverride = selectedActions.some((action) => action.type === 'set-override');
  const hasParent = selectedActions.some((action) => action.type === 'update-dependency' && action.package !== pkg.packageName);
  const fixType = hasOverride ? 'override-required' : breaking === true ? 'breaking-upgrade'
    : hasParent ? 'parent-upgrade' : breaking === false ? 'safe-fix' : 'unknown';
  return { fixType, breaking, reasons: [...new Set(reasons)] };
}

export function reconcilePackageRisk(pkg, actions = []) {
  return classifyPackageFix(pkg, actions);
}
