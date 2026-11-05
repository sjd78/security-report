import semver from 'semver';

const dangerousNames = new Set(['__proto__', 'constructor', 'prototype']);
const dependencySections = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];

function selectorSeparator(value) {
  if (value.startsWith('@')) {
    const slash = value.indexOf('/');
    return slash < 0 ? -1 : value.indexOf('@', slash + 1);
  }
  return value.indexOf('@');
}

function selectorNameFromKey(value) {
  if (typeof value !== 'string' || !value || value === '.') return null;
  const separator = selectorSeparator(value);
  const name = separator < 0 ? value : value.slice(0, separator);
  return name && !dangerousNames.has(name) ? name : null;
}

export function parseOverrideSelector(value) {
  if (typeof value !== 'string' || !value || value === '.') return null;
  const separator = selectorSeparator(value);
  const name = separator < 0 ? value : value.slice(0, separator);
  const range = separator < 0 ? null : value.slice(separator + 1);
  if (!name || dangerousNames.has(name)) return null;
  if (!/^(@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/i.test(name)) return null;
  if (range !== null && (!range || !semver.validRange(range))) return null;
  return { name, range };
}

function actionSelectorPath(action) {
  if (!Array.isArray(action?.scope) || !action.scope.every((part) => typeof part === 'string')) return null;
  const rawPath = action.package === '.' ? action.scope : [...action.scope, action.package];
  if (!rawPath.length || rawPath.some((part) => part === '.')) return null;
  const path = rawPath.map(parseOverrideSelector);
  return path.every(Boolean) ? path : null;
}

function nodeName(node) {
  return node?.name || node?.packageName || node?.source?.name || node?.source?.packageName || null;
}

function nodeLocation(node) {
  return node?.location ?? node?.source?.location ?? '';
}

function nodeEdges(node) {
  const edges = node?.incoming || node?.edgesIn || node?.source?.edgesIn || [];
  return edges instanceof Map ? [...edges.values()] : Array.isArray(edges) ? edges : [];
}

function edgeRange(edge) {
  return edge?.rawSpec || edge?.spec || null;
}

function edgeIdentity(node, edge) {
  return JSON.stringify([nodeLocation(edge?.from), nodeName(node), edgeRange(edge)]);
}

// Arborist tests selector ranges against raw incoming specs, not the installed child version.
function edgeRangeMatch(selector, node, edge) {
  if (selector.name !== nodeName(node)) return false;
  const requested = edgeRange(edge);
  const requestedRange = typeof requested === 'string' ? semver.validRange(requested) : null;
  if (!requestedRange) return null;
  if (selector.range === null) return true;
  try {
    return semver.intersects(requestedRange, selector.range);
  } catch {
    return null;
  }
}

function isOrigin(node) {
  return Boolean(node?.isRoot || node?.isWorkspace || node?.isProjectRoot || node?.source?.isProjectRoot || node?.source?.isWorkspace || nodeLocation(node) === '');
}

function pathsToNode(node, visited = new Set()) {
  if (!node || isOrigin(node)) return [[]];
  const location = nodeLocation(node);
  if (visited.has(location)) return [[]];
  const nextVisited = new Set(visited).add(location);
  const incoming = nodeEdges(node);
  if (!incoming.length) return [[]];
  const paths = [];
  for (const edge of incoming) {
    const prefixes = pathsToNode(edge?.from, nextVisited);
    for (const prefix of prefixes) paths.push([...prefix, { node, edge }]);
  }
  return paths.length ? paths : [[]];
}

function inventoryEdgePaths(inventory) {
  const paths = [];
  for (const node of inventory?.nodes?.values?.() || []) {
    for (const edge of nodeEdges(node)) {
      const prefixPaths = pathsToNode(edge?.from);
      for (const prefix of prefixPaths) paths.push([...prefix, { node, edge }]);
    }
  }
  return paths;
}

function matchSelectorPath(selectors, path) {
  if (selectors.length > path.length) return false;
  let uncertain = false;
  const matchingPath = path.slice(path.length - selectors.length);
  for (let index = 0; index < selectors.length; index += 1) {
    const matched = edgeRangeMatch(selectors[index], matchingPath[index].node, matchingPath[index].edge);
    if (matched === false) return false;
    if (matched === null) uncertain = true;
  }
  return uncertain ? null : true;
}

function selectorPathHasUnsupportedSpec(selectors, path) {
  if (selectors.length > path.length) return false;
  const matchingPath = path.slice(path.length - selectors.length);
  let unsupported = false;
  for (let index = 0; index < selectors.length; index += 1) {
    if (selectors[index].name !== nodeName(matchingPath[index].node)) return false;
    const requested = edgeRange(matchingPath[index].edge);
    const requestedRange = typeof requested === 'string' ? semver.validRange(requested) : null;
    if (!requestedRange) {
      unsupported = true;
      continue;
    }
    if (selectors[index].range !== null) {
      try {
        if (!semver.intersects(requestedRange, selectors[index].range)) return false;
      } catch {
        unsupported = true;
      }
    }
  }
  return unsupported;
}

export function getOverrideCoverage(action, inventory) {
  const selectors = actionSelectorPath(action);
  const covered = new Set();
  if (!selectors) return covered;
  for (const path of inventoryEdgePaths(inventory)) {
    if (matchSelectorPath(selectors, path) === true) {
      const last = path.at(-1);
      covered.add(edgeIdentity(last.node, last.edge));
    }
  }
  return covered;
}

function plainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function ruleValue(rule) {
  if (rule.hasDot) return typeof rule.dotValue === 'string' && rule.dotValue === '' ? '*' : rule.dotValue;
  return rule.selector?.range ?? '*';
}

function createRule(key, rawValue, parent) {
  const selector = parseOverrideSelector(key);
  const objectValue = plainObject(rawValue);
  const rule = {
    key,
    selector,
    name: selector?.name || selectorNameFromKey(key),
    parent,
    children: [],
    hasDot: objectValue && Object.hasOwn(rawValue, '.') || typeof rawValue === 'string',
    dotValue: typeof rawValue === 'string' ? rawValue : (objectValue && Object.hasOwn(rawValue, '.') ? rawValue['.'] : undefined),
  };
  rule.value = ruleValue(rule);
  if (objectValue) {
    for (const [childKey, childValue] of Object.entries(rawValue)) {
      if (childKey === '.') continue;
      rule.children.push(createRule(childKey, childValue, rule));
    }
  }
  return rule;
}

function createRuleTree(overrides) {
  const root = { key: null, selector: null, name: null, parent: null, children: [], root: true };
  if (plainObject(overrides)) {
    for (const [key, value] of Object.entries(overrides)) {
      if (key !== '.') root.children.push(createRule(key, value, root));
    }
  }
  return root;
}

function findOrAddRule(parent, key, selector) {
  let rule = parent.children.find((child) => child.key === key);
  if (!rule) {
    rule = {
      key, selector, name: selector.name, parent, children: [], hasDot: false, dotValue: undefined,
    };
    rule.value = ruleValue(rule);
    parent.children.push(rule);
  }
  return rule;
}

function addProposedAction(root, action, selectors) {
  let parent = root;
  let terminal = null;
  const rawPath = action.package === '.' ? action.scope : [...action.scope, action.package];
  for (let index = 0; index < rawPath.length; index += 1) {
    terminal = findOrAddRule(parent, rawPath[index], selectors[index]);
    parent = terminal;
  }
  terminal.hasDot = true;
  terminal.dotValue = action.targetVersion;
  terminal.value = action.targetVersion;
  return terminal;
}

// Mirror OverrideSet.ruleset: the active scope's children win before ancestor scopes.
function ruleCandidates(active) {
  const candidates = [];
  const seenKeys = new Set();
  for (let level = active; level; level = level.parent) {
    for (const child of level.children) {
      if (!seenKeys.has(child.key)) {
        seenKeys.add(child.key);
        candidates.push(child);
      }
    }
    if (!level.root && !seenKeys.has(level.key)) {
      seenKeys.add(level.key);
      candidates.push(level);
    }
  }
  return candidates;
}

function matchRule(rule, node, edge) {
  if (rule.name !== nodeName(node)) return false;
  if (!rule.selector) return null;
  return edgeRangeMatch(rule.selector, node, edge);
}

function selectRule(active, node, edge) {
  const candidates = ruleCandidates(active);
  const matches = [];
  let uncertainBeforeWinner = false;
  let winner = null;
  for (const rule of candidates) {
    const result = matchRule(rule, node, edge);
    if (result === null) {
      if (!winner) uncertainBeforeWinner = true;
      continue;
    }
    if (result) {
      matches.push(rule);
      if (!winner) winner = rule;
    }
  }
  return { candidates, matches, winner, uncertainBeforeWinner };
}

function simulatePath(root, path) {
  let active = root;
  let finalSelection = null;
  for (let index = 0; index < path.length; index += 1) {
    const { node, edge } = path[index];
    const selection = selectRule(active, node, edge);
    if (selection.uncertainBeforeWinner) {
      return { uncertain: { node, edge, selection }, finalSelection };
    }
    if (selection.winner) active = selection.winner;
    if (index === path.length - 1) finalSelection = selection;
  }
  return { finalSelection };
}

function displayPath(selectors) {
  return selectors.map((selector) => selector.range ? `${selector.name}@${selector.range}` : selector.name).join(' > ');
}


function prefixPath(action) {
  return action.package === '.' ? [...action.scope] : [...action.scope, action.package];
}

function isPrefix(left, right) {
  return left.length < right.length && left.every((part, index) => part === right[index]);
}

function pathLabel(path) {
  return path.join(' > ');
}

function addReason(reasons, reason) {
  reasons.add(reason);
}

function directDeclarations(rootManifest) {
  const declarations = [];
  for (const section of dependencySections) {
    const values = rootManifest?.[section];
    if (!plainObject(values)) continue;
    for (const [name, range] of Object.entries(values)) {
      if (typeof range === 'string') declarations.push({ name, range, section });
    }
  }
  return declarations;
}

function directTargetRange(actions, declaration) {
  const updates = actions.filter((action) => action?.type === 'update-dependency'
    && action.file === 'package.json' && action.package === declaration.name
    && action.section === declaration.section && typeof action.targetRange === 'string');
  const ranges = [...new Set(updates.map((action) => action.targetRange))];
  return ranges.length === 1 ? ranges[0] : declaration.range;
}

function addStructuralConflicts(overrides, reasons) {
  for (let leftIndex = 0; leftIndex < overrides.length; leftIndex += 1) {
    const left = overrides[leftIndex];
    const leftPath = prefixPath(left.action);
    for (let rightIndex = leftIndex + 1; rightIndex < overrides.length; rightIndex += 1) {
      const right = overrides[rightIndex];
      const rightPath = prefixPath(right.action);
      if (leftPath.length === rightPath.length && leftPath.every((part, index) => part === rightPath[index])) {
        if (left.action.targetVersion !== right.action.targetVersion
          || left.action.expectedValue !== right.action.expectedValue) {
          addReason(reasons, `Conflicting override actions target the same path ${pathLabel(leftPath)} with different targets or preconditions.`);
        }
      } else if (isPrefix(leftPath, rightPath) || isPrefix(rightPath, leftPath)) {
        addReason(reasons, `Override paths ${pathLabel(leftPath)} and ${pathLabel(rightPath)} overlap by prefix and may replace shared manifest structure.`);
      }
    }
  }
}

function addDirectOverrideConflicts(root, actions, overrideRecords, rootManifest, reasons) {
  const proposedFirstSelectors = overrideRecords.map(({ selectors }) => selectors[0]);
  for (const declaration of directDeclarations(rootManifest)) {
    const updatedRange = directTargetRange(actions, declaration);
    const relevant = proposedFirstSelectors.some((selector) => selector.name === declaration.name
      && edgeRangeMatch(selector, { name: declaration.name }, { rawSpec: updatedRange }) !== false);
    if (!relevant) continue;
    if (!semver.validRange(updatedRange)) {
      addReason(reasons, `Cannot validate a root override for direct dependency ${declaration.name}: its declaration ${updatedRange} is not a semver range.`);
      continue;
    }
    const declarationEdge = { rawSpec: updatedRange, spec: updatedRange };
    const selection = selectRule(root, { name: declaration.name }, declarationEdge);
    if (selection.uncertainBeforeWinner) {
      addReason(reasons, `Cannot validate npm override precedence for direct dependency ${declaration.name} because a matching override uses an unsupported selector.`);
      continue;
    }
    if (!selection.winner) continue;
    const effective = selection.winner.value;
    if (typeof effective === 'string' && effective.startsWith('$')) continue;
    if (effective !== updatedRange) {
      addReason(reasons, `Root override for ${declaration.name} (${effective}) conflicts with direct dependency ${declaration.name} (${updatedRange}); npm requires the same spec (EOVERRIDE).`);
    }
  }
}


function addEdgeConflicts(root, overrideRecords, inventory, reasons) {
  const groups = new Map();
  for (const path of inventoryEdgePaths(inventory)) {
    if (!path.length) continue;
    const last = path.at(-1);
    const identity = edgeIdentity(last.node, last.edge);
    const matchingActions = [];
    const uncertainActions = [];
    for (const record of overrideRecords) {
      const match = matchSelectorPath(record.selectors, path);
      if (match === true) matchingActions.push(record);
      else if (selectorPathHasUnsupportedSpec(record.selectors, path)) uncertainActions.push(record);
    }
    if (!groups.has(identity)) groups.set(identity, []);
    groups.get(identity).push({ path, matchingActions, uncertainActions });
  }

  for (const [identity, paths] of groups) {
    const packageName = nodeName(paths[0].path.at(-1).node);
    const packageActions = overrideRecords.filter((record) => record.selectors.at(-1).name === packageName);
    const relevant = paths.some((entry) => entry.matchingActions.length || entry.uncertainActions.length)
      || packageActions.length > 0;
    if (!relevant) continue;

    const competingValues = new Set();
    for (const entry of paths) {
      const simulated = simulatePath(root, entry.path);
      const edge = entry.path.at(-1).edge;
      if (simulated.uncertain) {
        const raw = edgeRange(simulated.uncertain.edge);
        addReason(reasons, `Cannot determine override coverage for incoming edge ${identity}: ${raw ?? '<missing>'} is not a supported semver range.`);
        continue;
      }
      const matches = simulated.finalSelection?.matches || [];
      if (entry.matchingActions.length) {
        for (const rule of matches) {
          competingValues.add(typeof rule.value === 'string' ? rule.value : '<unknown>');
        }
        for (const record of entry.matchingActions) {
          if (!matches.includes(record.rule)) {
            addReason(reasons, `Proposed override ${displayPath(record.selectors)} is not selected by npm precedence for incoming edge ${identity}.`);
          }
        }
      } else if (entry.uncertainActions.length || (packageActions.length && !semver.validRange(edgeRange(edge)))) {
        for (const record of entry.uncertainActions) {
          addReason(reasons, `Cannot determine whether override ${displayPath(record.selectors)} covers incoming edge ${identity} because its ancestry contains a non-semver dependency spec.`);
        }
        if (!entry.uncertainActions.length) {
          addReason(reasons, `Cannot determine whether a proposed override for ${packageName} affects incoming edge ${identity}: its dependency spec is not semver.`);
        }
      } else {
        for (const record of packageActions) {
          const installedVersion = semver.valid(entry.path.at(-1).node.version);
          const targetVersion = semver.valid(record.action.targetVersion);
          const sameLine = installedVersion && targetVersion
            && semver.major(installedVersion) === semver.major(targetVersion)
            && semver.minor(installedVersion) === semver.minor(targetVersion);
          for (const rule of matches) {
            if (rule !== record.rule && (rule.value !== record.action.targetVersion || !sameLine)) {
              addReason(reasons, `A broader existing override for ${packageName} affects incoming edge ${identity} with target ${String(rule.value)}, outside proposed coverage ${displayPath(record.selectors)} (${record.action.targetVersion}).`);
            }
          }
        }
      }
    }
    if (competingValues.size > 1) {
      addReason(reasons, `Different override targets overlap: incoming edge ${identity} matches competing targets ${[...competingValues].sort().join(', ')}.`);
    }
  }
}

export function findOverrideConflicts(actions, inventory, rootManifest) {
  const reasons = new Set();
  const actionRows = Array.isArray(actions) ? actions : [];
  const overrideRecords = [];
  for (const action of actionRows) {
    if (action?.type !== 'set-override') continue;
    const selectors = actionSelectorPath(action);
    if (!selectors) {
      addReason(reasons, `Invalid override selector path for ${JSON.stringify(action?.package)}.`);
      continue;
    }
    if (typeof action.targetVersion !== 'string' || !semver.valid(action.targetVersion)) {
      addReason(reasons, `Override ${displayPath(selectors)} must use an exact semver target.`);
      continue;
    }
    overrideRecords.push({ action, selectors, rule: null });
  }

  addStructuralConflicts(overrideRecords, reasons);
  const root = createRuleTree(rootManifest?.overrides);
  for (const record of overrideRecords) record.rule = addProposedAction(root, record.action, record.selectors);
  addDirectOverrideConflicts(root, actionRows, overrideRecords, rootManifest, reasons);
  addEdgeConflicts(root, overrideRecords, inventory, reasons);
  return [...reasons].sort((left, right) => left.localeCompare(right));
}
