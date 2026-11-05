import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { createRequire } from 'node:module';
import { execFile, execSync } from 'node:child_process';
import { promisify } from 'node:util';
import semver from 'semver';

const execFileAsync = promisify(execFile);

let cachedArborist = null;

export function getArboristClass() {
  if (cachedArborist) return cachedArborist;

  // First attempt: local node_modules
  try {
    const req = createRequire(import.meta.url);
    const mod = req('@npmcli/arborist');
    cachedArborist = mod.default || mod;
    return cachedArborist;
  } catch {
    // continue to fallback
  }

  // Fallback attempt: dynamically locate npm's bundled Arborist via npm root -g
  try {
    const globalRoot = execSync('npm root -g', { encoding: 'utf8' }).trim();
    const req = createRequire(import.meta.url);
    const candidatePaths = [
      path.join(globalRoot, 'npm/node_modules/@npmcli/arborist'),
      path.join(globalRoot, '@npmcli/arborist'),
    ];
    for (const cand of candidatePaths) {
      try {
        const mod = req(cand);
        cachedArborist = mod.default || mod;
        return cachedArborist;
      } catch {
        // try next
      }
    }
  } catch {
    // fallback failed
  }

  return null;
}

export async function loadArboristTree({ dir = null, pkgJson = null, pkgLock = null } = {}) {
  const Arborist = getArboristClass();
  if (!Arborist) return null;

  if (dir && fs.existsSync(path.resolve(dir, 'package.json'))) {
    try {
      const arb = new Arborist({ path: dir, offline: true });
      return await arb.loadVirtual();
    } catch {
      return null;
    }
  }

  if (pkgJson || pkgLock) {
    let tmpDir = null;
    try {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-arb-'));
      if (pkgJson) {
        fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify(pkgJson, null, 2));
      } else {
        const rootPkg = pkgLock?.packages?.[''] || { name: 'temp-root' };
        fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify(rootPkg, null, 2));
      }
      if (pkgLock) {
        fs.writeFileSync(path.join(tmpDir, 'package-lock.json'), JSON.stringify(pkgLock, null, 2));
      }

      // Automatically create workspace directories and package.json if packages exist in pkgLock
      if (pkgLock?.packages) {
        for (const [loc, meta] of Object.entries(pkgLock.packages)) {
          if (loc && !loc.includes('node_modules')) {
            const wsDir = path.join(tmpDir, loc);
            fs.mkdirSync(wsDir, { recursive: true });
            fs.writeFileSync(
              path.join(wsDir, 'package.json'),
              JSON.stringify(
                {
                  name: meta.name || path.basename(loc),
                  version: meta.version || '1.0.0',
                  ...meta,
                },
                null,
                2
              )
            );
          }
        }
      }

      const arb = new Arborist({ path: tmpDir, offline: true });
      return await arb.loadVirtual();
    } catch {
      return null;
    } finally {
      if (tmpDir) {
        try {
          fs.rmSync(tmpDir, { recursive: true, force: true });
        } catch {}
      }
    }
  }

  return null;
}

export function readPackageJson(dir) {
  const pkgPath = path.resolve(dir, 'package.json');
  if (!fs.existsSync(pkgPath)) return null;
  return JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
}

export function readPackageLock(dir) {
  const lockPath = path.resolve(dir, 'package-lock.json');
  if (!fs.existsSync(lockPath)) return null;
  return JSON.parse(fs.readFileSync(lockPath, 'utf8'));
}

export function findWorkspacePackageJsons(worktreeDir, rootPkgJson = null) {
  if (!worktreeDir) return [];
  const root = rootPkgJson || readPackageJson(worktreeDir);
  if (!root) return [];

  const results = [];
  const rootPkgPath = path.resolve(worktreeDir, 'package.json');
  results.push({
    name: root.name || 'root',
    workspacePath: worktreeDir,
    relativePath: 'package.json',
    packageJsonPath: rootPkgPath,
    pkgJson: root,
    isRoot: true,
  });

  let patterns = [];
  if (Array.isArray(root.workspaces)) {
    patterns = root.workspaces;
  } else if (root.workspaces && typeof root.workspaces === 'object' && Array.isArray(root.workspaces.packages)) {
    patterns = root.workspaces.packages;
  }

  const seenPaths = new Set([rootPkgPath]);

  for (const pattern of patterns) {
    const cleanPattern = pattern.replace(/\/+$/, '');
    if (cleanPattern.endsWith('/*')) {
      const parentDir = path.resolve(worktreeDir, cleanPattern.replace(/\/\*$/, ''));
      if (fs.existsSync(parentDir) && fs.statSync(parentDir).isDirectory()) {
        const entries = fs.readdirSync(parentDir, { withFileTypes: true });
        for (const entry of entries) {
          if (entry.isDirectory()) {
            const nestedPkgPath = path.join(parentDir, entry.name, 'package.json');
            if (fs.existsSync(nestedPkgPath) && !seenPaths.has(nestedPkgPath)) {
              seenPaths.add(nestedPkgPath);
              try {
                const nestedPkg = JSON.parse(fs.readFileSync(nestedPkgPath, 'utf8'));
                results.push({
                  name: nestedPkg.name || entry.name,
                  workspacePath: path.join(parentDir, entry.name),
                  relativePath: path.relative(worktreeDir, nestedPkgPath),
                  packageJsonPath: nestedPkgPath,
                  pkgJson: nestedPkg,
                  isRoot: false,
                });
              } catch {
                // ignore
              }
            }
          }
        }
      }
    } else {
      const directDir = path.resolve(worktreeDir, cleanPattern);
      const nestedPkgPath = path.join(directDir, 'package.json');
      if (fs.existsSync(nestedPkgPath) && !seenPaths.has(nestedPkgPath)) {
        seenPaths.add(nestedPkgPath);
        try {
          const nestedPkg = JSON.parse(fs.readFileSync(nestedPkgPath, 'utf8'));
          results.push({
            name: nestedPkg.name || path.basename(directDir),
            workspacePath: directDir,
            relativePath: path.relative(worktreeDir, nestedPkgPath),
            packageJsonPath: nestedPkgPath,
            pkgJson: nestedPkg,
            isRoot: false,
          });
        } catch {
          // ignore
        }
      }
    }
  }

  return results;
}

export function buildWorkspaceLookup(pkgLock = null, worktreeOrWorkspaces = null) {
  const pathToName = new Map();
  const nameToPath = new Map();
  const workspacePaths = new Set(['']);

  // 1. Ingest preloaded workspaces list
  if (Array.isArray(worktreeOrWorkspaces)) {
    for (const ws of worktreeOrWorkspaces) {
      if (!ws.isRoot) {
        const folder = ws.relativePath.replace(/[/\\]package\.json$/, '');
        pathToName.set(folder, ws.name);
        nameToPath.set(ws.name, folder);
        workspacePaths.add(folder);
      }
    }
  }

  // 2. Ingest package-lock.json packages entries
  if (pkgLock?.packages) {
    for (const [pPath, pInfo] of Object.entries(pkgLock.packages)) {
      if (pPath !== '' && !pPath.includes('node_modules')) {
        const wsName = pInfo.name || pPath;
        pathToName.set(pPath, wsName);
        nameToPath.set(wsName, pPath);
        workspacePaths.add(pPath);
      }
    }
  }

  return {
    pathToName,
    nameToPath,
    workspacePaths,
    getWorkspaceName: (folderPath) => pathToName.get(folderPath) || folderPath,
    getFolderPath: (wsName) => nameToPath.get(wsName) || wsName,
    isWorkspaceFolder: (folderPath) => workspacePaths.has(folderPath),
  };
}

export function getDirectDependencies(pkgJson, worktreeOrWorkspaces = null) {
  const direct = new Map();
  const sections = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];

  let workspaceEntries = [];
  if (Array.isArray(worktreeOrWorkspaces)) {
    workspaceEntries = [...worktreeOrWorkspaces];
  } else if (typeof worktreeOrWorkspaces === 'string') {
    workspaceEntries = findWorkspacePackageJsons(worktreeOrWorkspaces, pkgJson);
  } else if (pkgJson) {
    workspaceEntries = [{ pkgJson, relativePath: 'package.json', name: 'root', isRoot: true }];
  }
  if (pkgJson && !workspaceEntries.some((workspace) => workspace.isRoot || workspace.relativePath === 'package.json')) {
    workspaceEntries.unshift({ pkgJson, relativePath: 'package.json', name: pkgJson.name || 'root', isRoot: true });
  }

  for (const ws of workspaceEntries) {
    const wsPkg = ws.pkgJson;
    if (!wsPkg) continue;

    for (const section of sections) {
      if (wsPkg[section] && typeof wsPkg[section] === 'object') {
        for (const [name, range] of Object.entries(wsPkg[section])) {
          const decl = {
            workspace: ws.name,
            packageJsonPath: ws.relativePath,
            section,
            range,
            isRoot: ws.isRoot,
          };

          if (!direct.has(name)) {
            direct.set(name, {
              name,
              range,
              section,
              workspace: ws.isRoot ? null : ws.name,
              packageJsonPath: ws.relativePath,
              declarations: [decl],
            });
          } else {
            const existing = direct.get(name);
            existing.declarations.push(decl);
          }
        }
      }
    }
  }

  return direct;
}

function compareInstalledVersions(a, b) {
  const validA = semver.valid(a);
  const validB = semver.valid(b);
  if (validA && validB) return semver.compare(validA, validB) || a.localeCompare(b);
  if (validA) return -1;
  if (validB) return 1;
  return a.localeCompare(b);
}

export function sortInstalledVersions(versions) {
  return [...new Set(versions.filter((version) => typeof version === 'string').map((version) => version.trim()).filter(Boolean))]
    .sort(compareInstalledVersions);
}

const dependencySections = [
  ['dependencies', 'prod'],
  ['devDependencies', 'dev'],
  ['optionalDependencies', 'optional'],
  ['peerDependencies', 'peer'],
];

function inventoryName(location, entry) {
  if (entry?.name) return entry.name;
  const marker = '/node_modules/';
  const index = location.lastIndexOf(marker);
  if (index >= 0) return location.slice(index + marker.length);
  return location.startsWith('node_modules/') ? location.slice('node_modules/'.length) : null;
}

export function resolveInventoryInstalled(nodes, links, location, name) {
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

function connectInventoryEdge(parent, child, name, requestedRange, type) {
  const edge = {
    from: parent,
    to: child,
    rawSpec: requestedRange ?? null,
    spec: requestedRange ?? null,
    type,
  };
  child.incoming.push(edge);
  child.parents.add(parent);
}

export function buildDependencyInventory(branch = {}) {
  const nodes = new Map();
  const links = new Map();
  const lock = branch.pkgLock;
  const manifests = new Map([['', branch.pkgJson || {}]]);
  for (const workspace of branch.workspaces || []) {
    if (!workspace.relativePath || !workspace.pkgJson) continue;
    const location = path.posix.dirname(workspace.relativePath);
    manifests.set(location === '.' ? '' : location, workspace.pkgJson);
  }
  const add = (location, entry, name = null, options = {}) => {
    const node = {
      location,
      name: entry?.name || name || inventoryName(location, entry),
      version: entry?.version,
      entry: entry || {},
      parents: new Set(),
      incoming: [],
      source: options.source || null,
      isRoot: location === '',
      isWorkspace: options.isWorkspace || false,
    };
    nodes.set(location, node);
    return node;
  };

  if (lock?.packages && typeof lock.packages === 'object') {
    for (const [location, entry] of Object.entries(lock.packages)) {
      if (!entry || typeof entry !== 'object') continue;
      if (entry.link && typeof entry.resolved === 'string') {
        links.set(location, entry.resolved.replace(/^\.\//, ''));
      } else {
        add(location, entry, inventoryName(location, entry), {
          isWorkspace: location !== '' && !location.includes('node_modules/'),
        });
      }
    }
    if (!nodes.has('')) add('', branch.pkgJson || {}, branch.pkgJson?.name);
    for (const [location, manifest] of manifests) {
      if (location && !nodes.has(location)) add(location, manifest, manifest.name, { isWorkspace: true });
      else if (location && nodes.has(location)) nodes.get(location).isWorkspace = true;
    }
  } else if (lock?.dependencies && typeof lock.dependencies === 'object') {
    add('', branch.pkgJson || {}, branch.pkgJson?.name);
    const visit = (dependencies, parentLocation = '') => {
      for (const [name, entry] of Object.entries(dependencies || {})) {
        if (!entry || typeof entry !== 'object') continue;
        const location = `${parentLocation ? `${parentLocation}/` : ''}node_modules/${name}`;
        add(location, entry, name);
        visit(entry.dependencies, location);
      }
    };
    visit(lock.dependencies);
    for (const [location, manifest] of manifests) {
      if (location && !nodes.has(location)) add(location, manifest, manifest.name, { isWorkspace: true });
      else if (location && nodes.has(location)) nodes.get(location).isWorkspace = true;
    }
  } else if (branch.arboristTree?.inventory?.values) {
    for (const source of branch.arboristTree.inventory.values()) {
      nodes.set(source.location, {
        location: source.location,
        name: source.packageName || source.name,
        version: source.version,
        entry: source.package || {},
        parents: new Set(),
        incoming: [],
        source,
        isRoot: Boolean(source.isProjectRoot),
        isWorkspace: Boolean(source.isWorkspace),
      });
    }
    for (const node of nodes.values()) {
      for (const edge of node.source.edgesIn || []) {
        const parent = nodes.get(edge.from.location);
        if (!parent) continue;
        node.incoming.push(edge);
        node.parents.add(parent);
      }
    }
    return { nodes, links, raw: true, scoped: true };
  } else {
    return { nodes, links, raw: false, scoped: false };
  }

  for (const parent of nodes.values()) {
    const manifest = manifests.get(parent.location);
    const declared = new Map();
    for (const [section, type] of dependencySections) {
      for (const [name, range] of Object.entries(parent.entry?.[section] || {})) declared.set(name, { range, type });
      for (const [name, range] of Object.entries(manifest?.[section] || {})) declared.set(name, { range, type });
    }
    if (parent.location && lock?.dependencies && !manifest) {
      for (const [name, range] of Object.entries(parent.entry?.requires || {})) {
        if (!declared.has(name)) declared.set(name, { range, type: 'prod' });
      }
    }
    for (const [name, { range, type }] of declared) {
      const child = resolveInventoryInstalled(nodes, links, parent.location, name);
      if (child) connectInventoryEdge(parent, child, name, range, type);
    }
  }
  const chains = [
    ...(branch.dependencyChains || []),
    ...(branch.vulnerabilities || []).flatMap((row) => row.dependencyChains || row.chains || []),
  ];
  for (const chain of chains) {
    if (!Array.isArray(chain)) continue;
    for (let index = 1; index < chain.length; index += 1) {
      const previous = chain[index - 1];
      const current = chain[index];
      const parents = [...nodes.values()].filter((node) => node.name === previous.name && node.version === previous.version);
      const children = [...nodes.values()].filter((node) => node.name === current.name && node.version === current.version);
      if (parents.length === 1 && children.length === 1) children[0].parents.add(parents[0]);
    }
  }
  return { nodes, links, raw: true, scoped: true };
}

function instanceEdges(node) {
  const edges = node.edgesIn || node.source?.edgesIn || node.incoming || [];
  const incoming = edges instanceof Map ? [...edges.values()] : [...edges];
  for (const link of node.linksIn || node.source?.linksIn || []) {
    incoming.push(...(link.edgesIn || []));
  }
  return [...new Set(incoming)].flatMap((edge) => {
    if (edge.type !== 'workspace') return [edge];
    // Arborist's workspace membership edges are not dependency declarations.
    const manifest = edge.from?.package || {};
    const declaration = dependencySections.find(([section]) => Object.hasOwn(manifest[section] || {}, edge.name));
    if (!declaration) return [];
    const [section, type] = declaration;
    const range = manifest[section][edge.name];
    return [{ from: edge.from, to: edge.to, rawSpec: range, spec: range, type }];
  });
}

function isOriginNode(node) {
  return Boolean(node.isProjectRoot || node.isWorkspace || node.isRoot || node.source?.isProjectRoot || node.source?.isWorkspace);
}

function instanceLocation(node) {
  return node.location ?? node.source?.location ?? '';
}

function instanceName(node) {
  return node.packageName || node.name || node.source?.packageName || node.source?.name || null;
}

function instanceVersion(node) {
  return node.version ?? node.source?.version ?? null;
}

function originForNode(node, edge, chain) {
  const workspace = Boolean(node.isWorkspace || node.source?.isWorkspace);
  const location = instanceLocation(node);
  const packageJsonPath = workspace ? `${location.replace(/\/$/, '')}/package.json` : 'package.json';
  const type = edge.type;
  const section = type === 'dev' ? 'devDependencies' : type === 'optional' ? 'optionalDependencies'
    : type === 'peer' ? 'peerDependencies' : 'dependencies';
  return {
    packageJsonPath,
    section,
    workspace: workspace ? instanceName(node) : null,
    chain,
  };
}

function instanceChainLink(node, requiredRange) {
  return {
    name: instanceName(node),
    version: instanceVersion(node),
    location: instanceLocation(node),
    requiredRange: requiredRange || null,
  };
}

function collectInstanceOrigins(target) {
  const origins = [];
  const walk = (node, chain, visited) => {
    const nodeId = instanceLocation(node) || node;
    if (visited.has(nodeId)) return;
    const nextVisited = new Set(visited).add(nodeId);
    for (const edge of instanceEdges(node)) {
      const parent = edge.from;
      if (!parent) continue;
      const requested = edge.rawSpec || edge.spec || null;
      const adjusted = chain.map((link, index) => index === 0 ? { ...link, requiredRange: requested } : link);
      if (isOriginNode(parent)) {
        origins.push(originForNode(parent, edge, adjusted));
        if (!parent.isWorkspace && !parent.source?.isWorkspace) continue;
      }
      const parentLink = instanceChainLink(parent, null);
      walk(parent, [parentLink, ...adjusted], nextVisited);
    }
  };
  walk(target, [instanceChainLink(target, null)], new Set());
  return [...new Map(origins.map((origin) => [JSON.stringify(origin), origin])).values()]
    .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
}

export function getPackageInstances(packageName, branch = {}) {
  if (!packageName) return [];
  const tree = branch.arboristTree;
  const candidates = [];
  if (tree?.inventory?.query) {
    candidates.push(...tree.inventory.query('name', packageName));
  } else {
    const inventory = branch.dependencyInventory || buildDependencyInventory(branch);
    candidates.push(...[...inventory.nodes.values()].filter((node) => node.name === packageName));
  }

  const instances = new Map();
  for (const node of candidates) {
    const location = instanceLocation(node);
    const installedVersion = instanceVersion(node);
    if (!location || typeof installedVersion !== 'string') continue;
    const incoming = instanceEdges(node).map((edge) => ({
      parentName: instanceName(edge.from),
      parentVersion: instanceVersion(edge.from),
      parentLocation: instanceLocation(edge.from),
      requestedRange: edge.rawSpec || edge.spec || null,
      effectiveRange: edge.spec || null,
      type: edge.type || null,
    })).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
    instances.set(location, {
      installedVersion,
      location,
      incoming: [...new Map(incoming.map((edge) => [JSON.stringify(edge), edge])).values()],
      origins: collectInstanceOrigins(node),
    });
  }
  return [...instances.values()].sort((a, b) => {
    const order = compareInstalledVersions(a.installedVersion, b.installedVersion);
    return order || a.location.localeCompare(b.location);
  });
}

function reportChainsFromInstances(instances, branch = {}) {
  const chains = [];
  for (const instance of instances) {
    for (const origin of instance.origins) {
      const location = path.posix.dirname(origin.packageJsonPath);
      const isWorkspace = location !== '.';
      const anchorLocation = isWorkspace ? location : '';
      const version = branch.arboristTree?.inventory?.get(anchorLocation)?.version
        || branch.pkgLock?.packages?.[anchorLocation]?.version
        || (isWorkspace
          ? branch.workspaces?.find((workspace) => workspace.relativePath === origin.packageJsonPath)?.pkgJson?.version
          : branch.pkgJson?.version)
        || (isWorkspace ? 'workspace' : null);
      const anchor = {
        name: isWorkspace ? origin.workspace : '[root]',
        version,
        location: isWorkspace ? location : '',
        isWorkspace,
        isRoot: !isWorkspace,
        packageJsonPath: origin.packageJsonPath,
        specifier: isWorkspace ? `${origin.workspace} (${origin.packageJsonPath})` : '[root]',
      };
      const type = dependencySections.find(([section]) => section === origin.section)?.[1] || 'prod';
      chains.push([anchor, ...origin.chain.map((link, index) => ({
        ...link,
        specifier: `${link.name}@${link.version}`,
        ...(index === 0 ? { type, packageJsonPath: origin.packageJsonPath, workspace: origin.workspace } : {}),
      }))]);
    }
  }
  return [...new Map(chains.map((chain) => [JSON.stringify(chain), chain])).values()]
    .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
}

export function parseNodePath(nodePathStr) {
  if (!nodePathStr) return [];
  const segments = nodePathStr.split(/node_modules[/\\]/).filter(Boolean);
  return segments.map((s) => s.replace(/[/\\]$/, ''));
}

export function extractChainsFromNpmLs(npmLsData, targetPkgName, workspaceLookup = null) {
  if (!npmLsData) return [];
  const results = [];

  function walk(node, currentChain = []) {
    if (!node || typeof node !== 'object') return;

    const depCollections = [node.dependencies, node.devDependencies].filter(Boolean);

    for (const deps of depCollections) {
      for (const [name, depNode] of Object.entries(deps)) {
        const ver = depNode.version || 'unknown';
        const link = {
          name,
          version: ver,
          specifier: `${name}@${ver}`,
          requiredRange: depNode.required?.version || null,
        };

        const newChain = [...currentChain, link];

        if (name === targetPkgName) {
          results.push(newChain);
        }

        if (depNode.dependencies) {
          walk(depNode, newChain);
        }
      }
    }
  }

  walk(npmLsData);
  return results;
}

export function tracePathsFromPackageLock(pkgLock, targetPkgName, directDeps, worktreeOrWorkspaces = null) {
  if (!pkgLock) return [];
  const pkgJson = { ...(pkgLock.packages?.[''] || {}) };
  for (const [name, info] of directDeps || []) {
    for (const declaration of info.declarations || [info]) {
      if (declaration.packageJsonPath && declaration.packageJsonPath !== 'package.json') continue;
      const section = declaration.section || 'dependencies';
      pkgJson[section] = { ...pkgJson[section], [name]: declaration.range };
    }
  }
  const branch = {
    pkgJson,
    pkgLock,
    workspaces: Array.isArray(worktreeOrWorkspaces) ? worktreeOrWorkspaces
      : typeof worktreeOrWorkspaces === 'string' ? findWorkspacePackageJsons(worktreeOrWorkspaces, pkgJson) : [],
  };
  return reportChainsFromInstances(getPackageInstances(targetPkgName, branch), branch)
    .map((chain) => chain[0].isRoot ? chain.slice(1) : chain);
}

export function extractDependencyChains(vulnData, pkgLock, directDeps, npmLsData = null, worktreeOrWorkspaces = null) {
  const wsLookup = buildWorkspaceLookup(pkgLock, worktreeOrWorkspaces);

  if (npmLsData) {
    const lsChains = extractChainsFromNpmLs(npmLsData, vulnData.name, wsLookup);
    if (lsChains.length > 0) {
      return lsChains;
    }
  }

  if (pkgLock?.packages || pkgLock?.dependencies) {
    const lockChains = tracePathsFromPackageLock(pkgLock, vulnData.name, directDeps, worktreeOrWorkspaces);
    if (lockChains.length > 0) {
      return lockChains;
    }
  }

  const chains = [];
  const nodes = vulnData.nodes || [];

  for (const nodePath of nodes) {
    const pkgNames = parseNodePath(nodePath);
    if (pkgNames.length === 0) continue;

    const chain = [];
    let accumulatedPath = '';
    for (let i = 0; i < pkgNames.length; i++) {
      const name = pkgNames[i];
      accumulatedPath = accumulatedPath ? `${accumulatedPath}/node_modules/${name}` : `node_modules/${name}`;

      let version = 'unknown';
      if (pkgLock?.packages && pkgLock.packages[accumulatedPath]) {
        version = pkgLock.packages[accumulatedPath].version || 'unknown';
      } else if (pkgLock?.dependencies && i === 0 && pkgLock.dependencies[name]) {
        version = pkgLock.dependencies[name].version || 'unknown';
      }

      chain.push({
        name,
        version,
        specifier: `${name}@${version}`,
      });
    }

    chains.push(chain);
  }

  if (chains.length === 0) {
    const isDirect = directDeps.has(vulnData.name);
    const directInfo = directDeps.get(vulnData.name);
    chains.push([
      {
        name: vulnData.name,
        version: vulnData.version || 'unknown',
        specifier: `${vulnData.name}@${vulnData.version || (directInfo ? directInfo.range : 'unknown')}`,
      },
    ]);
  }

  return chains;
}

export function findDirectRoots(chains, directDeps) {
  const rootsMap = new Map(findDirectRootsFromArborist(
    chains.filter((chain) => chain[0]?.isRoot || chain[0]?.isWorkspace)
  ).map((root) => [JSON.stringify([root.packageJsonPath, root.section, root.name, root.location]), root]));

  for (const chain of chains) {
    if (chain.length === 0 || chain[0].isRoot || chain[0].isWorkspace) continue;
    const top = chain[0];
    const directInfo = directDeps.get(top.name);
    if (!directInfo) continue;
    const declarations = (directInfo.declarations || [directInfo])
      .filter((decl) => !top.packageJsonPath || decl.packageJsonPath === top.packageJsonPath);
    for (const decl of declarations) {
      const key = JSON.stringify([decl.packageJsonPath, decl.section, top.name, top.location]);
      rootsMap.set(key, {
        name: top.name,
        currentRange: decl.range,
        section: decl.section,
        installedVersion: top.version,
        workspace: decl.isRoot ? null : decl.workspace,
        packageJsonPath: decl.packageJsonPath,
        location: top.location,
        declarations: [decl],
      });
    }
  }

  return Array.from(rootsMap.values());
}

function getIncomingEdges(node) {
  const edges = Array.from(node.edgesIn || []).filter((e) => e.type !== 'peer');
  if (node.isWorkspace && node.linksIn) {
    for (const link of node.linksIn) {
      for (const edge of link.edgesIn || []) {
        if (!edge.from.isProjectRoot && edge.type !== 'peer') {
          edges.push(edge);
        }
      }
    }
  }
  return edges;
}

function getNodeLabel(node) {
  const pkgName = node.packageName || node.name;
  if (node.isProjectRoot) {
    return '[root]';
  }
  if (node.isWorkspace) {
    const pkgJsonPath = path.join(node.location, 'package.json');
    return `${pkgName} (${pkgJsonPath})`;
  }
  return `${pkgName}@${node.version || 'unknown'}`;
}

export function getArboristLogicalChains(tree, targetName) {
  if (!tree) return [];
  const branch = { arboristTree: tree };
  return reportChainsFromInstances(getPackageInstances(targetName, branch), branch);
}

export function traceArboristChains(nodeOrTree, targetNameOrVisited = null) {
  if (typeof targetNameOrVisited === 'string') {
    return getArboristLogicalChains(nodeOrTree, targetNameOrVisited);
  }

  const node = nodeOrTree;
  const visited = targetNameOrVisited instanceof Set ? targetNameOrVisited : new Set();
  if (visited.has(node)) return [];
  const nextVisited = new Set(visited);
  nextVisited.add(node);

  const edges = getIncomingEdges(node);

  const currentStep = {
    name: node.packageName || node.name,
    version: node.version,
    location: node.location,
    isWorkspace: Boolean(node.isWorkspace),
    isRoot: Boolean(node.isProjectRoot),
    packageJsonPath: node.isWorkspace ? path.join(node.location, 'package.json') : (node.isProjectRoot ? 'package.json' : null),
    specifier: getNodeLabel(node),
  };

  if (edges.length === 0) {
    return [[currentStep]];
  }

  const chains = [];
  for (const edge of edges) {
    const parent = edge.from;
    const parentChains = traceArboristChains(parent, nextVisited);
    for (const pChain of parentChains) {
      chains.push([
        ...pChain,
        {
          ...currentStep,
          requiredRange: edge.spec,
          type: edge.type,
        },
      ]);
    }
  }
  return chains;
}

export function findDirectRootsFromArborist(chains, targetPkgName = null) {
  const rootsMap = new Map();
  for (const chain of chains) {
    if (!chain || chain.length < 2) continue;
    let anchorIdx = 0;
    for (let i = 0; i < chain.length - 1; i++) {
      if (chain[i].isRoot || chain[i].isWorkspace) {
        anchorIdx = i;
      }
    }
    const parent = chain[anchorIdx];
    const directChild = chain[anchorIdx + 1];
    if (!directChild) continue;

    const pkgJsonPath = parent.packageJsonPath || (parent.isWorkspace && parent.location ? path.join(parent.location, 'package.json') : 'package.json');
    const key = JSON.stringify([pkgJsonPath, directChild.type, directChild.name, directChild.location]);
    if (!rootsMap.has(key)) {
      const section = directChild.type === 'dev' ? 'devDependencies' :
                      directChild.type === 'optional' ? 'optionalDependencies' :
                      directChild.type === 'peer' ? 'peerDependencies' : 'dependencies';
      const range = directChild.requiredRange || directChild.version;
      rootsMap.set(key, {
        name: directChild.name,
        range,
        currentRange: range,
        section,
        installedVersion: directChild.version,
        workspace: parent.isWorkspace ? (parent.packageName || parent.name) : null,
        packageJsonPath: pkgJsonPath,
        location: directChild.location,
        declarations: [
          {
            workspace: parent.isWorkspace ? (parent.packageName || parent.name) : null,
            packageJsonPath: pkgJsonPath,
            section,
            range,
            isRoot: Boolean(parent.isRoot),
          },
        ],
      });
    }
  }
  return Array.from(rootsMap.values());
}

export function lookupPackageInstalledInfo(pkgName, pkgJson, pkgLock, npmLsData = null, worktreeOrWorkspaces = null, arboristTree = null) {
  if (!pkgName) {
    return {
      isDirect: false,
      isIndirect: false,
      dependencyType: 'Unknown',
      currentVersion: 'unknown',
      installedVersions: [],
      directRoots: [],
      dependencyPaths: [],
      chains: [],
      directInfo: null,
      workspaceDeclarations: [],
    };
  }

  let tree = arboristTree;
  if (!tree && worktreeOrWorkspaces && typeof worktreeOrWorkspaces === 'object' && worktreeOrWorkspaces.inventory) {
    tree = worktreeOrWorkspaces;
  }

  const snapshotWorkspaces = Object.entries(pkgLock?.packages || {})
    .filter(([location, entry]) => location && !location.includes('node_modules/') && !entry.link)
    .map(([location, entry]) => ({
      name: entry.name || location,
      relativePath: `${location}/package.json`,
      pkgJson: entry,
      isRoot: false,
    }));
  const declaredWorkspaces = Array.isArray(worktreeOrWorkspaces) ? worktreeOrWorkspaces
    : typeof worktreeOrWorkspaces === 'string' ? findWorkspacePackageJsons(worktreeOrWorkspaces, pkgJson) : [];
  const workspaces = [...new Map([...snapshotWorkspaces, ...declaredWorkspaces]
    .map((workspace) => [workspace.relativePath, workspace])).values()];
  const directDeps = getDirectDependencies(pkgJson || pkgLock?.packages?.[''], workspaces);
  const isDirectInPkg = directDeps.has(pkgName);
  const directInfoFallback = isDirectInPkg ? directDeps.get(pkgName) : null;

  if (tree) {
    const nodes = Array.from(tree.inventory.query('name', pkgName));
    const workspaceDeclarations = [];
    let hasDirect = false;
    let hasTransitive = false;

    let allChains = getArboristLogicalChains(tree, pkgName);
    if (allChains.length === 0) {
      for (const node of nodes) {
        allChains.push(...traceArboristChains(node));
      }
    }

    for (const node of nodes) {
      // Check incoming edges
      for (const edge of node.edgesIn || []) {
        const parent = edge.from;
        const isRoot = Boolean(parent.isProjectRoot);
        const isWs = Boolean(parent.isWorkspace);

        if (isRoot || isWs) {
          hasDirect = true;
          const wsName = isWs ? (parent.packageName || parent.name) : null;
          const wsLoc = isWs ? parent.location : '';
          const packageJsonPath = isWs ? path.join(wsLoc, 'package.json') : 'package.json';
          const section = edge.type === 'dev' ? 'devDependencies' :
                          edge.type === 'optional' ? 'optionalDependencies' :
                          edge.type === 'peer' ? 'peerDependencies' : 'dependencies';
          workspaceDeclarations.push({
            workspace: wsName,
            packageJsonPath,
            range: edge.spec,
            section,
            isRoot,
            location: wsLoc,
          });
        } else {
          hasTransitive = true;
        }
      }

      if (node.location && node.location.includes('/node_modules/') && !node.location.startsWith('node_modules/' + pkgName)) {
        hasTransitive = true;
      }
    }

    if (isDirectInPkg) {
      hasDirect = true;
      if (directInfoFallback) {
        for (const decl of directInfoFallback.declarations || [directInfoFallback]) {
          if (!workspaceDeclarations.some((w) => w.packageJsonPath === decl.packageJsonPath)) {
            workspaceDeclarations.push(decl);
          }
        }
      }
    }

    if (allChains.some((c) => c.length > 2 || (c.length === 2 && !c[0].isRoot && !c[0].isWorkspace))) {
      hasTransitive = true;
    }

    let dependencyType = 'Unknown';
    if (hasDirect && hasTransitive) {
      dependencyType = 'Direct & Indirect';
    } else if (hasDirect) {
      dependencyType = 'Direct';
    } else if (hasTransitive) {
      dependencyType = 'Indirect (Transitive)';
    }

    const versionsList = sortInstalledVersions(nodes.map((node) => node.version));
    let currentVersion = 'unknown';
    if (versionsList.length === 1) {
      currentVersion = versionsList[0];
    } else if (versionsList.length > 1) {
      currentVersion = versionsList.join(', ');
    } else if (directInfoFallback?.range) {
      currentVersion = directInfoFallback.range;
    }

    const directRoots = findDirectRootsFromArborist(allChains, pkgName);
    const dependencyPaths = allChains.map((c) => c.map((l) => l.specifier).join(' -> '));
    const directInfo = workspaceDeclarations[0] || directInfoFallback || null;

    return {
      isDirect: hasDirect,
      isIndirect: hasTransitive,
      dependencyType,
      currentVersion,
      installedVersions: versionsList,
      directRoots,
      dependencyPaths,
      chains: allChains,
      directInfo,
      workspaceDeclarations,
      arboristTree: tree,
    };
  }

  // Snapshot lookup shares the physical inventory and exhaustive origins used by planning.
  const isDirect = isDirectInPkg;
  const directInfo = directInfoFallback;
  const workspaceDeclarations = directInfo?.declarations || [];

  const instances = getPackageInstances(pkgName, {
    pkgJson,
    pkgLock,
    workspaces,
  });
  const installedVersionSet = new Set(instances.map((instance) => instance.installedVersion));
  const installedPaths = instances.map((instance) => instance.location);
  const originChains = reportChainsFromInstances(instances, { pkgJson, pkgLock, workspaces });
  const chains = originChains.length > 0 ? originChains
    : extractDependencyChains({ name: pkgName, nodes: installedPaths }, pkgLock, directDeps, npmLsData, worktreeOrWorkspaces);
  const directRoots = findDirectRoots(chains, directDeps);

  if (originChains.length === 0 && isDirect && workspaceDeclarations.length > 0) {
    const directVer = sortInstalledVersions([...installedVersionSet])[0] || directInfo?.range || 'installed';
    for (const decl of workspaceDeclarations) {
      const sectionTag = decl.section === 'devDependencies' ? ' (devDependencies)' : ' (dependencies)';
      const wsName = decl.isRoot ? '[root]' : (decl.workspace || decl.packageJsonPath);
      const directPathStr = `${wsName}${sectionTag} -> ${pkgName}@${decl.range || directVer}`;

      if (!chains.some((c) => c.length === 1 && c[0].specifier === directPathStr)) {
        chains.unshift([{ name: pkgName, version: directVer, specifier: directPathStr, isDirectDecl: true }]);
      }
    }
  }

  const isIndirect = chains.some((chain) => chain[0]?.isRoot || chain[0]?.isWorkspace
    ? chain.length > 2 : chain.length > 1 || (chain.length === 1 && !chain[0].isDirectDecl && chain[0].name !== pkgName));

  let dependencyType = 'Unknown';
  if (isDirect && isIndirect) {
    dependencyType = 'Direct & Indirect';
  } else if (isDirect) {
    dependencyType = 'Direct';
  } else if (isIndirect) {
    dependencyType = 'Indirect (Transitive)';
  }

  const versionsList = sortInstalledVersions([...installedVersionSet]);
  let currentVersion = 'unknown';

  if (versionsList.length === 1) {
    currentVersion = versionsList[0];
  } else if (versionsList.length > 1) {
    currentVersion = versionsList.join(', ');
  } else if (directInfo?.range) {
    currentVersion = directInfo.range;
  }

  const dependencyPaths = chains.map((c) => c.map((link) => link.specifier).join(' -> '));

  return {
    isDirect,
    isIndirect,
    dependencyType,
    currentVersion,
    installedVersions: versionsList,
    directRoots,
    dependencyPaths,
    chains,
    directInfo,
    workspaceDeclarations,
  };
}

export async function runNpmLs(cwd, pkgName = null) {
  try {
    const args = ['ls', '--all', '--json'];
    if (pkgName) args.push(pkgName);
    const { stdout } = await execFileAsync('npm', args, {
      cwd,
      maxBuffer: 20 * 1024 * 1024,
    });
    return JSON.parse(stdout);
  } catch (err) {
    if (err.stdout) {
      try {
        return JSON.parse(err.stdout);
      } catch {
        // ignore
      }
    }
    return null;
  }
}
