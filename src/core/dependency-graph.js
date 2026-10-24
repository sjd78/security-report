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
    workspaceEntries = worktreeOrWorkspaces;
  } else if (typeof worktreeOrWorkspaces === 'string') {
    workspaceEntries = findWorkspacePackageJsons(worktreeOrWorkspaces, pkgJson);
  } else if (pkgJson) {
    workspaceEntries = [{ pkgJson, relativePath: 'package.json', name: 'root', isRoot: true }];
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
  if (!pkgLock?.packages) return [];
  const packages = pkgLock.packages;
  const wsLookup = buildWorkspaceLookup(pkgLock, worktreeOrWorkspaces);

  const dependentsMap = new Map();
  const packageVersions = new Map();

  for (const [pkgPath, pkgInfo] of Object.entries(packages)) {
    let parentName = pkgPath;
    if (pkgPath === '') {
      parentName = '__ROOT__';
    } else if (wsLookup.isWorkspaceFolder(pkgPath)) {
      parentName = wsLookup.getWorkspaceName(pkgPath);
    } else {
      parentName = pkgPath.replace(/^.*node_modules\//, '');
    }

    const ver = pkgInfo.version || 'unknown';
    packageVersions.set(pkgPath, ver);

    const allDeps = {
      ...(pkgInfo.dependencies || {}),
      ...(pkgInfo.devDependencies || {}),
      ...(pkgInfo.optionalDependencies || {}),
    };

    for (const [depName, range] of Object.entries(allDeps)) {
      if (!dependentsMap.has(depName)) {
        dependentsMap.set(depName, []);
      }
      dependentsMap.get(depName).push({
        parentPath: pkgPath,
        parentName,
        requiredRange: range,
        isWorkspaceRoot: wsLookup.isWorkspaceFolder(pkgPath),
      });
    }
  }

  const targetPaths = Object.keys(packages).filter(
    (p) => p === `node_modules/${targetPkgName}` || p.endsWith(`/node_modules/${targetPkgName}`)
  );

  const targetVersion = targetPaths.length > 0 ? packages[targetPaths[0]].version : 'unknown';

  const chains = [];

  function backtrack(currentPkgName, currentPath = []) {
    const parents = dependentsMap.get(currentPkgName) || [];

    for (const parent of parents) {
      if (parent.parentPath === '') {
        chains.push(currentPath);
      } else if (parent.isWorkspaceRoot) {
        // Reached workspace root folder (e.g. 'client', 'cypress')
        const wsName = wsLookup.getWorkspaceName(parent.parentPath);
        const wsFolder = parent.parentPath;
        const wsSpecifier = `${wsName} (${wsFolder}/package.json)`;
        const wsLink = {
          name: wsName,
          version: 'workspace',
          specifier: wsSpecifier,
          isWorkspaceRoot: true,
          folderPath: wsFolder,
        };
        chains.push([wsLink, ...currentPath]);
      } else {
        const parentVer = packageVersions.get(parent.parentPath) || 'unknown';
        const link = {
          name: parent.parentName,
          version: parentVer,
          specifier: `${parent.parentName}@${parentVer}`,
          requiredRange: parent.requiredRange,
        };

        if (!currentPath.some((p) => p.name === parent.parentName)) {
          backtrack(parent.parentName, [link, ...currentPath]);
        }
      }
    }
  }

  const initialLink = {
    name: targetPkgName,
    version: targetVersion,
    specifier: `${targetPkgName}@${targetVersion}`,
  };

  backtrack(targetPkgName, [initialLink]);

  return chains;
}

export function extractDependencyChains(vulnData, pkgLock, directDeps, npmLsData = null, worktreeOrWorkspaces = null) {
  const wsLookup = buildWorkspaceLookup(pkgLock, worktreeOrWorkspaces);

  if (npmLsData) {
    const lsChains = extractChainsFromNpmLs(npmLsData, vulnData.name, wsLookup);
    if (lsChains.length > 0) {
      return lsChains;
    }
  }

  if (pkgLock?.packages) {
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
  const rootsMap = new Map();

  for (const chain of chains) {
    if (chain.length === 0) continue;
    const top = chain[0];
    if (directDeps.has(top.name)) {
      const directInfo = directDeps.get(top.name);
      rootsMap.set(top.name, {
        name: top.name,
        currentRange: directInfo.range,
        section: directInfo.section,
        installedVersion: top.version,
        workspace: directInfo.workspace,
        packageJsonPath: directInfo.packageJsonPath,
        declarations: directInfo.declarations || [],
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
  const chains = [];
  const seenNodes = new Set();
  const queue = [];

  // 1. Direct dependencies of root project
  for (const edge of tree.edgesOut.values()) {
    if (edge.type === 'peer' || !edge.to) continue;
    if (edge.to.isWorkspace) continue;
    const directRootName = edge.to.packageName || edge.to.name;
    const step = {
      name: directRootName,
      version: edge.to.version,
      requiredRange: edge.spec,
      type: edge.type,
      location: edge.to.location,
      packageJsonPath: 'package.json',
      workspace: null,
      isRoot: false,
      specifier: `${directRootName}@${edge.to.version}`,
    };
    const rootAnchor = {
      name: '[root]',
      version: tree.version,
      location: '',
      isWorkspace: false,
      isRoot: true,
      packageJsonPath: 'package.json',
      specifier: '[root]',
    };
    queue.push([edge.to, [rootAnchor, step]]);
  }

  // 2. Direct dependencies of each workspace
  if (tree.workspaces) {
    for (const [wsName, wsPath] of tree.workspaces) {
      const wsLoc = wsPath.replace(tree.path + '/', '');
      const wsNode = tree.inventory.get(wsLoc);
      if (!wsNode) continue;
      const wsPkgPath = path.join(wsLoc, 'package.json');
      const wsAnchor = {
        name: wsName,
        version: wsNode.version,
        location: wsLoc,
        isWorkspace: true,
        isRoot: false,
        packageJsonPath: wsPkgPath,
        specifier: `${wsName} (${wsPkgPath})`,
      };

      for (const edge of wsNode.edgesOut.values()) {
        if (edge.type === 'peer' || !edge.to) continue;
        const targetNode = edge.to.isLink ? edge.to.target : edge.to;
        const isWs = Boolean(targetNode.isWorkspace);
        const step = {
          name: targetNode.packageName || targetNode.name,
          version: targetNode.version,
          requiredRange: edge.spec,
          type: edge.type,
          location: targetNode.location,
          isWorkspace: isWs,
          isRoot: false,
          packageJsonPath: isWs ? path.join(targetNode.location, 'package.json') : wsPkgPath,
          workspace: isWs ? (targetNode.packageName || targetNode.name) : wsName,
          specifier: isWs
            ? `${targetNode.packageName || targetNode.name} (${path.join(targetNode.location, 'package.json')})`
            : `${targetNode.packageName || targetNode.name}@${targetNode.version}`,
        };
        queue.push([targetNode, [wsAnchor, step]]);
      }
    }
  }

  while (queue.length > 0) {
    const [node, currentChain] = queue.shift();

    if (node.name === targetName) {
      chains.push(currentChain);
      continue;
    }

    if (seenNodes.has(node.path)) {
      continue;
    }
    seenNodes.add(node.path);

    const targetNode = node.isLink ? node.target : node;
    for (const edge of targetNode.edgesOut.values()) {
      if (edge.type === 'peer' || !edge.to) continue;
      const childNode = edge.to.isLink ? edge.to.target : edge.to;
      const isWs = Boolean(childNode.isWorkspace);
      const step = {
        name: childNode.packageName || childNode.name,
        version: childNode.version,
        requiredRange: edge.spec,
        type: edge.type,
        location: childNode.location,
        isWorkspace: isWs,
        isRoot: false,
        specifier: isWs
          ? `${childNode.packageName || childNode.name} (${path.join(childNode.location, 'package.json')})`
          : `${childNode.packageName || childNode.name}@${childNode.version}`,
      };
      queue.push([childNode, [...currentChain, step]]);
    }
  }

  return chains;
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
    const key = `${pkgJsonPath}:${directChild.name}`;
    if (!rootsMap.has(key)) {
      const section = directChild.type === 'dev' ? 'devDependencies' :
                      directChild.type === 'optional' ? 'optionalDependencies' :
                      directChild.type === 'peer' ? 'peerDependencies' : 'dependencies';
      rootsMap.set(key, {
        name: directChild.name,
        currentRange: directChild.requiredRange || directChild.version,
        section,
        installedVersion: directChild.version,
        workspace: parent.isWorkspace ? (parent.packageName || parent.name) : null,
        packageJsonPath: pkgJsonPath,
        location: directChild.location,
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

  const directDeps = getDirectDependencies(pkgJson, worktreeOrWorkspaces);
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

    const installedVersionSet = new Set(nodes.map((n) => n.version).filter(Boolean));
    const versionsList = Array.from(installedVersionSet);
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

  // Fallback: Legacy parsing for unit tests and environments without preloaded Arborist tree
  const isDirect = isDirectInPkg;
  const directInfo = directInfoFallback;
  const workspaceDeclarations = directInfo?.declarations || [];

  const installedVersionSet = new Set();
  const installedPaths = [];

  if (pkgLock?.packages) {
    for (const [pPath, pInfo] of Object.entries(pkgLock.packages)) {
      if (pPath === `node_modules/${pkgName}` || pPath.endsWith(`/node_modules/${pkgName}`)) {
        if (pInfo.version) installedVersionSet.add(pInfo.version);
        installedPaths.push(pPath);
      }
    }
  } else if (pkgLock?.dependencies) {
    if (pkgLock.dependencies[pkgName]?.version) {
      installedVersionSet.add(pkgLock.dependencies[pkgName].version);
    }
  }

  const chains = extractDependencyChains({ name: pkgName, nodes: installedPaths }, pkgLock, directDeps, npmLsData, worktreeOrWorkspaces);
  const directRoots = findDirectRoots(chains, directDeps);

  if (isDirect && workspaceDeclarations.length > 0) {
    const directVer = installedVersionSet.size > 0 ? Array.from(installedVersionSet)[0] : directInfo?.range || 'installed';
    for (const decl of workspaceDeclarations) {
      const sectionTag = decl.section === 'devDependencies' ? ' (devDependencies)' : ' (dependencies)';
      const wsName = decl.isRoot ? '[root]' : (decl.workspace || decl.packageJsonPath);
      const directPathStr = `${wsName}${sectionTag} -> ${pkgName}@${decl.range || directVer}`;

      if (!chains.some((c) => c.length === 1 && c[0].specifier === directPathStr)) {
        chains.unshift([{ name: pkgName, version: directVer, specifier: directPathStr, isDirectDecl: true }]);
      }
    }
  }

  const isIndirect = chains.some((c) => c.length > 1 || (c.length === 1 && !c[0].isDirectDecl && c[0].name !== pkgName));

  let dependencyType = 'Unknown';
  if (isDirect && isIndirect) {
    dependencyType = 'Direct & Indirect';
  } else if (isDirect) {
    dependencyType = 'Direct';
  } else if (isIndirect) {
    dependencyType = 'Indirect (Transitive)';
  }

  const versionsList = Array.from(installedVersionSet);
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
