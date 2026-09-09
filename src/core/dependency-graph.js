import path from 'node:path';
import fs from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import semver from 'semver';

const execFileAsync = promisify(execFile);

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

export function lookupPackageInstalledInfo(pkgName, pkgJson, pkgLock, npmLsData = null, worktreeOrWorkspaces = null) {
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

  const directDeps = getDirectDependencies(pkgJson, worktreeOrWorkspaces);
  const isDirect = directDeps.has(pkgName);
  const directInfo = isDirect ? directDeps.get(pkgName) : null;
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

  // If directly declared in a workspace or root, add every declaration as a direct path entry
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
