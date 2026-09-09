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

export function getDirectDependencies(pkgJson) {
  if (!pkgJson) return new Map();
  const direct = new Map();

  const sections = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
  for (const section of sections) {
    if (pkgJson[section] && typeof pkgJson[section] === 'object') {
      for (const [name, range] of Object.entries(pkgJson[section])) {
        direct.set(name, {
          name,
          range,
          section,
        });
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

export function extractChainsFromNpmLs(npmLsData, targetPkgName) {
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

export function tracePathsFromPackageLock(pkgLock, targetPkgName, directDeps) {
  if (!pkgLock?.packages) return [];
  const packages = pkgLock.packages;

  const dependentsMap = new Map();
  const packageVersions = new Map();

  for (const [pkgPath, pkgInfo] of Object.entries(packages)) {
    const parentName = pkgPath === '' ? '__ROOT__' : pkgPath.replace(/^.*node_modules\//, '');
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
      if (parent.parentName === '__ROOT__') {
        chains.push(currentPath);
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

export function extractDependencyChains(vulnData, pkgLock, directDeps, npmLsData = null) {
  // 1. Try npm ls graph first if available
  if (npmLsData) {
    const lsChains = extractChainsFromNpmLs(npmLsData, vulnData.name);
    if (lsChains.length > 0) {
      return lsChains;
    }
  }

  // 2. Try package-lock.json dependency graph traversal
  if (pkgLock?.packages) {
    const lockChains = tracePathsFromPackageLock(pkgLock, vulnData.name, directDeps);
    if (lockChains.length > 0) {
      return lockChains;
    }
  }

  // 3. Fallback to audit nodes parsing
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

  // 4. Default direct representation
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
      });
    }
  }

  return Array.from(rootsMap.values());
}

export function lookupPackageInstalledInfo(pkgName, pkgJson, pkgLock, npmLsData = null) {
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
    };
  }

  const directDeps = getDirectDependencies(pkgJson);
  const isDirect = directDeps.has(pkgName);
  const directInfo = isDirect ? directDeps.get(pkgName) : null;

  // Find all installed instances and paths in package-lock.json
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

  // Extract chains
  const chains = extractDependencyChains({ name: pkgName, nodes: installedPaths }, pkgLock, directDeps, npmLsData);
  const directRoots = findDirectRoots(chains, directDeps);

  // Check if there are indirect chains (chain length > 1 or chain not starting with direct pkgName)
  const isIndirect = chains.some((c) => c.length > 1 || (c.length === 1 && c[0].name !== pkgName));

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
