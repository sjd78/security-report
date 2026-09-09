import path from 'node:path';
import fs from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

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
  // Format: "node_modules/direct-dep/node_modules/sub-dep/node_modules/vuln-pkg"
  // or "node_modules/@scope/pkg/node_modules/child"
  if (!nodePathStr) return [];

  const segments = nodePathStr.split(/node_modules[/\\]/).filter(Boolean);
  return segments.map((s) => s.replace(/[/\\]$/, ''));
}

export function extractDependencyChains(vulnData, pkgLock, directDeps) {
  const chains = [];
  const nodes = vulnData.nodes || [];

  for (const nodePath of nodes) {
    const pkgNames = parseNodePath(nodePath);
    if (pkgNames.length === 0) continue;

    const chain = [];
    let currentLockNode = pkgLock?.packages ? pkgLock.packages[''] : null;

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

  // If no nodes array or empty, construct minimal chain from directDeps or package name
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
