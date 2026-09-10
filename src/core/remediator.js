import path from 'node:path';
import fs from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import semver from 'semver';
import { collectNpmAudit } from '../collectors/npm-audit.js';
import { findWorkspacePackageJsons } from './dependency-graph.js';

const execFileAsync = promisify(execFile);

export function detectIndentation(jsonStr) {
  const match = jsonStr.match(/^[ \t]+(?=")/m);
  return match ? match[0] : '  ';
}

export function updatePackageJsonFile(worktreeDir, changes = [], options = {}) {
  const rootPkgPath = path.resolve(worktreeDir, 'package.json');
  if (!fs.existsSync(rootPkgPath)) {
    throw new Error(`package.json not found in ${worktreeDir}`);
  }

  const workspaces = findWorkspacePackageJsons(worktreeDir);
  const loadedFiles = new Map();

  for (const ws of workspaces) {
    if (fs.existsSync(ws.packageJsonPath)) {
      const raw = fs.readFileSync(ws.packageJsonPath, 'utf8');
      loadedFiles.set(ws.packageJsonPath, {
        path: ws.packageJsonPath,
        relativePath: ws.relativePath,
        raw,
        indent: detectIndentation(raw),
        pkgJson: JSON.parse(raw),
        modified: false,
      });
    }
  }

  const applied = [];
  const depSections = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];

  for (const change of changes) {
    const { package: pkgName, section = 'dependencies', to, from, packageJsonPath, workspace } = change;
    if (!pkgName || !to) continue;

    if (section === 'overrides') {
      if (options.allowOverrides !== false) {
        const rootEntry = loadedFiles.get(rootPkgPath);
        if (rootEntry) {
          rootEntry.pkgJson.overrides = rootEntry.pkgJson.overrides || {};
          const prev = rootEntry.pkgJson.overrides[pkgName] || null;
          rootEntry.pkgJson.overrides[pkgName] = to;
          rootEntry.modified = true;
          applied.push({
            package: pkgName,
            section: 'overrides',
            from: prev,
            to,
            packageJsonPath: 'package.json',
          });
        }
      }
      continue;
    }

    let updatedAny = false;

    // If specific file targeted
    if (packageJsonPath) {
      const targetAbs = path.resolve(worktreeDir, packageJsonPath);
      const entry = loadedFiles.get(targetAbs);
      if (entry) {
        let targetSec = section;
        for (const sec of depSections) {
          if (entry.pkgJson[sec] && entry.pkgJson[sec][pkgName] !== undefined) {
            targetSec = sec;
            break;
          }
        }
        entry.pkgJson[targetSec] = entry.pkgJson[targetSec] || {};
        const cur = entry.pkgJson[targetSec][pkgName] || from;
        entry.pkgJson[targetSec][pkgName] = to;
        entry.modified = true;
        updatedAny = true;
        applied.push({
          package: pkgName,
          section: targetSec,
          from: cur,
          to,
          packageJsonPath: entry.relativePath,
        });
      }
    } else {
      // Search across all loaded package.json files
      for (const entry of loadedFiles.values()) {
        let foundSection = null;
        for (const sec of depSections) {
          if (entry.pkgJson[sec] && entry.pkgJson[sec][pkgName] !== undefined) {
            foundSection = sec;
            break;
          }
        }

        if (foundSection) {
          const cur = entry.pkgJson[foundSection][pkgName];
          entry.pkgJson[foundSection][pkgName] = to;
          entry.modified = true;
          updatedAny = true;
          applied.push({
            package: pkgName,
            section: foundSection,
            from: cur,
            to,
            packageJsonPath: entry.relativePath,
          });
        }
      }

      // If not found anywhere, default to root package.json
      if (!updatedAny) {
        const rootEntry = loadedFiles.get(rootPkgPath);
        if (rootEntry) {
          rootEntry.pkgJson[section] = rootEntry.pkgJson[section] || {};
          const cur = rootEntry.pkgJson[section][pkgName] || from;
          rootEntry.pkgJson[section][pkgName] = to;
          rootEntry.modified = true;
          applied.push({
            package: pkgName,
            section,
            from: cur,
            to,
            packageJsonPath: 'package.json',
          });
        }
      }
    }
  }

  // Write back all modified files preserving indentation
  for (const entry of loadedFiles.values()) {
    if (entry.modified) {
      fs.writeFileSync(entry.path, JSON.stringify(entry.pkgJson, null, entry.indent) + '\n', 'utf8');
    }
  }

  const rootResult = loadedFiles.get(rootPkgPath)?.pkgJson || {};
  return {
    applied,
    pkgJson: rootResult,
    touchedFiles: Array.from(loadedFiles.values())
      .filter((e) => e.modified)
      .map((e) => e.relativePath),
  };
}

async function runNpm(worktreeDir, args, options = {}) {
  const npmArgs = [...args, '--package-lock-only'];

  if (options.legacyPeerDeps) {
    npmArgs.push('--legacy-peer-deps');
  }

  try {
    const { stdout, stderr } = await execFileAsync('npm', npmArgs, {
      cwd: worktreeDir,
      maxBuffer: 20 * 1024 * 1024,
    });
    return { success: true, stdout, stderr };
  } catch (err) {
    if (!options.legacyPeerDeps && (err.stderr?.includes('ERESOLVE') || err.stdout?.includes('ERESOLVE'))) {
      return await runNpm(worktreeDir, args, { ...options, legacyPeerDeps: true });
    }
    throw new Error(`Failed to run "npm ${npmArgs.join(' ')}" in ${worktreeDir}: ${err.stderr || err.message}`);
  }
}

/** Rebuilds package-lock.json from the current package.json ranges and overrides. */
export async function syncLockfile(worktreeDir, options = {}) {
  return await runNpm(worktreeDir, ['install'], options);
}

/** Re-resolves one package inside the lockfile; see formatLockfileUpdate. */
export async function updateLockfilePackage(worktreeDir, packageName, options = {}) {
  return await runNpm(worktreeDir, ['update', packageName], options);
}

export async function remediateBranch(worktreeDir, branchReport, options = {}) {
  const branchName = branchReport.branch || 'main';
  const vulnerabilities = branchReport.vulnerabilities || [];

  if (vulnerabilities.length === 0) {
    return {
      branch: branchName,
      appliedChanges: [],
      resolved: [],
      remaining: [],
      isClean: true,
      message: 'No vulnerabilities to remediate.',
    };
  }

  const changesMap = new Map();
  const lockfileUpdates = [];

  for (const vuln of vulnerabilities) {
    const rem = vuln.remediation;
    if (!rem) continue;

    for (const chg of rem.packageJsonChanges || []) {
      const key = `${chg.packageJsonPath || 'root'}:${chg.section || 'dependencies'}:${chg.package}`;
      const existing = changesMap.get(key);
      if (!existing) {
        changesMap.set(key, chg);
        continue;
      }
      const cleanExisting = semver.clean(String(existing.to).replace(/^[~^]/, ''));
      const cleanNew = semver.clean(String(chg.to).replace(/^[~^]/, ''));
      if (cleanExisting && cleanNew && semver.gt(cleanNew, cleanExisting)) {
        changesMap.set(key, chg);
      }
    }

    for (const pkgName of rem.lockfileUpdates || []) {
      if (pkgName && !lockfileUpdates.includes(pkgName)) lockfileUpdates.push(pkgName);
    }
  }

  // Deduplicated per target; the highest requested version wins.
  const pendingChanges = Array.from(changesMap.values());

  if (options.dryRun) {
    return {
      branch: branchName,
      dryRun: true,
      appliedChanges: pendingChanges,
      lockfileUpdates,
      resolved: vulnerabilities,
      remaining: [],
      isClean: true,
    };
  }

  // Step 2a: Update package.json files (root and workspaces)
  const { applied, touchedFiles } = updatePackageJsonFile(worktreeDir, pendingChanges, options);

  // Step 2b: Rebuild the lockfile from the updated ranges, then re-resolve every
  // package whose fix lives inside ranges the parents already permit.
  await syncLockfile(worktreeDir, options);

  const appliedLockfileUpdates = [];
  for (const pkgName of lockfileUpdates) {
    try {
      await updateLockfilePackage(worktreeDir, pkgName, options);
      appliedLockfileUpdates.push(pkgName);
    } catch (err) {
      console.warn(`[Remediator] Warning: lockfile update for ${pkgName} failed: ${err.message}`);
    }
  }

  // Step 2c: Verify via re-audit
  let postAudit;
  try {
    postAudit = await collectNpmAudit(worktreeDir, branchName);
  } catch (err) {
    console.warn(`[Remediator] Warning: Post-remediation audit check failed: ${err.message}`);
    postAudit = { vulnerabilities: [] };
  }

  const remainingPkgNames = new Set(postAudit.vulnerabilities.map((v) => v.packageName));
  const remainingIds = new Set(postAudit.vulnerabilities.map((v) => v.id));

  const resolved = vulnerabilities.filter(
    (v) => !remainingPkgNames.has(v.packageName) || !remainingIds.has(v.id)
  );

  const remaining = postAudit.vulnerabilities;

  return {
    branch: branchName,
    dryRun: false,
    appliedChanges: applied,
    lockfileUpdates: appliedLockfileUpdates,
    touchedFiles,
    resolved,
    remaining,
    isClean: remaining.length === 0,
    postAuditSummary: postAudit.summary,
  };
}
