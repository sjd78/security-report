import path from 'node:path';
import fs from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import semver from 'semver';
import { collectNpmAudit } from '../collectors/npm-audit.js';

const execFileAsync = promisify(execFile);

export function detectIndentation(jsonStr) {
  const match = jsonStr.match(/^[ \t]+(?=")/m);
  return match ? match[0] : '  ';
}

export function updatePackageJsonFile(worktreeDir, changes = [], options = {}) {
  const pkgPath = path.resolve(worktreeDir, 'package.json');
  if (!fs.existsSync(pkgPath)) {
    throw new Error(`package.json not found in ${worktreeDir}`);
  }

  const rawContent = fs.readFileSync(pkgPath, 'utf8');
  const indent = detectIndentation(rawContent);
  const pkgJson = JSON.parse(rawContent);
  const applied = [];

  for (const change of changes) {
    const { package: pkgName, section = 'dependencies', to, from } = change;
    if (!pkgName || !to) continue;

    if (section === 'overrides') {
      if (options.allowOverrides !== false) {
        pkgJson.overrides = pkgJson.overrides || {};
        const prev = pkgJson.overrides[pkgName] || null;
        pkgJson.overrides[pkgName] = to;
        applied.push({
          package: pkgName,
          section: 'overrides',
          from: prev,
          to,
        });
      }
      continue;
    }

    // Check specified section or search across all dep sections
    const depSections = [section, 'dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
    let targetSection = null;

    for (const sec of depSections) {
      if (pkgJson[sec] && pkgJson[sec][pkgName] !== undefined) {
        targetSection = sec;
        break;
      }
    }

    if (!targetSection) {
      // Default to dependencies if not found
      targetSection = section || 'dependencies';
      pkgJson[targetSection] = pkgJson[targetSection] || {};
    }

    const currentRange = pkgJson[targetSection][pkgName] || null;
    pkgJson[targetSection][pkgName] = to;

    applied.push({
      package: pkgName,
      section: targetSection,
      from: currentRange,
      to,
    });
  }

  // Write back formatted JSON
  fs.writeFileSync(pkgPath, JSON.stringify(pkgJson, null, indent) + '\n', 'utf8');
  return { applied, pkgJson };
}

export async function syncLockfile(worktreeDir, options = {}) {
  const npmArgs = ['install', '--package-lock-only'];

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
    // Retry with --legacy-peer-deps if peer dependency conflict occurred
    if (!options.legacyPeerDeps && (err.stderr?.includes('ERESOLVE') || err.stdout?.includes('ERESOLVE'))) {
      return await syncLockfile(worktreeDir, { ...options, legacyPeerDeps: true });
    }
    throw new Error(`Failed to update lockfile in ${worktreeDir}: ${err.stderr || err.message}`);
  }
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

  // Collect all package.json updates from the report
  const pendingChanges = [];
  const changesMap = new Map();

  for (const vuln of vulnerabilities) {
    const rem = vuln.remediation;
    if (!rem || !rem.packageJsonChanges) continue;

    for (const chg of rem.packageJsonChanges) {
      const key = `${chg.section || 'dependencies'}:${chg.package}`;
      // Deduplicate / keep the latest or highest target version
      if (!changesMap.has(key)) {
        changesMap.set(key, chg);
        pendingChanges.push(chg);
      } else {
        const existing = changesMap.get(key);
        // If clean semver, pick the higher version
        const cleanExisting = semver.clean(existing.to.replace(/^[~^]/, ''));
        const cleanNew = semver.clean(chg.to.replace(/^[~^]/, ''));
        if (cleanExisting && cleanNew && semver.gt(cleanNew, cleanExisting)) {
          changesMap.set(key, chg);
        }
      }
    }
  }

  if (options.dryRun) {
    return {
      branch: branchName,
      dryRun: true,
      appliedChanges: pendingChanges,
      resolved: vulnerabilities,
      remaining: [],
      isClean: true,
    };
  }

  // Step 2a: Update package.json
  const { applied } = updatePackageJsonFile(worktreeDir, pendingChanges, options);

  // Step 2b: Update package-lock.json
  await syncLockfile(worktreeDir, options);

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
    resolved,
    remaining,
    isClean: remaining.length === 0,
    postAuditSummary: postAudit.summary,
  };
}
