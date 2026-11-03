import path from 'node:path';
import fs from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import semver from 'semver';
import { collectNpmAudit } from '../collectors/npm-audit.js';
import { findWorkspacePackageJsons, getArboristClass } from './dependency-graph.js';
import { reconcilePackageRisk, isCompatibleUpgrade } from './remediation-policy.js';

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
          let prev = null;
          if (change.workspaceScope) {
            rootEntry.pkgJson.overrides[change.workspaceScope] =
              rootEntry.pkgJson.overrides[change.workspaceScope] || {};
            prev = rootEntry.pkgJson.overrides[change.workspaceScope][pkgName] || null;
            rootEntry.pkgJson.overrides[change.workspaceScope][pkgName] = to;
          } else if (change.parentPackage) {
            rootEntry.pkgJson.overrides[change.parentPackage] =
              rootEntry.pkgJson.overrides[change.parentPackage] || {};
            prev = rootEntry.pkgJson.overrides[change.parentPackage][pkgName] || null;
            rootEntry.pkgJson.overrides[change.parentPackage][pkgName] = to;
          } else {
            prev = rootEntry.pkgJson.overrides[pkgName] || null;
            rootEntry.pkgJson.overrides[pkgName] = to;
          }
          rootEntry.modified = true;
          applied.push({
            package: pkgName,
            section: 'overrides',
            workspaceScope: change.workspaceScope || null,
            parentPackage: change.parentPackage || null,
            from: prev,
            to,
            packageJsonPath: 'package.json',
            isSemVerMajor: Boolean(change.isSemVerMajor),
            isBreaking: Boolean(change.isBreaking),
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
          isSemVerMajor: Boolean(change.isSemVerMajor),
          isBreaking: Boolean(change.isBreaking),
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
            isSemVerMajor: Boolean(change.isSemVerMajor),
            isBreaking: Boolean(change.isBreaking),
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
            isSemVerMajor: Boolean(change.isSemVerMajor),
            isBreaking: Boolean(change.isBreaking),
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

async function runNpm(worktreeDir, args) {
  const npmArgs = [...args, '--package-lock-only', '--ignore-scripts'];
  try {
    const { stdout, stderr } = await execFileAsync('npm', npmArgs, {
      cwd: worktreeDir,
      maxBuffer: 20 * 1024 * 1024,
    });
    return { success: true, stdout, stderr };
  } catch (err) {
    throw new Error(`Failed to run "npm ${npmArgs.join(' ')}" in ${worktreeDir}: ${err.stderr || err.message}`);
  }
}

/** Rebuilds package-lock.json from the current package.json ranges and overrides. */
export async function syncLockfile(worktreeDir) {
  return await runNpm(worktreeDir, ['install']);
}

/** Re-resolves one package inside the lockfile; see formatLockfileUpdate. */
export async function updateLockfilePackage(worktreeDir, packageName) {
  return await runNpm(worktreeDir, ['update', packageName]);
}

const dependencySections = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
const dangerousKeys = new Set(['__proto__', 'constructor', 'prototype']);
const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const owns = (object, key) => Object.hasOwn(object, key);
const cleanVersion = (value) => typeof value === 'string' ? semver.valid(value.replace(/^[~^]/, '')) : null;

function packageName(value) {
  return typeof value === 'string' && !dangerousKeys.has(value)
    && /^(?:@[a-zA-Z0-9._~-]+\/)?[a-zA-Z0-9_~][a-zA-Z0-9._~-]*$/.test(value);
}

function overrideKey(value) {
  if (typeof value !== 'string' || dangerousKeys.has(value) || !value) return false;
  if (value === '.') return true;
  const separator = value.lastIndexOf('@');
  return packageName(value) || (separator > 0 && packageName(value.slice(0, separator))
    && Boolean(semver.validRange(value.slice(separator + 1))));
}

function inside(root, target) {
  const relative = path.relative(root, target);
  return relative === '' || (!path.isAbsolute(relative) && relative !== '..' && !relative.startsWith(`..${path.sep}`));
}

function containedFile(root, realRoot, file, required = true) {
  if (typeof file !== 'string' || !file || file.includes('\\') || path.posix.isAbsolute(file)
    || /^[a-zA-Z]:/.test(file) || file.split('/').some((part) => !part || part === '.' || part === '..')) {
    throw new Error(`Unsafe repository-relative file path: ${JSON.stringify(file)}`);
  }
  const absolute = path.resolve(root, file);
  if (!inside(root, absolute)) throw new Error(`File escapes worktree: ${file}`);
  // Resolve the parent even for a not-yet-created lockfile; dangling symlinks are not missing files.
  const parent = fs.realpathSync(path.dirname(absolute));
  if (!inside(realRoot, parent)) throw new Error(`File symlink escapes worktree: ${file}`);
  let stat;
  try {
    stat = fs.lstatSync(absolute);
  } catch (error) {
    if (!required && error.code === 'ENOENT') return absolute;
    throw error;
  }
  const real = fs.realpathSync(absolute);
  if (!inside(realRoot, real)) throw new Error(`File symlink escapes worktree: ${file}`);
  if (!(stat.isFile() || (stat.isSymbolicLink() && fs.statSync(real).isFile()))) {
    throw new Error(`Expected a regular file: ${file}`);
  }
  return absolute;
}

function stringList(value, label, validate = (entry) => typeof entry === 'string' && entry.length > 0) {
  if (!Array.isArray(value) || !value.every(validate)) throw new Error(`Invalid ${label}`);
}

function safeForFinding(version, finding) {
  if (!semver.valid(version)) return false;
  const range = finding.vulnerableVersionRange;
  if (range && (!semver.validRange(range) || semver.satisfies(version, range, { includePrerelease: true }))) return false;
  const fixes = [...(finding.patchedVersions || []), finding.targetSafeVersion]
    .map(cleanVersion).filter(Boolean).filter((fix) => semver.major(fix) === semver.major(version));
  if (fixes.length) return semver.gte(version, fixes.sort(semver.compare)[0]);
  // A different major's patch floor does not establish safety on this major.
  return Boolean(range && semver.validRange(range));
}

/**
 * Validate the complete saved intent and simulate it without filesystem writes.
 * Reuse requires the final values, not a mixture of pre- and post-execution values.
 */
export function validateBranchActions(worktreeDir, branchPlan, options = {}) {
  if (!isObject(branchPlan) || typeof branchPlan.branch !== 'string' || !branchPlan.branch
    || !['ready', 'no-op'].includes(branchPlan.status)
    || !Array.isArray(branchPlan.actions) || !Array.isArray(branchPlan.packages)
    || !Array.isArray(branchPlan.blockers) || branchPlan.blockers.length) {
    throw new Error('Invalid or blocked branch plan; generate a valid saved plan before execution');
  }
  const root = path.resolve(worktreeDir);
  const realRoot = fs.realpathSync(root);
  const manifests = new Map();
  const loadManifest = (file) => {
    if (path.posix.basename(file) !== 'package.json') throw new Error(`Action must target a package.json file: ${file}`);
    if (!manifests.has(file)) {
      const absolute = containedFile(root, realRoot, file);
      const real = fs.realpathSync(absolute);
      if ([...manifests.values()].some((entry) => entry.real === real)) {
        throw new Error(`Multiple manifest paths alias the same file: ${file}`);
      }
      const raw = fs.readFileSync(absolute, 'utf8');
      const json = JSON.parse(raw);
      if (!isObject(json)) throw new Error(`Invalid manifest object: ${file}`);
      manifests.set(file, { file, absolute, real, raw, json, modified: false });
    }
    return manifests.get(file);
  };
  loadManifest('package.json');
  containedFile(root, realRoot, 'package-lock.json', false);
  // npm prefers shrinkwrap over package-lock; it is not an executable plan target.
  if (fs.existsSync(path.join(root, 'npm-shrinkwrap.json'))) {
    throw new Error('npm-shrinkwrap.json is not supported by package-lock remediation plans');
  }
  const ready = new Map();
  for (const pkg of branchPlan.packages) {
    if (!isObject(pkg) || !packageName(pkg.packageName)
      || !['ready', 'resolved', 'manual-review', 'no-fix', 'not-installed', 'skipped'].includes(pkg.status)) {
      throw new Error('Invalid package entry in branch plan');
    }
    if (pkg.status !== 'ready') continue;
    if (ready.has(pkg.packageName)) throw new Error(`Duplicate ready package: ${pkg.packageName}`);
    if (!Array.isArray(pkg.findings) || !pkg.findings.length) throw new Error(`Missing findings for ${pkg.packageName}`);
    for (const finding of pkg.findings) {
      if (!isObject(finding) || typeof finding.id !== 'string' || !finding.id
        || (finding.vulnerableVersionRange != null && !semver.validRange(finding.vulnerableVersionRange))
        || (finding.patchedVersions != null && (!Array.isArray(finding.patchedVersions)
          || !finding.patchedVersions.every((version) => Boolean(cleanVersion(version)))))
        || (finding.targetSafeVersion != null && !cleanVersion(finding.targetSafeVersion))
        || (!finding.vulnerableVersionRange && !finding.targetSafeVersion && !finding.patchedVersions?.length)) {
        throw new Error(`Invalid or incomplete finding for ${pkg.packageName}`);
      }
    }
    ready.set(pkg.packageName, pkg);
  }
  if (branchPlan.status === 'no-op' && (branchPlan.actions.length || ready.size)) {
    throw new Error('No-op branch plan cannot contain ready packages or actions');
  }
  const keys = new Set();
  const motivated = new Set();
  const lockfileUpdates = [];
  for (const action of branchPlan.actions) {
    if (!isObject(action)) throw new Error('Invalid branch action');
    const fields = {
      'update-dependency': ['type', 'file', 'section', 'package', 'expectedRange', 'targetRange', 'packageNames', 'findingIds'],
      'set-override': ['type', 'file', 'package', 'scope', 'expectedValue', 'targetVersion', 'packageNames', 'findingIds'],
      'update-lockfile': ['type', 'package', 'packageNames', 'findingIds'],
    }[action.type];
    if (!fields || Object.keys(action).some((field) => !fields.includes(field))
      || fields.some((field) => !owns(action, field))) {
      throw new Error(`Invalid fields for action ${JSON.stringify(action.type)}`);
    }
    stringList(action.packageNames, 'action packageNames', packageName);
    stringList(action.findingIds, 'action findingIds');
    if (!action.packageNames.length || !action.findingIds.length
      || action.packageNames.some((name) => !ready.has(name))) {
      throw new Error('Actions must identify motivating ready packages and findings');
    }
    const knownFindings = new Set(action.packageNames.flatMap((name) => ready.get(name).findings.map((finding) => finding.id)));
    if (action.findingIds.some((id) => !knownFindings.has(id))) throw new Error('Action references an unknown finding');
    for (const name of action.packageNames) motivated.add(name);
    if (action.type === 'update-lockfile') {
      if (!packageName(action.package)) throw new Error('Invalid lockfile update package');
      const key = `lockfile:${action.package}`;
      if (keys.has(key)) throw new Error(`Duplicate action: ${key}`);
      keys.add(key);
      lockfileUpdates.push(action.package);
      continue;
    }
    if (typeof action.file !== 'string') throw new Error('Missing action manifest file');
    const entry = loadManifest(action.file);
    let container;
    let expected;
    let target;
    let key;
    if (action.type === 'update-dependency') {
      if (!dependencySections.includes(action.section) || !packageName(action.package)
        || typeof action.expectedRange !== 'string' || !semver.validRange(action.expectedRange)
        || typeof action.targetRange !== 'string' || !semver.validRange(action.targetRange)) {
        throw new Error('Invalid dependency action section, package, or range');
      }
      container = entry.json[action.section];
      if (!isObject(container) || !owns(container, action.package) || typeof container[action.package] !== 'string') {
        throw new Error(`Missing declaration: ${action.file} ${action.section}.${action.package}`);
      }
      expected = action.expectedRange;
      target = action.targetRange;
      key = JSON.stringify([entry.real, action.section, action.package]);
    } else {
      if (options.allowOverrides === false) throw new Error('Saved plan requires overrides, but overrides are disabled');
      if (action.file !== 'package.json' || !overrideKey(action.package)
        || !Array.isArray(action.scope) || !action.scope.every(overrideKey)
        || (action.expectedValue !== null && typeof action.expectedValue !== 'string')
        || !cleanVersion(action.targetVersion)) {
        throw new Error('Invalid override action scope, package, or version');
      }
      if (owns(entry.json, 'overrides') && !isObject(entry.json.overrides)) {
        throw new Error('Existing overrides must be an object');
      }
      container = entry.json.overrides ??= {};
      for (const scope of action.scope) {
        if (owns(container, scope) && !isObject(container[scope])) {
          throw new Error(`Override scope is not an object: ${scope}`);
        }
        if (!owns(container, scope)) container[scope] = {};
        container = container[scope];
      }
      expected = action.expectedValue;
      target = action.targetVersion;
      key = JSON.stringify([entry.real, 'overrides', ...action.scope, action.package]);
    }
    if (keys.has(key)) throw new Error(`Duplicate action: ${key}`);
    keys.add(key);
    const present = owns(container, action.package);
    const actual = present ? container[action.package] : null;
    const required = options.reuse ? target : expected;
    if (actual !== required || (required === null && present)) {
      throw new Error(`Manifest precondition conflict at ${action.file} ${action.section || 'overrides'}.${action.package}: expected ${JSON.stringify(required)}, found ${JSON.stringify(actual)}`);
    }
    if (!options.reuse && actual !== target) {
      container[action.package] = target;
      entry.modified = true;
    }
  }
  if (options.allowBreaking === false) {
    for (const pkg of ready.values()) {
      const risk = reconcilePackageRisk(pkg, branchPlan.actions.filter((action) => action.packageNames.includes(pkg.packageName)));
      if (risk.breaking !== false) throw new Error(`No-breaking policy rejects ${pkg.packageName}: ${risk.reasons.join(' ') || 'breaking or unknown compatibility'}`);
    }
  }
  for (const name of ready.keys()) {
    if (!motivated.has(name)) throw new Error(`Ready package has no executable branch action: ${name}`);
  }
  const rootManifest = manifests.get('package.json').json;
  for (const section of dependencySections) {
    for (const [name, range] of Object.entries(rootManifest[section] || {})) {
      const override = rootManifest.overrides?.[name];
      const spec = isObject(override) ? override['.'] : override;
      if (typeof spec === 'string' && !spec.startsWith('$') && spec !== range) {
        throw new Error(`Direct dependency override for ${name} must exactly match ${section} (${range}); npm would reject EOVERRIDE`);
      }
    }
  }
  return { manifests, lockfileUpdates };
}

/** Apply canonical saved actions, then prove the installed graph and audit are safe. */
export async function executeBranchPlan(worktreeDir, branchPlan, options = {}) {
  const { manifests, lockfileUpdates } = validateBranchActions(worktreeDir, branchPlan, options);
  const ready = branchPlan.packages.filter((pkg) => pkg.status === 'ready');
  const unresolved = branchPlan.packages.filter((pkg) => ['manual-review', 'no-fix', 'not-installed', 'skipped'].includes(pkg.status));
  const appliedChanges = branchPlan.actions.filter((action) => action.type !== 'update-lockfile').map((action) => ({
    package: action.package,
    section: action.type === 'set-override' ? 'overrides' : action.section,
    from: action.type === 'set-override' ? action.expectedValue : action.expectedRange,
    to: action.type === 'set-override' ? action.targetVersion : action.targetRange,
    packageJsonPath: action.file,
    ...(action.type === 'set-override' ? { scope: [...action.scope] } : {}),
  }));
  const result = {
    branch: branchPlan.branch,
    dryRun: Boolean(options.dryRun),
    verified: false,
    appliedChanges,
    lockfileUpdates,
    touchedFiles: [],
    resolved: [],
    remaining: [],
    unresolved: options.dryRun ? [...ready, ...unresolved] : unresolved,
    isClean: false,
    postAuditSummary: null,
  };
  if (options.dryRun) return result;
  let beforeInstances;
  if (options.allowBreaking === false && ready.length && !options.reuse) {
    const Arborist = getArboristClass();
    if (!Arborist) throw new Error('Arborist is required to establish non-breaking upgrade baselines');
    const beforeTree = await new Arborist({ path: worktreeDir, offline: true }).loadVirtual();
    beforeInstances = new Map(ready.map((pkg) => [pkg.packageName, new Map()]));
    for (const node of beforeTree.inventory.values()) {
      const instances = beforeInstances.get(node.package?.name || node.name);
      if (instances && !node.isProjectRoot) instances.set(node.location, node.package?.version || node.version);
    }
  }
  if (!options.reuse) {
    for (const entry of manifests.values()) {
      if (!entry.modified) continue;
      fs.writeFileSync(entry.absolute, JSON.stringify(entry.json, null, detectIndentation(entry.raw)) + '\n', 'utf8');
      result.touchedFiles.push(entry.file);
    }
    const lockfilePath = path.join(worktreeDir, 'package-lock.json');
    const previousLockfile = fs.existsSync(lockfilePath) ? fs.readFileSync(lockfilePath, 'utf8') : null;
    if (result.touchedFiles.length) await syncLockfile(worktreeDir);
    for (const name of lockfileUpdates) await updateLockfilePackage(worktreeDir, name);
    if (branchPlan.actions.length && fs.existsSync(lockfilePath)
      && fs.readFileSync(lockfilePath, 'utf8') !== previousLockfile) result.touchedFiles.push('package-lock.json');
  }
  let tree;
  if (ready.length) {
    const Arborist = getArboristClass();
    if (!Arborist) throw new Error('Arborist is required to verify planned package instances');
    tree = await new Arborist({ path: worktreeDir, offline: true }).loadVirtual();
    if (!tree?.inventory) throw new Error('Failed to load the virtual dependency graph for verification');
  }
  const installed = new Map(ready.map((pkg) => [pkg.packageName, []]));
  for (const node of tree?.inventory.values() || []) {
    const nodes = installed.get(node.package?.name || node.name);
    if (nodes && !node.isProjectRoot) nodes.push(node);
  }
  const resolved = [];
  for (const pkg of ready) {
    const nodes = installed.get(pkg.packageName);
    if (!nodes.length) throw new Error(`Verification failed: planned package ${pkg.packageName} is absent from the virtual dependency graph`);
    for (const node of nodes) {
      const version = node.package?.version || node.version;
      if (!pkg.findings.every((finding) => safeForFinding(version, finding))) {
        throw new Error(`Verification failed: ${pkg.packageName}@${version || 'unknown'} at ${node.location} remains vulnerable or lacks a safe patched major line`);
      }
      if (options.allowBreaking === false) {
        const instances = beforeInstances?.get(pkg.packageName);
        const locationBaseline = instances?.get(node.location);
        const before = locationBaseline ? [locationBaseline] : instances ? [...instances.values()]
          : pkg.installedVersions?.length ? pkg.installedVersions : String(pkg.currentVersion || '').split(',').map((value) => value.trim());
        // A newly hoisted instance has no exact location baseline: do not guess which major it replaced.
        const compatible = before.length > 0 && (instances && !locationBaseline
          ? before.every((baseline) => isCompatibleUpgrade(baseline, version))
          : before.some((baseline) => isCompatibleUpgrade(baseline, version)));
        if (!compatible) {
          throw new Error(`No-breaking verification failed: ${pkg.packageName}@${version || 'unknown'} crosses its scanned compatible version line; refusing to publish.`);
        }
      }
    }
    resolved.push({ ...pkg, installedVersions: [...new Set(nodes.map((node) => node.package?.version || node.version))].sort(semver.compare) });
  }
  const postAudit = await collectNpmAudit(worktreeDir, branchPlan.branch, {
    githubToken: options.githubToken,
    githubApiUrl: options.githubApiUrl,
    ...(tree ? { arboristTree: tree } : {}),
  });
  // Advisory IDs change between npm, GHSA and CVE; package-level audit evidence wins.
  for (const pkg of ready) {
    if (postAudit.vulnerabilities.some((finding) => finding.packageName === pkg.packageName)) {
      throw new Error(`Verification failed: npm audit still reports planned package ${pkg.packageName} as vulnerable`);
    }
  }
  return {
    ...result,
    verified: true,
    resolved,
    remaining: postAudit.vulnerabilities,
    isClean: postAudit.vulnerabilities.length === 0 && unresolved.length === 0,
    postAuditSummary: postAudit.summary,
  };
}
