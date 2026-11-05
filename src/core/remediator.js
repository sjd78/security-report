import path from 'node:path';
import fs from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import semver from 'semver';
import { collectNpmAudit } from '../collectors/npm-audit.js';
import { isVersionSafe } from './advisory-evidence.js';
import { buildDependencyInventory, findWorkspacePackageJsons, getArboristClass, getPackageInstances } from './dependency-graph.js';
import { findOverrideConflicts } from './override-coverage.js';
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

function repositoryLocation(value, allowRoot = false) {
  return typeof value === 'string' && (allowRoot && value === '' || value !== '')
    && !value.includes('\\') && !path.posix.isAbsolute(value)
    && !/^[a-zA-Z]:/.test(value) && value.split('/').every((part) => part !== '.' && part !== '..');
}

function resolutionInstanceValid(instance) {
  if (!isObject(instance) || !repositoryLocation(instance.location) || !Array.isArray(instance.incoming)
    || !Array.isArray(instance.origins)) return false;
  for (const edge of instance.incoming) {
    if (!isObject(edge) || !repositoryLocation(edge.parentLocation, true)
      || (edge.parentName !== null && typeof edge.parentName !== 'string')
      || (edge.parentVersion !== null && !cleanVersion(edge.parentVersion))
      || (edge.requestedRange !== null && typeof edge.requestedRange !== 'string')
      || (edge.effectiveRange !== null && typeof edge.effectiveRange !== 'string')
      || (edge.type !== null && typeof edge.type !== 'string')) return false;
  }
  for (const origin of instance.origins) {
    if (!isObject(origin) || typeof origin.packageJsonPath !== 'string'
      || !repositoryLocation(origin.packageJsonPath) || path.posix.basename(origin.packageJsonPath) !== 'package.json'
      || !dependencySections.includes(origin.section)
      || (origin.workspace !== null && typeof origin.workspace !== 'string')
      || !Array.isArray(origin.chain) || !origin.chain.length) return false;
    for (const link of origin.chain) {
      if (!isObject(link) || typeof link.name !== 'string' || !cleanVersion(link.version)
        || !repositoryLocation(link.location) || (link.requiredRange !== null && typeof link.requiredRange !== 'string')) return false;
    }
  }
  return true;
}

function validFinding(finding) {
  const keys = ['id', 'cves', 'title', 'severity', 'url', 'constraints', 'references'];
  return isObject(finding) && Object.keys(finding).every((key) => keys.includes(key))
    && keys.every((key) => owns(finding, key))
    && typeof finding.id === 'string' && finding.id.length > 0
    && Array.isArray(finding.cves) && finding.cves.every((value) => typeof value === 'string')
    && typeof finding.title === 'string' && typeof finding.severity === 'string'
    && (finding.url === null || typeof finding.url === 'string')
    && Array.isArray(finding.constraints) && finding.constraints.every((constraint) => isObject(constraint)
      && Object.keys(constraint).every((key) => ['vulnerableRange', 'firstPatchedVersion'].includes(key))
      && owns(constraint, 'vulnerableRange') && owns(constraint, 'firstPatchedVersion')
      && (constraint.vulnerableRange === null || typeof constraint.vulnerableRange === 'string')
      && (constraint.firstPatchedVersion === null || typeof constraint.firstPatchedVersion === 'string')
      && (constraint.vulnerableRange !== null || constraint.firstPatchedVersion !== null))
    && Array.isArray(finding.references) && finding.references.every((reference) => isObject(reference)
      && Object.keys(reference).every((key) => ['source', 'id', 'url'].includes(key))
      && ['npm-audit', 'jira', 'dependabot', 'advisory'].includes(reference.source)
      && (reference.id === null || typeof reference.id === 'string')
      && (reference.url === null || typeof reference.url === 'string'));
}

function validResolution(resolution, packageName, findingIds) {
  const keys = ['id', 'installedVersion', 'line', 'status', 'targetVersion', 'strategy', 'findingIds', 'reasons', 'instances'];
  if (!isObject(resolution) || Object.keys(resolution).some((key) => !keys.includes(key))
    || keys.some((key) => !owns(resolution, key))
    || resolution.id !== `${packageName}@${resolution.installedVersion}`
    || !cleanVersion(resolution.installedVersion)
    || resolution.line !== `${semver.major(resolution.installedVersion)}.${semver.minor(resolution.installedVersion)}`
    || !['ready', 'resolved', 'manual-review', 'no-fix'].includes(resolution.status)
    || (resolution.targetVersion !== null && !cleanVersion(resolution.targetVersion))
    || !['bump-direct', 'bump-direct-and-lockfile', 'bump-direct-parent', 'lockfile-update', 'package-override', 'none'].includes(resolution.strategy)
    || !Array.isArray(resolution.findingIds) || !resolution.findingIds.every((id) => typeof id === 'string' && findingIds.has(id))
    || !Array.isArray(resolution.reasons) || !resolution.reasons.every((reason) => typeof reason === 'string')
    || !Array.isArray(resolution.instances) || !resolution.instances.every(resolutionInstanceValid)) return false;
  if (resolution.status === 'ready' && (!resolution.targetVersion || !resolution.instances.length)) return false;
  if (resolution.status === 'resolved' && resolution.targetVersion !== resolution.installedVersion) return false;
  return true;
}

function incomingIdentity(edges, reuse) {
  return edges.map((edge) => JSON.stringify(reuse
    ? [edge.parentName, edge.parentLocation, edge.type]
    : [edge.parentName, edge.parentVersion, edge.parentLocation, edge.requestedRange, edge.type])).sort();
}

function originIdentity(origins, reuse) {
  return origins.map((origin) => JSON.stringify(reuse
    ? {
      packageJsonPath: origin.packageJsonPath,
      section: origin.section,
      workspace: origin.workspace,
      chain: origin.chain.map(({ name, location }) => ({ name, location })),
    }
    : origin)).sort();
}

function verifyResolutionBaseline(pkg, actualInstances, reuse) {
  const actualByLocation = new Map(actualInstances.map((instance) => [instance.location, instance]));
  const plannedLocations = new Set();
  for (const resolution of pkg.resolutions) {
    for (const expected of resolution.instances) {
      if (plannedLocations.has(expected.location)) {
        throw new Error(`Resolution baseline contains duplicate instance location for ${pkg.packageName}: ${expected.location}`);
      }
      plannedLocations.add(expected.location);
      const actual = actualByLocation.get(expected.location);
      const version = reuse ? resolution.targetVersion : resolution.installedVersion;
      if (!actual || actual.installedVersion !== version
        || JSON.stringify(incomingIdentity(actual.incoming, reuse)) !== JSON.stringify(incomingIdentity(expected.incoming, reuse))
        || JSON.stringify(originIdentity(actual.origins, reuse)) !== JSON.stringify(originIdentity(expected.origins, reuse))) {
        throw new Error(`Resolution baseline differs from the current installed graph for ${pkg.packageName}@${resolution.installedVersion} at ${expected.location}`);
      }
    }
  }
  if (actualByLocation.size !== plannedLocations.size) {
    throw new Error(`Resolution baseline instance set differs from the current installed graph for ${pkg.packageName}`);
  }
}

function actionOverrideName(action) {
  if (action.package !== '.') return action.package.split('@').slice(0, action.package.startsWith('@') ? 2 : 1).join('@');
  const selector = action.scope.at(-1);
  if (typeof selector !== 'string') return null;
  const split = selector.lastIndexOf('@');
  return split > 0 ? selector.slice(0, split) : selector;
}

function overrideMatchesResolution(action, resolution, packageName) {
  const selector = `${packageName}@${resolution.line}.x`;
  return resolution.instances.some((instance) => instance.origins.some((origin) => {
    if (origin.chain.length < 2) return false;
    const parents = origin.chain.slice(0, -1).map((link) => `${link.name}@${link.version}`);
    if (action.package === '.') {
      return action.scope.at(-1) === selector
        && JSON.stringify(action.scope.slice(0, -1)) === JSON.stringify(parents);
    }
    return action.package === selector && JSON.stringify(action.scope) === JSON.stringify(parents);
  }));
}

function dependencyActionMatchesResolution(action, resolution, packageName) {
  return resolution.instances.some((instance) => instance.origins.some((origin) => {
    if (origin.packageJsonPath !== action.file || origin.section !== action.section || !origin.chain.length) return false;
    if (action.package === packageName) return origin.chain.length === 1 && origin.chain[0].name === packageName;
    return origin.chain.length > 1 && origin.chain[0].name === action.package;
  }));
}

/**
 * Validate the complete version-2 saved intent and simulate it without filesystem writes.
 * Reuse requires final manifest values; resolution references remain the scanned baseline.
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
      manifests.set(file, { file, absolute, real, raw, original: structuredClone(json), json, modified: false });
    }
    return manifests.get(file);
  };
  loadManifest('package.json');
  const lockfilePath = containedFile(root, realRoot, 'package-lock.json', false);
  let pkgLock = null;
  if (fs.existsSync(lockfilePath)) {
    pkgLock = JSON.parse(fs.readFileSync(lockfilePath, 'utf8'));
    if (!isObject(pkgLock)) throw new Error('Invalid package-lock.json snapshot');
  }
  if (fs.existsSync(path.join(root, 'npm-shrinkwrap.json'))) {
    throw new Error('npm-shrinkwrap.json is not supported by package-lock remediation plans');
  }
  const ready = new Map();
  const resolutionsById = new Map();
  const findingsByPackage = new Map();
  for (const pkg of branchPlan.packages) {
    const packageKeys = ['packageName', 'installedVersions', 'status', 'summary', 'reasons', 'resolutions', 'findings', 'risk'];
    if (!isObject(pkg) || Object.keys(pkg).some((key) => !packageKeys.includes(key))
      || packageKeys.some((key) => !owns(pkg, key)) || !packageName(pkg.packageName)
      || !['ready', 'resolved', 'manual-review', 'no-fix', 'not-installed', 'skipped'].includes(pkg.status)
      || !Array.isArray(pkg.installedVersions) || !pkg.installedVersions.every(cleanVersion)
      || !Array.isArray(pkg.reasons) || !pkg.reasons.every((reason) => typeof reason === 'string')
      || typeof pkg.summary !== 'string' || !Array.isArray(pkg.findings) || !pkg.findings.length
      || !pkg.findings.every(validFinding) || !Array.isArray(pkg.resolutions)
      || !isObject(pkg.risk) || !['safe-fix', 'override-required', 'parent-upgrade', 'breaking-upgrade', 'unknown'].includes(pkg.risk.fixType)
      || ![true, false, null].includes(pkg.risk.breaking) || !Array.isArray(pkg.risk.reasons)) {
      throw new Error('Invalid package entry in branch plan');
    }
    if (findingsByPackage.has(pkg.packageName)) throw new Error(`Duplicate package entry: ${pkg.packageName}`);
    const findingIds = new Set(pkg.findings.map((finding) => finding.id));
    if (findingIds.size !== pkg.findings.length) throw new Error(`Duplicate finding identity for ${pkg.packageName}`);
    findingsByPackage.set(pkg.packageName, findingIds);
    const seenResolutionIds = new Set();
    for (const resolution of pkg.resolutions) {
      if (!validResolution(resolution, pkg.packageName, findingIds) || seenResolutionIds.has(resolution.id)) {
        throw new Error(`Invalid or duplicate resolution for ${pkg.packageName}`);
      }
      seenResolutionIds.add(resolution.id);
      if (resolutionsById.has(resolution.id)) throw new Error(`Duplicate resolution identity: ${resolution.id}`);
      resolutionsById.set(resolution.id, { packageName: pkg.packageName, package: pkg, resolution });
      if (resolution.status === 'ready' || resolution.status === 'resolved') {
        if (isVersionSafe(resolution.targetVersion, pkg.findings) !== true) {
          throw new Error(`Resolution ${resolution.id} is not proven safe against every package finding`);
        }
      }
    }
    const resolutionVersions = [...new Set(pkg.resolutions.map((resolution) => resolution.installedVersion))].sort(semver.compare);
    if (pkg.status === 'not-installed') {
      if (pkg.installedVersions.length || pkg.resolutions.length) throw new Error(`Not-installed package ${pkg.packageName} has installed resolutions`);
    } else if (pkg.status !== 'skipped' && JSON.stringify(resolutionVersions) !== JSON.stringify([...pkg.installedVersions].sort(semver.compare))) {
      throw new Error(`Installed version summary differs from resolutions for ${pkg.packageName}`);
    }
    if (pkg.status === 'ready') {
      const states = pkg.resolutions.map((resolution) => resolution.status);
      if (!states.includes('ready') || states.some((status) => !['ready', 'resolved'].includes(status))) {
        throw new Error(`Ready package ${pkg.packageName} has uncovered or unresolved version lines`);
      }
      ready.set(pkg.packageName, pkg);
    }
  }
  if (branchPlan.status === 'no-op' && (branchPlan.actions.length || ready.size)) {
    throw new Error('No-op branch plan cannot contain ready packages or actions');
  }
  const actionKeys = new Set();
  const motivatedResolutions = new Set();
  const actionsByResolution = new Map();
  const lockfileUpdates = [];
  for (const action of branchPlan.actions) {
    if (!isObject(action)) throw new Error('Invalid branch action');
    const fields = {
      'update-dependency': ['type', 'file', 'section', 'package', 'expectedRange', 'targetRange', 'packageNames', 'findingIds', 'resolutionIds'],
      'set-override': ['type', 'file', 'package', 'scope', 'expectedValue', 'targetVersion', 'packageNames', 'findingIds', 'resolutionIds'],
      'update-lockfile': ['type', 'package', 'packageNames', 'findingIds', 'resolutionIds'],
    }[action.type];
    if (!fields || Object.keys(action).some((field) => !fields.includes(field))
      || fields.some((field) => !owns(action, field))) {
      throw new Error(`Invalid fields for action ${JSON.stringify(action.type)}`);
    }
    stringList(action.packageNames, 'action packageNames', packageName);
    stringList(action.findingIds, 'action findingIds');
    stringList(action.resolutionIds, 'action resolutionIds');
    if (!action.packageNames.length || !action.findingIds.length || !action.resolutionIds.length
      || new Set(action.packageNames).size !== action.packageNames.length
      || new Set(action.findingIds).size !== action.findingIds.length
      || new Set(action.resolutionIds).size !== action.resolutionIds.length
      || action.packageNames.some((name) => !ready.has(name))) {
      throw new Error('Actions must identify motivating ready packages, findings, and resolutions');
    }
    const linked = action.resolutionIds.map((id) => resolutionsById.get(id));
    if (linked.some((entry) => !entry || entry.resolution.status !== 'ready' || !action.packageNames.includes(entry.packageName))) {
      throw new Error('Action references an unknown, unready, or unrelated resolution');
    }
    const expectedPackages = [...new Set(linked.map((entry) => entry.packageName))].sort();
    if (JSON.stringify(expectedPackages) !== JSON.stringify([...action.packageNames].sort())) {
      throw new Error('Action packageNames do not match its resolution references');
    }
    const expectedFindingIds = [...new Set(linked.flatMap((entry) => entry.resolution.findingIds))].sort();
    if (JSON.stringify(expectedFindingIds) !== JSON.stringify([...action.findingIds].sort())) {
      throw new Error('Action findingIds do not match its resolution references');
    }
    for (const id of action.resolutionIds) {
      motivatedResolutions.add(id);
      if (!actionsByResolution.has(id)) actionsByResolution.set(id, []);
      actionsByResolution.get(id).push(action);
    }
    if (action.type === 'update-lockfile') {
      if (!packageName(action.package) || linked.some((entry) => entry.packageName !== action.package)) {
        throw new Error('Invalid lockfile update package or resolution');
      }
      const key = `lockfile:${action.package}`;
      if (actionKeys.has(key)) throw new Error(`Duplicate action: ${key}`);
      actionKeys.add(key);
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
      for (const { packageName: leaf, resolution } of linked) {
        if (!dependencyActionMatchesResolution(action, resolution, leaf)) {
          throw new Error(`Dependency action does not match a direct installed origin for ${resolution.id}`);
        }
        if (action.package === leaf && !semver.subset(action.targetRange, `~${resolution.targetVersion}`)) {
          throw new Error(`Dependency action target exceeds the approved patch line for ${resolution.id}`);
        }
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
        || !cleanVersion(action.targetVersion)
        || linked.some(({ packageName: leaf, resolution }) => actionOverrideName(action) !== leaf
          || action.targetVersion !== resolution.targetVersion
          || !overrideMatchesResolution(action, resolution, leaf))) {
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
    if (actionKeys.has(key)) throw new Error(`Duplicate action: ${key}`);
    actionKeys.add(key);
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
  for (const pkg of ready.values()) {
    for (const resolution of pkg.resolutions.filter((entry) => entry.status === 'ready')) {
      const actions = actionsByResolution.get(resolution.id) || [];
      if (!actions.length) throw new Error(`Ready resolution has no executable action: ${resolution.id}`);
      const dependencyActions = actions.filter((action) => action.type === 'update-dependency');
      const hasParentUpgrade = dependencyActions.some((action) => action.package !== pkg.packageName);
      const hasLeafBump = dependencyActions.some((action) => action.package === pkg.packageName);
      const hasLockfileUpdate = actions.some((action) => action.type === 'update-lockfile');
      const hasOverride = actions.some((action) => action.type === 'set-override');
      const expectedStrategy = hasOverride ? 'package-override'
        : hasParentUpgrade ? 'bump-direct-parent'
          : hasLeafBump && hasLockfileUpdate ? 'bump-direct-and-lockfile'
            : hasLeafBump ? 'bump-direct' : 'lockfile-update';
      if (resolution.strategy !== expectedStrategy) {
        throw new Error(`Resolution action types do not match the planned strategy for ${resolution.id}`);
      }
    }
  }
  const originalRoot = manifests.get('package.json').original;
  for (const pkg of ready.values()) {
    for (const resolution of pkg.resolutions) {
      for (const instance of resolution.instances) {
        for (const origin of instance.origins) loadManifest(origin.packageJsonPath);
      }
    }
  }
  const workspaceSnapshots = [...manifests.values()].map((entry) => ({
    relativePath: entry.file, pkgJson: entry.original, isRoot: entry.file === 'package.json',
  }));
  const inventory = pkgLock ? buildDependencyInventory({ pkgJson: originalRoot, pkgLock, workspaces: workspaceSnapshots }) : null;
  if (ready.size && !inventory) throw new Error('A package-lock.json snapshot is required to verify ready resolution origins');
  for (const pkg of ready.values()) {
    const actualInstances = getPackageInstances(pkg.packageName, { dependencyInventory: inventory });
    verifyResolutionBaseline(pkg, actualInstances, Boolean(options.reuse));
  }
  if (inventory && (originalRoot.overrides || branchPlan.actions.some((action) => action.type === 'set-override'))) {
    const conflicts = findOverrideConflicts(branchPlan.actions, inventory, originalRoot);
    if (conflicts.length) throw new Error(`Override coverage conflict: ${conflicts.join(' ')}`);
  }
  if (options.allowBreaking === false) {
    for (const pkg of ready.values()) {
      const actions = branchPlan.actions.filter((action) => action.packageNames.includes(pkg.packageName));
      const risk = reconcilePackageRisk(pkg, actions);
      if (risk.breaking !== false) throw new Error(`No-breaking policy rejects ${pkg.packageName}: ${risk.reasons.join(' ') || 'breaking or unknown compatibility'}`);
    }
  }
  return { manifests, lockfileUpdates, inventory };
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
    const approvedTargets = new Set(pkg.resolutions.filter((resolution) => ['ready', 'resolved'].includes(resolution.status))
      .map((resolution) => resolution.targetVersion));
    for (const node of nodes) {
      const version = node.package?.version || node.version;
      if (isVersionSafe(version, pkg.findings) !== true) {
        throw new Error(`Verification failed: ${pkg.packageName}@${version || 'unknown'} at ${node.location} remains vulnerable or lacks complete safe advisory evidence`);
      }
      if (options.allowBreaking === false) {
        const instances = beforeInstances?.get(pkg.packageName);
        const locationBaseline = instances?.get(node.location);
        const before = locationBaseline ? [locationBaseline] : instances ? [...instances.values()]
          : pkg.installedVersions || [];
        // A newly hoisted instance has no exact location baseline: do not guess which major it replaced.
        const compatible = before.length > 0 && (instances && !locationBaseline
          ? before.every((baseline) => isCompatibleUpgrade(baseline, version))
          : before.some((baseline) => isCompatibleUpgrade(baseline, version)));
        if (!compatible) {
          throw new Error(`No-breaking verification failed: ${pkg.packageName}@${version || 'unknown'} crosses its scanned compatible version line; refusing to publish.`);
        }
      }
      if (!approvedTargets.has(version)) {
        throw new Error(`Verification failed: ${pkg.packageName}@${version} at ${node.location} is outside the approved resolution targets (${[...approvedTargets].join(', ')})`);
      }
    }
    const installedVersions = new Set(nodes.map((node) => node.package?.version || node.version));
    for (const resolution of pkg.resolutions.filter((entry) => entry.status === 'ready')) {
      if (!installedVersions.has(resolution.targetVersion)) {
        throw new Error(`Verification failed: approved target ${resolution.targetVersion} for ${resolution.id} is absent from the installed dependency graph`);
      }
    }
    resolved.push({ ...pkg, installedVersions: [...installedVersions].sort(semver.compare) });
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
