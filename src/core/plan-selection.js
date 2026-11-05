import { reconcilePackageRisk } from './remediation-policy.js';

const fixTypes = new Set(['safe-fix', 'override-required', 'parent-upgrade', 'breaking-upgrade']);

function selector(value, name) {
  if (value === undefined) return null;
  if (typeof value !== 'string' && !Array.isArray(value)) {
    throw new Error(`${name} must be a comma-separated string or an array of names.`);
  }
  const entries = Array.isArray(value) ? value : [value];
  if (!entries.length || entries.some((entry) => typeof entry !== 'string')) {
    throw new Error(`${name} must contain at least one non-empty name.`);
  }
  const names = entries.flatMap((entry) => entry.split(',')).map((entry) => entry.trim());
  if (names.some((entry) => !entry)) throw new Error(`${name} must not contain empty names.`);
  return [...new Set(names)];
}

function branchSummary(branch) {
  const count = (status) => branch.packages.filter((pkg) => pkg.status === status).length;
  const prefix = branch.status === 'blocked' ? 'Execution blocked; '
    : branch.status === 'no-op' ? 'No executable actions selected; ' : '';
  return `${prefix}${count('ready')} package(s) selected for remediation, ${count('skipped')} skipped, ${count('manual-review')} require manual review, ${count('no-fix')} have no known fix, ${count('resolved')} are resolved, and ${count('not-installed')} are not installed.`;
}

/** Select whole package remediations without changing any approved action target. */
export function selectRemediationBranches(plan, config = {}) {
  const requestedBranches = selector(config.branches, 'branches');
  const requestedPackages = selector(config.packages, 'packages');
  const requestedTypes = selector(config.fixTypes, 'fixTypes');
  if (config.allowBreaking !== undefined && typeof config.allowBreaking !== 'boolean') {
    throw new Error('allowBreaking must be a boolean.');
  }
  const unknownTypes = requestedTypes?.filter((type) => !fixTypes.has(type)) || [];
  if (unknownTypes.length) throw new Error(`Unknown fixTypes: ${unknownTypes.join(', ')}.`);
  const unknownBranches = requestedBranches?.filter((name) => !plan.branches.some((branch) => branch.branch === name)) || [];
  if (unknownBranches.length) throw new Error(`Requested branches must exist in the saved remediation plan: ${unknownBranches.join(', ')}.`);
  const branches = plan.branches.filter((branch) => !requestedBranches || requestedBranches.includes(branch.branch));
  if (!branches.length) throw new Error('No branches selected from the remediation plan.');
  const knownPackages = new Set(branches.flatMap((branch) => branch.packages.map((pkg) => pkg.packageName)));
  const unknownPackages = requestedPackages?.filter((name) => !knownPackages.has(name)) || [];
  if (unknownPackages.length) throw new Error(`Requested packages must exist in the selected branches of the saved remediation plan: ${unknownPackages.join(', ')}.`);

  return branches.map((source) => {
    const branch = structuredClone(source);
    const canonicalActions = branch.actions;
    const blocked = branch.status === 'blocked' || branch.blockers.length > 0;
    for (const pkg of branch.packages) {
      if (pkg.status !== 'ready') continue;
      const actions = canonicalActions.filter((action) => action.packageNames.includes(pkg.packageName));
      if (!actions.length && !blocked) {
        throw new Error(`Ready package ${pkg.packageName} on ${branch.branch} has no canonical remediation actions; generate a valid saved plan.`);
      }
      pkg.risk = reconcilePackageRisk(pkg, actions);
      const reasons = [];
      if (requestedPackages && !requestedPackages.includes(pkg.packageName)) {
        reasons.push('Excluded by package selection (--packages).');
      }
      if (requestedTypes && !requestedTypes.includes(pkg.risk.fixType)) {
        reasons.push(`Excluded by fix type selection (--fix-types): canonical remediation is ${pkg.risk.fixType}.`);
      }
      if (config.allowBreaking === false && pkg.risk.breaking !== false) {
        reasons.push(pkg.risk.breaking === true
          ? 'Excluded by --no-breaking: canonical remediation includes a breaking upgrade.'
          : 'Excluded by --no-breaking: canonical remediation compatibility is unknown.');
      }
      if (reasons.length) {
        pkg.status = 'skipped';
        pkg.reasons = [...new Set([...(pkg.reasons || []), ...reasons])];
      }
    }
    const selected = branch.packages.filter((pkg) => pkg.status === 'ready');
    const selectedNames = new Set(selected.map((pkg) => pkg.packageName));
    const selectedFindings = new Set(selected.flatMap((pkg) => pkg.findings.map((finding) => finding.id)));
    const selectedResolutions = new Set(selected.flatMap((pkg) => pkg.resolutions.map((resolution) => resolution.id)));
    const excluded = branch.packages.filter((pkg) => !selectedNames.has(pkg.packageName));
    const excludedFindings = new Set(excluded.flatMap((pkg) => pkg.findings.map((finding) => finding.id)));
    const excludedResolutions = new Set(excluded.flatMap((pkg) => pkg.resolutions.map((resolution) => resolution.id)));
    const pruneReferences = (references, selectedReferences, excludedReferences, kind) => references.filter((id) => {
      if (selectedReferences.has(id)) return true;
      if (excludedReferences.has(id)) return false;
      throw new Error(`Canonical action on ${branch.branch} has no matching selected ${kind} references.`);
    });
    const sharedPackages = new Set();
    branch.actions = canonicalActions.filter((action) => action.packageNames.some((name) => selectedNames.has(name))).map((action) => {
      for (const name of action.packageNames) if (!selectedNames.has(name)) sharedPackages.add(name);
      const packageNames = action.packageNames.filter((name) => selectedNames.has(name));
      const findingIds = pruneReferences(action.findingIds, selectedFindings, excludedFindings, 'finding');
      const resolutionIds = pruneReferences(action.resolutionIds, selectedResolutions, excludedResolutions, 'resolution');
      if (!findingIds.length) throw new Error(`Canonical action for ${packageNames.join(', ')} on ${branch.branch} has no matching selected finding references.`);
      if (!resolutionIds.length) throw new Error(`Canonical action for ${packageNames.join(', ')} on ${branch.branch} has no matching selected resolution references.`);
      return { ...action, packageNames, findingIds, resolutionIds };
    });
    for (const pkg of branch.packages) {
      if (pkg.status === 'skipped' && sharedPackages.has(pkg.packageName)) {
        pkg.reasons = [...new Set([...(pkg.reasons || []), 'A retained shared action may also affect this package; it remains skipped and is not counted as fixed.'])];
      }
    }
    branch.status = blocked ? 'blocked' : branch.actions.length ? 'ready' : 'no-op';
    branch.selection = {
      selectedPackages: selected.map((pkg) => pkg.packageName),
      skippedPackages: branch.packages.filter((pkg) => pkg.status === 'skipped')
        .map((pkg) => ({ packageName: pkg.packageName, reasons: [...(pkg.reasons || [])] })),
    };
    branch.summary = branchSummary(branch);
    return branch;
  });
}
