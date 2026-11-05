import semver from 'semver';
import { extractCveId, extractGhsaId } from '../collectors/advisories.js';

const severityRank = { critical: 5, high: 4, moderate: 3, medium: 3, low: 2, info: 1, none: 0 };
const unique = (values) => [...new Set(values.filter((value) => value !== null && value !== undefined && value !== ''))];

function normalizeRange(value) {
  if (typeof value !== 'string' || !value.trim()) return null;
  const normalized = value.trim().replace(/,\s*(?=[<>=~^])/g, ' ');
  return semver.validRange(normalized) || normalized;
}

function cleanVersion(value) {
  if (typeof value !== 'string') return null;
  return semver.valid(value) || value.trim() || null;
}

function deduplicateConstraints(constraints) {
  const patchedRanges = new Set(constraints.filter((item) => semver.valid(item.firstPatchedVersion))
    .map((item) => item.vulnerableRange));
  return [...new Map(constraints.map((item) => [JSON.stringify(item), item])).values()]
    .filter((item) => item.firstPatchedVersion !== null || !patchedRanges.has(item.vulnerableRange))
    .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
}

function constraintsFor(advisory, row) {
  const affected = Array.isArray(advisory.affectedVersions) && advisory.affectedVersions.length
    ? advisory.affectedVersions : (Array.isArray(row.affectedVersions) && advisory === row ? row.affectedVersions : null);
  const constraints = [];
  if (affected) {
    for (const item of affected) {
      if (!item || typeof item !== 'object') continue;
      const vulnerableRange = normalizeRange(item.vulnerableRange ?? item.vulnerableVersionRange);
      const firstPatchedVersion = cleanVersion(item.firstPatchedVersion ?? item.first_patched_version);
      if (vulnerableRange || firstPatchedVersion) constraints.push({ vulnerableRange, firstPatchedVersion });
    }
  } else {
    const vulnerableRange = normalizeRange(advisory.vulnerableVersionRange ?? (advisory === row ? row.vulnerableVersionRange : null));
    const floors = unique([
      ...(Array.isArray(advisory.patchedVersions) ? advisory.patchedVersions : []),
      ...(Array.isArray(advisory.targetSafeVersions) ? advisory.targetSafeVersions : []),
      advisory.targetSafeVersion,
      advisory.firstPatchedVersion,
    ]).map(cleanVersion).filter(Boolean);
    if (floors.length) {
      for (const floor of floors) constraints.push({ vulnerableRange, firstPatchedVersion: floor });
    } else if (vulnerableRange) constraints.push({ vulnerableRange, firstPatchedVersion: null });
  }

  const byConstraint = new Map();
  for (const constraint of constraints) {
    const floor = constraint.firstPatchedVersion;
    const floorLine = semver.valid(floor) ? `${semver.major(floor)}.${semver.minor(floor)}` : floor || '';
    const key = JSON.stringify([constraint.vulnerableRange || '', floorLine]);
    const prior = byConstraint.get(key);
    if (!prior || (floor && semver.valid(floor) && semver.valid(prior.firstPatchedVersion) && semver.gt(floor, prior.firstPatchedVersion))) {
      byConstraint.set(key, constraint);
    }
  }
  return deduplicateConstraints([...byConstraint.values()]);
}

function reference(source, id, url) {
  const cleanId = source === 'jira' ? (typeof id === 'string' ? id : null)
    : source === 'dependabot' ? (id === null || id === undefined ? null : String(id))
      : extractGhsaId(id) || extractCveId(id) || (typeof id === 'string' ? id : null);
  if (!cleanId && !url) return null;
  return { source, id: cleanId, url: typeof url === 'string' && url ? url : null };
}

function referencesFor(row, advisory) {
  const refs = [];
  const add = (source, id, url) => {
    const value = reference(source, id, url);
    if (value) refs.push(value);
  };
  const sources = row.sources || {};
  const npm = sources.npmAudit;
  if (npm) {
    const npmId = npm.advisoryId || npm.id || advisory.id || row.id;
    add('npm-audit', npmId, npm.url);
    for (const url of npm.urls || []) add('npm-audit', npmId, url);
    for (const item of npm.advisories || []) add('npm-audit', item.advisoryId || item.id || npmId, item.url);
  }
  for (const ticket of [sources.jira, ...(sources.jiraTickets || [])].filter(Boolean)) {
    const id = ticket.ticketKey || ticket.key || null;
    add('jira', id, ticket.url || ticket.advisoryUrl);
    for (const url of ticket.remoteLinks || []) add('jira', id, url);
  }
  for (const alert of [sources.dependabot, ...(sources.dependabotAlerts || [])].filter(Boolean)) {
    const id = alert.alertNumber ?? alert.number ?? alert.ghsaId ?? alert.cve ?? null;
    add('dependabot', id, alert.url || alert.htmlUrl);
  }
  const advisoryId = advisory.id || advisory.ghsaId || advisory.cve || row.id || row.cve;
  const advisoryUrl = advisory.url || row.url;
  if (advisoryUrl || extractGhsaId(advisoryId) || extractCveId(advisoryId)) add('advisory', advisoryId, advisoryUrl);
  for (const url of advisory.references || []) add('advisory', advisoryId, url);
  return [...new Map(refs.map((item) => [JSON.stringify(item), item])).values()]
    .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
}

function identityFor(advisory, references, packageName, index) {
  const ghsa = extractGhsaId(advisory.id) || extractGhsaId(advisory.ghsaId) || extractGhsaId(advisory.url)
    || references.map((item) => extractGhsaId(item.id) || extractGhsaId(item.url)).find(Boolean);
  if (ghsa) return ghsa;
  const cve = extractCveId(advisory.id) || extractCveId(advisory.cve) || extractCveId(advisory.url)
    || references.map((item) => extractCveId(item.id) || extractCveId(item.url)).find(Boolean);
  if (cve) return cve;
  const collector = references.find((item) => item.source !== 'advisory' && item.id)?.id;
  return String(collector || advisory.id || `${packageName}:finding-${index + 1}`).toUpperCase();
}

function makeFinding(row, advisory, packageName, index) {
  const references = referencesFor(row, advisory);
  const cves = unique([
    advisory.cve,
    ...(Array.isArray(advisory.cves) ? advisory.cves : []),
    ...((advisory === row || !row.advisories?.length) ? [row.cve, ...(row.cves || [])] : []),
  ]).map((value) => extractCveId(value)).filter(Boolean).sort();
  const id = identityFor(advisory, references, packageName, index);
  const title = advisory.title || row.title || `${packageName} vulnerability`;
  const severity = advisory.severity || row.severity || 'unknown';
  return {
    id,
    cves,
    title,
    severity,
    url: advisory.url || row.url || null,
    constraints: constraintsFor(advisory, row),
    references,
  };
}

function mergeFinding(target, next) {
  target.cves = unique([...target.cves, ...next.cves]).sort();
  target.references = [...new Map([...target.references, ...next.references].map((item) => [JSON.stringify(item), item])).values()]
    .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  if ((severityRank[next.severity.toLowerCase()] || 0) > (severityRank[target.severity.toLowerCase()] || 0)) target.severity = next.severity;
  if (!target.url && next.url) target.url = next.url;
  if ((!target.title || target.title.endsWith(' vulnerability')) && next.title) target.title = next.title;
  target.constraints = deduplicateConstraints([...target.constraints, ...next.constraints]);
}

function aggregateAddsCoverage(aggregate, children) {
  const range = normalizeRange(aggregate);
  if (!range || !semver.validRange(range)) return true;
  const childRanges = children.flatMap((finding) => finding.constraints.map((item) => item.vulnerableRange).filter((value) => value && semver.validRange(value)));
  if (!childRanges.length) return true;
  const union = childRanges.join(' || ');
  return !(typeof semver.subset === 'function' && semver.subset(range, union));
}

export function normalizePlanFindings(rows, packageName) {
  const byId = new Map();
  for (const [rowIndex, row] of rows.entries()) {
    if (Array.isArray(row.findings)) {
      for (const finding of row.findings) {
        const prior = byId.get(finding.id);
        const copy = structuredClone(finding);
        if (prior) mergeFinding(prior, copy);
        else byId.set(finding.id, copy);
      }
      continue;
    }
    const children = Array.isArray(row.advisories) && row.advisories.length ? row.advisories : [row];
    for (const [index, advisory] of children.entries()) {
      const finding = makeFinding(row, advisory, packageName, rowIndex + index);
      const prior = byId.get(finding.id);
      if (prior) mergeFinding(prior, finding);
      else byId.set(finding.id, finding);
    }
    if (children.length && row.vulnerableVersionRange) {
      const childFindings = children.map((advisory, index) => makeFinding(row, advisory, packageName, rowIndex + index));
      if (aggregateAddsCoverage(row.vulnerableVersionRange, childFindings)) {
        const aggregate = makeFinding({ ...row, advisories: null }, { ...row, id: `${packageName}:aggregate:${row.id || rowIndex}` }, packageName, rowIndex);
        aggregate.id = `${packageName}:aggregate:${row.id || rowIndex}`;
        const prior = byId.get(aggregate.id);
        if (prior) mergeFinding(prior, aggregate);
        else byId.set(aggregate.id, aggregate);
      } else {
        const aggregateRefs = referencesFor(row, row);
        for (const finding of childFindings) {
          const prior = byId.get(finding.id);
          if (prior) prior.references = [...new Map([...prior.references, ...aggregateRefs].map((item) => [JSON.stringify(item), item])).values()]
            .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
        }
      }
    }
  }
  return [...byId.values()].sort((a, b) => a.id.localeCompare(b.id));
}

export function isVersionSafe(version, findings) {
  if (!semver.valid(version) || !Array.isArray(findings) || !findings.length) return null;
  let unknown = false;
  for (const finding of findings) {
    const constraints = Array.isArray(finding?.constraints) ? finding.constraints : [];
    if (!constraints.length) { unknown = true; continue; }
    for (const constraint of constraints) {
      const range = constraint.vulnerableRange;
      const floor = constraint.firstPatchedVersion;
      const rangeKnown = Boolean(range && semver.validRange(range));
      if (range) {
        if (!rangeKnown) unknown = true;
        else if (semver.satisfies(version, range)) return false;
      }
      if (floor) {
        if (!semver.valid(floor)) { unknown = true; continue; }
        if (rangeKnown) continue;
        if (semver.major(version) === semver.major(floor) && semver.minor(version) === semver.minor(floor)) {
          if (semver.lt(version, floor)) return false;
        } else if (!rangeKnown) unknown = true;
      } else if (!rangeKnown) unknown = true;
    }
  }
  return unknown ? null : true;
}

export function selectLatestSafePatch(installedVersion, publishedVersions, findings) {
  const installed = semver.valid(installedVersion);
  if (!installed || !Array.isArray(publishedVersions)) return null;
  const candidates = publishedVersions.filter((version) => {
    const clean = semver.valid(version);
    return clean && !semver.prerelease(clean)
      && semver.major(clean) === semver.major(installed)
      && semver.minor(clean) === semver.minor(installed)
      && semver.gte(clean, installed)
      && isVersionSafe(clean, findings) === true;
  }).sort(semver.compare);
  return candidates.at(-1) || null;
}
