import path from 'node:path';
import fs from 'node:fs';
import { sortVulnerabilities } from '../core/blender.js';
import { sortInstalledVersions } from '../core/dependency-graph.js';

export function normalizeInstalledVersionDisplay(vulnerability) {
  const installedVersions = Array.isArray(vulnerability.installedVersions)
    ? sortInstalledVersions(vulnerability.installedVersions) : null;
  const versions = installedVersions?.length ? installedVersions
    : sortInstalledVersions(String(vulnerability.currentVersion || '').split(','));
  return {
    ...vulnerability,
    ...(installedVersions ? { installedVersions } : {}),
    ...(versions.length ? { currentVersion: versions.join(', ') } : {}),
  };
}

export function generateJsonReport(repository, branchReports, options = {}) {
  const sortedBranches = (branchReports || []).map((b) => ({
    ...b,
    vulnerabilities: (b.vulnerabilities || []).map(normalizeInstalledVersionDisplay).sort(sortVulnerabilities),
  }));

  const totalVulns = sortedBranches.reduce((acc, b) => acc + (b.vulnerabilities?.length || 0), 0);
  const report = {
    schemaVersion: '1.0.0',
    generatedAt: new Date().toISOString(),
    repository: {
      name: repository.name || 'unknown',
      org: repository.org || 'unknown',
      fullName: repository.fullName || `${repository.org}/${repository.name}`,
      path: repository.repoPath || repository.localPath || '',
      remoteUrl: repository.remoteUrl || null,
    },
    summary: {
      totalBranches: sortedBranches.length,
      totalVulnerabilities: totalVulns,
      branchesWithVulnerabilities: sortedBranches.filter((b) => (b.vulnerabilities?.length || 0) > 0).length,
    },
    branches: sortedBranches,
  };

  return report;
}

export function writeJsonReport(report, outputDir, filename = 'security-report.json') {
  fs.mkdirSync(outputDir, { recursive: true });
  const targetPath = path.resolve(outputDir, filename);
  fs.writeFileSync(targetPath, JSON.stringify(report, null, 2), 'utf8');
  return targetPath;
}
