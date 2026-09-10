import path from 'node:path';
import fs from 'node:fs';
import { sortVulnerabilities } from '../core/blender.js';

export function generateJsonReport(repository, branchReports, options = {}) {
  const sortedBranches = (branchReports || []).map((b) => ({
    ...b,
    vulnerabilities: [...(b.vulnerabilities || [])].sort(sortVulnerabilities),
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
