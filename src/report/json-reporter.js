import path from 'node:path';
import fs from 'node:fs';

export function generateJsonReport(repository, branchReports, options = {}) {
  const totalVulns = branchReports.reduce((acc, b) => acc + (b.vulnerabilities?.length || 0), 0);
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
      totalBranches: branchReports.length,
      totalVulnerabilities: totalVulns,
      branchesWithVulnerabilities: branchReports.filter((b) => (b.vulnerabilities?.length || 0) > 0).length,
    },
    branches: branchReports,
  };

  return report;
}

export function writeJsonReport(report, outputDir, filename = 'security-report.json') {
  fs.mkdirSync(outputDir, { recursive: true });
  const targetPath = path.resolve(outputDir, filename);
  fs.writeFileSync(targetPath, JSON.stringify(report, null, 2), 'utf8');
  return targetPath;
}
