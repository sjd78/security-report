import path from 'node:path';
import fs from 'node:fs';

export function generateMarkdownReport(report) {
  const lines = [];

  lines.push(`# 🛡️ Security Vulnerability & Remediation Report`);
  lines.push(``);
  lines.push(`**Repository:** \`${report.repository?.fullName || 'unknown'}\``);
  lines.push(`**Generated:** ${report.generatedAt}`);
  lines.push(`**Branches Scanned:** ${report.summary?.totalBranches || 0}`);
  lines.push(`**Total Vulnerabilities Identified:** ${report.summary?.totalVulnerabilities || 0}`);
  lines.push(``);

  // Cross-branch Summary Table
  lines.push(`## 📊 Cross-Branch Summary`);
  lines.push(``);
  lines.push(`| Branch | Critical | High | Moderate | Low | Total Issues |`);
  lines.push(`| :--- | :---: | :---: | :---: | :---: | :---: |`);

  for (const b of report.branches || []) {
    const s = b.summary || {};
    lines.push(
      `| **\`${b.branch}\`** | ${s.critical || 0} | ${s.high || 0} | ${s.moderate || 0} | ${s.low || 0} | **${(b.vulnerabilities || []).length}** |`
    );
  }
  lines.push(``);

  // Detailed branch sections
  for (const b of report.branches || []) {
    lines.push(`---`);
    lines.push(`## 🌿 Branch: \`${b.branch}\``);
    lines.push(``);

    if (!b.vulnerabilities || b.vulnerabilities.length === 0) {
      lines.push(`✅ **No vulnerabilities found on this branch.**`);
      lines.push(``);
      continue;
    }

    lines.push(`### Vulnerability Overview`);
    lines.push(``);
    lines.push(`| Package | Severity | Type | Range | Target Fix | Advisory / CVE |`);
    lines.push(`| :--- | :---: | :---: | :--- | :--- | :--- |`);

    for (const v of b.vulnerabilities) {
      const typeLabel = v.isDirect ? 'Direct' : 'Indirect';
      const cveOrId = v.cve || v.id;
      const link = v.url ? `[${cveOrId}](${v.url})` : `\`${cveOrId}\``;
      const targetFix = v.targetSafeVersion ? `\`${v.targetSafeVersion}\`` : '_No fix_';
      lines.push(
        `| **\`${v.packageName}\`** | **${v.severity.toUpperCase()}** | ${typeLabel} | \`${v.vulnerableVersionRange || 'unknown'}\` | ${targetFix} | ${link} |`
      );
    }
    lines.push(``);

    lines.push(`### Detailed Findings & Remediation Steps`);
    lines.push(``);

    for (const [idx, v] of b.vulnerabilities.entries()) {
      lines.push(`#### ${idx + 1}. \`${v.packageName}\` — ${v.severity.toUpperCase()}`);
      lines.push(``);
      lines.push(`- **Title:** ${v.title}`);
      if (v.cve) lines.push(`- **CVE:** \`${v.cve}\``);
      if (v.url) lines.push(`- **Advisory:** ${v.url}`);
      if (v.sources?.jira) {
        lines.push(`- **Jira Ticket:** [${v.sources.jira.ticketKey}](${v.sources.jira.url})`);
      }
      if (v.sources?.dependabot) {
        lines.push(`- **Dependabot Alert:** [#${v.sources.dependabot.alertNumber}](${v.sources.dependabot.url})`);
      }
      lines.push(`- **Dependency Type:** ${v.isDirect ? 'Direct Dependency' : 'Indirect (Transitive)'}`);
      lines.push(`- **Installed Version:** \`${v.currentVersion}\``);
      lines.push(`- **Vulnerable Range:** \`${v.vulnerableVersionRange || 'N/A'}\``);
      lines.push(`- **Target Safe Version:** \`${v.targetSafeVersion || 'N/A'}\``);
      lines.push(``);

      // Dependency Chain
      lines.push(`**Dependency Path:**`);
      lines.push(`\`\`\`text`);
      if (v.dependencyPaths && v.dependencyPaths.length > 0) {
        for (const p of v.dependencyPaths) {
          lines.push(p);
        }
      } else {
        lines.push(v.packageName);
      }
      lines.push(`\`\`\``);
      lines.push(``);

      // Remediation Plan
      const rem = v.remediation || {};
      lines.push(`**Remediation Plan (${rem.strategy || 'manual'}):**`);
      if (rem.packageJsonChanges && rem.packageJsonChanges.length > 0) {
        lines.push(`1. Update \`package.json\`:`);
        for (const chg of rem.packageJsonChanges) {
          if (chg.section === 'overrides') {
            lines.push(`   - Add to \`overrides\`: \`"${chg.package}": "${chg.to}"\``);
          } else {
            lines.push(`   - Bump \`${chg.package}\` from \`${chg.from || 'none'}\` to \`${chg.to}\` in \`${chg.section}\``);
          }
        }
      }
      if (rem.lockfileActions && rem.lockfileActions.length > 0) {
        lines.push(`2. Synchronize lockfile:`);
        for (const act of rem.lockfileActions) {
          lines.push(`   \`\`\`bash\n   ${act}\n   \`\`\``);
        }
      }
      lines.push(``);
    }
  }

  return lines.join('\n');
}

export function writeMarkdownReport(report, outputDir, filename = 'security-report.md') {
  fs.mkdirSync(outputDir, { recursive: true });
  const mdContent = generateMarkdownReport(report);
  const targetPath = path.resolve(outputDir, filename);
  fs.writeFileSync(targetPath, mdContent, 'utf8');
  return targetPath;
}
