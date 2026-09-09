import path from 'node:path';
import fs from 'node:fs';

export function formatTicketLinks(v) {
  const links = [];

  if (v.sources?.jiraTickets && v.sources.jiraTickets.length > 0) {
    for (const jt of v.sources.jiraTickets) {
      links.push(`[${jt.ticketKey}](${jt.url})`);
    }
  } else if (v.sources?.jira?.ticketKey) {
    links.push(`[${v.sources.jira.ticketKey}](${v.sources.jira.url})`);
  }

  if (v.sources?.dependabotAlerts && v.sources.dependabotAlerts.length > 0) {
    for (const da of v.sources.dependabotAlerts) {
      links.push(`[#${da.alertNumber}](${da.url})`);
    }
  } else if (v.sources?.dependabot?.alertNumber) {
    links.push(`[#${v.sources.dependabot.alertNumber}](${v.sources.dependabot.url})`);
  }

  if (v.cves && v.cves.length > 0) {
    const cveStr = v.cves.join(', ');
    return links.length > 0 ? `\`${cveStr}\`<br/>${links.join(', ')}` : `\`${cveStr}\``;
  }

  if (v.cve || v.id) {
    const mainId = v.cve || v.id;
    const directLink = v.url ? `[${mainId}](${v.url})` : `\`${mainId}\``;
    return links.length > 0 ? `${directLink}<br/>${links.join(', ')}` : directLink;
  }

  return links.join(', ') || '_None_';
}

export function generateMarkdownReport(report) {
  const lines = [];

  lines.push(`# 🛡️ Security Vulnerability & Remediation Report`);
  lines.push(``);
  lines.push(`**Repository:** \`${report.repository?.fullName || 'unknown'}\``);
  lines.push(`**Generated:** ${report.generatedAt}`);
  lines.push(`**Branches Scanned:** ${report.summary?.totalBranches || 0}`);
  lines.push(`**Total Vulnerable Packages Identified:** ${report.summary?.totalVulnerabilities || 0}`);
  lines.push(``);

  // Cross-branch Summary Table
  lines.push(`## 📊 Cross-Branch Summary`);
  lines.push(``);
  lines.push(`| Branch | Critical | High | Moderate | Low | Total Vulnerable Packages |`);
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
      lines.push(`✅ **No vulnerable packages found on this branch.**`);
      lines.push(``);
      continue;
    }

    lines.push(`### Package Vulnerability Overview`);
    lines.push(``);
    lines.push(`| Package | Severity | Type | Current Version | Target Fix | CVEs / Jira / Dependabot |`);
    lines.push(`| :--- | :---: | :---: | :--- | :--- | :--- |`);

    for (const v of b.vulnerabilities) {
      const typeLabel = v.dependencyType || (v.isDirect && v.isIndirect ? 'Direct & Indirect' : (v.isDirect ? 'Direct' : 'Indirect (Transitive)'));
      const targetFix = v.targetSafeVersion ? `\`${v.targetSafeVersion}\`` : '_No fix_';
      const links = formatTicketLinks(v);
      lines.push(
        `| **\`${v.packageName}\`** | **${v.severity.toUpperCase()}** | ${typeLabel} | \`${v.currentVersion}\` | ${targetFix} | ${links} |`
      );
    }
    lines.push(``);

    lines.push(`### Detailed Package Findings & Consolidated Remediation`);
    lines.push(``);

    for (const [idx, v] of b.vulnerabilities.entries()) {
      lines.push(`#### ${idx + 1}. \`${v.packageName}\` — ${v.severity.toUpperCase()}`);
      lines.push(``);

      if (v.cves && v.cves.length > 0) {
        lines.push(`- **CVE Identifiers (${v.cves.length}):** ${v.cves.map((c) => `\`${c}\``).join(', ')}`);
      } else if (v.cve) {
        lines.push(`- **CVE:** \`${v.cve}\``);
      }

      if (v.sources?.jiraTickets && v.sources.jiraTickets.length > 0) {
        const jiraList = v.sources.jiraTickets.map((j) => `[${j.ticketKey}](${j.url}) (${j.status || 'Open'})`).join(', ');
        lines.push(`- **Jira Tickets:** ${jiraList}`);
      } else if (v.sources?.jira) {
        lines.push(`- **Jira Ticket:** [${v.sources.jira.ticketKey}](${v.sources.jira.url})`);
      }

      if (v.sources?.dependabotAlerts && v.sources.dependabotAlerts.length > 0) {
        const depList = v.sources.dependabotAlerts.map((d) => `[#${d.alertNumber}](${d.url})`).join(', ');
        lines.push(`- **Dependabot Alerts:** ${depList}`);
      } else if (v.sources?.dependabot) {
        lines.push(`- **Dependabot Alert:** [#${v.sources.dependabot.alertNumber}](${v.sources.dependabot.url})`);
      }

      const depTypeStr = v.dependencyType || (v.isDirect && v.isIndirect ? 'Direct & Indirect' : (v.isDirect ? 'Direct Dependency' : 'Indirect (Transitive)'));
      lines.push(`- **Dependency Type:** ${depTypeStr}`);
      if (v.workspaceDeclarations && v.workspaceDeclarations.length > 0) {
        lines.push(`- **Direct Package Declarations (${v.workspaceDeclarations.length}):**`);
        for (const decl of v.workspaceDeclarations) {
          const wsLabel = decl.isRoot ? '`package.json`' : `\`${decl.packageJsonPath}\` (${decl.workspace})`;
          lines.push(`  - ${wsLabel} [${decl.section}: \`${decl.range}\`]`);
        }
      }
      lines.push(``);
      // List of individual advisories for this package
      if (v.advisories && v.advisories.length > 0) {
        lines.push(`**Tracked Advisories & CVEs (${v.advisories.length}):**`);
        for (const adv of v.advisories) {
          const advTitle = adv.title || 'Security finding';
          const advCve = adv.cve ? `\`${adv.cve}\` — ` : '';
          const advLink = adv.url ? `([Advisory](${adv.url}))` : '';
          const advJira = adv.sources?.jira?.ticketKey ? `([Jira ${adv.sources.jira.ticketKey}](${adv.sources.jira.url}))` : '';
          lines.push(`- ${advCve}${advTitle} ${advLink} ${advJira}`);
        }
        lines.push(``);
      } else if (v.title) {
        lines.push(`- **Title:** ${v.title}`);
        if (v.url) lines.push(`- **Advisory:** ${v.url}`);
        lines.push(``);
      }
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

      // Consolidated Remediation Plan
      const rem = v.remediation || {};
      lines.push(`**Consolidated Remediation Plan (${rem.strategy || 'manual'}):**`);
      if (rem.note) {
        lines.push(`> _Note: ${rem.note}_`);
        lines.push(``);
      }

      if (rem.packageJsonChanges && rem.packageJsonChanges.length > 0) {
        lines.push(`1. Update \`package.json\` file(s):`);
        for (const chg of rem.packageJsonChanges) {
          const fileNote = chg.packageJsonPath ? ` (\`${chg.packageJsonPath}\`)` : '';
          if (chg.section === 'overrides') {
            lines.push(`   - Add to \`overrides\`: \`"${chg.package}": "${chg.to}"\`${fileNote}`);
          } else {
            lines.push(`   - Bump \`${chg.package}\` from \`${chg.from || 'none'}\` to \`${chg.to}\` in \`${chg.section}\`${fileNote}`);
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
