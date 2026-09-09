export function generateCommitMessage(branchName, remediationResult, options = {}) {
  const resolved = remediationResult.resolved || [];
  const appliedChanges = remediationResult.appliedChanges || [];
  const remaining = remediationResult.remaining || [];

  const count = resolved.length;
  const title = `fix(deps): remediate ${count} vulnerable ${count === 1 ? 'package' : 'packages'} on branch ${branchName}`;

  const bodyLines = [];
  bodyLines.push(title);
  bodyLines.push('');
  bodyLines.push('Automated security remediation applied based on aggregated audit findings.');
  bodyLines.push('');

  if (resolved.length > 0) {
    bodyLines.push('### Resolved Packages & Security Advisories:');
    for (const v of resolved) {
      const cveList = v.cves && v.cves.length > 0 ? v.cves.join(', ') : (v.cve || '');
      const cveStr = cveList ? ` (${cveList})` : '';
      const safeVerStr = v.targetSafeVersion ? ` -> ${v.targetSafeVersion}` : '';
      bodyLines.push(`- [${v.severity?.toUpperCase() || 'HIGH'}] ${v.packageName} (${v.currentVersion || 'installed'}${safeVerStr})${cveStr}`);

      if (v.title) {
        bodyLines.push(`  - Title: ${v.title}`);
      }
      if (v.url) {
        bodyLines.push(`  - Advisory: ${v.url}`);
      }

      // Format Jira tickets
      if (v.sources?.jiraTickets && v.sources.jiraTickets.length > 0) {
        const jiraStr = v.sources.jiraTickets.map((j) => `${j.ticketKey} (${j.url})`).join(', ');
        bodyLines.push(`  - Jira: ${jiraStr}`);
      } else if (v.sources?.jira?.ticketKey) {
        bodyLines.push(`  - Jira: ${v.sources.jira.ticketKey} (${v.sources.jira.url})`);
      }

      // Format Dependabot alerts
      if (v.sources?.dependabotAlerts && v.sources.dependabotAlerts.length > 0) {
        const depStr = v.sources.dependabotAlerts.map((d) => `#${d.alertNumber} (${d.url})`).join(', ');
        bodyLines.push(`  - Dependabot: ${depStr}`);
      } else if (v.sources?.dependabot?.alertNumber) {
        bodyLines.push(`  - Dependabot: #${v.sources.dependabot.alertNumber} (${v.sources.dependabot.url})`);
      }

      if (v.dependencyPaths && v.dependencyPaths.length > 0) {
        bodyLines.push(`  - Chain: ${v.dependencyPaths[0]}`);
      }
    }
    bodyLines.push('');
  }

  if (appliedChanges.length > 0) {
    bodyLines.push('### Changes Applied:');
    for (const chg of appliedChanges) {
      if (chg.section === 'overrides') {
        bodyLines.push(`- Added override: "${chg.package}": "${chg.to}"`);
      } else {
        bodyLines.push(`- Updated ${chg.package} ${chg.from || 'none'} -> ${chg.to} in ${chg.section || 'dependencies'}`);
      }
    }
    bodyLines.push('- Synchronized package-lock.json');
    bodyLines.push('');
  }

  if (remaining.length === 0) {
    bodyLines.push('Verification: Post-remediation npm audit scan reported 0 remaining vulnerabilities.');
  } else {
    bodyLines.push(`Verification: Post-remediation npm audit scan resolved ${count} package issues (${remaining.length} remaining).`);
  }

  return bodyLines.join('\n');
}
