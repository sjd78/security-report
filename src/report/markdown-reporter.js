import path from 'node:path';
import fs from 'node:fs';
import { sortVulnerabilities } from '../core/blender.js';
import { formatLockfileUpdate } from '../collectors/npm-audit.js';
import { extractGhsaId } from '../collectors/advisories.js';

export function formatCves(v) {
  const cves = [];
  const seen = new Set();

  const addCve = (c) => {
    if (!c || typeof c !== 'string') return;
    const trimmed = c.trim();
    if (trimmed && !seen.has(trimmed)) {
      seen.add(trimmed);
      cves.push(trimmed);
    }
  };

  if (Array.isArray(v.cves)) {
    for (const c of v.cves) addCve(c);
  }
  if (v.cve) addCve(v.cve);

  if (Array.isArray(v.advisories)) {
    for (const adv of v.advisories) {
      if (adv.cve) addCve(adv.cve);
      if (Array.isArray(adv.cves)) {
        for (const c of adv.cves) addCve(c);
      }
    }
  }

  if (cves.length === 0 && v.id && typeof v.id === 'string' && v.id.startsWith('CVE-')) {
    addCve(v.id);
  }

  if (cves.length === 0) {
    return '_None_';
  }

  return cves.map((c) => (c.startsWith('`') ? c : `\`${c}\``)).join('<br>');
}

export function formatSources(v) {
  const sources = [];
  const seen = new Set();

  const addSource = (s) => {
    if (!s || typeof s !== 'string') return;
    const trimmed = s.trim();
    if (trimmed && !seen.has(trimmed)) {
      seen.add(trimmed);
      sources.push(trimmed);
    }
  };

  // 1. npm audit
  const hasExplicitNpmAudit = Boolean(v.sources?.npmAudit) || (Array.isArray(v.advisories) && v.advisories.some((a) => Boolean(a.sources?.npmAudit)));
  const hasOtherSources = Boolean(
    v.sources?.jira ||
    v.sources?.dependabot ||
    (v.sources?.jiraTickets && v.sources.jiraTickets.length > 0) ||
    (v.sources?.dependabotAlerts && v.sources.dependabotAlerts.length > 0)
  );

  if (hasExplicitNpmAudit || (!hasOtherSources && (!v.sources || Object.keys(v.sources).length === 0))) {
    const advisoryUrls = new Set();
    if (v.sources?.npmAudit?.url) advisoryUrls.add(v.sources.npmAudit.url);
    if (Array.isArray(v.sources?.npmAudit?.urls)) {
      for (const u of v.sources.npmAudit.urls) if (u) advisoryUrls.add(u);
    }
    if (Array.isArray(v.sources?.npmAudit?.advisories)) {
      for (const a of v.sources.npmAudit.advisories) if (a?.url) advisoryUrls.add(a.url);
    }
    if (Array.isArray(v.advisories)) {
      for (const a of v.advisories) {
        if (a?.url && (a.url.includes('github.com/advisories') || a.sources?.npmAudit)) {
          advisoryUrls.add(a.url);
        }
      }
    }
    if (v.url && v.url.includes('github.com/advisories')) {
      advisoryUrls.add(v.url);
    }

    const urlList = Array.from(advisoryUrls);
    if (urlList.length === 0) {
      addSource('npm audit');
    } else if (urlList.length === 1) {
      addSource(`[npm audit](${urlList[0]})`);
    } else {
      for (const u of urlList) {
        const ghsa = extractGhsaId(u);
        const label = ghsa ? `npm audit (${ghsa})` : 'npm audit';
        addSource(`[${label}](${u})`);
      }
    }
  }
  // 2. Jira ticket(s)
  if (v.sources?.jiraTickets && v.sources.jiraTickets.length > 0) {
    for (const jt of v.sources.jiraTickets) {
      if (jt?.ticketKey) {
        addSource(jt.url ? `[${jt.ticketKey}](${jt.url})` : jt.ticketKey);
      }
    }
  } else if (v.sources?.jira?.ticketKey) {
    const jt = v.sources.jira;
    addSource(jt.url ? `[${jt.ticketKey}](${jt.url})` : jt.ticketKey);
  }

  // 3. GitHub Dependabot alert(s)
  if (v.sources?.dependabotAlerts && v.sources.dependabotAlerts.length > 0) {
    for (const da of v.sources.dependabotAlerts) {
      if (da?.alertNumber) {
        addSource(da.url ? `[#${da.alertNumber}](${da.url})` : `#${da.alertNumber}`);
      }
    }
  } else if (v.sources?.dependabot?.alertNumber) {
    const da = v.sources.dependabot;
    addSource(da.url ? `[#${da.alertNumber}](${da.url})` : `#${da.alertNumber}`);
  }

  if (sources.length === 0) {
    return '_None_';
  }

  return sources.join('<br>');
}
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

export function formatCompactDependencyPaths(v) {
  const compactPaths = new Set();

  // 1. Add direct declarations
  if (v.workspaceDeclarations && v.workspaceDeclarations.length > 0) {
    for (const decl of v.workspaceDeclarations) {
      const pkgFile = decl.packageJsonPath || 'package.json';
      const sec = decl.section || 'dependencies';
      const range = decl.range ? `@${decl.range}` : '';
      compactPaths.add(`${pkgFile}/${sec}/${v.packageName}${range}`);
    }
  } else if (v.isDirect) {
    compactPaths.add(`package.json/dependencies/${v.packageName}`);
  }

  // 2. Parse transitive paths into <project package.json>/<section>/<direct package>/.../<transitive package>
  const directRootsMap = new Map();
  for (const root of v.directRoots || []) {
    directRootsMap.set(root.name, root);
  }

  for (const pathStr of v.dependencyPaths || []) {
    // Skip single-node direct declarations handled above
    if (pathStr.includes(' (dependencies) -> ') || pathStr.includes(' (devDependencies) -> ')) {
      continue;
    }

    const segments = pathStr.split(/\s*->\s*/).filter(Boolean);
    if (segments.length === 0) continue;

    if (segments.length === 1 && segments[0].startsWith(v.packageName)) {
      if (compactPaths.size === 0) {
        compactPaths.add(`package.json/dependencies/${segments[0]}`);
      }
      continue;
    }

    let pkgFile = 'package.json';
    let directRootPkg = null;
    const targetSegment = segments[segments.length - 1];

    const firstSeg = segments[0];
    const wsMatch = firstSeg.match(/\(([^/)]+\/package\.json)\)/);

    if (wsMatch) {
      pkgFile = wsMatch[1];
      if (segments.length > 1) {
        directRootPkg = segments[1].split('@')[0];
      }
    } else {
      directRootPkg = firstSeg.split('@')[0];
    }

    let section = 'dependencies';
    if (directRootPkg && directRootsMap.has(directRootPkg)) {
      const rootMeta = directRootsMap.get(directRootPkg);
      if (rootMeta.section) section = rootMeta.section;
      if (rootMeta.packageJsonPath && !wsMatch) pkgFile = rootMeta.packageJsonPath;
    }

    if (directRootPkg) {
      if (directRootPkg === v.packageName) {
        compactPaths.add(`${pkgFile}/${section}/${targetSegment}`);
      } else {
        compactPaths.add(`${pkgFile}/${section}/${directRootPkg}/.../${targetSegment}`);
      }
    } else {
      compactPaths.add(`${pkgFile}/${section}/.../${targetSegment}`);
    }
  }

  if (compactPaths.size === 0) {
    compactPaths.add(v.packageName);
  }

  return Array.from(compactPaths);
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

    const sortedVulns = [...(b.vulnerabilities || [])].sort(sortVulnerabilities);

    if (sortedVulns.length === 0) {
      lines.push(`✅ **No vulnerable packages found on this branch.**`);
      lines.push(``);
      continue;
    }

    lines.push(`### Package Vulnerability Overview`);
    lines.push(``);
    lines.push(`| Package | Severity | Type | Current Version | Target Fix | CVEs | Sources |`);
    lines.push(`| :--- | :---: | :---: | :--- | :--- | :--- | :--- |`);

    for (const v of sortedVulns) {
      const typeLabel = v.dependencyType || (v.isDirect && v.isIndirect ? 'Direct & Indirect' : (v.isDirect ? 'Direct' : 'Indirect (Transitive)'));
      const targetFix = v.targetSafeVersion ? `\`${v.targetSafeVersion}\`` : '_No fix_';
      const cves = formatCves(v);
      const sources = formatSources(v);
      lines.push(
        `| **\`${v.packageName}\`** | **${v.severity.toUpperCase()}** | ${typeLabel} | \`${v.currentVersion}\` | ${targetFix} | ${cves} | ${sources} |`
      );
    }
    lines.push(``);

    lines.push(`### Detailed Package Findings & Consolidated Remediation`);
    lines.push(``);

    for (const [idx, v] of sortedVulns.entries()) {
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

      // Compact Dependency Path
      const compactPaths = formatCompactDependencyPaths(v);
      lines.push(`**Dependency Path:**`);
      lines.push(`\`\`\`text`);
      for (const cp of compactPaths) {
        lines.push(cp);
      }
      lines.push(`\`\`\``);
      if (compactPaths.some((p) => p.includes('/.../'))) {
        lines.push(`> _Note: Compact path summary shown. To inspect full transitive tree, run \`npm ls ${v.packageName}\` or \`npm why ${v.packageName}\`._`);
      }
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

      if (rem.lockfileUpdates && rem.lockfileUpdates.length > 0) {
        lines.push(`2. Synchronize lockfile:`);
        for (const pkgName of rem.lockfileUpdates) {
          lines.push(`   \`\`\`bash\n   ${formatLockfileUpdate(pkgName)}\n   \`\`\``);
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
