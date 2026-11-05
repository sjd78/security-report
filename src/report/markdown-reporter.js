import path from 'node:path';
import fs from 'node:fs';
import semver from 'semver';
import { sortVulnerabilities, isVulnerabilityResolved } from '../core/blender.js';
import { extractGhsaId } from '../collectors/advisories.js';
import { normalizeInstalledVersionDisplay } from './json-reporter.js';

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

export function formatStatus(v) {
  const resolved = v.status === 'resolved' || isVulnerabilityResolved(v);
  return resolved ? '✅ Resolved' : '⚠️ Open';
}

export function formatRemediationStatus(v) {
  if (v.status === 'resolved' || isVulnerabilityResolved(v)) {
    return '✅ Resolved';
  }

  const rem = v.remediation || {};
  const targetFix = formatTargetFix(v);
  const noFix = rem.strategy === 'none' || targetFix === '_No fix_';

  if (noFix) {
    return '❌ No fix';
  }

  const isBreaking = Boolean(rem.isBreaking || rem.isSemVerMajor || v.isBreaking || v.isSemVerMajor);
  const strategy = rem.strategy || '';

  if (strategy === 'package-override') {
    return '🛡️ Override required';
  }

  if (isBreaking) {
    return '⚠️ Breaking upgrade';
  }

  if (strategy === 'bump-direct-parent') {
    return '⬆️ Parent upgrade';
  }

  return '⚡ Safe fix';
}

export function formatFixStrategy(rem, v) {
  if (!rem || !rem.strategy || rem.strategy === 'none') {
    return 'none';
  }

  if (rem.strategyLabel) {
    return rem.strategyLabel;
  }

  const strategy = rem.strategy;

  if (strategy === 'lockfile-update') {
    const hasTransient = Array.isArray(rem.transientOverrides) && rem.transientOverrides.length > 0;
    const isTransitive = (v?.isIndirect && !v?.isDirect) || rem.directRoot || (!rem.workspaceDeclarations?.length);
    if (hasTransient || isTransitive) {
      return 'lockfile-update (transitive pin)';
    }
    return 'lockfile-update (direct)';
  }

  if (strategy === 'package-override') {
    const changes = rem.packageJsonChanges || [];
    if (changes.some((c) => c.workspaceScope)) {
      return 'package-override (workspace-scoped)';
    }
    if (changes.some((c) => c.parentPackage)) {
      return 'package-override (parent-scoped)';
    }
    return 'package-override (root override)';
  }

  if (strategy === 'bump-direct-and-lockfile') {
    return 'bump-direct-and-lockfile (direct + transitive pin)';
  }

  if (strategy === 'bump-direct-parent') {
    return 'bump-direct-parent';
  }

  if (strategy === 'bump-direct') {
    return 'bump-direct';
  }

  return strategy;
}

export function formatTargetFix(v, joiner = '<br>') {
  const versions = [];
  const seen = new Set();

  const addVer = (ver) => {
    if (!ver || typeof ver !== 'string') return;
    const trimmed = ver.trim();
    if (trimmed && !seen.has(trimmed)) {
      seen.add(trimmed);
      versions.push(trimmed);
    }
  };

  if (Array.isArray(v.affectedVersions)) {
    for (const interval of v.affectedVersions) addVer(interval.firstPatchedVersion);
  } else {
    if (Array.isArray(v.targetSafeVersions)) {
      for (const ver of v.targetSafeVersions) addVer(ver);
    }
    if (Array.isArray(v.patchedVersions)) {
      for (const ver of v.patchedVersions) addVer(ver);
    }
    if (Array.isArray(v.advisories)) {
      for (const adv of v.advisories) {
        if (Array.isArray(adv.patchedVersions)) {
          for (const ver of adv.patchedVersions) addVer(ver);
        }
        if (Array.isArray(adv.targetSafeVersions)) {
          for (const ver of adv.targetSafeVersions) addVer(ver);
        }
        if (adv.targetSafeVersion) addVer(adv.targetSafeVersion);
      }
    }
    if (v.targetSafeVersion) addVer(v.targetSafeVersion);
  }

  if (versions.length === 0) {
    return '_No fix_';
  }

  versions.sort((a, b) => {
    const cleanA = semver.clean(a) || a;
    const cleanB = semver.clean(b) || b;
    const vA = semver.valid(cleanA);
    const vB = semver.valid(cleanB);
    if (vA && vB) return semver.compare(vA, vB);
    return a.localeCompare(b);
  });

  return versions.map((ver) => (ver.startsWith('`') ? ver : `\`${ver}\``)).join(joiner);
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

  // 1. Jira ticket(s)
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

  // 2. GitHub Dependabot alert(s)
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

  // 3. npm audit
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

export function formatDirectDependencyPaths(v) {
  const directPaths = new Set();

  if (v.workspaceDeclarations && v.workspaceDeclarations.length > 0) {
    for (const decl of v.workspaceDeclarations) {
      const pkgFile = decl.packageJsonPath || 'package.json';
      const sec = decl.section || 'dependencies';
      const range = decl.range ? `@${decl.range}` : '';
      directPaths.add(`${pkgFile}/${sec}/${v.packageName}${range}`);
    }
  } else if (v.isDirect) {
    const pkgFile = 'package.json';
    const sec = v.section || 'dependencies';
    const range = v.range ? `@${v.range}` : '';
    directPaths.add(`${pkgFile}/${sec}/${v.packageName}${range}`);
  }

  return Array.from(directPaths).sort((a, b) => {
    const isRootA = a.startsWith('package.json');
    const isRootB = b.startsWith('package.json');
    if (isRootA && !isRootB) return -1;
    if (!isRootA && isRootB) return 1;
    return a.localeCompare(b);
  });
}

function parseDependencyPath(pathStr) {
  if (/\s\((?:dependencies|devDependencies|optionalDependencies|peerDependencies)\)\s*->/.test(pathStr)) return [];
  return pathStr.split(/\s*->\s*/).filter(Boolean).map((segment) => {
    if (segment === '[root]') return { name: '[root]', isRoot: true, packageJsonPath: 'package.json' };
    const workspace = segment.match(/^(.*?) \(([^)]+\/package\.json)\)$/);
    if (workspace) return { name: workspace[1], isWorkspace: true, packageJsonPath: workspace[2] };
    const match = segment.match(/^((?:@[^/\s]+\/)?[^@\s(]+)(?:@([^\s(]+))?(?: \(([^)]+)\))?$/);
    return match ? { name: match[1], version: match[2], requiredRange: match[3] } : { name: segment };
  });
}

function dependencyChainKey(chain) {
  const anchor = chain[0];
  const anchored = anchor?.isRoot || anchor?.isWorkspace || anchor?.isWorkspaceRoot;
  const manifest = anchor?.packageJsonPath || (anchor?.folderPath ? `${anchor.folderPath}/package.json` : 'package.json');
  return JSON.stringify([manifest, ...(anchored ? chain.slice(1) : chain).map((link) => [link.name, link.version])]);
}

export function formatTransitiveDependencyPaths(v) {
  const transitivePaths = new Set();
  const chains = v.dependencyChains || v.chains || [];
  const structuredPaths = new Set(chains.map(dependencyChainKey));
  const allChains = [
    ...chains,
    ...(v.dependencyPaths || []).map(parseDependencyPath).filter((chain) => !structuredPaths.has(dependencyChainKey(chain))),
  ];
  for (const chain of allChains) {
    if (chain.length < 2) continue;
    let anchorIndex = -1;
    for (let index = 0; index < chain.length - 1; index += 1) {
      if (chain[index].isRoot || chain[index].isWorkspace || chain[index].isWorkspaceRoot) anchorIndex = index;
    }
    const anchor = chain[anchorIndex];
    const directRoot = chain[anchorIndex + 1];
    const target = chain.at(-1);
    if (!directRoot?.name || directRoot === target) continue;
    const manifest = anchor?.packageJsonPath || (anchor?.folderPath ? `${anchor.folderPath}/package.json` : null)
      || (anchor?.isRoot ? 'package.json' : directRoot.packageJsonPath);
    const roots = (v.directRoots || []).filter((root) => root.name === directRoot.name
      && (!manifest || (root.packageJsonPath || 'package.json') === manifest)
      && (!root.installedVersion || !directRoot.version || root.installedVersion === directRoot.version)
      && (!root.location || !directRoot.location || root.location === directRoot.location));
    for (const root of roots.length ? roots : [null]) {
      const pkgFile = manifest || root?.packageJsonPath || 'package.json';
      const section = directRoot.type === 'dev' ? 'devDependencies'
        : directRoot.type === 'optional' ? 'optionalDependencies'
          : directRoot.type === 'peer' ? 'peerDependencies'
            : directRoot.type === 'prod' ? 'dependencies' : root?.section || 'dependencies';
      const targetSegment = `${target.name}@${target.version || 'unknown'}${target.requiredRange ? ` (${target.requiredRange})` : ''}`;
      transitivePaths.add(`${pkgFile}/${section}/${directRoot.name}/.../${targetSegment}`);
    }
  }

  return Array.from(transitivePaths).sort((a, b) => {
    const isRootA = a.startsWith('package.json');
    const isRootB = b.startsWith('package.json');
    if (isRootA && !isRootB) return -1;
    if (!isRootA && isRootB) return 1;

    const fileA = a.substring(0, a.indexOf('/'));
    const fileB = b.substring(0, b.indexOf('/'));
    if (fileA !== fileB) return fileA.localeCompare(fileB);

    const isDepA = a.includes('/dependencies/');
    const isDepB = b.includes('/dependencies/');
    if (isDepA && !isDepB) return -1;
    if (!isDepA && isDepB) return 1;

    return a.localeCompare(b);
  });
}

export function formatCompactDependencyPaths(v, includeDirect = true) {
  if (!includeDirect) {
    return formatTransitiveDependencyPaths(v);
  }
  const all = new Set([
    ...formatDirectDependencyPaths(v),
    ...formatTransitiveDependencyPaths(v),
  ]);
  if (all.size === 0) {
    all.add(v.packageName);
  }
  return Array.from(all);
}

export function generateMarkdownReport(report) {
  const lines = [];

  lines.push(`# 🛡️ Security Vulnerability & Remediation Report`);
  lines.push(``);
  lines.push(`**Repository:** \`${report.repository?.fullName || 'unknown'}\``);
  lines.push(``);
  lines.push(`**Generated:** ${report.generatedAt}`);
  lines.push(``);
  lines.push(`**Branches Scanned:** ${report.summary?.totalBranches || 0}`);
  lines.push(``);
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

    const sortedVulns = (b.vulnerabilities || []).map(normalizeInstalledVersionDisplay).sort(sortVulnerabilities);

    if (sortedVulns.length === 0) {
      lines.push(`✅ **No vulnerable packages found on this branch.**`);
      lines.push(``);
      continue;
    }

    lines.push(`### Package Vulnerability Overview`);
    lines.push(``);
    lines.push(`| Package | Status | Remediation | Severity | Type | Current Version | Target Fix | CVEs | Sources |`);
    lines.push(`| :--- | :---: | :---: | :---: | :---: | :--- | :--- | :--- | :--- |`);

    for (const v of sortedVulns) {
      const typeLabel = v.dependencyType || (v.isDirect && v.isIndirect ? 'Direct & Indirect' : (v.isDirect ? 'Direct' : 'Indirect (Transitive)'));
      const statusBadge = formatStatus(v);
      const targetFix = formatTargetFix(v);
      const cves = formatCves(v);
      const sources = formatSources(v);
      const remediationBadge = formatRemediationStatus(v);
      lines.push(
        `| **\`${v.packageName}\`** | ${statusBadge} | ${remediationBadge} | **${(v.severity || 'moderate').toUpperCase()}** | ${typeLabel} | \`${v.currentVersion}\` | ${targetFix} | ${cves} | ${sources} |`
      );
    }
    lines.push(``);

    lines.push(`### Detailed Package Findings & Consolidated Remediation`);
    lines.push(``);

    for (const [idx, v] of sortedVulns.entries()) {
      const isResolved = v.status === 'resolved' || isVulnerabilityResolved(v);
      const statusBadge = isResolved ? '✅ Resolved' : '⚠️ Open';
      lines.push(`#### \`${v.packageName}\` — ${(v.severity || 'moderate').toUpperCase()} (${statusBadge})`);
      const statusNote = isResolved
        ? `✅ Resolved (installed version \`${v.currentVersion}\` satisfies target fix)`
        : `⚠️ Open (installed version \`${v.currentVersion}\` is vulnerable)`;

      lines.push(``);
      lines.push(`##### Details`);
      lines.push(`- **Status:** ${statusNote}`);
      lines.push(`- **Current Version:** \`${v.currentVersion}\``);
      const targetFixFormatted = formatTargetFix(v, ' | ');
      const isBreaking = Boolean(v.remediation?.isBreaking || v.remediation?.isSemVerMajor || v.isBreaking || v.isSemVerMajor);
      const isOutOfRange = Boolean(v.remediation?.isOutOfRange || v.isOutOfRange);
      if (targetFixFormatted === '_No fix_') {
        lines.push(`- **Target Fix Version:** _⚠️ No known patched version is currently available for \`${v.packageName}\`._`);
      } else if (isBreaking) {
        lines.push(`- **Target Fix Version:** ${targetFixFormatted} _⚠️ major version upgrade required_`);
        lines.push(`- **Breaking Change:** ⚠️ Yes (major version upgrade)`);
        if (isOutOfRange) {
          lines.push(`- **Out of Range Upgrade:** ⚠️ Yes (outside declared range)`);
        }
      } else if (isOutOfRange) {
        lines.push(`- **Target Fix Version:** ${targetFixFormatted} _⚠️ out of range upgrade required_`);
        lines.push(`- **Out of Range Upgrade:** ⚠️ Yes (outside declared range)`);
      } else {
        lines.push(`- **Target Fix Version:** ${targetFixFormatted}`);
      }
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

      // List of individual advisories for this package
      const advisories = v.findings ?? ((v.advisories && v.advisories.length > 0) ? v.advisories : [{ title: v.title, url: v.url }]);
      lines.push(`- **Tracked Advisories & CVEs (${advisories.length}):**`);
      for (const adv of advisories) {
        lines.push("  - " + [
          adv.url ? `[Advisory](${adv.url}) -` : '',
          adv.sources?.jira?.ticketKey ? `[Jira ${adv.sources.jira.ticketKey}](${adv.sources.jira.url}) -` : '',
          adv.cves?.length ? adv.cves.map((cve) => `\`${cve}\``).join(', ') : adv.cve ? `\`${adv.cve}\`` : '_(no CVE)_',
          " - ",
          adv.title || 'Security finding',
        ].filter(Boolean).join(' '));
        for (const interval of adv.constraints || []) {
          lines.push(`    - Affected: \`${interval.vulnerableRange || 'unknown'}\`; first patched: ${interval.firstPatchedVersion ? `\`${interval.firstPatchedVersion}\`` : 'unknown'}.`);
        }
      }
      lines.push(``);

      const depTypeStr = v.dependencyType || (v.isDirect && v.isIndirect ? 'Direct & Indirect' : (v.isDirect ? 'Direct Dependency' : 'Indirect (Transitive)'));
      lines.push(`- **Dependency Type:** ${depTypeStr}`);

      // Direct Dependencies
      const directPaths = formatDirectDependencyPaths(v);
      if (directPaths.length > 0) {
        lines.push(`- **Direct Dependencies:**`);
        lines.push("  ```text");
        for (const dp of directPaths) {
          lines.push("  " + dp);
        }
        lines.push("  ```");
      }

      // Transitive Dependency Paths
      const transitivePaths = formatTransitiveDependencyPaths(v);
      if (transitivePaths.length > 0) {
        lines.push(`- **Transitive Dependency Path:**`);
        lines.push("  ```text");
        for (const cp of transitivePaths) {
          lines.push("  " + cp);
        }
        lines.push("  ```");
      }

      // Consolidated Remediation Plan
      const rem = v.remediation || {};
      const noFix = rem.strategy === 'none' || (!v.targetSafeVersion && (!v.patchedVersions || v.patchedVersions.length === 0));
      lines.push(``);
      lines.push(`##### Remediation Plan`);
      if (noFix) {
        lines.push(`- > ⚠️ **No fix available**: No patched release of \`${v.packageName}\` currently exists. Mitigations or alternative dependencies should be investigated.`);
        lines.push(``);
      } else {
        lines.push(`- **Fix Strategy:** ${formatFixStrategy(rem, v)}`);
        if (rem.strategy === 'package-override') {
          lines.push(`- > ⚠️ **Out of range override:** Transitive dependency requires a persistent override in root \`package.json\` because parent constraints forbid the safe version.`);
        }
        if (isBreaking) {
          const targetPkg = rem.targetPackage || v.packageName;
          const targetVer = rem.targetVersion || v.targetSafeVersion;
          lines.push(`- > ⚠️ **Breaking Change:** This remediation requires a major version upgrade (\`${targetPkg}\` to \`${targetVer}\`). Review the package changelog and test thoroughly for breaking changes.`);
        } else if (isOutOfRange && rem.strategy !== 'package-override') {
          lines.push(`- > ⚠️ **Out of Range Upgrade:** This update moves beyond the declared semver range.`);
        }
        if (rem.note) {
          lines.push(`- > **Note:** _${rem.note}_`);
        }

        if (rem.packageJsonChanges && rem.packageJsonChanges.length > 0) {
          lines.push(``);
          lines.push(`Update \`package.json\` file(s):`);
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
          lines.push(``);
          lines.push(`Required lockfile resolution (not a standalone command):`);
          lines.push(`- Packages to re-resolve: ${rem.lockfileUpdates.map((name) => `\`${name}\``).join(', ')}.`);
          lines.push(`- Resolve the reviewed targets after approved manifest edits, then verify every affected instance against the final manifest and run the post-change audit. A standalone npm update is not sufficient proof of a transitive fix.`);
          if (rem.strategy === 'lockfile-update' || rem.transientOverrides?.length) {
            lines.push(`- For in-range transitive copies, the chosen policy is scoped temporary pins during resolution, followed by removal of generated pins before final verification. That execution policy is not yet implemented; no one-command fix is provided here.`);
          }
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
