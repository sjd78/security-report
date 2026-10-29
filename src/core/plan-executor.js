import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { ensureRepo, execGit, getOriginUrl, gitAuthEnv, createWorktree, removeWorktree, sanitizeBranchName, stageAndCommit, pushBranch } from './git-manager.js';
import { executeBranchPlan, validateBranchActions } from './remediator.js';
import { renderPrTitle, generatePullRequestBody, publishPullRequest } from './pull-request.js';

export function readRemediationPlan(filename) {
  let plan;
  try { plan = JSON.parse(fs.readFileSync(filename, 'utf8')); }
  catch (error) { throw new Error(`Cannot read remediation plan ${filename}: ${error.message}`); }
  if (plan?.schemaVersion !== '1.0.0' || plan.kind !== 'security-remediation-plan'
    || !plan.repository || typeof plan.repository !== 'object' || Array.isArray(plan.repository) || !Array.isArray(plan.branches)) {
    throw new Error('Expected a version 1.0.0 security-remediation-plan; generate it with scan first.');
  }
  const names = new Set();
  for (const branch of plan.branches) {
    if (!branch || typeof branch.branch !== 'string' || names.has(branch.branch)
      || !['ready', 'blocked', 'no-op'].includes(branch.status)
      || !Array.isArray(branch.packages) || !Array.isArray(branch.actions) || !Array.isArray(branch.blockers)) {
      throw new Error('Invalid or duplicate branch in remediation plan.');
    }
    names.add(branch.branch);
  }
  return plan;
}

function planIdentity(branch) {
  return createHash('sha256').update(JSON.stringify({ branch: branch.branch, baseCommit: branch.baseCommit,
    actions: branch.actions, packages: branch.packages })).digest('hex');
}

async function resolveRef(repo, ref) {
  return (await execGit(['rev-parse', '--verify', '--quiet', ref], repo).catch(() => ({ stdout: '' }))).stdout || null;
}

async function assertBase(repo, branch) {
  if (!/^[0-9a-f]{40,64}$/i.test(branch.baseCommit || '')) throw new Error(`Invalid scanned commit for ${branch.branch}.`);
  await execGit(['check-ref-format', '--branch', branch.branch], repo);
  const current = await resolveRef(repo, `refs/remotes/origin/${branch.branch}`)
    || await resolveRef(repo, `refs/heads/${branch.branch}`);
  if (current !== branch.baseCommit) {
    throw new Error(`Stale remediation plan for ${branch.branch}: scanned ${branch.baseCommit}, current ${current || 'missing'}. Scan and review a new plan.`);
  }
}

function githubRepository(remoteUrl) {
  if (!remoteUrl) throw new Error('PR publishing requires an origin remote identifying the GitHub owner/repository.');
  let pathname;
  if (/^[^/@]+@[^:]+:/.test(remoteUrl)) pathname = remoteUrl.slice(remoteUrl.indexOf(':') + 1);
  else {
    try { pathname = new URL(remoteUrl).pathname; }
    catch { throw new Error('Cannot determine GitHub owner/repository from origin. Use a GitHub HTTPS or SSH origin URL.'); }
  }
  const parts = pathname.replace(/\.git\/?$/, '').split('/').filter(Boolean);
  if (parts.length !== 2 || parts.some((part) => !/^[a-zA-Z0-9_.-]+$/.test(part))) {
    throw new Error('Cannot determine GitHub owner/repository from origin.');
  }
  return { org: parts[0], name: parts[1] };
}

function allowedFiles(branch) {
  return new Set(['package-lock.json', ...branch.actions.filter((action) => action.file).map((action) => action.file)]);
}

async function assertOwnedHead(repo, ref, branch, identity, expectedManifests) {
  const { stdout: message } = await execGit(['log', '-1', '--format=%B', ref], repo);
  if (!message.split('\n').includes(`Security-Remediation-Plan: ${identity}`)) {
    throw new Error(`Refusing to overwrite ${ref}: it is not a commit created from this remediation plan.`);
  }
  await execGit(['merge-base', '--is-ancestor', branch.baseCommit, ref], repo);
  const { stdout: changed } = await execGit(['diff', '--name-only', branch.baseCommit, ref], repo);
  const allowed = allowedFiles(branch);
  if (changed.split('\n').filter(Boolean).some((file) => !allowed.has(file))) {
    throw new Error(`Remediation branch ${ref} contains changes outside the saved plan.`);
  }
  for (const [file, expected] of expectedManifests) {
    const { stdout } = await execGit(['show', `${ref}:${file}`], repo);
    if (!isDeepStrictEqual(JSON.parse(stdout), expected)) {
      throw new Error(`Remediation branch ${ref} contains unplanned manifest changes in ${file}.`);
    }
  }
}

async function prepareHead(repo, branch, head, identity, expectedManifests) {
  const { stdout: worktrees } = await execGit(['worktree', 'list', '--porcelain'], repo);
  let holdingPath;
  for (const line of worktrees.split('\n')) {
    if (line.startsWith('worktree ')) holdingPath = line.slice(9);
    if (line === `branch refs/heads/${head}`) {
      throw new Error(`Remediation worktree retained at ${holdingPath}; review or remove it before executing this plan again.`);
    }
  }
  const localRef = `refs/heads/${head}`;
  const remoteRef = `refs/remotes/origin/${head}`;
  const local = await resolveRef(repo, localRef);
  const remote = await resolveRef(repo, remoteRef);
  if (local) await assertOwnedHead(repo, localRef, branch, identity, expectedManifests);
  if (remote) await assertOwnedHead(repo, remoteRef, branch, identity, expectedManifests);
  if (local && remote && local !== remote) {
    const localBehind = await execGit(['merge-base', '--is-ancestor', local, remote], repo).then(() => true, () => false);
    if (localBehind) await execGit(['update-ref', localRef, remote, local], repo);
    else await execGit(['merge-base', '--is-ancestor', remote, local], repo);
  } else if (!local && remote) {
    await execGit(['branch', head, remoteRef], repo);
  }
  return Boolean(local || remote);
}

async function refreshBeforePublish(repo, branch, remoteUrl, githubToken) {
  await execGit(['fetch', 'origin', '--prune'], repo, gitAuthEnv(remoteUrl, githubToken));
  await assertBase(repo, branch);
}

export async function executeRemediationPlan(plan, config = {}) {
  const reportsDir = path.resolve(config.reportsDir || 'reports');
  const resultsPath = path.join(reportsDir, 'security-remediation-results.json');
  const results = { schemaVersion: '1.0.0', kind: 'security-remediation-results',
    generatedAt: new Date().toISOString(), planGeneratedAt: plan.generatedAt, repository: plan.repository, branches: [] };
  const save = () => { fs.mkdirSync(reportsDir, { recursive: true }); fs.writeFileSync(resultsPath, JSON.stringify(results, null, 2) + '\n'); };
  try {
    if (config.push && !config.commit && !config.createPr) throw new Error('--push requires --commit.');
    const requested = config.branches
      ? (Array.isArray(config.branches) ? config.branches : String(config.branches).split(',')).map((branch) => branch.trim()).filter(Boolean)
      : null;
    if (requested?.some((name) => !plan.branches.some((branch) => branch.branch === name))) {
      throw new Error('Requested branches must exist in the saved remediation plan.');
    }
    const branches = plan.branches.filter((branch) => !requested || requested.includes(branch.branch));
    if (!branches.length) throw new Error('No branches selected from the remediation plan.');
    const blocked = branches.filter((branch) => branch.status === 'blocked' || branch.blockers.length);
    if (blocked.length) throw new Error(blocked.map((branch) => `${branch.branch}: ${branch.blockers.join(' ') || 'plan is blocked'}`).join('\n'));
    const target = config.repo || plan.repository.path;
    if (!target) throw new Error('The plan has no repository path; specify a target repository.');
    const repository = await ensureRepo(target, { ...config, strictFetch: true });
    const repo = repository.repoPath;
    const remoteUrl = await getOriginUrl(repo);
    if (plan.repository.remoteUrl && plan.repository.remoteUrl !== remoteUrl) {
      throw new Error('Repository origin differs from the origin recorded in the remediation plan.');
    }
    const shouldCommit = Boolean(config.commit || config.createPr);
    const shouldPush = Boolean(config.push || config.createPr);
    if (shouldPush && !remoteUrl) throw new Error('Publishing requires an origin remote.');
    if (config.createPr && !config.dryRun && !config.githubToken) throw new Error('PR publishing requires githubToken or GITHUB_TOKEN.');
    const github = config.createPr ? githubRepository(remoteUrl) : null;
    const prepared = [];
    // Check every selected base before applying anything to any branch.
    for (const branch of branches) {
      await assertBase(repo, branch);
      if (branch.status === 'no-op') {
        if (branch.actions.length) throw new Error(`No-op branch ${branch.branch} unexpectedly contains actions.`);
        results.branches.push({ branch: branch.branch, status: 'no-op', summary: branch.summary,
          unresolved: branch.packages.filter((pkg) => ['manual-review', 'no-fix'].includes(pkg.status)) });
        continue;
      }
      if (!branch.actions.length || !branch.packages.some((pkg) => pkg.status === 'ready')) throw new Error(`Ready branch ${branch.branch} has no executable package actions.`);
      const identity = planIdentity(branch);
      const head = `security-remediation/${sanitizeBranchName(branch.branch).slice(0, 80)}-${branch.baseCommit.slice(0, 12)}-${identity.slice(0, 12)}`;
      const targetPackages = branch.packages.filter((pkg) => pkg.status === 'ready').map((pkg) => pkg.packageName);
      const title = renderPrTitle(config.prTitleTemplate ?? 'fix(deps): {summary} ({targetBranch})', {
        targetBranch: branch.branch, targetPackages, summary: branch.summary,
      });
      if (config.createPr && !await resolveRef(repo, `refs/remotes/origin/${branch.branch}`)) throw new Error(`PR base ${branch.branch} is not present on origin.`);
      // This snapshot is read-only and disposable, even if validation fails.
      const snapshot = await createWorktree(repo, branch.branch, null, { snapshot: true });
      let expectedManifests;
      try {
        const { manifests } = validateBranchActions(snapshot, branch, { ...config, reuse: false });
        expectedManifests = new Map([...manifests].map(([file, entry]) => [file, entry.json]));
      }
      finally { await removeWorktree(repo, snapshot); }
      prepared.push({ branch, identity, head, title, expectedManifests });
    }
    for (const { branch, identity, head, title, expectedManifests } of prepared) {
      const item = { branch: branch.branch, head, title, status: config.dryRun ? 'planned' : 'applying' };
      results.branches.push(item);
      if (config.dryRun) {
        Object.assign(item, { verified: false, actions: branch.actions, summary: branch.summary });
        console.log(`[DRY RUN] ${branch.branch} -> ${head}: ${title}\n${JSON.stringify(branch.actions, null, 2)}`);
        continue;
      }
      let worktreeDir;
      try {
        const reuse = await prepareHead(repo, branch, head, identity, expectedManifests);
        worktreeDir = path.resolve(repo, '.worktrees', sanitizeBranchName(head));
        if (fs.existsSync(worktreeDir)) throw new Error(`Refusing to overwrite retained worktree ${worktreeDir}.`);
        fs.mkdirSync(path.dirname(worktreeDir), { recursive: true });
        await execGit(reuse ? ['worktree', 'add', worktreeDir, head]
          : ['worktree', 'add', '-b', head, worktreeDir, branch.baseCommit], repo);
        item.worktreeDir = worktreeDir;
        const execution = await executeBranchPlan(worktreeDir, branch, { ...config, reuse });
        Object.assign(item, { execution, status: 'applied' });
        if (!execution.verified) throw new Error(`Remediation for ${branch.branch} was not verified; refusing to publish.`);
        for (const [file, expected] of expectedManifests) {
          if (!isDeepStrictEqual(JSON.parse(fs.readFileSync(path.join(worktreeDir, file), 'utf8')), expected)) {
            throw new Error(`npm changed ${file} outside the saved manifest actions; refusing to publish.`);
          }
        }
        if (shouldCommit) {
          const body = generatePullRequestBody(branch, execution);
          const commit = await stageAndCommit(worktreeDir, {
            message: `${title}\n\n${body}\n\nSecurity-Remediation-Plan: ${identity}`,
            files: [...allowedFiles(branch)].filter((file) => fs.existsSync(path.join(worktreeDir, file))), branch: head,
          });
          const headCommit = await resolveRef(repo, `refs/heads/${head}`);
          if (!commit.committed && headCommit === branch.baseCommit) throw new Error('The saved plan produced no changes; no commit or PR was created.');
          item.commit = { ...commit, commitHash: headCommit };
          item.status = 'committed';
          if (shouldPush) {
            await refreshBeforePublish(repo, branch, remoteUrl, config.githubToken);
            await pushBranch(worktreeDir, head, { githubToken: config.githubToken });
            item.status = 'pushed';
            if (config.createPr) {
              item.pullRequest = await publishPullRequest({ ...github, head, base: branch.branch,
                title, body, githubToken: config.githubToken, githubApiUrl: config.githubApiUrl });
              item.status = 'published';
              console.log(`PR for ${branch.branch}: ${item.pullRequest.url}`);
            }
          }
          await removeWorktree(repo, worktreeDir);
          delete item.worktreeDir;
        } else console.log(`Verified remediation worktree retained: ${worktreeDir}`);
      } catch (error) {
        item.status = 'failed';
        item.error = error.message;
        if (worktreeDir) console.error(`Remediation worktree retained for inspection: ${worktreeDir}`);
        throw error;
      } finally { save(); }
    }
    save();
    console.log(`Remediation execution results: ${resultsPath}`);
    return { results, resultsPath };
  } catch (error) {
    results.error = error.message;
    save();
    throw new Error(`${error.message}\nExecution results: ${resultsPath}`, { cause: error });
  }
}
