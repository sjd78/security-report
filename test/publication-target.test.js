import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { execGit } from '../src/core/git-manager.js';
import { resolvePublicationTarget, refreshPublicationHead } from '../src/core/publication-target.js';

const upstream = 'https://github.com/konveyor/tackle2-ui.git';
const forkRepo = 'sjd78/tackle2-ui';
const head = 'security/remediation/main';

test('resolvePublicationTarget preserves the no-fork destination and upstream identity', () => {
  assert.deepEqual(resolvePublicationTarget(upstream), {
    remote: 'origin', remoteUrl: upstream, trackingNamespace: 'origin',
    repository: { org: 'konveyor', name: 'tackle2-ui' }, isFork: false,
  });
  assert.deepEqual(resolvePublicationTarget(upstream, null), resolvePublicationTarget(upstream));
  assert.deepEqual(resolvePublicationTarget('http://git.example/upstream/project.git').repository, { org: 'upstream', name: 'project' });
  for (const origin of ['/tmp/local.git', 'file:///tmp/local.git', null]) {
    assert.deepEqual(resolvePublicationTarget(origin), {
      remote: 'origin', remoteUrl: origin, trackingNamespace: 'origin', repository: null, isFork: false,
    });
  }
});

test('resolvePublicationTarget derives a direct HTTPS fork URL and stable isolated namespace', () => {
  const target = resolvePublicationTarget(upstream, forkRepo);
  assert.deepEqual(target, {
    remote: 'https://github.com/sjd78/tackle2-ui.git',
    remoteUrl: 'https://github.com/sjd78/tackle2-ui.git',
    trackingNamespace: target.trackingNamespace,
    repository: { org: 'sjd78', name: 'tackle2-ui' }, isFork: true,
  });
  assert.match(target.trackingNamespace, /^security-remediation-fork\/[a-f0-9]{64}$/);
  assert.deepEqual(resolvePublicationTarget(upstream, forkRepo), target);
  assert.equal(resolvePublicationTarget(upstream, 'SJD78/TACKLE2-UI').trackingNamespace, target.trackingNamespace);
  assert.notEqual(resolvePublicationTarget(upstream, 'another/tackle2-ui').trackingNamespace, target.trackingNamespace);
  assert.notEqual(resolvePublicationTarget('https://git.example/konveyor/tackle2-ui', forkRepo).trackingNamespace, target.trackingNamespace);
});

test('resolvePublicationTarget preserves Enterprise host, explicit port, and HTTPS or SSH transport', () => {
  for (const [origin, expected] of [
    ['https://git.example:8443/upstream/project.git', 'https://git.example:8443/sjd78/tackle2-ui.git'],
    ['https://git.example:443/upstream/project/', 'https://git.example:443/sjd78/tackle2-ui.git'],
    ['git@git.example:upstream/project.git', 'git@git.example:sjd78/tackle2-ui.git'],
    ['git.example:upstream/project', 'git@git.example:sjd78/tackle2-ui.git'],
    ['ssh://git@git.example:2222/upstream/project.git', 'ssh://git@git.example:2222/sjd78/tackle2-ui.git'],
    ['ssh://service@git.example/upstream/project', 'ssh://service@git.example/sjd78/tackle2-ui.git'],
    ['ssh://git.example:2222/upstream/project.git', 'ssh://git@git.example:2222/sjd78/tackle2-ui.git'],
    ['ssh://git@[::1]:2222/upstream/project.git', 'ssh://git@[::1]:2222/sjd78/tackle2-ui.git'],
  ]) {
    const target = resolvePublicationTarget(origin, forkRepo);
    assert.equal(target.remote, expected, origin);
    assert.equal(target.remoteUrl, expected, origin);
    assert.deepEqual(resolvePublicationTarget(origin).repository, { org: 'upstream', name: 'project' });
  }
});

test('resolvePublicationTarget rejects invalid fork identities instead of falling back to origin', () => {
  for (const fork of [
    '', ' ', '\n', false, 1, {}, [], 'sjd78', '/sjd78/repo', 'sjd78/repo/', 'sjd78/repo/extra',
    'https://github.com/sjd78/repo', 'git@github.com:sjd78/repo', '--mirror', '-owner/repo',
    'owner/-repo', 'owner/..', 'owner/.', '../repo', 'owner/repo name', 'owner/repo\n',
    ' owner/repo', 'owner/repo?query', 'owner/repo#fragment', 'owner/repo%2Fother',
    'owner:password/repo', 'owner@host/repo', 'owner/repo\\other', 'owner/repo:other',
  ]) assert.throws(() => resolvePublicationTarget(upstream, fork), /forkRepo/, String(fork));
  assert.deepEqual(resolvePublicationTarget(upstream, 'owner-1/.github').repository, { org: 'owner-1', name: '.github' });
});

test('resolvePublicationTarget rejects upstream and destination identity aliases case-insensitively', () => {
  for (const origin of [upstream, 'git@github.com:konveyor/tackle2-ui.git', 'ssh://git@git.example/konveyor/tackle2-ui']) {
    assert.throws(() => resolvePublicationTarget(origin, 'KONVEYOR/TACKLE2-UI'), /must differ/);
  }
});

test('resolvePublicationTarget refuses unsupported, credential-bearing, or ambiguous fork origins', () => {
  for (const origin of [
    null, '', '/tmp/local.git', 'file:///tmp/local.git', 'http://github.com/upstream/repo.git',
    'git://github.com/upstream/repo.git', 'https://github.com/upstream',
    'https://github.com/upstream/repo/extra', 'https://github.com/upstream/../owner/repo',
    'https://github.com/upstream/repo.git?token=secret', 'https://github.com/upstream/repo#head',
    'https://token@github.com/upstream/repo.git', 'https://@github.com/upstream/repo.git',
    'https://user:password@github.com/upstream/repo', 'ssh://git:password@git.example/upstream/repo',
    'ssh://git:@git.example/upstream/repo', 'https://github.com/upstream/repo%2Fextra',
    'https://github.com\\evil.example/upstream/repo', 'git@github.com:upstream/repo extra',
  ]) assert.throws(() => resolvePublicationTarget(origin, forkRepo), /origin URL/, String(origin));
});

async function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'publication-target-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const source = path.join(root, 'source');
  const origin = path.join(root, 'origin.git');
  const fork = path.join(root, 'fork.git');
  const repo = path.join(root, 'clone');
  await execGit(['init', '-b', 'main', source], root);
  await execGit(['config', 'user.name', 'Publication Test'], source);
  await execGit(['config', 'user.email', 'publication@example.com'], source);
  fs.writeFileSync(path.join(source, 'file.txt'), 'base\n');
  await execGit(['add', '.'], source);
  await execGit(['commit', '-m', 'base'], source);
  const base = (await execGit(['rev-parse', 'HEAD'], source)).stdout;
  await execGit(['init', '--bare', '-b', 'main', origin], root);
  await execGit(['init', '--bare', '-b', 'main', fork], root);
  await execGit(['push', origin, 'refs/heads/main:refs/heads/main', `refs/heads/main:refs/heads/${head}`], source);
  await execGit(['push', fork, 'refs/heads/main:refs/heads/main'], source);
  await execGit(['checkout', '-b', head], source);
  fs.writeFileSync(path.join(source, 'file.txt'), 'fork remediation\n');
  await execGit(['commit', '-am', 'remediation'], source);
  const forkHead = (await execGit(['rev-parse', 'HEAD'], source)).stdout;
  await execGit(['push', fork, `refs/heads/${head}:refs/heads/${head}`], source);
  await execGit(['clone', origin, repo], root);
  const target = resolvePublicationTarget(upstream, forkRepo);
  // Native Git rewrites this test-only HTTPS destination to a real local bare fork.
  await execGit(['config', `url.${fork}.insteadOf`, target.remoteUrl], repo);
  return { root, source, origin, fork, repo, base, forkHead, target, ref: `refs/remotes/${target.trackingNamespace}/${head}` };
}

async function refValue(repo, ref) {
  return (await execGit(['rev-parse', '--verify', ref], repo)).stdout;
}

async function protectedRefs(repo) {
  return (await execGit(['for-each-ref', '--format=%(refname) %(objectname)', 'refs/heads', 'refs/remotes/origin'], repo)).stdout;
}

test('refreshPublicationHead fetches only the fork head without origin or remote configuration changes', async (t) => {
  const { repo, origin, fork, target, base, forkHead, ref } = await fixture(t);
  const config = fs.readFileSync(path.join(repo, '.git', 'config'), 'utf8');
  const refs = await protectedRefs(repo);
  const originRefs = (await execGit(['show-ref'], origin)).stdout;
  const forkRefs = (await execGit(['show-ref'], fork)).stdout;
  assert.equal(await refreshPublicationHead(repo, target, head, 'test-only-token'), forkHead);
  assert.equal(await refValue(repo, ref), forkHead);
  assert.equal(await refValue(repo, `refs/remotes/origin/${head}`), base);
  assert.equal(await protectedRefs(repo), refs);
  assert.equal(fs.readFileSync(path.join(repo, '.git', 'config'), 'utf8'), config);
  assert.equal((await execGit(['remote'], repo)).stdout, 'origin');
  assert.equal((await execGit(['show-ref'], origin)).stdout, originRefs);
  assert.equal((await execGit(['show-ref'], fork)).stdout, forkRefs);
  await assert.rejects(() => refValue(repo, `refs/remotes/${target.trackingNamespace}/main`));
});

test('refreshPublicationHead clears only its stale tracking head when the fork branch is absent', async (t) => {
  const { repo, fork, target, base, forkHead, ref } = await fixture(t);
  await refreshPublicationHead(repo, target, head);
  const otherRef = `refs/remotes/${target.trackingNamespace}/security/other`;
  const otherTarget = resolvePublicationTarget(upstream, 'other-owner/tackle2-ui');
  const otherForkRef = `refs/remotes/${otherTarget.trackingNamespace}/${head}`;
  await execGit(['update-ref', otherRef, forkHead], repo);
  await execGit(['update-ref', otherForkRef, base], repo);
  await execGit(['branch', head, base], repo);
  const refs = await protectedRefs(repo);
  await execGit(['update-ref', '-d', `refs/heads/${head}`], fork);
  assert.equal(await refreshPublicationHead(repo, target, head), null);
  await assert.rejects(() => refValue(repo, ref));
  assert.equal(await refValue(repo, otherRef), forkHead);
  assert.equal(await refValue(repo, otherForkRef), base);
  assert.equal(await protectedRefs(repo), refs);
  assert.equal(await refreshPublicationHead(repo, target, head), null);
});

test('refreshPublicationHead propagates an inaccessible fork error without clearing stale tracking or using origin', async (t) => {
  const { root, repo, fork, target, forkHead, ref } = await fixture(t);
  await refreshPublicationHead(repo, target, head);
  const refs = await protectedRefs(repo);
  const config = fs.readFileSync(path.join(repo, '.git', 'config'), 'utf8');
  fs.renameSync(fork, path.join(root, 'inaccessible-fork.git'));
  await assert.rejects(() => refreshPublicationHead(repo, target, head), (error) => {
    assert.notEqual(error.code, 2);
    assert.match(error.message, /ls-remote/);
    return true;
  });
  assert.equal(await refValue(repo, ref), forkHead);
  assert.equal(await protectedRefs(repo), refs);
  assert.equal(fs.readFileSync(path.join(repo, '.git', 'config'), 'utf8'), config);
});

test('refreshPublicationHead reads the existing upstream tracking SHA without contacting origin', async (t) => {
  const { root, repo, origin, base } = await fixture(t);
  fs.renameSync(origin, path.join(root, 'offline-origin.git'));
  const target = resolvePublicationTarget(origin);
  assert.equal(await refreshPublicationHead(repo, target, head), base);
  assert.equal(await refreshPublicationHead(repo, target, 'security/missing'), null);
});

test('refreshPublicationHead rejects invalid branches and nonprivate fork tracking namespaces', async (t) => {
  const { repo, target } = await fixture(t);
  const refs = (await execGit(['show-ref'], repo)).stdout;
  for (const invalid of ['', '-option', 'HEAD', '../head', 'head..next', 'a b', 'a:b', 'head@{1}', 'a*', 'head.lock', '@{-1}']) {
    await assert.rejects(() => refreshPublicationHead(repo, target, invalid));
  }
  for (const trackingNamespace of ['origin', 'refs/remotes/origin', 'security-remediation-fork/../origin', 'security-remediation-fork/not-a-hash']) {
    await assert.rejects(() => refreshPublicationHead(repo, { ...target, trackingNamespace }, head), /private tracking namespace/);
  }
  assert.equal((await execGit(['show-ref'], repo)).stdout, refs);
});

test('refreshPublicationHead preserves stale tracking on a fork authorization failure', async (t) => {
  const { repo, target, forkHead, ref } = await fixture(t);
  await refreshPublicationHead(repo, target, head);
  let requests = 0;
  const server = http.createServer((request, response) => {
    requests += 1;
    response.writeHead(401, { 'WWW-Authenticate': 'Basic realm="fork"' });
    response.end('Unauthorized');
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const remoteUrl = `http://127.0.0.1:${server.address().port}/private-fork.git`;
  const unavailable = { ...target, remote: remoteUrl, remoteUrl };
  const refs = await protectedRefs(repo);
  await assert.rejects(() => refreshPublicationHead(repo, unavailable, head), (error) => {
    assert.notEqual(error.code, 2);
    assert.match(error.message, /ls-remote/);
    return true;
  });
  assert.ok(requests > 0);
  assert.equal(await refValue(repo, ref), forkHead);
  assert.equal(await protectedRefs(repo), refs);
});
