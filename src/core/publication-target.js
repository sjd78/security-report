import { createHash } from 'node:crypto';
import { execGit, gitAuthEnv } from './git-manager.js';

const OWNER = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i;
const REPOSITORY = /^[a-z0-9_.-]+$/i;
const FORK_NAMESPACE = /^security-remediation-fork\/[a-f0-9]{64}$/;

function repositoryIdentity(value) {
  if (typeof value !== 'string' || /\s/.test(value)) return null;
  const parts = value.split('/');
  if (parts.length !== 2) return null;
  const [org, name] = parts;
  if (!OWNER.test(org) || !REPOSITORY.test(name) || name.startsWith('-') || ['.', '..'].includes(name)) return null;
  return { org, name };
}

function parseOrigin(originUrl, allowHttp = false) {
  if (typeof originUrl !== 'string' || /[\s\\?#%]/.test(originUrl)) return null;
  const absolute = originUrl.match(/^(https|http|ssh):\/\/([^/]+)\/(.+)$/i);
  if (absolute) {
    let url;
    try {
      url = new URL(originUrl);
    } catch {
      return null;
    }
    if (url.protocol === 'http:' && !allowHttp) return null;
    const authority = absolute[2];
    const userInfo = authority.includes('@') ? authority.slice(0, authority.lastIndexOf('@')) : null;
    if (!url.hostname || (url.protocol !== 'ssh:' && userInfo !== null) || userInfo?.includes(':')) return null;
    if (userInfo !== null && !/^[a-z0-9_.-]+$/i.test(userInfo)) return null;
    const repository = repositoryIdentity(absolute[3].replace(/\/$/, '').replace(/\.git$/i, ''));
    if (!repository) return null;
    return { repository, host: authority.slice(authority.lastIndexOf('@') + 1), protocol: url.protocol, user: url.username || 'git' };
  }
  const ssh = originUrl.match(/^(?:([a-z0-9_.-]+)@)?(\[[a-f0-9:]+\]|[a-z0-9.-]+):(.+)$/i);
  if (!ssh || ssh[1]?.startsWith('-') || ssh[2].startsWith('-')) return null;
  const repository = repositoryIdentity(ssh[3].replace(/\/$/, '').replace(/\.git$/i, ''));
  if (!repository) return null;
  return { repository, host: ssh[2], protocol: 'scp:', user: ssh[1] || 'git' };
}

/** Resolve a push destination without adding or changing any Git remotes. */
export function resolvePublicationTarget(originUrl, forkRepo) {
  const origin = parseOrigin(originUrl, forkRepo === null || forkRepo === undefined);
  if (forkRepo === null || forkRepo === undefined) {
    return { remote: 'origin', remoteUrl: originUrl, trackingNamespace: 'origin', repository: origin?.repository || null, isFork: false };
  }
  const repository = repositoryIdentity(forkRepo);
  if (!repository) throw new Error('forkRepo must be a repository identity in owner/repo form, without a URL, credentials, or extra path.');
  if (!origin) throw new Error('Fork publication requires a credential-free GitHub-compatible HTTPS or SSH origin URL.');
  if (origin.repository.org.toLowerCase() === repository.org.toLowerCase() && origin.repository.name.toLowerCase() === repository.name.toLowerCase()) {
    throw new Error('The fork repository must differ from the upstream origin repository.');
  }
  const repoPath = `${repository.org}/${repository.name}.git`;
  const remoteUrl = origin.protocol === 'scp:'
    ? `${origin.user}@${origin.host}:${repoPath}`
    : origin.protocol === 'ssh:'
      ? `ssh://${origin.user}@${origin.host}/${repoPath}`
      : `https://${origin.host}/${repoPath}`;
  const destination = `${origin.host}/${repository.org}/${repository.name}`.toLowerCase();
  const hash = createHash('sha256').update(destination).digest('hex');
  return { remote: remoteUrl, remoteUrl, trackingNamespace: `security-remediation-fork/${hash}`, repository, isFork: true };
}

async function trackingHead(repoPath, ref) {
  try {
    return (await execGit(['rev-parse', '--verify', '--quiet', `${ref}^{commit}`], repoPath)).stdout;
  } catch (error) {
    if (error.code === 1) return null;
    throw error;
  }
}

/** Refresh only the chosen remediation head in its private fork namespace. */
export async function refreshPublicationHead(repoPath, target, head, githubToken = '') {
  if (typeof head !== 'string' || !head || head.startsWith('-') || head === 'HEAD') throw new Error('A valid publication head branch is required.');
  await execGit(['check-ref-format', `refs/heads/${head}`], repoPath);
  if (!target || (target.isFork !== true && target.isFork !== false)) throw new Error('A resolved publication target is required.');
  if (!target.isFork) {
    if (target.trackingNamespace !== 'origin') throw new Error('Invalid upstream publication tracking namespace.');
    return trackingHead(repoPath, `refs/remotes/origin/${head}`);
  }
  if (!FORK_NAMESPACE.test(target.trackingNamespace) || typeof target.remote !== 'string' || !target.remote || target.remote.startsWith('-') || target.remote !== target.remoteUrl) {
    throw new Error('Invalid fork publication destination or private tracking namespace.');
  }
  const branchRef = `refs/heads/${head}`;
  const trackingRef = `refs/remotes/${target.trackingNamespace}/${head}`;
  const authEnv = gitAuthEnv(target.remoteUrl, githubToken);
  try {
    await execGit(['ls-remote', '--exit-code', '--heads', target.remote, branchRef], repoPath, authEnv);
  } catch (error) {
    if (error.code !== 2) throw error;
    await execGit(['update-ref', '-d', trackingRef], repoPath);
    return null;
  }
  await execGit(['fetch', '--no-tags', target.remote, `${branchRef}:${trackingRef}`], repoPath, authEnv);
  return trackingHead(repoPath, trackingRef);
}
