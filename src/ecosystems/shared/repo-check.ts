import type { RepoCheck } from '../../types.js';

const GITHUB_API = 'https://api.github.com';

function authHeaders(): Record<string, string> {
  const token = process.env.GITHUB_TOKEN;
  return token ? { Authorization: `Bearer ${token}` } : {};
}

/** Normalize various repo URL formats into a plain HTTPS GitHub/GitLab URL. */
export function normalizeRepoUrl(raw?: string): string | undefined {
  if (!raw) return undefined;
  let url = raw.trim();

  // GitHub shorthand: "owner/repo"
  if (/^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(url)) {
    url = `https://github.com/${url}`;
  }

  url = url
    .replace(/^git\+/, '')
    .replace(/^git:\/\//, 'https://')
    .replace(/\.git$/, '')
    .replace(/\/$/, '')
    .replace(/\/(tree|blob|commit)\/.*$/, '');

  if (!url.startsWith('https://github.com/') && !url.startsWith('https://gitlab.com/')) {
    return undefined;
  }

  // Must have exactly owner + repo path segments
  const parts = url
    .replace('https://github.com/', '')
    .replace('https://gitlab.com/', '')
    .split('/');
  if (parts.length < 2 || !parts[0] || !parts[1]) return undefined;

  const host = url.startsWith('https://github.com/') ? 'https://github.com' : 'https://gitlab.com';
  return `${host}/${parts[0]}/${parts[1]}`;
}

function parseGitHub(url: string): { owner: string; repo: string } | undefined {
  const m = url.match(/^https:\/\/github\.com\/([^/]+)\/([^/]+)$/);
  return m ? { owner: m[1], repo: m[2] } : undefined;
}

async function tagExists(owner: string, repo: string, tag: string): Promise<boolean> {
  try {
    const res = await fetch(
      `${GITHUB_API}/repos/${owner}/${repo}/git/ref/tags/${encodeURIComponent(tag)}`,
      {
        headers: {
          Accept: 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28',
          ...authHeaders(),
        },
      },
    );
    return res.status === 200;
  } catch {
    return false;
  }
}

async function findTag(
  owner: string,
  repo: string,
  version: string,
  packageName: string,
): Promise<string | undefined> {
  // Most packages use one of these tag conventions
  const baseName = packageName.replace(/^@[^/]+\//, ''); // strip npm scope
  const candidates = [
    `v${version}`,
    version,
    `${baseName}-${version}`,
    `${baseName}/v${version}`,
    `${baseName}-v${version}`,
    `${packageName}-${version}`,
  ];
  for (const tag of candidates) {
    if (await tagExists(owner, repo, tag)) return tag;
  }
  return undefined;
}

export async function checkRepoRelease(params: {
  repoUrl?: string;
  packageName: string;
  oldVersion?: string | null;
  newVersion?: string | null;
}): Promise<RepoCheck | undefined> {
  const { packageName, oldVersion, newVersion } = params;
  const repoUrl = normalizeRepoUrl(params.repoUrl);
  if (!repoUrl) return undefined;

  const gh = parseGitHub(repoUrl);
  if (!gh) return undefined; // GitLab support can be added later

  const { owner, repo } = gh;

  const [oldTag, newTag] = await Promise.all([
    oldVersion ? findTag(owner, repo, oldVersion, packageName) : Promise.resolve(undefined),
    newVersion ? findTag(owner, repo, newVersion, packageName) : Promise.resolve(undefined),
  ]);

  const oldRelease = oldVersion ? { found: oldTag !== undefined, tag: oldTag } : undefined;
  const newRelease = newVersion ? { found: newTag !== undefined, tag: newTag } : undefined;
  const releaseDropped = !!(oldRelease?.found && newRelease && !newRelease.found);

  // Only return a result when there's something meaningful to report
  if (!oldRelease && !newRelease) return undefined;
  if (!oldRelease?.found && !newRelease?.found && !releaseDropped) return undefined;

  return { repoUrl, oldRelease, newRelease, releaseDropped };
}
