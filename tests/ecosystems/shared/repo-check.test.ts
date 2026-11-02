import { afterEach, describe, expect, it, vi } from 'vitest';
import { checkRepoRelease, tagCandidates } from '../../../src/ecosystems/shared/repo-check.js';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('tagCandidates', () => {
  it('tries the exact spellings before aliases', () => {
    expect(tagCandidates('6.6', 'tornado').slice(0, 2)).toEqual(['v6.6', '6.6']);
  });

  it('adds a .0 alias for a two-part version', () => {
    expect(tagCandidates('6.6', 'tornado')).toEqual(expect.arrayContaining(['v6.6.0', '6.6.0']));
  });

  it('strips a trailing .0 but never down to a bare major', () => {
    const tags = tagCandidates('1.0.0', 'pkg');
    expect(tags).toEqual(expect.arrayContaining(['v1.0', '1.0']));
    expect(tags).not.toContain('v1');
    expect(tags).not.toContain('1');
  });

  it('adds nothing for non-numeric versions', () => {
    expect(tagCandidates('2.0.0rc1', 'pkg').every((t) => t.includes('2.0.0rc1'))).toBe(true);
  });
});

describe('checkRepoRelease', () => {
  it('finds a v6.6.0 tag for version 6.6 instead of reporting a dropped release', async () => {
    const existing = new Set(['v6.5.9', 'v6.6.0']);
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => ({
        status: existing.has(decodeURIComponent(url.split('/git/ref/tags/')[1])) ? 200 : 404,
      })),
    );

    const result = await checkRepoRelease({
      repoUrl: 'https://github.com/tornadoweb/tornado',
      packageName: 'tornado',
      oldVersion: '6.5.9',
      newVersion: '6.6',
    });

    expect(result?.releaseDropped).toBe(false);
    expect(result?.newRelease).toEqual({ found: true, tag: 'v6.6.0' });
  });
});
