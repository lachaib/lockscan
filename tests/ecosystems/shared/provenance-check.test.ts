import { afterEach, describe, expect, it, vi } from 'vitest';
import { fetchNpmProvenance, type NpmVersion } from '../../../src/ecosystems/javascript/npm.js';
import { fetchPyPIProvenance } from '../../../src/ecosystems/python/pypi.js';
import { compareProvenance } from '../../../src/ecosystems/shared/provenance-check.js';

const attested = (source: string, workflow: string) => ({ attested: true, source, workflow });

describe('compareProvenance', () => {
  const old = attested('https://github.com/acme/lib', '.github/workflows/release.yml');

  it('flags a dropped attestation', () => {
    expect(compareProvenance(old, { attested: false })).toMatchObject({
      dropped: true,
      sourceChanged: false,
    });
  });

  it('flags a changed source repository', () => {
    const next = attested('https://github.com/evil/lib', '.github/workflows/release.yml');
    expect(compareProvenance(old, next)).toMatchObject({ dropped: false, sourceChanged: true });
  });

  it('flags a changed workflow in the same repository as a lesser signal', () => {
    const next = attested('https://github.com/acme/lib', '.github/workflows/publish.yml');
    expect(compareProvenance(old, next)).toMatchObject({
      sourceChanged: false,
      workflowChanged: true,
    });
  });

  it('stays silent for identical, unknown or previously unattested provenance', () => {
    expect(compareProvenance(old, { ...old })).toBeUndefined();
    expect(compareProvenance(old, undefined)).toBeUndefined();
    expect(compareProvenance(undefined, { attested: false })).toBeUndefined();
    expect(compareProvenance({ attested: false }, old)).toBeUndefined();
  });
});

describe('registry fetchers', () => {
  afterEach(() => vi.unstubAllGlobals());

  const stubFetch = (handler: (url: string) => { status: number; body?: unknown }) =>
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        const { status, body } = handler(url);
        return { ok: status < 400, status, statusText: '', json: async () => body };
      }),
    );

  const npmMeta = (withProvenance: boolean): NpmVersion =>
    ({
      name: 'pkg',
      version: '1.0.0',
      dist: {
        tarball: 'https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz',
        shasum: 'x',
        ...(withProvenance && {
          attestations: {
            url: 'https://registry.npmjs.org/-/npm/v1/attestations/pkg@1.0.0',
            provenance: { predicateType: 'https://slsa.dev/provenance/v1' },
          },
        }),
      },
    }) as NpmVersion;

  it('npm: reads the workflow identity from the SLSA statement', async () => {
    const statement = {
      predicate: {
        buildDefinition: {
          externalParameters: {
            workflow: {
              repository: 'https://github.com/acme/lib',
              path: '.github/workflows/r.yml',
            },
          },
        },
      },
    };
    stubFetch(() => ({
      status: 200,
      body: {
        attestations: [
          { predicateType: 'https://github.com/npm/attestation/tree/main/specs/publish/v0.1' },
          {
            predicateType: 'https://slsa.dev/provenance/v1',
            bundle: {
              dsseEnvelope: {
                payload: Buffer.from(JSON.stringify(statement)).toString('base64'),
              },
            },
          },
        ],
      },
    }));
    expect(await fetchNpmProvenance(npmMeta(true))).toEqual({
      attested: true,
      source: 'https://github.com/acme/lib',
      workflow: '.github/workflows/r.yml',
    });
  });

  it('npm: no attestation metadata means unattested; an unreadable bundle stays attested', async () => {
    expect(await fetchNpmProvenance(npmMeta(false))).toEqual({ attested: false });
    stubFetch(() => ({ status: 500 }));
    expect(await fetchNpmProvenance(npmMeta(true))).toEqual({ attested: true });
  });

  const artifact = (filename: string) => ({ filename, url: '', sha256: '' });

  it('pypi: reads the Trusted Publisher and requires every artifact to be attested', async () => {
    stubFetch((url) =>
      url.includes('-1.0.0.tar.gz')
        ? { status: 404 }
        : {
            status: 200,
            body: {
              attestation_bundles: [
                { publisher: { kind: 'GitHub', repository: 'acme/lib', workflow: 'release.yml' } },
              ],
            },
          },
    );
    expect(
      await fetchPyPIProvenance('lib', '1.0.0', [artifact('lib-1.0.0-py3-none-any.whl')]),
    ).toEqual({ attested: true, source: 'acme/lib', workflow: 'release.yml' });
    expect(
      await fetchPyPIProvenance('lib', '1.0.0', [
        artifact('lib-1.0.0-py3-none-any.whl'),
        artifact('lib-1.0.0.tar.gz'),
      ]),
    ).toEqual({ attested: false });
  });

  it('pypi: returns undefined on API errors so they are never read as a dropped attestation', async () => {
    stubFetch(() => ({ status: 503 }));
    expect(
      await fetchPyPIProvenance('lib', '1.0.0', [artifact('lib-1.0.0.tar.gz')]),
    ).toBeUndefined();
  });
});
