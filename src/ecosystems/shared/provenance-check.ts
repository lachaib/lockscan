import type { Provenance, ProvenanceCheck } from '../../types.js';

/**
 * Compare the build provenance of the old and new version of a package.
 * Returns undefined when either side is unknown or nothing regressed.
 */
export function compareProvenance(
  oldProv: Provenance | undefined,
  newProv: Provenance | undefined,
): ProvenanceCheck | undefined {
  if (!oldProv?.attested || !newProv) return undefined;

  const dropped = !newProv.attested;
  const sourceChanged =
    newProv.attested && !!oldProv.source && !!newProv.source && oldProv.source !== newProv.source;
  const workflowChanged =
    newProv.attested &&
    !sourceChanged &&
    !!oldProv.workflow &&
    !!newProv.workflow &&
    oldProv.workflow !== newProv.workflow;

  if (!dropped && !sourceChanged && !workflowChanged) return undefined;
  return { old: oldProv, new: newProv, dropped, sourceChanged, workflowChanged };
}
