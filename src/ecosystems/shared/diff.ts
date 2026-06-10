import { createPatch } from 'diff';
import type { CodeDelta } from '../../types.js';
import type { FileMap } from '../../utils/extract.js';

const MAX_DIFF_CHARS = 80_000;

export function diffFiles(oldFiles: FileMap, newFiles: FileMap): CodeDelta {
  const added = [...newFiles.keys()].filter((k) => !oldFiles.has(k)).sort();
  const removed = [...oldFiles.keys()].filter((k) => !newFiles.has(k)).sort();
  const common = [...oldFiles.keys()].filter((k) => newFiles.has(k)).sort();

  const chunks: string[] = [];
  if (added.length) chunks.push(`### NEW FILES: ${added.join(', ')}`);
  if (removed.length) chunks.push(`### REMOVED FILES: ${removed.join(', ')}`);

  let filesChanged = 0;
  for (const k of common) {
    const oldContent = oldFiles.get(k)!;
    const newContent = newFiles.get(k)!;
    if (oldContent === newContent) continue;
    filesChanged++;
    chunks.push(createPatch(k, oldContent, newContent, 'old', 'new', { context: 3 }));
  }

  let diff = chunks.join('\n') || '(no changes)';
  if (diff.length > MAX_DIFF_CHARS) {
    const head = Math.floor(MAX_DIFF_CHARS * 0.75);
    const tail = MAX_DIFF_CHARS - head;
    const omitted = diff.length - MAX_DIFF_CHARS;
    diff = `${diff.slice(0, head)}\n[...${omitted.toLocaleString()} chars omitted...]\n${diff.slice(-tail)}`;
  }

  return { filesAdded: added.length, filesRemoved: removed.length, filesChanged, diff };
}
