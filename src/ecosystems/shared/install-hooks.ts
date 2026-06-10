import type { InstallHook } from '../../types.js';
import type { FileMap } from '../../utils/extract.js';

/** npm lifecycle scripts that execute automatically during install. */
const NPM_INSTALL_SCRIPTS = new Set([
  'install',
  'preinstall',
  'postinstall',
  'prepare',
  'prepublish',
]);

export function detectNpmHooks(files: FileMap): InstallHook[] {
  const raw = files.get('package.json');
  if (!raw) return [];
  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return [];
  }
  const scripts = pkg.scripts as Record<string, string> | undefined;
  if (!scripts) return [];
  const hooks: InstallHook[] = [];
  for (const name of NPM_INSTALL_SCRIPTS) {
    const command = scripts[name];
    if (command) hooks.push({ type: 'npm-script', name, command, isNew: false, changed: false });
  }
  return hooks;
}

export function detectPythonWheelHooks(files: FileMap): InstallHook[] {
  const hooks: InstallHook[] = [];
  for (const [filename, content] of files) {
    // .pth files are executed by the site module on Python startup — can run arbitrary code
    if (filename.endsWith('.pth')) {
      hooks.push({
        type: 'pth-file',
        name: filename,
        command: content.slice(0, 300),
        isNew: false,
        changed: false,
      });
    }
    // Scripts in *.data/scripts/ are installed as executables into the Python bin directory
    if (/[.-]data[/\\]scripts[/\\]/.test(filename)) {
      hooks.push({
        type: 'data-script',
        name: filename,
        command: content.slice(0, 300),
        isNew: false,
        changed: false,
      });
    }
  }
  return hooks;
}

/**
 * Annotate new hooks with isNew/changed flags by comparing against old version hooks.
 * Returns only hooks that are new or modified.
 */
export function diffHooks(oldHooks: InstallHook[], newHooks: InstallHook[]): InstallHook[] {
  const oldByName = new Map(oldHooks.map((h) => [h.name, h]));
  return newHooks
    .map((h) => {
      const old = oldByName.get(h.name);
      return { ...h, isNew: !old, changed: !!old && old.command !== h.command };
    })
    .filter((h) => h.isNew || h.changed);
}

/** Returns all hooks, flagging any that are new compared to old version. */
export function annotateHooks(oldHooks: InstallHook[], newHooks: InstallHook[]): InstallHook[] {
  const oldByName = new Map(oldHooks.map((h) => [h.name, h]));
  return newHooks.map((h) => {
    const old = oldByName.get(h.name);
    return { ...h, isNew: !old, changed: !!old && old.command !== h.command };
  });
}
