import * as core from '@actions/core';
import { context } from '@actions/github';
import { readFileSync, writeFileSync } from 'node:fs';
import { emitAnnotations } from './github/annotations.js';
import { postOrUpdateComment, resolvedComment } from './github/comment.js';
import { formatMarkdown } from './github/markdown.js';
import { generateSarif } from './github/sarif.js';
import { reportMaxSeverity, shouldFail } from './github/severity.js';
import { analyze } from './index.js';
import { parsePlatform } from './platforms.js';

(async () => {
  try {
    // --- Read lockdelta output ---
    const lockdeltaRaw = core.getInput('lockdelta-output', { required: true });
    let diffJson: string;
    // Inline JSON string (from a previous step output) or a file path.
    if (lockdeltaRaw.trimStart().startsWith('{')) {
      diffJson = lockdeltaRaw;
    } else {
      diffJson = readFileSync(lockdeltaRaw, 'utf-8');
    }
    const diffReport = JSON.parse(diffJson);

    // --- Parse options ---
    const platformInput = core.getInput('platform');
    const platforms = platformInput
      ? platformInput.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean).map(parsePlatform)
      : undefined;

    const onlyInput = core.getInput('only');
    const onlyTypes = onlyInput
      ? onlyInput.split(',').map((s) => s.trim()).filter(Boolean)
      : undefined;

    const githubToken = core.getInput('github-token');
    const repo = `${context.repo.owner}/${context.repo.repo}`;
    const workspace = process.env.GITHUB_WORKSPACE ?? process.cwd();
    const prNumber = context.payload.pull_request?.number;

    // --- Analyze ---
    const report = await analyze(diffReport, { platforms, onlyTypes });

    // --- Outputs ---
    core.setOutput('report', JSON.stringify(report));

    const maxSev = reportMaxSeverity(report);
    const hasFindings = maxSev !== null;
    core.setOutput('has-findings', String(hasFindings));
    core.setOutput('has-critical', String(maxSev === 'critical'));
    core.setOutput('has-high', String(maxSev === 'critical' || maxSev === 'high'));

    // --- Annotations ---
    if (core.getInput('annotate') !== 'false') {
      emitAnnotations(report, workspace);
    }

    // --- Markdown & step summary ---
    const wantsMarkdown = core.getInput('markdown') === 'true';
    const postCommentMode = core.getInput('post-comment'); // 'false' | 'true' | 'if-findings'
    const needsMarkdown = wantsMarkdown || postCommentMode !== 'false';

    let markdown = '';
    if (needsMarkdown) {
      markdown = formatMarkdown(report);
      core.setOutput('summary', markdown);

      const markdownFile = core.getInput('markdown-to-file');
      if (markdownFile) writeFileSync(markdownFile, markdown);
    }

    if (core.getInput('write-summary') !== 'false') {
      await core.summary.addRaw(markdown || formatMarkdown(report)).write();
    }

    // --- SARIF ---
    const sarifFile = core.getInput('sarif-to-file');
    if (sarifFile) {
      const sarif = generateSarif(report, workspace);
      writeFileSync(sarifFile, JSON.stringify(sarif, null, 2));
      core.setOutput('sarif', JSON.stringify(sarif));
    }

    // --- PR comment ---
    const postCommentEnabled = postCommentMode !== 'false';
    if (postCommentEnabled && !prNumber) {
      core.notice('post-comment is set but this run is not associated with a pull request — skipping comment');
    } else if (postCommentEnabled && prNumber) {
      const shouldPost =
        postCommentMode === 'true' || (postCommentMode === 'if-findings' && hasFindings);
      const shouldResolve = postCommentMode === 'if-findings' && !hasFindings;

      if (shouldPost) {
        await postOrUpdateComment(markdown || formatMarkdown(report), String(prNumber), repo, githubToken);
      } else if (shouldResolve) {
        await resolvedComment(String(prNumber), repo, githubToken);
      }
    }

    // --- fail-on ---
    const failOn = core.getInput('fail-on') || 'never';
    if (shouldFail(failOn, maxSev)) {
      core.setFailed(
        `lockscan: findings at severity '${maxSev}' detected (fail-on: ${failOn})`,
      );
      return;
    }

    const total = report.summary.analyzed;
    const eco = report.summary.ecosystems.join(', ') || 'none';
    core.notice(
      `lockscan: analyzed ${total} package(s) across ${eco}` +
        (hasFindings ? ` — ${maxSev?.toUpperCase()} severity findings detected` : ' — clean'),
    );
  } catch (err) {
    core.setFailed(err instanceof Error ? err.message : String(err));
  }
})();
