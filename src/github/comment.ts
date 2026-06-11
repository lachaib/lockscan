import { getOctokit } from '@actions/github';
import { COMMENT_MARKER } from './markdown.js';

type Octokit = ReturnType<typeof getOctokit>;

async function findExistingCommentId(
  octokit: Octokit,
  owner: string,
  repo: string,
  issueNumber: number,
): Promise<number | null> {
  const { data: comments } = await octokit.rest.issues.listComments({
    owner,
    repo,
    issue_number: issueNumber,
    per_page: 100,
  });
  return comments.find((c) => c.body?.includes(COMMENT_MARKER))?.id ?? null;
}

function splitRepo(repo: string): { owner: string; repo: string } {
  const [owner, name] = repo.split('/');
  if (!owner || !name) throw new Error(`Invalid repo format: "${repo}" (expected owner/name)`);
  return { owner, repo: name };
}

export async function postOrUpdateComment(
  markdown: string,
  prNumber: string,
  repo: string,
  token: string,
): Promise<void> {
  const octokit = getOctokit(token);
  const { owner, repo: repoName } = splitRepo(repo);
  const issueNumber = Number(prNumber);
  const body = `${COMMENT_MARKER}\n\n${markdown}`;

  const existingId = await findExistingCommentId(octokit, owner, repoName, issueNumber);
  if (existingId != null) {
    await octokit.rest.issues.updateComment({
      owner,
      repo: repoName,
      comment_id: existingId,
      body,
    });
  } else {
    await octokit.rest.issues.createComment({
      owner,
      repo: repoName,
      issue_number: issueNumber,
      body,
    });
  }
}

export async function resolvedComment(
  prNumber: string,
  repo: string,
  token: string,
): Promise<void> {
  const octokit = getOctokit(token);
  const { owner, repo: repoName } = splitRepo(repo);
  const issueNumber = Number(prNumber);

  const existingId = await findExistingCommentId(octokit, owner, repoName, issueNumber);
  if (existingId == null) return;

  const body =
    `${COMMENT_MARKER}\n\n` +
    `## 🔍 lockscan Security Report\n\n` +
    `✅ **All findings resolved.** No security findings in the latest dependency changes.\n`;

  await octokit.rest.issues.updateComment({ owner, repo: repoName, comment_id: existingId, body });
}
