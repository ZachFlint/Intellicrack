---
description: Review, merge, and clean up worktrees produced by the /batch skill. Invoke with /merge.
argument-hint: [branch-glob...] [--dry-run]
allowed-tools: Read, Glob, Grep, Bash, Agent, AskUserQuestion
---

You review, merge, and clean up the git worktrees that `/batch` produced. Work autonomously. Only escalate via `AskUserQuestion` on scope drift or unresolvable review failures.

## Arguments

`$ARGUMENTS` may contain:
- `--dry-run` — perform review but print "WOULD MERGE / WOULD REMOVE" instead of executing merges/removals
- One or more branch-name glob filters (e.g. `agent-a*`) to restrict which worktrees are processed

## Preflight

Run (stop with a clear message if any fails):
- `gh auth status`
- `git -C D:/Intellicrack rev-parse --abbrev-ref HEAD` must be `main`
- `git -C D:/Intellicrack fetch --prune origin`
- `git -C D:/Intellicrack status --porcelain` must be empty

## Discover

`git worktree list` and enumerate every `.claude/worktrees/agent-*`. For each worktree, determine:
- Branch name
- `commits_ahead` = `git rev-list --count main..<branch>`
- `is_dirty` = `git -C <path> status --porcelain` non-empty
- `pr_number` = `gh pr list --head <branch> --state all --json number,state --jq '.[0]'` (null if none)
- State:
  - `commits_ahead == 0` and branch tip is an ancestor of `origin/main` → **ALREADY_MERGED**
  - `commits_ahead == 0` otherwise → **EMPTY**
  - `is_dirty` → **DIRTY** (skip, leave alone)
  - else → **HAS_WORK**

Apply any glob filters from `$ARGUMENTS`. Print a table: branch | state | commits | PR#.

## Review (HAS_WORK only, in parallel)

For every HAS_WORK worktree, spawn a `worktree-reviewer` agent in parallel (one Agent tool call per worktree, all in a single message). Each spawn prompt MUST include the stated intent for that specific worktree — you (Claude running this skill) know what each `/batch` agent was asked to do because the `/batch` plan was produced earlier in this same session. Recall the per-worktree task from your session context and include it in the prompt:

```
Review worktree at <absolute_path> on branch <branch>.

Stated intent for this worktree (from the /batch plan Claude generated this session):
<the specific task assigned to the agent that worked in this worktree>

Commits: <output of git log --oneline main..<branch>>
Diff stat: <output of git diff --stat main..<branch>>
Changed files: <output of git diff --name-only main..<branch>>

Return a verdict. Your instructions are in your agent definition.
```

If you cannot recall a specific per-worktree intent (e.g. `/merge` was invoked in a fresh session, or the plan is no longer in context), spawn the reviewer without a stated intent and it will skip the scope-drift check — code-quality checks still run normally.

Collect each agent's final reply. The verdict is either `PASS` or `FAIL` followed by a bulleted list of reasons (scope drift, lint, type, docstring, tests, placeholder, suppression, config tampering, forbidden file).

## Act on verdicts

For each worktree:

- **PASS**: queue for merge.
- **FAIL with SCOPE_DRIFT**: `AskUserQuestion` with options: Revert out-of-scope changes then merge (recommended) / Merge everything / Abandon worktree / Leave for manual review. Show the agent's out-of-scope file list.
- **FAIL for any other reason**: `AskUserQuestion` with options: Abandon worktree (recommended) / Leave for manual review / Merge anyway (discouraged, warn it violates standards). Show the agent's reason list.

Record each decision in-memory for the summary.

## Merge (sequential, smallest diff first)

If `--dry-run`: print `WOULD MERGE: <branch>` for each, skip.

Otherwise, for each queued worktree:
1. `git -C <worktree_path> fetch origin main`
2. `git -C <worktree_path> rebase origin/main` — on conflict, `git rebase --abort` and flag as MANUAL_REVIEW_CONFLICT, continue.
3. If `pr_number` is open: `gh pr merge <pr_number> --squash --delete-branch --admin`
4. Else, from the primary repo on `main`:
   - `git merge --squash <branch>`
   - `git -c core.hooksPath=/dev/null commit --no-verify -m "<squashed subject>"` (user has opted out of pre-commit hooks for this pipeline)
   - `git push origin main`
   - `git push origin --delete <branch>` if the branch exists on the remote

## Cleanup (physical disk removal)

Cleanup queue = merged + abandoned + EMPTY + ALREADY_MERGED worktrees.

If `--dry-run`: print `WOULD REMOVE: <path>` for each, skip.

Otherwise, for each:
1. `git worktree remove <worktree_path> --force` — this physically deletes the directory, reclaiming disk. `--force` is required because worktrees contain `.pixi`, `.ruff_cache`, etc.
2. `git branch -D <branch>` if still present locally.
3. `gh pr close <pr_number>` only if the PR is still open and wasn't merged.

Finally: `git worktree prune` to clear the registry. Prune any `tmp-worktree-agent-*` branches whose commits are ancestors of `origin/main`.

## Summary

Print a plain summary to stdout:
- Merged: count + list of `<branch> → <pr# or squash sha>`
- Abandoned: count + list with reason
- Left for manual review: count + list with reason + path
- Removed from disk: count + total MB reclaimed (use `du -sm` before each removal)
- Conflicts: count + list

## Rules

- **No auto-fix.** Never spawn `/lint`, `/typecheck`, `/docstrings`, or any fixer. A failed review escalates to the user.
- **Sequential merges**; parallel merges conflict on the repo lock.
- **Never force-push.** Never touch main except for squash commits. No resets.
- **`--force` is mandatory** on `git worktree remove` (build artifacts block non-force).
- **Skip pre-commit hooks** on the squash commit (explicit user opt-out for this pipeline).
- **Agent spawn errors** — log and treat that worktree as "left for manual review". Do not crash.
