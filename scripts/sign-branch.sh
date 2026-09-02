#!/usr/bin/env bash
# Sign (GPG) every commit on the current branch since <base> (default: main).
#
# WHY THIS EXISTS: `git rebase --exec 'git commit --amend -S' <base>` run cold can hang on
# pinentry INSIDE the rebase and strand the branch on the first commit (looks like the later
# commits vanished). This warms the gpg-agent FIRST, in the foreground, so the passphrase is
# cached before the rebase starts. See AGENTS.md and ElSereno .context/pitfalls.md (PITF-055).
#
# If a rebase ever gets stranded anyway, recover with:  git rebase --abort
#
# Usage:  scripts/sign-branch.sh [base]     # runnable from anywhere; base defaults to main
set -euo pipefail

# Operate on the repo this script lives in, regardless of the caller's working directory.
cd "$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "error: $(pwd) is not a git repository" >&2
  exit 1
fi

base="${1:-main}"
key="$(git config user.signingkey || true)"

echo "Warming gpg-agent (enter your passphrase if prompted)..."
if [ -n "${key}" ]; then
  echo warmup | gpg --local-user "${key}" --clearsign >/dev/null
else
  echo warmup | gpg --clearsign >/dev/null
fi

echo "Re-signing commits ${base}..HEAD ..."
if ! git rebase --exec 'git commit --amend --no-edit -S' "${base}"; then
  echo "Rebase failed. Recover the branch with: git rebase --abort" >&2
  exit 1
fi

echo "Done. Verify (want G on every line):"
git log --format='%h %G? %s' "${base}..HEAD"
