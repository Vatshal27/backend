# SentinelAI — Focused Coding Rules

Operate only on the task I explicitly request. Do not independently expand scope.

- Before accessing file contents, list only relevant filenames and explain which files you need.
- Read the minimum relevant files and line ranges; do not dump or scan the entire repository unless I explicitly request it.
- Avoid repeating file reads of unchanged content. Exclude node_modules, .git, dist, build, coverage, logs, generated assets and large dependency lockfiles from broad searches unless essential.
- Do not launch subagents or parallel investigations without my explicit approval for this task.
- Before modifying files, state a brief plan. Do not edit unrelated files.
- Run only targeted tests; ask before installing dependencies, running full test suites, Docker-based tests, or initiating network calls.
- Stop after two unsuccessful attempts at the same operation and explain the blocker.
- When the requested change and necessary verification are complete, summarize changed files and tests, then stop.
- If a task needs more than 10 tool calls, ask before continuing. This is a behavioral limit, not a technical enforcement mechanism.
- Never read or transmit .env, secrets, keys, tokens, or credentials without explicit necessity and permission.
