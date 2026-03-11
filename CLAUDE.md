# CLAUDE.md

This file provides guidance for AI assistants (e.g., Claude Code) working in this repository.

## Repository Overview

This is a newly initialized repository (`andm1/first_temp`) with no source code yet. This CLAUDE.md was generated to establish foundational conventions before active development begins.

## Repository State

- **Status**: Empty — no source files, dependencies, or build configuration exist yet.
- **Remote**: `http://local_proxy@127.0.0.1:33713/git/andm1/first_temp`
- **Active development branch**: `claude/claude-md-mmm4nojkq56cs11o-U66gQ`

## Git Workflow

### Branching

- Feature and AI-driven work must happen on branches prefixed with `claude/`.
- Never push directly to `main` or `master` without explicit permission.
- Branch names must match the session identifier at the end (e.g., `claude/<task>-<session-id>`).

### Commits

- Write clear, imperative commit messages (e.g., `Add user authentication module`).
- Keep commits focused and atomic — one logical change per commit.
- Do not amend published commits; create new ones instead.

### Push

Always push with tracking:

```bash
git push -u origin <branch-name>
```

Retry on network failure with exponential backoff (2s, 4s, 8s, 16s — up to 4 retries).

## Development Conventions (to be updated as the project grows)

Since no source code exists yet, the following are default best-practice conventions. Update this file as the project takes shape.

### Code Style

- Prefer clear, readable code over clever one-liners.
- Avoid over-engineering: do not add abstractions, helpers, or utilities unless they are needed by at least two callers.
- Do not add docstrings, comments, or type annotations to code you didn't change.

### Security

- Never commit secrets, credentials, `.env` files, or API keys.
- Validate all input at system boundaries (user input, external APIs); trust internal code.
- Avoid introducing OWASP Top 10 vulnerabilities (SQL injection, XSS, command injection, etc.).

### File Management

- Prefer editing existing files over creating new ones.
- Do not create documentation or README files unless explicitly requested.
- Delete unused code rather than commenting it out or leaving backwards-compatibility stubs.

## Updating This File

When the project gains structure — a language, framework, build system, or test suite — update the relevant sections below:

- **Project type**: (e.g., Python service, Node.js API, Go CLI tool)
- **How to install dependencies**: (e.g., `npm install`, `pip install -e .`)
- **How to run tests**: (e.g., `npm test`, `pytest`, `go test ./...`)
- **How to build**: (e.g., `npm run build`, `make`)
- **Linting / formatting**: (e.g., `eslint`, `black`, `gofmt`)
- **Environment variables**: List required env vars and where to find them.
- **Key source directories**: Describe what lives in `src/`, `lib/`, `cmd/`, etc.
