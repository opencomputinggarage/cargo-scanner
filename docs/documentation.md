# Documentation Update Guide

Keep user-facing documentation in sync with product changes. Any change that
adds, removes, renames, or changes behavior for a command, option, runtime,
scanner, report format, TUI screen, wizard step, installer flow, or update flow
must update the relevant docs in the same PR.

## Required Surfaces

- `README.md`: the shortest path for new users. Update this when the common
  workflow, install/update path, examples, or troubleshooting advice changes.
- `docs/usage.md`: command reference. Update this when flags, aliases,
  subcommands, defaults, or examples change.
- `site/src/main.tsx`: homepage copy and command examples. Update this when a
  feature should be visible to prospective users.
- Shell completion files in `cmd/cargo-scanner/completion_cmd.go`: update these
  when commands, subcommands, or flags change.

## Feature Change Checklist

For every user-facing feature change, answer these before merging:

- Does `cargo-scanner --help` still show the simplest path?
- Do README examples use the preferred current UX?
- Does `docs/usage.md` include any new flags, short aliases, or defaults?
- Does the homepage show the current first-run flow?
- Do shell completions include the new command or flag?
- Do non-interactive and CI users still have a plain command path?

## Writing Rules

- Prefer the easiest path first, then advanced options.
- Prefer short examples that users can run directly.
- Use short flags in quick examples when they improve readability, but include
  the long flag name in reference docs.
- Do not document every internal detail on the homepage.
- Keep README, usage docs, and homepage wording consistent.

## Verification

Run these before merging documentation-affecting changes:

```sh
go test ./...
cargo-scanner --help
cargo-scanner tui --print
```

```sh
cd site
pnpm build
```
