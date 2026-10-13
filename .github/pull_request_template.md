## What and why

<!-- What does this change, and what problem does it solve? Link issues with "Fixes #123". -->

## Checklist

- [ ] `pytest`, `ruff check .`, `ruff format --check .` and `mypy` pass
- [ ] New or changed detection has attack vectors in `tests/vectors/attacks.toml`
- [ ] `tests/vectors/benign.toml` still passes (and has new samples if relevant)
- [ ] Non-ASCII characters are written as escapes, never raw
- [ ] No technique ID was renumbered or reused
- [ ] `CHANGELOG.md` updated for user-visible changes
