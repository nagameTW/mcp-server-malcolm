<!-- Keep the summary short. The diff shows what changed; this box is for why. -->

## What this changes

<!-- One or two sentences. If it closes an issue, add "Closes #123". -->

## Why

<!-- The problem it solves, or the behavior it fixes. -->

## Type

- [ ] Bug fix
- [ ] New tool or feature
- [ ] Docs only
- [ ] Refactor or internal change
- [ ] CI / build

## If this touches write access

<!-- Skip this section for read-only changes. -->

- [ ] The new tool is additive (it does not delete data, remove a tag, or touch accounts)
- [ ] It sits behind an existing write class, or I've explained why it needs a new one
- [ ] Every write path emits an audit line

## Checklist

- [ ] `ruff check src tests` and `ruff format --check src tests` pass
- [ ] `pytest` passes, and I added tests for the change
- [ ] I updated the README (and README.zh-TW.md) if behavior or configuration changed
- [ ] I added a line under `[Unreleased]` in CHANGELOG.md
