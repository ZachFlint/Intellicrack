## Description

Please include a summary of the changes and which issue is fixed. Include
relevant motivation and context.

Fixes # (issue)

## Type of change

Please delete options that are not relevant.

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to
      not work as expected)
- [ ] Documentation update

## Checklist

- [ ] `just lint` reports no findings
- [ ] `just ruff-fmt` leaves the tree unchanged
- [ ] `just basedpyright` reports zero errors, warnings, and notes
- [ ] `just pydoclint` and `just pydocstyle` report zero violations
- [ ] No type or lint suppressions were added (`type: ignore`, `pyright: ignore`, `noqa`)
- [ ] Every change is covered by a test that fails when the behaviour breaks
- [ ] Tests exercise real inputs - no mocks, stubs, or placeholder implementations
- [ ] Tests live under `tests/` in the subdirectory matching the code under test
- [ ] `just test` passes locally
- [ ] Documentation was updated wherever behaviour changed

## Screenshots (if applicable)

Please add screenshots to help explain your changes.

## Additional context

Add any other context about the pull request here.
