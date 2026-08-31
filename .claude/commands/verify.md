---
description: Systematically reevaluate the previous response against the original request
    and standards
---

You must systematically re-evaluate your previous response and all code changes
against the original request and the critical standards defined in `CLAUDE.md`.
This verification is mandatory for ensuring production readiness and real-world
effectiveness.

Conduct a rigorous, line-by-line (you must read EVERY line of code that was
added/changed) review of your implementation using the following checklist. For
each point, you must explicitly confirm adherence or justify any deviation.

**1. Scope and Purpose Verification:** **_(Apply this section only if the
changes directly impact core analysis, tool integration, or bridge features.)_**

- [ ] **Primary Objective:** Does the implemented feature strengthen
      Intellicrack's role as a unified bridge for binary analysis tools, AI
      providers, and workflow orchestration?
- [ ] **Scope Limitation:** Confirm that the code introduces NO capabilities
      related to malware, system exploits, network attacks, or data theft.

**2. Production-Readiness and Functionality:**

- [ ] **No Placeholders:** Confirm that there are NO stubs, mocks, placeholders,
      `TODO` comments, or simulated implementations. All code must be fully
      functional and production-ready.
- [ ] **Real-World Effectiveness:** Is the implementation robust enough for
      real-world scenarios? It must not be a simplified or "example" version. It
      must be genuinely effective at its stated purpose.
- [ ] **Completeness:** Is the functionality completely implemented? Have all
      necessary edge cases and error conditions been handled with real, working
      code?

**3. Code Quality and Standards:**

- [ ] **Windows Compatibility:** Was the code written and tested for full,
      prioritized compatibility with Windows platforms?
- [ ] **Style and Conventions:** Does the code adhere strictly to the existing
      project's style, structure, naming conventions, and architectural
      patterns?
- [ ] **Docstrings:** Are all new public modules, functions, classes, and
      methods documented with informative docstrings that adhere to PEP 257
      standards?
- [ ] **Commenting:** Have you avoided all unnecessary comments? Comments should
      only exist to explain the _why_ behind complex logic, not the _what_.
- [ ] **Development Principles:** Does the code align with SOLID, DRY, and KISS
      principles where applicable?

**4. Error Handling and Robustness:**

- [ ] **Safe Access:** Are `getattr()` and `hasattr()` used for safe attribute
      access where appropriate?
- [ ] **Exception Handling:** Is error handling comprehensive? Are `try/except`
      blocks used for potential failures like I/O, network requests, or import
      errors? Are fallbacks graceful and functional?

**5. Verification and Testing:**

- [ ] **Testing:** Were new unit tests written to cover the changes? Do they
      validate both positive and negative cases, and do they always fail if the
      code does not perform, in real world scenarios, the task it was written
      for?
- [ ] **Real Data:** Do the tests use real data? They must use only real data.
      No mock, fake, simulated data that does not effectively test the code's
      ability to perform.
- [ ] **Test Execution:** Have all relevant tests been executed (`pytest`)?
      Confirm that all tests are passing.
- [ ] **Linting and Static Analysis:** Has the code been checked with the
      project's linter (`ruff check .`)? Confirm there are no new warnings or
      errors.
- [ ] **Type Checking:** Has the code been verified with basedpyright? Code must be
      absolutely and completely type correct with zero basedpyright findings
      acceptable. Confirm no type suppression comments (type-ignore directives,
      pyright-ignore directives, or any inline suppression mechanism) are
      present. Confirm the `[tool.basedpyright]` section in `pyproject.toml` has
      not been modified.

**Final Assessment:** Provide a concise summary of your verification.

- If all applicable criteria are met, explicitly state that the implementation
  is production-ready, providing specific examples from the code that
  demonstrate _how_ it meets key standards (e.g., "Error handling is robust, as
  shown by the `try...except` block in the `process_data` function").
- If any criteria are not met, you must provide a granular, step-by-step todo
  list detailing every specific change required to correct all violations. For
  each item, reference the failed checklist point. Do not proceed with
  corrections until you receive explicit approval.
