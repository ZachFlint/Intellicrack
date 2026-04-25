# False Positive Report - Unit 7 (providers/)

## Summary

77 findings resolved. 1 finding flagged as a false positive (cannot be fixed
without breaking abstract method semantics).

## False Positives

### 1. `src/intellicrack/providers/base.py` line 235 — `intellicrack-logging-i5-provider-completion-without-model`

**Finding**: The rule flags `async def chat(self, ...)` for missing a log call
that includes a `model=` kwarg.

**Why this is a false positive**: The `chat` method on `LLMProviderBase` is
declared `@abstractmethod`. Its body is intentionally empty (a docstring only)
because subclasses provide the concrete implementation. Abstract methods cannot
contain log emission - any log call would never execute and would obscure the
abstract contract. Concrete subclasses (`AnthropicProvider.chat`,
`OpenAIProvider.chat`, `GoogleProvider.chat`, `OllamaProvider.chat`,
`GrokProvider.chat`, `OpenRouterProvider.chat`,
`HuggingFaceProvider.chat`, `LocalTransformersProvider.chat`) all emit the
required `model=` kwargs in their own log calls.

**Resolution**: No code change. The rule's pattern-not clauses do not exclude
abstract methods, but adding `pattern-not-inside: @abstractmethod` clauses to
the rule would be a config edit (out of scope). Concrete provider chat
implementations satisfy the rule's intent at runtime.
