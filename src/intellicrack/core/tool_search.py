# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Search index over the live tool registry for dynamic tool loading.

Intellicrack's tool registry exposes hundreds of tool functions across seven bridges. Advertising all of them to an LLM provider on every
request is both too large for providers with a tool-count cap and wasteful of context budget. :class:`ToolSearchIndex` lets the
orchestrator's ``tools.search`` meta-tool resolve a natural-language query against the live registry so the model can discover and load only
the functions relevant to its current task.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from intellicrack.core.types import ToolDefinition, ToolFunction


_TOKEN_PATTERN = re.compile(r"[a-z0-9]+")

_FUNCTION_NAME_TOKEN_WEIGHT: float = 5.0
_TOOL_NAME_TOKEN_WEIGHT: float = 2.0
_DESCRIPTION_TOKEN_WEIGHT: float = 1.0
_FUNCTION_NAME_SUBSTRING_BONUS: float = 3.0
_DESCRIPTION_SUBSTRING_BONUS: float = 1.5
_BRIDGE_NAME_BOOST: float = 4.0

_DEFAULT_SEARCH_LIMIT: int = 10

_QUERY_STOPWORDS: frozenset[str] = frozenset({
    "a",
    "an",
    "the",
    "at",
    "in",
    "on",
    "of",
    "to",
    "for",
    "with",
    "and",
    "or",
    "is",
    "are",
    "be",
    "this",
    "that",
    "it",
    "as",
    "by",
    "from",
    "into",
    "using",
    "via",
})
"""Common English filler words excluded from query token matching.

A multi-word natural-language query (``"set a breakpoint at an address"``)
otherwise scores every function whose description happens to contain
``"a"`` or ``"at"``, drowning genuinely relevant matches in unrelated noise.
Filtering these out of the *query* only (never out of function names or
descriptions, which are matched as written) keeps token overlap scoring
meaningful for real natural-language queries.
"""


def _tokenize(text: str) -> list[str]:
    """Split text into normalized, lowercase alphanumeric tokens.

    Args:
        text: Raw text to tokenize (a query, function name, or description).

    Returns:
        list[str]: Lowercase alphanumeric tokens, punctuation and whitespace
        stripped out entirely rather than treated as token boundaries kept
        as separate empty entries.
    """
    return _TOKEN_PATTERN.findall(text.lower())


def _tokenize_query(text: str) -> set[str]:
    """Tokenize a search query, excluding common filler words.

    Args:
        text: Raw natural-language search query.

    Returns:
        set[str]: Normalized query tokens with :data:`_QUERY_STOPWORDS`
        removed.
    """
    return {token for token in _tokenize(text) if token not in _QUERY_STOPWORDS}


@dataclass(frozen=True, slots=True)
class ToolSearchMatch:
    """A single ranked tool-function search hit.

    Attributes:
        tool_name: Namespace of the bridge that owns ``function``.
        function: The matched :class:`ToolFunction` definition.
        score: Relevance score assigned by :meth:`ToolSearchIndex.search`;
            higher scores rank first.
    """

    tool_name: str
    function: ToolFunction
    score: float


class ToolSearchIndex:
    """Ranks tool functions from a registry snapshot against a text query.

    The index is a thin wrapper over a list of :class:`ToolDefinition` instances (typically :meth:`ToolRegistry.get_tool_definitions`'s live
    result) rather than a persistent structure: the registry rarely changes within a session, and re-scanning a few hundred functions per
    query is fast enough that no incremental index maintenance is worth the complexity.
    """

    def __init__(self, definitions: list[ToolDefinition]) -> None:
        """Build a search index snapshot from a list of tool definitions.

        Args:
            definitions: Tool definitions to index, as returned by
                :meth:`ToolRegistry.get_tool_definitions`.
        """
        self._definitions = definitions

    def search(self, query: str, *, limit: int = _DEFAULT_SEARCH_LIMIT) -> list[ToolSearchMatch]:
        """Rank every indexed function against ``query`` and return the top matches.

        Scoring combines three signals: token overlap against the function's
        leaf name (weighted highest), its owning bridge's name, and its
        description (weighted lowest); a substring bonus when the raw query
        appears verbatim in the function name or description; and a flat
        boost when the query names the owning bridge directly (e.g.
        ``"frida hook"`` boosts every Frida function). A query with no
        alphanumeric content and no non-empty text matches nothing.

        Args:
            query: Natural-language search query (e.g. ``"set a breakpoint"``).
            limit: Maximum number of matches to return.

        Returns:
            list[ToolSearchMatch]: Up to ``limit`` matches with positive
            score, ordered by descending score; ties keep the registry's
            original definition/function order for determinism.
        """
        query_tokens = _tokenize_query(query)
        lowered_query = query.lower().strip()
        if not query_tokens and not lowered_query:
            return []

        scored: list[ToolSearchMatch] = []
        for definition in self._definitions:
            tool_name_tokens = set(_tokenize(definition.tool_name))
            bridge_hit = bool(query_tokens & tool_name_tokens) or (bool(lowered_query) and definition.tool_name in lowered_query)
            for func in definition.functions:
                score = self._score_function(
                    func=func,
                    query_tokens=query_tokens,
                    lowered_query=lowered_query,
                    tool_name_tokens=tool_name_tokens,
                    bridge_hit=bridge_hit,
                )
                if score > 0:
                    scored.append(ToolSearchMatch(tool_name=definition.tool_name, function=func, score=score))

        scored.sort(key=lambda match: -match.score)
        return scored[:limit]

    @staticmethod
    def _score_function(
        *,
        func: ToolFunction,
        query_tokens: set[str],
        lowered_query: str,
        tool_name_tokens: set[str],
        bridge_hit: bool,
    ) -> float:
        """Score a single function against a tokenized and raw query.

        Args:
            func: The candidate function to score.
            query_tokens: Normalized tokens from the search query.
            lowered_query: The raw query, lowercased and stripped, used for
                substring matching.
            tool_name_tokens: Normalized tokens from the owning bridge's
                :class:`ToolName` value.
            bridge_hit: Whether the query already matched the owning
                bridge's name, used to apply :data:`_BRIDGE_NAME_BOOST`.

        Returns:
            float: The combined relevance score; ``0.0`` or below means no
            match.
        """
        leaf_name = func.name.split(".", maxsplit=1)[-1] if "." in func.name else func.name
        name_tokens = set(_tokenize(leaf_name))
        description_tokens = set(_tokenize(func.description))

        score = 0.0
        score += _FUNCTION_NAME_TOKEN_WEIGHT * len(query_tokens & name_tokens)
        score += _TOOL_NAME_TOKEN_WEIGHT * len(query_tokens & tool_name_tokens)
        score += _DESCRIPTION_TOKEN_WEIGHT * len(query_tokens & description_tokens)

        if lowered_query:
            if lowered_query in leaf_name.lower():
                score += _FUNCTION_NAME_SUBSTRING_BONUS
            if lowered_query in func.description.lower():
                score += _DESCRIPTION_SUBSTRING_BONUS

        if bridge_hit:
            score += _BRIDGE_NAME_BOOST

        return score

    def search_grouped(self, query: str, *, limit: int = _DEFAULT_SEARCH_LIMIT) -> list[ToolDefinition]:
        """Search and regroup the top matches back into per-bridge tool definitions.

        Args:
            query: Natural-language search query.
            limit: Maximum number of matched functions to return in total,
                across every bridge.

        Returns:
            list[ToolDefinition]: One :class:`ToolDefinition` per bridge that
            contributed at least one match, carrying only its matched
            functions in their original registry order. Bridges are ordered
            by the rank of their best-scoring match.
        """
        matches = self.search(query, limit=limit)
        if not matches:
            return []

        matched_names_by_tool: dict[str, set[str]] = {}
        order: list[str] = []
        for match in matches:
            if match.tool_name not in matched_names_by_tool:
                matched_names_by_tool[match.tool_name] = set()
                order.append(match.tool_name)
            matched_names_by_tool[match.tool_name].add(match.function.name)

        definition_by_name = {definition.tool_name: definition for definition in self._definitions}
        grouped: list[ToolDefinition] = []
        for tool_name in order:
            source = definition_by_name.get(tool_name)
            if source is None:
                continue
            matched_functions = [func for func in source.functions if func.name in matched_names_by_tool[tool_name]]
            if matched_functions:
                grouped.append(
                    ToolDefinition(
                        tool_name=source.tool_name,
                        description=source.description,
                        functions=matched_functions,
                    ),
                )
        return grouped
