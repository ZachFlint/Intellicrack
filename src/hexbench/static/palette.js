/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Zachary Flint
   This file is part of Intellicrack. See LICENSE for details.

   The command palette is generated from /api/catalog and nothing else, so it
   covers every operation the engine exposes and gains new ones the moment the
   Rust crate grows them. There is no list of commands in this file. */

const CONSECUTIVE_BONUS = 6;
const BOUNDARY_BONUS = 4;
const LEADING_PENALTY = 0.4;
const LABEL_WEIGHT = 0.85;
const MAX_RESULTS = 200;
const BOUNDARIES = new Set(['_', ' ', '.', '-']);

function humanLabel(name) {
  const words = name.split('_').filter(Boolean);
  if (words.length === 0) {
    return name;
  }
  const [first, ...rest] = words;
  return [first.charAt(0).toUpperCase() + first.slice(1), ...rest].join(' ');
}

function signature(operation) {
  const args = operation.parameters.map((parameter) => `${parameter.name}: ${parameter.annotation}`).join(', ');
  return `(${args}) -> ${operation.returns}`;
}

/**
 * Score a subsequence match, or return null when the query is not one.
 *
 * The score rewards runs of adjacent characters and matches that land on a word
 * boundary, which is what makes `sb` prefer `search_bytes` over `set_bit`'s
 * scattered letters.
 */
export function fuzzyMatch(query, text) {
  if (query === '') {
    return { score: 0, positions: [] };
  }
  const haystack = text.toLowerCase();
  const needle = query.toLowerCase();
  const positions = [];
  let score = 0;
  let cursor = 0;
  let previous = -2;
  for (const character of needle) {
    const found = haystack.indexOf(character, cursor);
    if (found < 0) {
      return null;
    }
    positions.push(found);
    score += 1;
    if (found === previous + 1) {
      score += CONSECUTIVE_BONUS;
    }
    if (found === 0 || BOUNDARIES.has(haystack[found - 1])) {
      score += BOUNDARY_BONUS;
    }
    previous = found;
    cursor = found + 1;
  }
  return { score: score - positions[0] * LEADING_PENALTY, positions };
}

function markup(text, positions) {
  const marked = new Set(positions);
  const fragment = document.createDocumentFragment();
  let run = '';
  let runMarked = false;
  const flush = () => {
    if (run === '') {
      return;
    }
    if (runMarked) {
      const span = document.createElement('span');
      span.className = 'hb-match';
      span.textContent = run;
      fragment.appendChild(span);
    } else {
      fragment.appendChild(document.createTextNode(run));
    }
    run = '';
  };
  for (let index = 0; index < text.length; index += 1) {
    const isMarked = marked.has(index);
    if (isMarked !== runMarked) {
      flush();
      runMarked = isMarked;
    }
    run += text[index];
  }
  flush();
  return fragment;
}

/** Ctrl+Shift+P: every catalogued operation, searchable. */
export class CommandPalette {
  #host;
  #onRun;
  #onOpen;
  #operations = [];
  #groups = [];
  #matches = [];
  #active = 0;
  #open = false;

  #overlay;
  #input;
  #results;
  #count;

  constructor(host, handlers = {}) {
    this.#host = host;
    this.#onRun = handlers.onRun ?? (() => undefined);
    this.#onOpen = handlers.onOpen ?? (() => undefined);
    this.#build();
  }

  /** Take the catalogue the palette searches over. */
  setCatalog(catalog) {
    this.#groups = catalog.groups;
    this.#operations = catalog.operations.map((operation) => ({
      operation,
      label: humanLabel(operation.name),
      signature: signature(operation),
      tag: operation.mutating ? 'mutating' : operation.receiver,
    }));
    if (this.#open) {
      this.#refresh();
    }
  }

  get isOpen() {
    return this.#open;
  }

  #build() {
    this.#overlay = document.createElement('div');
    this.#overlay.className = 'hbx-overlay';
    this.#overlay.hidden = true;

    const scrim = document.createElement('div');
    scrim.className = 'hb-scrim';
    scrim.addEventListener('mousedown', () => this.close());

    const panel = document.createElement('div');
    panel.className = 'hb-palette';

    const field = document.createElement('div');
    field.className = 'hb-palette-field';
    const glyph = document.createElement('span');
    glyph.className = 'hb-palette-glyph';
    glyph.textContent = '›';
    this.#input = document.createElement('input');
    this.#input.className = 'hb-palette-input';
    this.#input.type = 'text';
    this.#input.spellcheck = false;
    this.#input.autocomplete = 'off';
    this.#input.placeholder = 'Run an operation';
    this.#input.setAttribute('aria-label', 'Command');
    field.append(glyph, this.#input);

    this.#results = document.createElement('div');
    this.#results.className = 'hb-palette-results';

    const footer = document.createElement('div');
    footer.className = 'hb-palette-footer';
    footer.append(
      this.#hint(['↑', '↓'], 'navigate'),
      this.#hint(['↵'], 'run'),
      this.#hint(['Esc'], 'dismiss'),
    );
    const spacer = document.createElement('span');
    spacer.className = 'hb-grow';
    this.#count = document.createElement('span');
    footer.append(spacer, this.#count);

    panel.append(field, this.#results, footer);
    this.#overlay.append(scrim, panel);
    this.#host.appendChild(this.#overlay);

    this.#input.addEventListener('input', () => this.#refresh());
    this.#input.addEventListener('keydown', (event) => this.#onKeyDown(event));
    this.#results.addEventListener('mousedown', (event) => this.#onResultsMouseDown(event));
  }

  #hint(keys, text) {
    const wrapper = document.createElement('span');
    for (const key of keys) {
      const kbd = document.createElement('span');
      kbd.className = 'hb-kbd';
      kbd.textContent = key;
      wrapper.appendChild(kbd);
    }
    wrapper.appendChild(document.createTextNode(` ${text}`));
    return wrapper;
  }

  /** Show the palette, optionally with the query already filled in. */
  open(initialQuery = '') {
    this.#open = true;
    this.#overlay.hidden = false;
    this.#input.value = initialQuery;
    this.#refresh();
    this.#input.focus();
    this.#input.select();
  }

  /** Hide the palette. */
  close() {
    if (!this.#open) {
      return;
    }
    this.#open = false;
    this.#overlay.hidden = true;
  }

  #onKeyDown(event) {
    switch (event.key) {
      case 'Escape':
        event.preventDefault();
        this.close();
        return;
      case 'ArrowDown':
        event.preventDefault();
        this.#moveActive(1);
        return;
      case 'ArrowUp':
        event.preventDefault();
        this.#moveActive(-1);
        return;
      case 'Home':
        event.preventDefault();
        this.#setActive(0);
        return;
      case 'End':
        event.preventDefault();
        this.#setActive(this.#matches.length - 1);
        return;
      case 'Enter':
        event.preventDefault();
        this.#launch(this.#active);
        return;
      default:
        break;
    }
  }

  #onResultsMouseDown(event) {
    const target = event.target;
    if (!(target instanceof HTMLElement)) {
      return;
    }
    const item = target.closest('.hb-palette-item');
    if (!item || item.dataset.index === undefined) {
      return;
    }
    event.preventDefault();
    this.#launch(Number(item.dataset.index));
  }

  #launch(index) {
    const match = this.#matches[index];
    if (!match) {
      return;
    }
    this.close();
    if (match.entry.operation.parameters.length === 0) {
      this.#onRun(match.entry.operation);
      return;
    }
    this.#onOpen(match.entry.operation.name);
  }

  #moveActive(delta) {
    if (this.#matches.length === 0) {
      return;
    }
    const next = (this.#active + delta + this.#matches.length) % this.#matches.length;
    this.#setActive(next);
  }

  #setActive(index) {
    if (this.#matches.length === 0) {
      return;
    }
    this.#active = Math.max(0, Math.min(index, this.#matches.length - 1));
    const items = this.#results.querySelectorAll('.hb-palette-item');
    for (const item of items) {
      const isActive = Number(item.dataset.index) === this.#active;
      item.classList.toggle('is-active', isActive);
      if (isActive) {
        item.scrollIntoView({ block: 'nearest' });
      }
    }
  }

  #refresh() {
    const query = this.#input.value.trim();
    const scored = [];
    for (const entry of this.#operations) {
      const byLabel = fuzzyMatch(query, entry.label);
      const byName = fuzzyMatch(query, entry.operation.name);
      if (byLabel === null && byName === null) {
        continue;
      }
      const labelScore = byLabel === null ? -Infinity : byLabel.score * LABEL_WEIGHT;
      const nameScore = byName === null ? -Infinity : byName.score;
      const useName = nameScore >= labelScore;
      scored.push({
        entry,
        score: Math.max(labelScore, nameScore),
        positions: useName ? byName.positions : [],
        text: entry.operation.name,
      });
    }
    scored.sort((left, right) => right.score - left.score || left.text.localeCompare(right.text));
    this.#matches = scored.slice(0, MAX_RESULTS);
    this.#active = 0;
    this.#renderResults(query);
  }

  #renderResults(query) {
    this.#results.replaceChildren();
    if (this.#matches.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'hb-empty';
      const title = document.createElement('div');
      title.className = 'hb-empty-title';
      title.textContent = 'No operation matches';
      const hint = document.createElement('div');
      hint.className = 'hb-empty-hint';
      hint.textContent = `Nothing in the catalogue is a fuzzy match for "${query}".`;
      empty.append(title, hint);
      this.#results.appendChild(empty);
      this.#count.textContent = `0 of ${this.#operations.length} operations`;
      return;
    }

    const order = query === '' ? this.#groups : this.#orderedGroups();
    const buckets = new Map(order.map((group) => [group, []]));
    for (let index = 0; index < this.#matches.length; index += 1) {
      const match = this.#matches[index];
      const bucket = buckets.get(match.entry.operation.group);
      if (bucket) {
        bucket.push(index);
      }
    }

    const fragment = document.createDocumentFragment();
    for (const group of order) {
      const bucket = buckets.get(group) ?? [];
      if (bucket.length === 0) {
        continue;
      }
      const heading = document.createElement('div');
      heading.className = 'hb-palette-group';
      heading.textContent = group;
      fragment.appendChild(heading);
      for (const index of bucket) {
        fragment.appendChild(this.#renderItem(index));
      }
    }
    this.#results.appendChild(fragment);
    this.#count.textContent = `${this.#matches.length} of ${this.#operations.length} operations`;
    this.#setActive(0);
  }

  #orderedGroups() {
    const seen = [];
    for (const match of this.#matches) {
      const group = match.entry.operation.group;
      if (!seen.includes(group)) {
        seen.push(group);
      }
    }
    return seen;
  }

  #renderItem(index) {
    const match = this.#matches[index];
    const item = document.createElement('button');
    item.type = 'button';
    item.className = index === this.#active ? 'hb-palette-item is-active' : 'hb-palette-item';
    item.dataset.index = String(index);

    const mark = document.createElement('span');
    mark.className = 'hb-palette-mark';
    mark.textContent = '▸';

    const name = document.createElement('span');
    name.className = 'hb-palette-name';
    name.appendChild(markup(match.entry.operation.name, match.positions));

    const sig = document.createElement('span');
    sig.className = 'hb-palette-sig';
    sig.textContent = match.entry.signature;

    const tag = document.createElement('span');
    tag.className = 'hb-palette-tag';
    tag.textContent = match.entry.tag;

    item.append(mark, name, sig, tag);
    return item;
  }
}
