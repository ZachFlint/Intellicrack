/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Zachary Flint
   This file is part of Intellicrack. See LICENSE for details.

   Every operation the engine exposes, grouped, each with a real argument form
   and a real result view.

   This panel is the coverage guarantee, and it is one only because nothing in it
   is written down. The groups come from Operation.group, the cards come from
   /api/catalog and the forms come from the parameter lists, so an operation
   cannot exist in the engine and be missing from this list. The meter reads
   /api/jobs, which counts synchronous invocations as well as background ones, so
   what it reports is what the session has actually run - and the un-exercised
   names are listed rather than merely counted, because a number alone does not
   tell you what to try next. */

import { listJobs } from './api.js';
import { buildForm, element, primeSuggestions } from './forms.js';
import { renderError, renderResult } from './renderers.js';


const PANEL_ID = 'panels.console';
const COVERAGE_REFRESH_MS = 1500;
const PERCENT = 100;
const RESULT_SETTLE_MS = 1400;

function badge(text, tone) {
  return element('span', tone ? `hb-badge ${tone}` : 'hb-badge', text);
}

function signature(operation) {
  const params = operation.parameters.map((parameter) => `${parameter.name}: ${parameter.annotation}`).join(', ');
  return `(${params}) -> ${operation.returns}`;
}

function receiverTone(receiver) {
  switch (receiver) {
    case 'factory':
      return 'is-success';
    case 'static':
      return 'is-info';
    case 'module':
      return 'is-accent';
    default:
      return '';
  }
}

/**
 * Build the operation console panel.
 *
 * @param {object} env Environment callbacks: catalogue, reference, form context,
 *   result context, an invoker and a toast function.
 * @returns {object} A panel descriptor the shell's dock can host.
 */
export function createOperationConsole(env) {
  let body = null;
  let subtitle = null;
  let meterFill = null;
  let meterText = null;
  let missingHost = null;
  let filterInput = null;
  let lastCoverage = 0;
  let exercised = new Set();
  let operationCount = 0;
  const cards = new Map();

  const refreshCoverage = () => {
    lastCoverage = performance.now();
    return listJobs(1)
      .then((payload) => {
        exercised = new Set(payload.exercised);
        operationCount = payload.operation_count;
        paintCoverage();
      })
      .catch(() => undefined);
  };

  const paintTab = (text) => {
    const tab = document.querySelector(`.hb-dock-tab[data-panel="${PANEL_ID}"]`);
    if (tab === null) {
      return;
    }
    const existing = tab.querySelector('.hb-dock-tab-count');
    if (existing === null) {
      tab.appendChild(element('span', 'hb-dock-tab-count', text));
      return;
    }
    existing.textContent = text;
  };

  const paintCoverage = () => {
    if (subtitle === null) {
      return;
    }
    const total = operationCount || cards.size;
    const share = total === 0 ? 0 : (exercised.size / total) * PERCENT;
    subtitle.textContent = `${exercised.size} / ${total} exercised this session`;
    paintTab(`${exercised.size}/${total}`);
    if (meterFill !== null) {
      meterFill.style.setProperty('--hb-seg', share.toFixed(3));
      meterFill.textContent = share >= 8 ? `${share.toFixed(0)}%` : '';
      meterText.textContent = `${total - exercised.size} still untouched`;
    }
    for (const [name, card] of cards) {
      card.tick.hidden = !exercised.has(name);
    }
    if (missingHost !== null) {
      missingHost.replaceChildren();
      const missing = [...cards.keys()].filter((name) => !exercised.has(name)).sort();
      for (const name of missing) {
        const chip = element('button', 'hb-badge is-mono', name);
        chip.type = 'button';
        chip.title = 'Open this operation';
        chip.addEventListener('click', () => open(name));
        missingHost.appendChild(chip);
      }
      if (missing.length === 0) {
        missingHost.appendChild(element('span', 'hb-badge is-success', 'every operation has been run'));
      }
    }
  };

  const open = (name) => {
    const card = cards.get(name);
    if (!card) {
      return;
    }
    card.expand();
    card.root.scrollIntoView({ block: 'center', behavior: 'smooth' });
  };

  const buildCard = (operation) => {
    const root = element('div', 'hb-opcard');
    const header = element('div', 'hb-opcard-header');
    const tick = badge('run', 'is-success');
    tick.hidden = true;

    const title = element('button', 'hb-grow hb-row-flex');
    title.type = 'button';
    title.style.textAlign = 'left';
    title.append(element('span', 'hb-op-name', operation.name), badge(operation.receiver, receiverTone(operation.receiver)));
    if (operation.mutating) {
      title.appendChild(badge('mutates', 'is-warning'));
    }
    header.append(title, tick);
    root.appendChild(header);

    const cardBody = element('div', 'hb-opcard-body');
    cardBody.hidden = true;
    cardBody.appendChild(element('div', 'hb-op-sig', signature(operation)));
    const formHost = element('div');
    const resultHost = element('div');
    cardBody.append(formHost, resultHost);

    const footer = element('div', 'hb-opcard-footer');
    footer.hidden = true;
    const runButton = element('button', 'hb-run is-idle', 'Run');
    runButton.type = 'button';
    const status = element('span', 'hb-dim');
    const reset = element('button', 'hb-btn is-sm is-ghost', 'reset to caret');
    reset.type = 'button';
    footer.append(runButton, reset, status);
    root.append(cardBody, footer);

    let form = null;
    const rebuild = () => {
      const context = env.formContext();
      form = buildForm(operation, env.reference(), context);
      formHost.replaceChildren(form.element);
    };

    const expand = () => {
      if (!cardBody.hidden) {
        return;
      }
      cardBody.hidden = false;
      footer.hidden = false;
      root.classList.add('is-open');
      if (form === null) {
        primeSuggestions(operation, env.formContext())
          .catch(() => undefined)
          .finally(rebuild);
        rebuild();
      }
    };
    const collapse = () => {
      cardBody.hidden = true;
      footer.hidden = true;
      root.classList.remove('is-open');
    };

    title.addEventListener('click', () => (cardBody.hidden ? expand() : collapse()));
    reset.addEventListener('click', rebuild);

    runButton.addEventListener('click', () => {
      if (form === null) {
        return;
      }
      let args;
      try {
        args = form.read();
      } catch (error) {
        status.textContent = error.message;
        return;
      }
      const handle = operation.receiver === 'document' ? env.formContext().handle : null;
      if (operation.receiver === 'document' && !handle) {
        status.textContent = 'this operation acts on an open document; none is active';
        return;
      }
      runButton.className = 'hb-run is-running';
      runButton.textContent = 'Running…';
      status.textContent = '';
      env.run(operation.name, args, handle)
        .then((result) => {
          runButton.className = 'hb-run is-done';
          runButton.textContent = 'Done';
          status.textContent = `${result.duration_ms.toFixed(2)} ms`;
          resultHost.replaceChildren(renderResult(operation.name, result, env.resultContext(args, handle)));
          exercised.add(operation.name);
          paintCoverage();
          refreshCoverage();
        })
        .catch((error) => {
          runButton.className = 'hb-run is-error';
          runButton.textContent = 'Failed';
          resultHost.replaceChildren(renderError(error));
        })
        .finally(() => {
          window.setTimeout(() => {
            runButton.className = operation.mutating ? 'hb-run is-mutating' : 'hb-run is-idle';
            runButton.textContent = operation.mutating ? 'Run (mutates)' : 'Run';
          }, RESULT_SETTLE_MS);
        });
    });

    return { root, tick, expand, operation };
  };

  const paint = () => {
    const catalog = env.catalog();
    if (body === null || catalog === null) {
      return;
    }
    body.replaceChildren();
    cards.clear();

    const meter = element('div', 'hb-stack');
    const bar = element('div', 'hb-segbar');
    meterFill = element('div', 'hb-segbar-seg bc-print');
    bar.appendChild(meterFill);
    meterText = element('span', 'hb-dim');
    const meterRow = element('div', 'hb-row-flex');
    meterRow.append(element('span', 'hb-panel-title', 'coverage'), meterText);
    meter.append(meterRow, bar);
    missingHost = element('div', 'hb-legend');
    meter.appendChild(missingHost);
    body.appendChild(meter);

    const grouped = new Map();
    for (const operation of catalog.operations) {
      const bucket = grouped.get(operation.group) ?? [];
      bucket.push(operation);
      grouped.set(operation.group, bucket);
    }

    for (const group of catalog.groups) {
      const operations = grouped.get(group) ?? [];
      if (operations.length === 0) {
        continue;
      }
      const heading = element('div', 'hb-op-group');
      heading.append(element('span', undefined, group), badge(String(operations.length)));
      body.appendChild(heading);
      const stack = element('div', 'hb-stack');
      for (const operation of operations) {
        const card = buildCard(operation);
        cards.set(operation.name, card);
        stack.appendChild(card.root);
      }
      body.appendChild(stack);
    }
    paintCoverage();
  };

  const applyFilter = () => {
    const needle = (filterInput?.value ?? '').trim().toLowerCase();
    for (const [name, card] of cards) {
      const match = needle === ''
        || name.toLowerCase().includes(needle)
        || card.operation.group.toLowerCase().includes(needle)
        || card.operation.returns.toLowerCase().includes(needle);
      card.root.hidden = !match;
    }
    for (const heading of body?.querySelectorAll('.hb-op-group') ?? []) {
      const stack = heading.nextElementSibling;
      heading.hidden = stack !== null && [...stack.children].every((child) => child.hidden);
    }
  };

  return {
    id: PANEL_ID,
    title: 'Operations',
    dock: 'bottom',
    side: 'bottom',
    order: 40,
    count: () => (operationCount === 0 ? null : `${exercised.size}/${operationCount}`),
    open,
    mount: (host) => {
      const header = element('div', 'hb-panel-header');
      header.appendChild(element('span', 'hb-panel-title', 'operation console'));
      subtitle = element('span', 'hb-panel-subtitle', 'reading the catalogue…');
      header.appendChild(subtitle);
      filterInput = document.createElement('input');
      filterInput.type = 'text';
      filterInput.className = 'hb-input is-narrow';
      filterInput.placeholder = 'filter';
      filterInput.spellcheck = false;
      filterInput.addEventListener('input', applyFilter);
      const actions = element('div', 'hb-panel-actions');
      const reload = element('button', 'hb-panel-action', '⟳');
      reload.type = 'button';
      reload.title = 'Re-read the catalogue and the coverage';
      reload.addEventListener('click', () => {
        paint();
        refreshCoverage();
      });
      actions.append(filterInput, reload);
      header.appendChild(actions);

      body = element('div', 'hb-panel-body is-padded hb-stack');
      host.append(header, body);
      paint();
      refreshCoverage();
    },
    update: () => {
      if (body !== null && cards.size === 0) {
        paint();
      }
      if (performance.now() - lastCoverage > COVERAGE_REFRESH_MS) {
        refreshCoverage();
      }
    },
  };
}
