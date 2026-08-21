/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Zachary Flint
   This file is part of Intellicrack. See LICENSE for details.

   The element factory every other module builds its markup from, kept here
   because three byte-identical copies of it had grown across the application
   and none of them could set an attribute - which is what an accessible name,
   a role or a live-region hint has to be.

   Two rules this module exists to hold rather than to document. An icon-only
   button whose whole content is a glyph has no name at all for a screen
   reader, so iconButton refuses to build one without a label rather than
   letting an unnameable control reach the page. And a dialog that leaves the
   keyboard free to walk out from under its own scrim strands the user in a
   page they cannot see, so trapFocus keeps Tab inside the overlay and puts
   focus back where it found it.

   Nothing here reads `document` or `window` at module scope. charts.js imports
   this file, and the charts suite loads charts.js under plain node with no DOM
   of any kind, so a single module-level DOM reference would break that suite at
   import time. This module imports nothing for the same reason. */

const FOCUSABLE_SELECTORS = [
  'a[href]',
  'area[href]',
  'button:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  'iframe',
  'audio[controls]',
  'video[controls]',
  '[contenteditable]:not([contenteditable="false"])',
  '[tabindex]:not([tabindex="-1"])',
];

const FOCUSABLE_SELECTOR = FOCUSABLE_SELECTORS.join(', ');
const LIVE_REGION_ID = 'live';
const TAB_KEY = 'Tab';
const HIDDEN_TRUE = 'true';

/* Longer than the interval a held key repeats at, so a user arrowing across
   the grid is told where they landed rather than every offset they crossed. */
const ANNOUNCE_DELAY_MS = 200;
const ANNOUNCE_SEPARATOR = ', ';

let identitySequence = 0;

/* ------------------------------------------------------------- primitives */

/**
 * Create an element, optionally with a class, text content and attributes.
 *
 * @param {string} tag Tag name.
 * @param {string} [className] Class attribute.
 * @param {string} [text] Text content.
 * @param {Object<string, string|number|boolean>} [attrs] Attributes to set, each value stringified.
 * @returns {HTMLElement} The new element.
 */
export function element(tag, className, text, attrs) {
  const node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  if (text !== undefined) {
    node.textContent = text;
  }
  if (attrs) {
    for (const [name, value] of Object.entries(attrs)) {
      node.setAttribute(name, String(value));
    }
  }
  return node;
}

/**
 * A document-unique identifier, for the aria wiring that needs one on a node that has none.
 *
 * @param {string} prefix Readable prefix the identifier is built from.
 * @returns {string} An identifier no other call returns.
 */
export function nextId(prefix) {
  identitySequence += 1;
  return `${prefix}-${identitySequence}`;
}

/**
 * A span holding a glyph that carries no meaning of its own.
 *
 * @param {string} text Glyph to show.
 * @param {string} [className] Class attribute.
 * @returns {HTMLElement} A span hidden from assistive technology.
 */
export function decorativeGlyph(text, className) {
  return element('span', className, text, { 'aria-hidden': HIDDEN_TRUE });
}

/**
 * A button whose visible content is a glyph and whose name is `label`.
 *
 * The glyph is hidden from assistive technology and the label supplies both the
 * accessible name and the tooltip, so the button reads the same way to a
 * pointer and to a screen reader.
 *
 * @param {string} glyph Glyph shown inside the button.
 * @param {string} label Accessible name, also used as the tooltip.
 * @param {(event: MouseEvent) => void} [onClick] Click handler.
 * @param {string} [className] Class attribute.
 * @returns {HTMLElement} The new button.
 * @throws {TypeError} When `label` is absent or blank.
 */
export function iconButton(glyph, label, onClick, className) {
  if (typeof label !== 'string' || label.trim() === '') {
    throw new TypeError('iconButton needs a non-empty label: a glyph-only button without one has no accessible name');
  }
  const node = element('button', className, undefined, { type: 'button', title: label, 'aria-label': label });
  node.appendChild(decorativeGlyph(glyph));
  if (onClick) {
    node.addEventListener('click', onClick);
  }
  return node;
}

/* -------------------------------------------------------------- tab strips */

/**
 * The elements of `strip` that stand for a tab, in visual order.
 *
 * Read from the strip's own children rather than by descendant query, because a
 * document tab carries a close button tagged with the same key attribute and a
 * descendant query would return both.
 *
 * @param {HTMLElement} strip Element holding the tabs.
 * @param {string} keyAttribute Dataset key each tab is identified by.
 * @returns {HTMLElement[]} The tab elements, excluding any child without the key.
 */
function tabsOf(strip, keyAttribute) {
  return [...strip.children].filter((node) => node.getAttribute(`data-${keyAttribute}`) !== null);
}

/**
 * Give a rendered strip the roles, names and roving tabindex a tablist owes.
 *
 * Called after every render rather than once at wiring time: both strips in
 * this application rebuild their children wholesale, so the roles have to be
 * reapplied to the new nodes.
 *
 * @param {HTMLElement} strip Element holding the tabs.
 * @param {Object} options Wiring description.
 * @param {string} options.keyAttribute Dataset key each tab is identified by.
 * @param {string|null} options.activeKey Key of the selected tab, or null when none is.
 * @param {HTMLElement} [options.panel] Element the tabs control, given `role="tabpanel"`.
 * @param {string} [options.label] Accessible name for the strip itself.
 * @returns {void}
 */
export function applyTabStripRoles(strip, options) {
  const { keyAttribute, activeKey, panel, label } = options;
  strip.setAttribute('role', 'tablist');
  if (label) {
    strip.setAttribute('aria-label', label);
  }
  let activeTab = null;
  for (const tab of tabsOf(strip, keyAttribute)) {
    const selected = tab.getAttribute(`data-${keyAttribute}`) === activeKey;
    if (!tab.getAttribute('id')) {
      tab.setAttribute('id', nextId('tab'));
    }
    tab.setAttribute('role', 'tab');
    tab.setAttribute('aria-selected', selected ? 'true' : 'false');
    tab.setAttribute('tabindex', selected ? '0' : '-1');
    if (panel) {
      if (!panel.getAttribute('id')) {
        panel.setAttribute('id', nextId('tabpanel'));
      }
      tab.setAttribute('aria-controls', panel.getAttribute('id'));
    }
    if (selected) {
      activeTab = tab;
    }
  }
  if (!panel) {
    return;
  }
  panel.setAttribute('role', 'tabpanel');
  if (activeTab) {
    panel.setAttribute('aria-labelledby', activeTab.getAttribute('id'));
  } else {
    panel.removeAttribute('aria-labelledby');
  }
}

/**
 * Bind the tablist keyboard contract to `strip`, once, at construction.
 *
 * Selection follows focus, which is what the ARIA pattern calls automatic
 * activation and what both strips here already do on click. Because activating
 * re-renders the strip and discards the element the browser was focusing, focus
 * is re-sought by key afterwards rather than kept on the stale node.
 *
 * @param {HTMLElement} strip Element holding the tabs.
 * @param {Object} options Wiring description.
 * @param {string} options.keyAttribute Dataset key each tab is identified by.
 * @param {(key: string) => void} options.onActivate Called with the key of the tab to select.
 * @param {(key: string) => void} [options.onClose] Called with the key of the tab Delete should close.
 * @param {string} [options.ignoreSelector] Descendants matching this keep their own Enter and Space.
 * @returns {void}
 */
export function wireTabStrip(strip, options) {
  const { keyAttribute, onActivate, onClose, ignoreSelector } = options;

  const focusKey = (key) => {
    const target = tabsOf(strip, keyAttribute).find((tab) => tab.getAttribute(`data-${keyAttribute}`) === key);
    if (target && typeof target.focus === 'function') {
      target.focus();
    }
  };

  const select = (key) => {
    onActivate(key);
    focusKey(key);
  };

  strip.addEventListener('keydown', (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) {
      return;
    }
    const tab = target.closest(`[data-${keyAttribute}]`);
    if (!tab || !strip.contains(tab)) {
      return;
    }
    const tabs = tabsOf(strip, keyAttribute);
    const index = tabs.indexOf(tab);
    if (index === -1) {
      return;
    }
    const keyOf = (node) => node.getAttribute(`data-${keyAttribute}`);

    switch (event.key) {
      case 'ArrowRight':
      case 'ArrowDown':
        event.preventDefault();
        select(keyOf(tabs[(index + 1) % tabs.length]));
        return;
      case 'ArrowLeft':
      case 'ArrowUp':
        event.preventDefault();
        select(keyOf(tabs[(index - 1 + tabs.length) % tabs.length]));
        return;
      case 'Home':
        event.preventDefault();
        select(keyOf(tabs[0]));
        return;
      case 'End':
        event.preventDefault();
        select(keyOf(tabs[tabs.length - 1]));
        return;
      case 'Delete':
        if (onClose) {
          event.preventDefault();
          onClose(keyOf(tab));
        }
        return;
      case 'Enter':
      case ' ':
        if (ignoreSelector && target.closest(ignoreSelector)) {
          return;
        }
        event.preventDefault();
        onActivate(keyOf(tab));
        return;
      default:
        break;
    }
  });
}

/* ------------------------------------------------------------------ focus */

function focusableWithin(overlay) {
  return [...overlay.querySelectorAll(FOCUSABLE_SELECTOR)].filter(
    (node) => !node.hasAttribute('disabled') && !node.hasAttribute('hidden') && node.getAttribute('aria-hidden') !== HIDDEN_TRUE,
  );
}

function restoreFocus(node) {
  if (node && typeof node.focus === 'function' && node.isConnected) {
    node.focus();
  }
}

/**
 * Hold keyboard focus inside `overlay` until the trap is released.
 *
 * The focusable descendants are queried on each Tab rather than once here,
 * because a dialog fills its body after it is shown and a list captured at trap
 * time would name controls that no longer exist and miss the ones that do.
 *
 * @param {HTMLElement} overlay Element the keyboard must stay inside.
 * @returns {{release: () => void}} Removes the trap and restores focus to whatever held it.
 */
export function trapFocus(overlay) {
  const previous = document.activeElement;

  const onKeyDown = (event) => {
    if (event.key !== TAB_KEY) {
      return;
    }
    const focusable = focusableWithin(overlay);
    if (focusable.length === 0) {
      event.preventDefault();
      return;
    }
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    const active = document.activeElement;
    const index = overlay.contains(active) ? focusable.indexOf(active) : -1;
    if (index === -1) {
      event.preventDefault();
      (event.shiftKey ? last : first).focus();
      return;
    }
    if (event.shiftKey && index === 0) {
      event.preventDefault();
      last.focus();
      return;
    }
    if (!event.shiftKey && index === focusable.length - 1) {
      event.preventDefault();
      first.focus();
    }
  };

  document.addEventListener('keydown', onKeyDown, true);

  return {
    release() {
      document.removeEventListener('keydown', onKeyDown, true);
      restoreFocus(previous);
    },
  };
}

/* ------------------------------------------------------------ live region */

/* Two concerns announcing at once is the failure this section exists to
   prevent. The region says one thing at a time: written twice in a row it
   reads as one run-on sentence, and rewritten with the text it already holds
   it is read out again by some screen readers. So the values that change while
   the user works - the caret, the selection, the hit counter - do not write it
   directly. Each names a channel and hands over its latest reading; every
   reading that arrives inside one debounce window is spoken as a single
   sentence, ordered by when the channel was first seen so the sentence keeps
   its shape from one announcement to the next. A channel whose reading has not
   changed since it was last spoken is left out of that sentence rather than
   repeated, which is what keeps one concern's change from dragging the others
   back through the region behind it. */

const pendingByChannel = new Map();
const spokenByChannel = new Map();
const channelOrder = new Map();

let announceTimer = null;
let lastAnnouncement = null;

/**
 * Say something through the one polite live region the page owns.
 *
 * A page that has not declared the region is not a failure worth throwing over:
 * every caller is announcing a side effect of work it has already done. The
 * caller is told whether it was heard so that a queued announcement is not
 * counted as spoken when there was nowhere to speak it.
 *
 * @param {string} text What to announce.
 * @returns {boolean} True when the region existed and now holds `text`.
 */
export function announce(text) {
  const region = document.getElementById(LIVE_REGION_ID);
  if (!region) {
    return false;
  }
  const message = String(text);
  region.textContent = message;
  lastAnnouncement = message;
  return true;
}

function flushAnnouncements() {
  announceTimer = null;
  const changed = [...pendingByChannel]
    .filter(([channel, text]) => spokenByChannel.get(channel) !== text)
    .sort(([left], [right]) => channelOrder.get(left) - channelOrder.get(right));
  pendingByChannel.clear();
  if (changed.length === 0) {
    return;
  }
  const message = changed.map(([, text]) => text).join(ANNOUNCE_SEPARATOR);
  if (message === lastAnnouncement || !announce(message)) {
    return;
  }
  for (const [channel, text] of changed) {
    spokenByChannel.set(channel, text);
  }
}

/**
 * Offer a channel's latest reading to the live region, to be spoken once the
 * changes have stopped.
 *
 * Nothing is said immediately: the reading replaces whatever that channel was
 * last waiting to say, and the window is reopened, so a value that changes on
 * every keystroke is announced when it settles rather than while it moves.
 *
 * @param {string} channel Name of the concern the reading belongs to, one per caller.
 * @param {string} text The reading as it should be spoken; blank means the channel has nothing to say.
 * @returns {void}
 * @throws {TypeError} When `channel` is absent or blank, which would merge unrelated concerns into one slot.
 */
export function announceChange(channel, text) {
  if (typeof channel !== 'string' || channel.trim() === '') {
    throw new TypeError('announceChange needs a non-empty channel: unnamed readings would overwrite each other in one slot');
  }
  const message = text === undefined || text === null ? '' : String(text).trim();
  if (message === '') {
    return;
  }
  if (!channelOrder.has(channel)) {
    channelOrder.set(channel, channelOrder.size);
  }
  pendingByChannel.set(channel, message);
  if (announceTimer !== null) {
    clearTimeout(announceTimer);
  }
  announceTimer = setTimeout(flushAnnouncements, ANNOUNCE_DELAY_MS);
}
