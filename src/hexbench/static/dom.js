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

/**
 * Say something through the one polite live region the page owns.
 *
 * A page that has not declared the region is not a failure worth throwing over:
 * every caller is announcing a side effect of work it has already done.
 *
 * @param {string} text What to announce.
 * @returns {void}
 */
export function announce(text) {
  const region = document.getElementById(LIVE_REGION_ID);
  if (!region) {
    return;
  }
  region.textContent = String(text);
}
