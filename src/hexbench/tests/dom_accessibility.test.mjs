/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * Gates the accessibility contract dom.js exists to hold, in two halves.
 *
 * The first half is behavioural. dom.js touches no DOM at module scope, so a
 * `globalThis.document` stub assigned before the dynamic import is enough to
 * call `element`, `decorativeGlyph`, `iconButton`, `trapFocus`, the two tab
 * strip helpers and both announcement calls for real. The stub is a genuine
 * (small) node model rather than a set of recording spies: attributes are
 * stored verbatim so `element`'s own `String(value)` is what is being
 * observed, `focus()` really moves `document.activeElement`, `contains()` and
 * `closest()` really walk the parent chain, and `querySelectorAll` really
 * matches the tag/class/attribute/`:not()` selector list dom.js hands it. Only
 * the three things the browser owns and the module does not -- creating a
 * node, dispatching an event to the registered listeners, and running a timer
 * -- are modelled here, and the live region is a real node whose writes are
 * counted, because saying a thing twice is the failure the queue exists to
 * prevent and a write nobody counted cannot be seen.
 *
 * The second half reads the other modules as text. It is the half that stops
 * the rules regressing somewhere dom.js cannot see: a glyph-only button built
 * by hand instead of through `iconButton`, a tooltip with no accessible name
 * beside it, a second live region, a caret readout written into the first one
 * undebounced, or an overlay that never says it is a dialog.
 *
 * Run by gate.ps1. Exits non-zero on the first failed expectation.
 */

import { readdir, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const failures = [];

function check(label, condition, detail) {
  if (!condition) {
    failures.push(`${label}: ${detail}`);
  }
}

/* ============================================================ the node model */

const SELECTOR_PART = /^([a-z]+)?((?:\.[\w-]+|\[[^\]]*\]|:not\([^)]*\))*)$/;
const SELECTOR_STEP = /\.([\w-]+)|\[([^\]]*)\]|:not\(([^)]*)\)/g;
const ATTRIBUTE_STEP = /^([A-Za-z][\w-]*)(?:="([^"]*)")?$/;

function matchesSelector(node, selector) {
  const parsed = SELECTOR_PART.exec(selector.trim());
  if (parsed === null) {
    throw new Error(`the node model cannot evaluate the selector ${selector}`);
  }
  if (parsed[1] !== undefined && node.localName !== parsed[1]) {
    return false;
  }
  for (const step of parsed[2].matchAll(SELECTOR_STEP)) {
    if (step[3] !== undefined) {
      if (matchesSelector(node, step[3])) {
        return false;
      }
      continue;
    }
    if (step[1] !== undefined) {
      if (!String(node.className).split(/\s+/).includes(step[1])) {
        return false;
      }
      continue;
    }
    const attribute = ATTRIBUTE_STEP.exec(step[2]);
    if (attribute === null) {
      throw new Error(`the node model cannot evaluate the attribute selector [${step[2]}]`);
    }
    if (!node.hasAttribute(attribute[1])) {
      return false;
    }
    if (attribute[2] !== undefined && node.getAttribute(attribute[1]) !== attribute[2]) {
      return false;
    }
  }
  return true;
}

class FakeNode {
  constructor(tag) {
    this.localName = tag;
    this.tagName = tag.toUpperCase();
    this.attributes = new Map();
    this.children = [];
    this.parent = null;
    this.listeners = new Map();
    this.className = '';
    this.textContent = '';
    this.isConnected = true;
  }

  setAttribute(name, value) {
    this.attributes.set(name, value);
  }

  getAttribute(name) {
    return this.attributes.has(name) ? this.attributes.get(name) : null;
  }

  hasAttribute(name) {
    return this.attributes.has(name);
  }

  removeAttribute(name) {
    this.attributes.delete(name);
  }

  closest(selector) {
    for (let cursor = this; cursor !== null && cursor !== undefined; cursor = cursor.parent) {
      if (matchesSelector(cursor, selector)) {
        return cursor;
      }
    }
    return null;
  }

  appendChild(node) {
    node.parent = this;
    this.children.push(node);
    return node;
  }

  append(...nodes) {
    for (const node of nodes) {
      this.appendChild(node);
    }
  }

  addEventListener(type, handler) {
    const bucket = this.listeners.get(type) ?? [];
    bucket.push(handler);
    this.listeners.set(type, bucket);
  }

  dispatch(type, event) {
    for (const handler of this.listeners.get(type) ?? []) {
      handler(event);
    }
  }

  contains(node) {
    for (let cursor = node; cursor !== null && cursor !== undefined; cursor = cursor.parent) {
      if (cursor === this) {
        return true;
      }
    }
    return false;
  }

  focus() {
    globalThis.document.activeElement = this;
  }

  descendants() {
    const found = [];
    for (const child of this.children) {
      found.push(child, ...child.descendants());
    }
    return found;
  }

  querySelectorAll(selector) {
    const parts = selector.split(',');
    return this.descendants().filter((node) => parts.some((part) => matchesSelector(node, part)));
  }
}

const fakeDocument = {
  activeElement: null,
  listeners: [],
  byId: new Map(),
  createElement(tag) {
    return new FakeNode(tag);
  },
  getElementById(id) {
    return this.byId.has(id) ? this.byId.get(id) : null;
  },
  addEventListener(type, handler, capture) {
    this.listeners.push({ type, handler, capture: Boolean(capture) });
  },
  removeEventListener(type, handler, capture) {
    const at = this.listeners.findIndex(
      (entry) => entry.type === type && entry.handler === handler && entry.capture === Boolean(capture),
    );
    if (at >= 0) {
      this.listeners.splice(at, 1);
    }
  },
};

globalThis.document = fakeDocument;
globalThis.window = { location: { search: '' } };
/* wireTabStrip refuses a keydown whose target is not an element, so the model
   has to be the element type this page has: with no HTMLElement in scope every
   key would be discarded and the strip's whole keyboard contract would look
   like it passed by doing nothing. */
globalThis.HTMLElement = FakeNode;

function pressTab(shiftKey = false) {
  let prevented = false;
  const event = {
    key: 'Tab',
    shiftKey,
    preventDefault() {
      prevented = true;
    },
  };
  for (const entry of [...fakeDocument.listeners]) {
    if (entry.type === 'keydown') {
      entry.handler(event);
    }
  }
  return prevented;
}

function refusalOf(action) {
  try {
    action();
  } catch (error) {
    return error;
  }
  return null;
}

const { announce, announceChange, applyTabStripRoles, decorativeGlyph, element, iconButton, trapFocus, wireTabStrip } = await import('../static/dom.js');

/* ------------------------------------------------ 1: iconButton names itself */

const clicks = [];
const dismiss = iconButton('✕', 'Dismiss notification', (event) => clicks.push(event), 'hb-toast-close');

check(
  'iconButton gives the button the label it was handed as its accessible name',
  dismiss.getAttribute('aria-label') === 'Dismiss notification',
  `expected aria-label "Dismiss notification", got ${JSON.stringify(dismiss.getAttribute('aria-label'))}`,
);
check(
  'the accessible name is a non-empty string, not a present-but-blank attribute',
  typeof dismiss.getAttribute('aria-label') === 'string' && dismiss.getAttribute('aria-label').trim() !== '',
  'an aria-label that is present but blank names the control no better than no label at all',
);
check(
  'the same label also becomes the pointer tooltip',
  dismiss.getAttribute('title') === 'Dismiss notification',
  `a glyph button must read the same way to a pointer and a screen reader; title was ${JSON.stringify(dismiss.getAttribute('title'))}`,
);
check('iconButton stamps type=button', dismiss.getAttribute('type') === 'button', `expected type="button", got ${JSON.stringify(dismiss.getAttribute('type'))}`);
check('iconButton passes the class through', dismiss.className === 'hb-toast-close', `expected class hb-toast-close, got ${JSON.stringify(dismiss.className)}`);
check(
  'the button itself is not hidden from assistive technology',
  dismiss.getAttribute('aria-hidden') === null,
  'hiding the button rather than its glyph would remove the control from the accessibility tree entirely',
);

check('iconButton builds exactly one child, the glyph', dismiss.children.length === 1, `expected 1 child, got ${dismiss.children.length}`);
const dismissGlyph = dismiss.children[0];
check(
  'the glyph inside the button is hidden from assistive technology',
  dismissGlyph !== undefined && dismissGlyph.getAttribute('aria-hidden') === 'true',
  `the glyph must carry aria-hidden="true" so it is not read out beside the label; got ${JSON.stringify(dismissGlyph?.getAttribute('aria-hidden'))}`,
);
check('the glyph still carries the visible character', dismissGlyph !== undefined && dismissGlyph.textContent === '✕', `expected the glyph text ✕, got ${JSON.stringify(dismissGlyph?.textContent)}`);

dismiss.dispatch('click', { type: 'click' });
check('iconButton wires the click handler it was given', clicks.length === 1, `expected the handler to run once, it ran ${clicks.length} time(s)`);

const noHandler = refusalOf(() => iconButton('⟳', 'Refresh'));
check('iconButton is happy to build a button with no handler', noHandler === null, `an omitted onClick must not be an error, got ${noHandler}`);

const missingLabel = refusalOf(() => iconButton('✕'));
check(
  'iconButton refuses a button with no label at all',
  missingLabel instanceof TypeError,
  `the refusal is the whole enforcement mechanism; expected a TypeError, got ${missingLabel === null ? 'a button' : missingLabel}`,
);
const emptyLabel = refusalOf(() => iconButton('✕', ''));
check('iconButton refuses an empty label', emptyLabel instanceof TypeError, `expected a TypeError, got ${emptyLabel === null ? 'a button' : emptyLabel}`);
const blankLabel = refusalOf(() => iconButton('✕', '   '));
check(
  'iconButton refuses a label that is only whitespace',
  blankLabel instanceof TypeError,
  `a whitespace label reads as no name at all; expected a TypeError, got ${blankLabel === null ? 'a button' : blankLabel}`,
);
const numericLabel = refusalOf(() => iconButton('✕', 42));
check('iconButton refuses a label that is not a string', numericLabel instanceof TypeError, `expected a TypeError, got ${numericLabel === null ? 'a button' : numericLabel}`);
check(
  'the refusal says why, so the next caller does not have to read dom.js to find out',
  missingLabel instanceof TypeError && /label/i.test(missingLabel.message) && /accessible name/i.test(missingLabel.message),
  `expected the message to name the label and the accessible name, got ${JSON.stringify(missingLabel?.message)}`,
);

/* -------------------------------------------- 2: decorativeGlyph hides itself */

const glyph = decorativeGlyph('⟳', 'hb-panel-glyph');
check('decorativeGlyph hides the glyph from assistive technology', glyph.getAttribute('aria-hidden') === 'true', `expected aria-hidden="true", got ${JSON.stringify(glyph.getAttribute('aria-hidden'))}`);
check('decorativeGlyph builds a span', glyph.localName === 'span', `expected a span, got ${glyph.localName}`);
check('decorativeGlyph keeps the visible character', glyph.textContent === '⟳', `expected ⟳, got ${JSON.stringify(glyph.textContent)}`);
check('decorativeGlyph passes the class through', glyph.className === 'hb-panel-glyph', `expected class hb-panel-glyph, got ${JSON.stringify(glyph.className)}`);
const bareGlyph = decorativeGlyph('…');
check('decorativeGlyph hides the glyph even with no class given', bareGlyph.getAttribute('aria-hidden') === 'true', 'the class argument is optional; hiding the glyph is not');

/* ---------------------------------------------------- 3: trapFocus holds Tab */

const overlay = fakeDocument.createElement('div');
const firstControl = fakeDocument.createElement('button');
const middleControl = fakeDocument.createElement('input');
const lastControl = fakeDocument.createElement('button');
overlay.append(firstControl, middleControl, lastControl);

const outside = fakeDocument.createElement('button');
outside.focus();
check('the node model reports focus before the trap is installed', fakeDocument.activeElement === outside, 'the stub must model activeElement for real or nothing below means anything');

const trap = trapFocus(overlay);
check('trapFocus registers exactly one document keydown listener', fakeDocument.listeners.length === 1, `expected 1 listener, got ${fakeDocument.listeners.length}`);
check(
  'the listener is registered in the capture phase',
  fakeDocument.listeners[0]?.type === 'keydown' && fakeDocument.listeners[0]?.capture === true,
  'a bubble-phase listener can be cancelled by anything inside the dialog before the trap ever sees the key',
);

lastControl.focus();
const wrappedForward = pressTab();
check('Tab from the last control is intercepted', wrappedForward === true, 'the trap must call preventDefault or the browser moves focus out of the dialog anyway');
check(
  'Tab from the last control wraps to the first',
  fakeDocument.activeElement === firstControl,
  `focus escaped the overlay instead of wrapping; activeElement is ${fakeDocument.activeElement === lastControl ? 'still the last control' : 'somewhere else'}`,
);

firstControl.focus();
const wrappedBackward = pressTab(true);
check('Shift+Tab from the first control is intercepted', wrappedBackward === true, 'the trap must call preventDefault or Shift+Tab leaves the dialog');
check('Shift+Tab from the first control wraps to the last', fakeDocument.activeElement === lastControl, 'focus escaped the overlay instead of wrapping backwards');

middleControl.focus();
const middlePrevented = pressTab();
check(
  'Tab in the middle of the dialog is left to the browser',
  middlePrevented === false,
  'a trap that swallows every Tab makes the dialog unnavigable rather than merely inescapable',
);
check('Tab in the middle of the dialog does not move focus itself', fakeDocument.activeElement === middleControl, 'the trap moved focus on a key it should have passed through');

outside.focus();
const pulledBack = pressTab();
check('Tab from outside the trapped overlay is intercepted', pulledBack === true, 'a Tab pressed while focus sits outside the dialog must be claimed by the trap');
check('Tab from outside the trapped overlay pulls focus into it', fakeDocument.activeElement === firstControl, `expected the first control inside the overlay, focus stayed outside: ${fakeDocument.activeElement === outside}`);

lastControl.focus();
trap.release();
check('release() removes the keydown listener it added', fakeDocument.listeners.length === 0, `expected 0 listeners after release, got ${fakeDocument.listeners.length}`);
check(
  'release() returns focus to whatever held it before the trap',
  fakeDocument.activeElement === outside,
  `expected focus back on the element that was active before trapFocus ran; it is on ${fakeDocument.activeElement === lastControl ? 'the last dialog control' : 'some other node'}`,
);

lastControl.focus();
const afterRelease = pressTab();
check('a released trap no longer claims Tab', afterRelease === false, 'the keydown handler survived release(), so a dismissed dialog still steals the keyboard');
check('a released trap no longer moves focus', fakeDocument.activeElement === lastControl, 'the released handler still wrapped focus');

const emptyOverlay = fakeDocument.createElement('div');
const emptyTrap = trapFocus(emptyOverlay);
const emptyPrevented = pressTab();
check('Tab inside an overlay with nothing focusable is swallowed', emptyPrevented === true, 'an empty dialog must still not let Tab walk out behind its own scrim');
check('Tab inside an overlay with nothing focusable moves nothing', fakeDocument.activeElement === lastControl, 'there was nothing to focus, so focus should not have moved');
emptyTrap.release();

/* Each unreachable control is placed at both ends of its own overlay, because
 * that is the only arrangement where counting it as focusable is observable:
 * it changes which control is first and which is last, and therefore whether
 * Tab at either end is intercepted at all. */
for (const [reason, attribute, value] of [['a disabled', 'disabled', ''], ['a hidden', 'hidden', ''], ['an aria-hidden', 'aria-hidden', 'true']]) {
  const guarded = fakeDocument.createElement('div');
  const head = fakeDocument.createElement('button');
  const tail = fakeDocument.createElement('button');
  head.setAttribute(attribute, value);
  tail.setAttribute(attribute, value);
  const opening = fakeDocument.createElement('button');
  const closing = fakeDocument.createElement('button');
  guarded.append(head, opening, fakeDocument.createElement('input'), closing, tail);

  const guardedTrap = trapFocus(guarded);
  closing.focus();
  const forward = pressTab();
  check(
    `${reason} control at the end of a dialog is not treated as focusable`,
    forward === true && fakeDocument.activeElement === opening,
    `Tab from the last reachable control must wrap to the first; it ${forward ? 'wrapped onto the unreachable control' : 'was not intercepted at all, so the trap thinks the unreachable control comes after it'}`,
  );
  opening.focus();
  const backward = pressTab(true);
  check(
    `${reason} control at the start of a dialog is not treated as focusable`,
    backward === true && fakeDocument.activeElement === closing,
    `Shift+Tab from the first reachable control must wrap to the last; it ${backward ? 'wrapped onto the unreachable control' : 'was not intercepted at all, so the trap thinks the unreachable control comes before it'}`,
  );
  guardedTrap.release();
}

check('every trap installed by this suite has been released', fakeDocument.listeners.length === 0, `expected 0 listeners, got ${fakeDocument.listeners.length}`);

/* ------------------------------------------------- 4: element applies attrs */

const attributed = element('div', 'hb-x', 'body text', { role: 'dialog', 'aria-modal': 'true', 'data-index': 7, 'data-flag': false });
check('element applies a string attribute from the 4th argument', attributed.getAttribute('role') === 'dialog', `expected role="dialog", got ${JSON.stringify(attributed.getAttribute('role'))}`);
check('element applies a hyphenated ARIA attribute', attributed.getAttribute('aria-modal') === 'true', `expected aria-modal="true", got ${JSON.stringify(attributed.getAttribute('aria-modal'))}`);
check('element stringifies a numeric attribute value', attributed.getAttribute('data-index') === '7', `expected the string "7", got ${JSON.stringify(attributed.getAttribute('data-index'))}`);
check('element stringifies a false attribute value rather than dropping it', attributed.getAttribute('data-flag') === 'false', `expected the string "false", got ${JSON.stringify(attributed.getAttribute('data-flag'))}`);
check('element applies every entry it was given', attributed.attributes.size === 4, `expected 4 attributes, got ${attributed.attributes.size}`);
check('element still sets the class alongside the attributes', attributed.className === 'hb-x', `expected class hb-x, got ${JSON.stringify(attributed.className)}`);
check('element still sets the text alongside the attributes', attributed.textContent === 'body text', `expected "body text", got ${JSON.stringify(attributed.textContent)}`);

const classic = element('span', 'hb-y', 'plain');
check('the classic three-argument call still sets the class', classic.className === 'hb-y', `expected class hb-y, got ${JSON.stringify(classic.className)}`);
check('the classic three-argument call still sets the text', classic.textContent === 'plain', `expected "plain", got ${JSON.stringify(classic.textContent)}`);
check('the classic three-argument call sets no attributes', classic.attributes.size === 0, `an omitted attrs argument must set nothing, got ${classic.attributes.size} attribute(s)`);
check('the classic three-argument call builds the requested tag', classic.localName === 'span', `expected a span, got ${classic.localName}`);

const minimal = element('div');
check('a tag-only call sets no class', minimal.className === '', `expected no class, got ${JSON.stringify(minimal.className)}`);
check('a tag-only call sets no attributes', minimal.attributes.size === 0, `expected no attributes, got ${minimal.attributes.size}`);
const emptyText = element('div', undefined, '');
check('an explicit empty text is still applied', emptyText.textContent === '', 'element must distinguish an empty string from an omitted text argument');

/* --------------------------------------- 5: the tab strip helpers build a tablist */

const PANEL_KEY = 'panel';
const DOCK_KEYS = ['strings', 'log', 'entropy'];

function renderStrip(strip, keyAttribute, keys) {
  strip.children = [];
  for (const key of keys) {
    strip.appendChild(element('button', 'hb-dock-tab', key, { [`data-${keyAttribute}`]: key }));
  }
}

function tabNamed(strip, keyAttribute, key) {
  return strip.children.find((node) => node.getAttribute(`data-${keyAttribute}`) === key) ?? null;
}

function pressOn(strip, target, key) {
  let prevented = false;
  strip.dispatch('keydown', {
    key,
    target,
    preventDefault() {
      prevented = true;
    },
  });
  return prevented;
}

const dockStrip = element('div', 'hb-dock-tabs');
const dockBody = element('div', 'hb-dock-body');
const dockRoles = (activeKey) => applyTabStripRoles(dockStrip, { keyAttribute: PANEL_KEY, activeKey, panel: dockBody, label: 'Bottom dock panels' });

renderStrip(dockStrip, PANEL_KEY, DOCK_KEYS);
dockRoles('strings');

check('applyTabStripRoles declares the strip a tablist', dockStrip.getAttribute('role') === 'tablist', `expected role="tablist", got ${JSON.stringify(dockStrip.getAttribute('role'))}`);
check('applyTabStripRoles names the strip', dockStrip.getAttribute('aria-label') === 'Bottom dock panels', `a tablist with no name is announced as an unlabelled group; got ${JSON.stringify(dockStrip.getAttribute('aria-label'))}`);
check(
  'every tab is given the tab role',
  dockStrip.children.every((tab) => tab.getAttribute('role') === 'tab'),
  `the dock's buttons still announce themselves as buttons: ${dockStrip.children.map((tab) => tab.getAttribute('role')).join(', ')}`,
);
check(
  'exactly one tab reports itself selected',
  dockStrip.children.filter((tab) => tab.getAttribute('aria-selected') === 'true').length === 1,
  `expected one aria-selected="true"; got ${dockStrip.children.map((tab) => tab.getAttribute('aria-selected')).join(', ')}`,
);
check('the selected tab is the one named by activeKey', tabNamed(dockStrip, PANEL_KEY, 'strings')?.getAttribute('aria-selected') === 'true', 'aria-selected is on a tab other than the active one');
check(
  'the unselected tabs say so rather than saying nothing',
  dockStrip.children.filter((tab) => tab.getAttribute('aria-selected') === 'false').length === DOCK_KEYS.length - 1,
  'a tab with no aria-selected at all is read as neither selected nor unselected',
);
check(
  'the roving tabindex puts the strip on one tab stop',
  dockStrip.children.filter((tab) => tab.getAttribute('tabindex') === '0').length === 1
    && dockStrip.children.filter((tab) => tab.getAttribute('tabindex') === '-1').length === DOCK_KEYS.length - 1,
  `every tab being reachable by Tab costs one press per open panel; got ${dockStrip.children.map((tab) => tab.getAttribute('tabindex')).join(', ')}`,
);
check('the reachable tab is the selected one', tabNamed(dockStrip, PANEL_KEY, 'strings')?.getAttribute('tabindex') === '0', 'Tab lands on a tab the strip does not consider selected');
check(
  'every tab is given an identifier of its own',
  new Set(dockStrip.children.map((tab) => tab.getAttribute('id'))).size === DOCK_KEYS.length
    && dockStrip.children.every((tab) => (tab.getAttribute('id') ?? '') !== ''),
  `aria-labelledby needs an id that names exactly one tab; got ${dockStrip.children.map((tab) => tab.getAttribute('id')).join(', ')}`,
);
check('the dock body is declared the tab panel', dockBody.getAttribute('role') === 'tabpanel', `expected role="tabpanel", got ${JSON.stringify(dockBody.getAttribute('role'))}`);
check(
  'every tab points at the panel it controls',
  dockStrip.children.every((tab) => tab.getAttribute('aria-controls') === dockBody.getAttribute('id') && (dockBody.getAttribute('id') ?? '') !== ''),
  `aria-controls must name the panel's own id; got ${dockStrip.children.map((tab) => tab.getAttribute('aria-controls')).join(', ')} against panel id ${JSON.stringify(dockBody.getAttribute('id'))}`,
);
check(
  'the panel is named by the selected tab',
  dockBody.getAttribute('aria-labelledby') === tabNamed(dockStrip, PANEL_KEY, 'strings')?.getAttribute('id'),
  `expected the panel to be labelled by the active tab; got ${JSON.stringify(dockBody.getAttribute('aria-labelledby'))}`,
);

const firstIdentifiers = dockStrip.children.map((tab) => tab.getAttribute('id'));
renderStrip(dockStrip, PANEL_KEY, DOCK_KEYS);
dockRoles('log');
check(
  'a re-rendered strip gets the roles again rather than keeping them on the discarded nodes',
  dockStrip.children.every((tab) => tab.getAttribute('role') === 'tab'),
  'both strips rebuild their children wholesale, so roles applied once are lost on the next render',
);
check('the roving tabindex follows the new active tab', tabNamed(dockStrip, PANEL_KEY, 'log')?.getAttribute('tabindex') === '0' && tabNamed(dockStrip, PANEL_KEY, 'strings')?.getAttribute('tabindex') === '-1', 'the tab stop stayed on the tab that is no longer selected');
check('the panel is relabelled by the new active tab', dockBody.getAttribute('aria-labelledby') === tabNamed(dockStrip, PANEL_KEY, 'log')?.getAttribute('id'), 'the panel is still named by the tab that was selected before');
check(
  'the new nodes are given identifiers of their own rather than the discarded ones',
  dockStrip.children.every((tab) => !firstIdentifiers.includes(tab.getAttribute('id'))),
  'two live elements sharing an id make aria-labelledby ambiguous',
);

const idleStrip = element('div', 'hb-dock-tabs');
const idleBody = element('div', 'hb-dock-body');
renderStrip(idleStrip, PANEL_KEY, ['strings', 'log']);
applyTabStripRoles(idleStrip, { keyAttribute: PANEL_KEY, activeKey: 'strings', panel: idleBody });
check('the strip that is about to be closed starts out labelling its panel', idleBody.hasAttribute('aria-labelledby'), 'the check below is about a label being taken away, so there has to be one there first');
applyTabStripRoles(idleStrip, { keyAttribute: PANEL_KEY, activeKey: null, panel: idleBody });
check(
  'a strip with nothing selected marks no tab selected',
  idleStrip.children.every((tab) => tab.getAttribute('aria-selected') === 'false'),
  `a closed dock must not claim one of its tabs is showing; got ${idleStrip.children.map((tab) => tab.getAttribute('aria-selected')).join(', ')}`,
);
check(
  'a panel with no selected tab carries no stale label',
  !idleBody.hasAttribute('aria-labelledby'),
  `aria-labelledby was left pointing at ${JSON.stringify(idleBody.getAttribute('aria-labelledby'))}, which names a tab that is no longer selected`,
);

const docStrip = element('div', 'hb-tabs');
const docTab = element('button', 'hb-tab', undefined, { 'data-tab': 'doc-1' });
const docClose = element('button', 'hb-tab-close', '✕', { 'data-tab': 'doc-1' });
docTab.appendChild(docClose);
const docFiller = element('div', 'hb-tabs-filler');
docStrip.appendChild(docTab);
docStrip.appendChild(docFiller);
applyTabStripRoles(docStrip, { keyAttribute: 'tab', activeKey: 'doc-1' });
check('the document tab itself is given the tab role', docTab.getAttribute('role') === 'tab', `expected role="tab", got ${JSON.stringify(docTab.getAttribute('role'))}`);
check(
  'the close button inside a tab is not treated as a tab of its own',
  docClose.getAttribute('role') === null && docClose.getAttribute('aria-selected') === null && docClose.getAttribute('tabindex') === null,
  'a close button carries the same key attribute as its tab, so reading the strip by descendant query would announce twice as many tabs as there are documents',
);
check('a child that is not a tab is left alone', docFiller.getAttribute('role') === null, 'a filler element given the tab role is announced as an empty tab');

/* -------------------------------- 6: the tab strip helpers hold the keyboard */

const activated = [];
const closed = [];

wireTabStrip(dockStrip, {
  keyAttribute: PANEL_KEY,
  onActivate: (key) => {
    activated.push(key);
    renderStrip(dockStrip, PANEL_KEY, DOCK_KEYS);
    dockRoles(key);
  },
});

const staleTab = tabNamed(dockStrip, PANEL_KEY, 'log');
const wentRight = pressOn(dockStrip, staleTab, 'ArrowRight');
check('ArrowRight is claimed by the strip', wentRight === true, 'an unclaimed arrow key scrolls the dock instead of moving between panels');
check('ArrowRight selects the next tab', activated.at(-1) === 'entropy', `expected the tab after "log", got ${JSON.stringify(activated.at(-1))}`);
check(
  'ArrowRight leaves focus on the newly rendered tab, not the node the activation discarded',
  fakeDocument.activeElement === tabNamed(dockStrip, PANEL_KEY, 'entropy') && fakeDocument.activeElement !== staleTab,
  'activating re-renders the strip, so focus has to be re-sought by key or it is left on a node that is no longer in the document',
);
check('selection follows focus', tabNamed(dockStrip, PANEL_KEY, 'entropy')?.getAttribute('aria-selected') === 'true', 'the arrow moved focus without selecting, which is not the automatic activation both strips already do on click');

const wrappedRight = pressOn(dockStrip, tabNamed(dockStrip, PANEL_KEY, 'entropy'), 'ArrowRight');
check('ArrowRight from the last tab wraps to the first', wrappedRight === true && activated.at(-1) === 'strings', `expected to wrap to "strings", got ${JSON.stringify(activated.at(-1))}`);

const wentLeft = pressOn(dockStrip, tabNamed(dockStrip, PANEL_KEY, 'strings'), 'ArrowLeft');
check('ArrowLeft from the first tab wraps to the last', wentLeft === true && activated.at(-1) === 'entropy', `expected to wrap to "entropy", got ${JSON.stringify(activated.at(-1))}`);

const wentDown = pressOn(dockStrip, tabNamed(dockStrip, PANEL_KEY, 'entropy'), 'ArrowDown');
check('ArrowDown moves forward like ArrowRight', wentDown === true && activated.at(-1) === 'strings', `a vertically stacked strip must answer the vertical keys too; got ${JSON.stringify(activated.at(-1))}`);
const wentUp = pressOn(dockStrip, tabNamed(dockStrip, PANEL_KEY, 'strings'), 'ArrowUp');
check('ArrowUp moves backward like ArrowLeft', wentUp === true && activated.at(-1) === 'entropy', `expected to move back to "entropy", got ${JSON.stringify(activated.at(-1))}`);

const wentHome = pressOn(dockStrip, tabNamed(dockStrip, PANEL_KEY, 'entropy'), 'Home');
check('Home selects the first tab', wentHome === true && activated.at(-1) === 'strings', `expected "strings", got ${JSON.stringify(activated.at(-1))}`);
const wentEnd = pressOn(dockStrip, tabNamed(dockStrip, PANEL_KEY, 'strings'), 'End');
check('End selects the last tab', wentEnd === true && activated.at(-1) === 'entropy', `expected "entropy", got ${JSON.stringify(activated.at(-1))}`);

const activatedByEnter = pressOn(dockStrip, tabNamed(dockStrip, PANEL_KEY, 'log'), 'Enter');
check('Enter activates the focused tab', activatedByEnter === true && activated.at(-1) === 'log', `expected "log", got ${JSON.stringify(activated.at(-1))}`);
const activatedBySpace = pressOn(dockStrip, tabNamed(dockStrip, PANEL_KEY, 'strings'), ' ');
check('Space activates the focused tab', activatedBySpace === true && activated.at(-1) === 'strings', `expected "strings", got ${JSON.stringify(activated.at(-1))}`);

const activationCount = activated.length;
const typed = pressOn(dockStrip, tabNamed(dockStrip, PANEL_KEY, 'strings'), 'x');
check('a key the strip has no use for is left to the page', typed === false && activated.length === activationCount, 'swallowing every key stops the application shortcuts working while the dock has focus');
const deletedWithoutHandler = pressOn(dockStrip, tabNamed(dockStrip, PANEL_KEY, 'strings'), 'Delete');
check('Delete does nothing on a strip whose tabs cannot be closed', deletedWithoutHandler === false && activated.length === activationCount, 'a claimed Delete with nothing behind it silently eats the key');
const fromStripItself = pressOn(dockStrip, dockStrip, 'ArrowRight');
check('a key pressed on the strip rather than a tab is ignored', fromStripItself === false && activated.length === activationCount, 'a keydown that reaches no tab has no tab to move from');
const fromNonElement = pressOn(dockStrip, { key: 'ArrowRight' }, 'ArrowRight');
check('a keydown whose target is not an element is ignored', fromNonElement === false && activated.length === activationCount, 'the handler must not throw on an event it cannot resolve to a tab');

/* A second document tab whose close button is not itself tagged with the tab
   key, because that is the shape in which the escape hatch is load-bearing: a
   close button that carries the key resolves to itself and is discarded for
   not being one of the strip's own children, while an untagged one resolves to
   the tab around it and would be activated by the Enter meant to press it. */
const docTab2 = element('button', 'hb-tab', 'doc-2', { 'data-tab': 'doc-2' });
const docClose2 = element('button', 'hb-tab-close', '✕');
docTab2.appendChild(docClose2);
docStrip.appendChild(docTab2);
applyTabStripRoles(docStrip, { keyAttribute: 'tab', activeKey: 'doc-1' });

wireTabStrip(docStrip, {
  keyAttribute: 'tab',
  onActivate: (key) => activated.push(key),
  onClose: (key) => closed.push(key),
  ignoreSelector: '.hb-tab-close',
});

const deleted = pressOn(docStrip, docTab, 'Delete');
check('Delete closes the focused document tab', deleted === true && closed.at(-1) === 'doc-1', `expected the close handler to be called with "doc-1", got ${JSON.stringify(closed.at(-1))}`);
check('Delete closes without also selecting', activated.length === activationCount, 'closing a tab must not run the activation handler as well');

const closeCount = closed.length;
const enterOnTaggedClose = pressOn(docStrip, docClose, 'Enter');
check(
  'a key pressed on a close button tagged with the key of its own tab reaches no tab',
  enterOnTaggedClose === false && activated.length === activationCount && closed.length === closeCount,
  'the tagged button resolves to itself, and it is not one of the strip children, so the strip has no tab to act on',
);

const enterOnClose = pressOn(docStrip, docClose2, 'Enter');
check(
  'Enter on the close button inside a tab is left to the close button',
  enterOnClose === false && activated.length === activationCount && closed.length === closeCount,
  'the strip claiming Enter would swallow the button underneath it, so the close control could never be operated by keyboard',
);

const enterOnTab = pressOn(docStrip, docTab2, 'Enter');
check(
  'Enter on the tab holding that button still selects the document',
  enterOnTab === true && activated.at(-1) === 'doc-2',
  `the escape hatch is for the control inside the tab, not for the tab itself; got ${JSON.stringify(activated.at(-1))}`,
);

/* ------------------------------------------ 7: the live region says one thing */

/* The debounce is driven rather than waited on: a real timer would make this
   gate a race against the host's scheduler, and what is being examined is not
   how long the window is but that there is one and that everything arriving
   inside it is spoken together. */
const realSetTimeout = globalThis.setTimeout;
const realClearTimeout = globalThis.clearTimeout;
const scheduled = [];
globalThis.setTimeout = (handler, delay) => {
  const timer = { handler, delay, live: true };
  scheduled.push(timer);
  return timer;
};
globalThis.clearTimeout = (timer) => {
  if (timer) {
    timer.live = false;
  }
};

function liveTimers() {
  return scheduled.filter((timer) => timer.live);
}

function advanceTimers() {
  for (const timer of liveTimers()) {
    timer.live = false;
    timer.handler();
  }
}

const unheard = announce('the region does not exist yet');
check('announce reports that an undeclared region heard nothing', unheard === false, `a queued reading must not be counted as spoken when there was nowhere to speak it; got ${JSON.stringify(unheard)}`);

const region = fakeDocument.createElement('div');
region.setAttribute('aria-live', 'polite');
let regionText = '';
let regionWrites = 0;
Object.defineProperty(region, 'textContent', {
  get() {
    return regionText;
  },
  set(value) {
    regionText = value;
    regionWrites += 1;
  },
});
fakeDocument.byId.set('live', region);

const heard = announce('Working');
check('announce writes the region it found', heard === true && region.textContent === 'Working', `expected the region to hold "Working" and announce to say so; got ${JSON.stringify(region.textContent)} and ${JSON.stringify(heard)}`);

const writesBeforeCaret = regionWrites;
announceChange('caret', 'offset 0x00000010');
check('announceChange says nothing straight away', regionWrites === writesBeforeCaret && region.textContent === 'Working', `a reading spoken on the keystroke that produced it makes the grid unusable with a screen reader; the region already reads ${JSON.stringify(region.textContent)}`);
check('announceChange opens exactly one window', liveTimers().length === 1, `expected one pending flush, got ${liveTimers().length}`);
check('the window is a real delay', (liveTimers()[0]?.delay ?? 0) > 0, `a zero delay coalesces nothing; got ${JSON.stringify(liveTimers()[0]?.delay)}`);

announceChange('caret', 'offset 0x00000020');
check('a second reading on the same channel reopens the window rather than queueing another', liveTimers().length === 1, `expected one pending flush after two readings, got ${liveTimers().length}`);
advanceTimers();
check('only the latest reading on a channel is spoken', region.textContent === 'offset 0x00000020', `expected the reading the caret settled on; got ${JSON.stringify(region.textContent)}`);
check('a run of changes writes the region once', regionWrites === writesBeforeCaret + 1, `expected one write for the whole run, got ${regionWrites - writesBeforeCaret}`);

const writesBeforePair = regionWrites;
announceChange('caret', 'offset 0x00000030');
announceChange('selection', '16 bytes at 0x00000030');
check('a second concern joins the open window instead of opening its own', liveTimers().length === 1, `two windows would speak twice in a row and a screen reader hears the second over the first; got ${liveTimers().length}`);
advanceTimers();
check('both concerns are spoken in one sentence', region.textContent === 'offset 0x00000030, 16 bytes at 0x00000030', `expected the caret and the selection in one reading, got ${JSON.stringify(region.textContent)}`);
check('two concerns still write the region once', regionWrites === writesBeforePair + 1, `expected one write, got ${regionWrites - writesBeforePair}`);

announceChange('selection', '32 bytes at 0x00000040');
announceChange('caret', 'offset 0x00000040');
advanceTimers();
check(
  'the sentence keeps its shape whichever concern changed first',
  region.textContent === 'offset 0x00000040, 32 bytes at 0x00000040',
  `the caret was first to use the region, so it stays first in the sentence; got ${JSON.stringify(region.textContent)}`,
);

announceChange('caret', 'offset 0x00000040');
announceChange('selection', '48 bytes at 0x00000040');
advanceTimers();
check(
  'a concern that has not changed is left out rather than repeated',
  region.textContent === '48 bytes at 0x00000040',
  `only the selection moved, so only the selection is worth hearing; got ${JSON.stringify(region.textContent)}`,
);

const writesWhileQuiet = regionWrites;
announceChange('caret', 'offset 0x00000040');
announceChange('selection', '48 bytes at 0x00000040');
advanceTimers();
check('a window in which nothing changed writes nothing', regionWrites === writesWhileQuiet, `expected no write, got ${regionWrites - writesWhileQuiet}`);

const writesBeforeEcho = regionWrites;
announce('12 hits');
announceChange('hits', '12 hits');
advanceTimers();
check(
  'a channel does not repeat what an immediate announcement has just said',
  regionWrites === writesBeforeEcho + 1 && region.textContent === '12 hits',
  `the region is read out again when it is rewritten with the text it already holds; it took ${regionWrites - writesBeforeEcho} write(s)`,
);

announce('Ready');
announceChange('hits', '12 hits');
advanceTimers();
check(
  'a reading suppressed as an echo is still owed once the region has moved on',
  region.textContent === '12 hits',
  `the hit count was never actually spoken, so dropping it for good loses it; the region reads ${JSON.stringify(region.textContent)}`,
);

fakeDocument.byId.delete('live');
announceChange('caret', 'offset 0x00000050');
advanceTimers();
fakeDocument.byId.set('live', region);
const writesAfterDeafWindow = regionWrites;
announceChange('caret', 'offset 0x00000050');
advanceTimers();
check(
  'a reading that had no region to reach is not counted as spoken',
  region.textContent === 'offset 0x00000050' && regionWrites === writesAfterDeafWindow + 1,
  `a flush that went nowhere must not mark the channel said; the region reads ${JSON.stringify(region.textContent)} after ${regionWrites - writesAfterDeafWindow} write(s)`,
);

announceChange('caret', '   offset 0x00000060   ');
advanceTimers();
check('a reading is spoken without the whitespace around it', region.textContent === 'offset 0x00000060', `expected the trimmed reading, got ${JSON.stringify(region.textContent)}`);

const writesBeforeBlank = regionWrites;
for (const [reason, blank] of [['an empty', ''], ['a whitespace', '    '], ['a null', null], ['an absent', undefined]]) {
  announceChange('caret', blank);
  check(`${reason} reading opens no window`, liveTimers().length === 0, `a channel with nothing to say must stay silent rather than announce a blank; ${liveTimers().length} window(s) are pending`);
}
advanceTimers();
check('a blank reading is never spoken', regionWrites === writesBeforeBlank, `expected no write, got ${regionWrites - writesBeforeBlank}`);

for (const [reason, channel] of [['no channel', undefined], ['an empty channel', ''], ['a whitespace channel', '   '], ['a channel that is not a string', 7]]) {
  const refusal = refusalOf(() => announceChange(channel, 'offset 0x00000070'));
  check(
    `announceChange refuses ${reason}`,
    refusal instanceof TypeError,
    `unnamed readings would share one slot and overwrite each other, which is the coalescing bug this channel exists to prevent; got ${refusal === null ? 'a queued reading' : refusal}`,
  );
}

check('the announcement gates left no timer running', liveTimers().length === 0, `${liveTimers().length} scheduled flush(es) would fire against the real clock once it is restored`);
globalThis.setTimeout = realSetTimeout;
globalThis.clearTimeout = realClearTimeout;
fakeDocument.byId.delete('live');

/* ========================================================== the source scans */

const staticDir = fileURLToPath(new URL('../static/', import.meta.url));

/* Read with line endings normalised to LF. The repository stores its sources
 * with CRLF terminators, and every structural pattern below is written against
 * "\n"; matching them against the raw bytes would fail on the line endings
 * rather than on the markup the checks are actually about. */
async function readSource(name) {
  return (await readFile(`${staticDir}${name}`, 'utf8')).replace(/\r\n/g, '\n');
}

const jsNames = (await readdir(staticDir)).filter((name) => name.endsWith('.js')).sort();
check('the static directory was actually read', jsNames.length >= 10, `expected the application's module set, found ${jsNames.length} .js file(s)`);

const jsSources = new Map();
for (const name of jsNames) {
  jsSources.set(name, await readSource(name));
}
const indexSource = await readSource('index.html');
check('index.html was actually read', indexSource.includes('hb-statusbar'), 'index.html does not look like the application document');

const SCANNED = ['shell.js', 'panels.js', 'renderers.js', 'forms.js'];
for (const name of SCANNED) {
  check(`${name} is present for the button scan`, jsSources.has(name), `${name} is missing from the static directory, so its construction sites went unexamined`);
}

function lineOf(source, index) {
  return source.slice(0, index).split('\n').length;
}

function escapeForRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/* Walk a call's argument list from the '(' that opens it, respecting nesting
 * and string literals, and hand back the top-level arguments as source text.
 * A regex cannot do this: several of the call sites below carry ternaries,
 * object literals and nested calls in the very argument being judged. */
function callAt(source, openIndex) {
  const args = [];
  let current = '';
  let depth = 0;
  let quote = null;
  for (let at = openIndex; at < source.length; at += 1) {
    const character = source[at];
    if (quote !== null) {
      current += character;
      if (character === '\\') {
        current += source[at + 1] ?? '';
        at += 1;
      } else if (character === quote) {
        quote = null;
      }
      continue;
    }
    if (character === "'" || character === '"' || character === '`') {
      quote = character;
      current += character;
      continue;
    }
    if (character === '(' || character === '[' || character === '{') {
      depth += 1;
      if (depth > 1) {
        current += character;
      }
      continue;
    }
    if (character === ')' || character === ']' || character === '}') {
      depth -= 1;
      if (depth === 0) {
        args.push(current.trim());
        return { args: args.filter((argument, position) => argument !== '' || position === 0), end: at + 1 };
      }
      current += character;
      continue;
    }
    if (character === ',' && depth === 1) {
      args.push(current.trim());
      current = '';
      continue;
    }
    current += character;
  }
  return null;
}

function blockAt(source, braceIndex) {
  let depth = 0;
  let quote = null;
  for (let at = braceIndex; at < source.length; at += 1) {
    const character = source[at];
    if (quote !== null) {
      if (character === '\\') {
        at += 1;
      } else if (character === quote) {
        quote = null;
      }
      continue;
    }
    if (character === "'" || character === '"' || character === '`') {
      quote = character;
      continue;
    }
    if (character === '{') {
      depth += 1;
    } else if (character === '}') {
      depth -= 1;
      if (depth === 0) {
        return source.slice(braceIndex, at + 1);
      }
    }
  }
  return null;
}

function methodBody(source, name) {
  const definition = new RegExp(`\\n[ \\t]*${escapeForRegExp(name)}\\([^)]*\\)[ \\t]*\\{`).exec(source);
  if (definition === null) {
    return null;
  }
  return blockAt(source, definition.index + definition[0].length - 1);
}

const STRING_LITERAL = /'([^'\\]*(?:\\.[^'\\]*)*)'|"([^"\\]*(?:\\.[^"\\]*)*)"|`([^`\\]*(?:\\.[^`\\]*)*)`/g;
const NAMEABLE = /[\p{L}\p{N}]/u;

function literalsIn(expression) {
  return [...expression.matchAll(STRING_LITERAL)].map((match) => match[1] ?? match[2] ?? match[3] ?? '');
}

const PROPERTY_READ = /^[A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*)*$/;

/* A text argument names its button when every string literal it can evaluate
 * to carries a letter or a digit. An argument with no literals at all names it
 * only when it is a plain read of a value out of the model -- `panel.title`,
 * `command.label`, `entry.name` -- which is a name by construction and cannot
 * be judged further from the source text. A computed expression is not: the
 * badge beside a dock tab is spelled `String(count)`, and a count is not a
 * name for the control it sits in. */
function carriesAName(expression) {
  if (expression === '' || expression === 'undefined' || expression === 'null') {
    return false;
  }
  const literals = literalsIn(expression);
  if (literals.length > 0) {
    return literals.every((literal) => NAMEABLE.test(literal));
  }
  return PROPERTY_READ.test(expression);
}

function acquiresNameLater(source, variable, from, until) {
  const region = source.slice(from, until);
  const escaped = escapeForRegExp(variable);
  if (new RegExp(`${escaped}\\.setAttribute\\(\\s*'aria-label'`).test(region)) {
    return true;
  }
  if (new RegExp(`${escaped}\\.textContent\\s*=`).test(region)) {
    return true;
  }
  const appends = [...region.matchAll(new RegExp(`${escaped}\\.(?:append|appendChild|replaceChildren)\\(`, 'g'))];
  for (const append of appends) {
    const call = callAt(region, append.index + append[0].length - 1);
    if (call === null) {
      continue;
    }
    for (const argument of call.args) {
      if (argument.startsWith('document.createTextNode(')) {
        const text = callAt(argument, argument.indexOf('('));
        if (text !== null && carriesAName(text.args[0] ?? '')) {
          return true;
        }
        continue;
      }
      if (argument.startsWith('decorativeGlyph(')) {
        continue;
      }
      if (!argument.startsWith('element(')) {
        continue;
      }
      const inner = callAt(argument, argument.indexOf('('));
      if (inner !== null && inner.args.length >= 3 && carriesAName(inner.args[2])) {
        return true;
      }
    }
  }
  return false;
}

/* ---------------------- 8: every glyph-only button is built by iconButton */

const HAND_BUILT = /\belement\(\s*'button'|\bdocument\.createElement\(\s*'button'\s*\)/g;
const DECLARATION = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*$/;

const unnamedButtons = [];
const unparsedButtons = [];
let handBuiltSites = 0;

for (const name of SCANNED) {
  const source = jsSources.get(name);
  if (source === undefined) {
    continue;
  }
  const sites = [...source.matchAll(HAND_BUILT)];
  for (const [position, site] of sites.entries()) {
    handBuiltSites += 1;
    const where = `${name}:${lineOf(source, site.index)}`;
    const call = callAt(source, source.indexOf('(', site.index));
    if (call === null) {
      unparsedButtons.push(where);
      continue;
    }
    const isFactory = site[0].startsWith('element(');
    const text = isFactory && call.args.length >= 3 ? call.args[2] : '';
    if (carriesAName(text)) {
      continue;
    }
    const declared = DECLARATION.exec(source.slice(Math.max(0, site.index - 160), site.index));
    if (declared === null) {
      unnamedButtons.push(`${where} (built inline, so nothing can give it a name afterwards)`);
      continue;
    }
    const next = sites[position + 1];
    const until = Math.min(source.length, next === undefined ? call.end + 1600 : Math.min(next.index, call.end + 1600));
    if (!acquiresNameLater(source, declared[1], call.end, until)) {
      unnamedButtons.push(`${where} (${declared[1]})`);
    }
  }
}

check(
  'the hand-built button scan examined a substantial number of construction sites',
  handBuiltSites >= 12,
  `only ${handBuiltSites} hand-built button site(s) were found across ${SCANNED.join(', ')}; a pattern that matches nothing cannot gate anything`,
);
check('every hand-built button construction site could be parsed', unparsedButtons.length === 0, `unparsed sites: ${unparsedButtons.join(', ')}`);
check(
  'no glyph-only button is constructed outside iconButton',
  unnamedButtons.length === 0,
  `these element('button', ...) sites acquire no text and no aria-label, so a screen reader has nothing to announce - build them with iconButton instead: ${unnamedButtons.join(', ')}`,
);

for (const name of SCANNED) {
  const source = jsSources.get(name) ?? '';
  check(
    `${name} imports iconButton from dom.js`,
    /import \{[^}]*\biconButton\b[^}]*\} from '\.\/dom\.js';/.test(source),
    `${name} no longer imports the one factory that can name a glyph-only button`,
  );
}

check(
  "renderers.js's actionButton delegates straight to iconButton",
  /function actionButton\([^)]*\) \{\n\s*return iconButton\(/.test(jsSources.get('renderers.js') ?? ''),
  'actionButton is the helper every renderer builds its buttons through; if it stops delegating, the glyph-only labels it is called with lose their enforcement',
);
check(
  "panels.js's panelAction delegates straight to iconButton",
  /function panelAction\([^)]*\) \{\n\s*return iconButton\(/.test(jsSources.get('panels.js') ?? ''),
  'panelAction is called with bare glyphs throughout panels.js; if it stops delegating, none of those buttons gets a name',
);
check(
  "forms.js's button() routes an unnameable label to iconButton",
  /if \(!NAMEABLE_LABEL\.test\(label\)\) \{\n\s*return iconButton\(/.test(jsSources.get('forms.js') ?? ''),
  'forms.js builds its own button for a nameable label and must hand anything else to iconButton, which is what refuses an unnamed one',
);

const GLYPH_CALL = /\b(?:iconButton|panelAction|actionButton|button)\(\s*'([^'\\]*)'/g;
let glyphOnlyCalls = 0;
for (const name of SCANNED) {
  for (const call of (jsSources.get(name) ?? '').matchAll(GLYPH_CALL)) {
    if (call[1] !== '' && !NAMEABLE.test(call[1])) {
      glyphOnlyCalls += 1;
    }
  }
}
check(
  'the application really does build glyph-only buttons, and routes them through the naming helpers',
  glyphOnlyCalls >= 12,
  `only ${glyphOnlyCalls} glyph-only button call(s) were found; if this collapses to nothing, the rule above is guarding an empty set`,
);

/* ------------------------------- 9: index.html names its titles and glyphs */

const OPEN_TAG = /<([a-zA-Z][\w-]*)\b([^>]*)>/g;
const titledTags = [...indexSource.matchAll(OPEN_TAG)].filter((tag) => /\stitle\s*=\s*"/.test(tag[2]));
check(
  'index.html carries a substantial number of title attributes to check',
  titledTags.length >= 10,
  `only ${titledTags.length} element(s) with a title attribute were found in index.html; the scan pattern has stopped matching the markup`,
);

const untitledNames = titledTags
  .filter((tag) => !/\saria-label\s*=\s*"[^"]*[^"\s][^"]*"/.test(tag[2]))
  .map((tag) => `${tag[1]} at index.html:${lineOf(indexSource, tag.index)}`);
check(
  'every element in index.html with a tooltip also carries an accessible name',
  untitledNames.length === 0,
  `a title attribute is not an accessible name; these elements have one without the other: ${untitledNames.join(', ')}`,
);

const mismatched = titledTags
  .filter((tag) => {
    const title = /\stitle\s*=\s*"([^"]*)"/.exec(tag[2]);
    const label = /\saria-label\s*=\s*"([^"]*)"/.exec(tag[2]);
    return title !== null && label !== null && title[1] !== label[1];
  })
  .map((tag) => `index.html:${lineOf(indexSource, tag.index)}`);
check(
  'the tooltip and the accessible name say the same thing',
  mismatched.length === 0,
  `a pointer user and a screen-reader user must not be told different things about the same control: ${mismatched.join(', ')}`,
);

const toolbarGlyphs = [...indexSource.matchAll(/<span\b[^>]*\bclass="[^"]*\bhb-tool-icon\b[^"]*"[^>]*>/g)];
check(
  'index.html carries a substantial number of toolbar glyph spans to check',
  toolbarGlyphs.length >= 10,
  `only ${toolbarGlyphs.length} hb-tool-icon span(s) were found; the scan pattern has stopped matching the toolbar`,
);
const audibleGlyphs = toolbarGlyphs
  .filter((span) => !/\baria-hidden="true"/.test(span[0]))
  .map((span) => `index.html:${lineOf(indexSource, span.index)}`);
check(
  'every toolbar glyph span is hidden from assistive technology',
  audibleGlyphs.length === 0,
  `an unhidden glyph is read out beside the button's own label, so the control announces itself twice: ${audibleGlyphs.join(', ')}`,
);

/* ----------------- 10: one live region, and the caret is not written into it raw */

let liveRegions = 0;
const liveHosts = [];
for (const [name, source] of [...jsSources, ['index.html', indexSource]]) {
  const count = (source.match(/aria-live/g) ?? []).length;
  liveRegions += count;
  if (count > 0) {
    liveHosts.push(`${name} (${count})`);
  }
}
check(
  'the page declares exactly one aria-live region',
  liveRegions === 1,
  `a second live region means two things talk over each other and neither is reliably heard; found ${liveRegions} across ${liveHosts.join(', ') || 'nothing'}`,
);
check('the one live region belongs to shell.js', liveHosts.length === 1 && liveHosts[0].startsWith('shell.js'), `expected shell.js to own it, found it in ${liveHosts.join(', ') || 'nothing'}`);

const shellSource = jsSources.get('shell.js') ?? '';
const liveAt = shellSource.indexOf('aria-live');
const liveCall = liveAt < 0 ? null : callAt(shellSource, shellSource.indexOf('(', shellSource.lastIndexOf('element(', liveAt)));
check('the live region is built through element()', liveCall !== null && liveCall.args[0] === "'div'", 'the aria-live attribute is no longer applied by an element() call that this gate can read');
check(
  'the live region is created empty rather than wrapped around existing markup',
  liveCall !== null && liveCall.args.length >= 3 && liveCall.args[2] === 'undefined',
  `the region must start with no content of its own; its text argument is ${JSON.stringify(liveCall?.args[2])}`,
);
check(
  'the live region is polite, not assertive',
  liveCall !== null && /'aria-live':\s*'polite'/.test(liveCall.args[3] ?? ''),
  'an assertive region interrupts the user for every announcement the shell makes',
);
check(
  'the live region is appended as its own node on the body',
  /document\.body\.appendChild\(region\)/.test(shellSource),
  'the region must be a sibling of the application chrome; anything else risks it enclosing content that then announces every change',
);

const statusbar = /<div class="hb-statusbar" id="statusbar">([\s\S]*?)<\/div>/.exec(indexSource);
check('the status bar could be located in index.html', statusbar !== null, 'the status bar block was not found, so this gate examined nothing');
const statusMarkup = statusbar === null ? '' : statusbar[1];
for (const slot of ['status-offset', 'status-selection', 'status-pane']) {
  check(`the ${slot} status slot exists to be checked`, statusMarkup.includes(`id="${slot}"`), `${slot} was not found inside the status bar, so this gate is examining the wrong markup`);
}
/* The caret readout carries a key rather than standing as a bare number. Which
   word it is belongs to UX-3, which shortened it to `off` because the value is
   already 0x-prefixed, so this gate asks that the offset slot is labelled at
   all - not that it is labelled with any particular string. The pane slot is
   deliberately unlabelled: it reads `hex hi` or `ascii`, which names itself. */
const offsetItem = /<span class="hb-status-item"[^>]*>(?:(?!<\/span><span class="hb-status-item").)*?id="status-offset"/s.exec(statusMarkup);
check(
  'the caret offset readout is labelled',
  offsetItem !== null && /class="hb-status-key">[^<]+</.test(offsetItem[0]),
  'the offset value sits in the status bar with no key beside it, so it reads as an unexplained number',
);
check(
  'the status bar is not itself a live region',
  statusbar !== null && !/aria-live|role="(?:status|alert|log)"|aria-atomic/.test(statusbar[0].slice(0, statusbar[0].indexOf('>'))),
  'making the status bar live would announce every caret movement, which is worse than announcing nothing',
);
check(
  'no status slot is marked live in the markup',
  !/aria-live|role="(?:status|alert|log)"/.test(statusMarkup),
  'a live status slot announces the caret, the offset or the selection on every keystroke',
);

const renderStatus = methodBody(shellSource, '#renderStatus');
check('#renderStatus could be located in shell.js', renderStatus !== null, 'the method that writes the status slots was not found, so this gate examined nothing');
const statusBody = renderStatus ?? '';

/* UX-3 turned the status bar into three tiers driven by one readout object, so
   the slots are no longer written by name here - they are written by iterating
   what statusReadout produced. The gate follows: the readout must still carry
   the caret, pane and selection values, and #renderStatus must still write each
   one into its own node. */
const readoutStart = shellSource.indexOf('function statusReadout(');
const readoutBody = readoutStart === -1 ? null : blockAt(shellSource, shellSource.indexOf('{', readoutStart));
check('statusReadout could be located in shell.js', readoutBody !== null, 'the function that computes the status values was not found, so this gate examined nothing');
for (const key of ['offset', 'pane', 'selection']) {
  check(
    `statusReadout still produces a ${key} value`,
    new RegExp(`^\\s*${key}:`, 'm').test(readoutBody ?? ''),
    `${key} is no longer part of the status readout, so the caret position it describes is never shown`,
  );
}
check(
  '#renderStatus writes every readout value into its slot',
  /Object\.entries\(readout\)/.test(statusBody) && /\.textContent = value/.test(statusBody),
  'the readout is no longer written into the status nodes, so the bar shows whatever it last held',
);
check(
  '#renderStatus hides an item rather than printing a placeholder for it',
  /value === null/.test(statusBody),
  'UX-3 requires an item with no real value to be hidden, not rendered as an em dash or the word none',
);
check(
  '#renderStatus writes the caret, offset and selection slots without announcing them itself',
  !statusBody.includes('announce('),
  'the status bar is repainted on every keystroke; writing the live region from here would speak every intermediate value. What changed is offered to announceChange, which is debounced and coalesced, and never to announce',
);

const announcedText = [];
let announceSites = 0;
for (const [name, source] of jsSources) {
  for (const call of source.matchAll(/\bannounce\(/g)) {
    const parsed = callAt(source, call.index + call[0].length - 1);
    if (parsed === null) {
      continue;
    }
    announceSites += 1;
    if (/\bcaret\b|\bselection\b|\bhits?\b|nodes\.offset|nodes\.selection|nodes\.hits|status-offset|status-selection|status-hits/.test(parsed.args[0] ?? '')) {
      announcedText.push(`${name}:${lineOf(source, call.index)}`);
    }
  }
}
check('the announce() scan examined the real call sites', announceSites >= 2, `only ${announceSites} announce() call site(s) were found; the scan has stopped matching`);
check(
  'the values that change as the user works reach the region only through the debounced route',
  announcedText.length === 0,
  `announce() writes the region there and then, so caret, selection and hit-count state must be handed to announceChange instead: ${announcedText.join(', ')}`,
);

/* ------------------------------ 11: every overlay says it is a modal dialog */

const OVERLAY_CLASS = "'hbx-overlay'";
const CLASSNAME_ASSIGNMENT = /([A-Za-z_$][\w$.#]*)\.className\s*=\s*$/;
const FACTORY_DECLARATION = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*element\(\s*'div',\s*$/;

const overlaySites = [];
for (const [name, source] of jsSources) {
  let at = source.indexOf(OVERLAY_CLASS);
  while (at >= 0) {
    overlaySites.push({ name, source, at });
    at = source.indexOf(OVERLAY_CLASS, at + 1);
  }
}

check(
  'every overlay construction site in the application was found',
  overlaySites.length === 5,
  `the application builds five overlays (two shell dialogs, the panel result modal, the argument dialog and the command palette); this scan found ${overlaySites.length}. A new one must be gated too.`,
);

const undeclaredDialogs = [];
for (const site of overlaySites) {
  const where = `${site.name}:${lineOf(site.source, site.at)}`;
  const before = site.source.slice(Math.max(0, site.at - 200), site.at);
  const missing = [];

  const factory = FACTORY_DECLARATION.exec(before);
  const assignment = CLASSNAME_ASSIGNMENT.exec(before);

  let inlineAttrs = '';
  if (factory !== null) {
    const call = callAt(site.source, site.source.indexOf('(', site.source.lastIndexOf('element(', site.at)));
    inlineAttrs = call === null ? '' : (call.args[3] ?? '');
  }

  const variable = factory?.[1] ?? assignment?.[1] ?? null;
  const escaped = variable === null ? null : escapeForRegExp(variable);
  const after = site.source.slice(site.at);

  const declaresRole = /role:\s*'dialog'/.test(inlineAttrs)
    || (escaped !== null && new RegExp(`${escaped}\\.setAttribute\\(\\s*'role'\\s*,\\s*'dialog'\\s*\\)`).test(after));
  const declaresModal = /'aria-modal':\s*'true'/.test(inlineAttrs)
    || (escaped !== null && new RegExp(`${escaped}\\.setAttribute\\(\\s*'aria-modal'\\s*,\\s*'true'\\s*\\)`).test(after));

  if (variable === null) {
    missing.push('the overlay node could not be named, so nothing can be traced to it');
  }
  if (!declaresRole) {
    missing.push('role="dialog"');
  }
  if (!declaresModal) {
    missing.push('aria-modal="true"');
  }
  if (missing.length > 0) {
    undeclaredDialogs.push(`${where} is missing ${missing.join(' and ')}`);
  }
}

check(
  'every overlay declares itself a modal dialog',
  undeclaredDialogs.length === 0,
  `an overlay that does not say it is a modal dialog leaves the page behind it readable, so the user is told about content the scrim has already taken away: ${undeclaredDialogs.join('; ')}`,
);

const buildMenus = methodBody(shellSource, '#buildMenus');
const toggleMenu = methodBody(shellSource, '#toggleMenu');
const closeMenu = methodBody(shellSource, '#closeMenu');

check('#buildMenus could be located in shell.js', buildMenus !== null, 'the method that prepares the menubar triggers was not found, so this gate examined nothing');
check(
  '#buildMenus finds the menubar triggers it decorates',
  (buildMenus ?? '').includes("querySelector('.hb-menu-item')"),
  'the trigger lookup changed, so the aria-expanded checks below may be watching the wrong element',
);
check(
  'the menubar triggers start out reporting a closed menu',
  /button\.setAttribute\('aria-expanded', 'false'\)/.test(buildMenus ?? ''),
  'a menubar trigger with no aria-expanded never tells the keyboard whether its menu is open',
);
check(
  'the menubar triggers declare that they own a popup',
  /button\.setAttribute\('aria-haspopup', 'true'\)/.test(buildMenus ?? ''),
  'without aria-haspopup the trigger reads as a plain button that happens to do something',
);
check('#toggleMenu could be located in shell.js', toggleMenu !== null, 'the method that opens a menu was not found, so this gate examined nothing');
check(
  'opening a menu updates its trigger to aria-expanded="true"',
  /button\.setAttribute\('aria-expanded', 'true'\)/.test(toggleMenu ?? ''),
  'an aria-expanded that never changes is worse than none: it reports the wrong state with confidence',
);
check('#closeMenu could be located in shell.js', closeMenu !== null, 'the method that shuts a menu was not found, so this gate examined nothing');
check(
  'closing a menu returns its trigger to aria-expanded="false"',
  /button\.setAttribute\('aria-expanded', 'false'\)/.test(closeMenu ?? ''),
  'a trigger left reporting an open menu after the popup is gone misdescribes the page',
);

if (failures.length > 0) {
  process.stdout.write(`${failures.length} accessibility expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write('dom accessibility contract: all expectations held\n');
