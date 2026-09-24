/**
 * @fileoverview Render-boundary escape for advisory text in tool `content[]`.
 * OSV strings are upstream-controlled Markdown. Rendered as-is, tag-shaped text becomes raw
 * HTML (a `<template>` in a summary hides the rest of the response), a reference definition
 * or a `](javascript:…)` tail can relink the server's own `[LABEL]` text, and a literal `</advisory_text>` reads like the
 * server's frame closer. These helpers neutralize exactly those constructs and leave the rest
 * of the Markdown alone; `structuredContent` never passes through them. Every step is a
 * single pass over the text (per-line regexes are anchored or fixed-width), so escape time
 * grows linearly with input size.
 * @module mcp-server/tools/render-escape
 */

/** Line breaks CommonMark honors, plus the Unicode separators some renderers break on. */
const LINE_BREAKS = /\r\n|\r|\n|\u2028|\u2029/g;

/**
 * A `<` that can start raw HTML or an autolink: before an ASCII letter, `/`, `!`, or `?`
 * (tags, comments, declarations, CDATA, processing instructions, URI autolinks), or before an
 * email-autolink local part (`<1a@b.co>`). A bare `<` in `a < b` or `<= 1.2` stays as is.
 */
const TAG_OPENER = /<(?=[A-Za-z/!?]|[\w.!#$%&'*+/=?^`{|}~-]+@)/g;

/**
 * The `]` of an inline link or image whose destination is not an `http(s)://` URL. Escaping it
 * leaves the brackets as text, so advisory text can neither link to `javascript:` (entity-encoded
 * or not) nor close one of the server's own `[LABEL]`s into a link.
 */
const UNSAFE_LINK_CLOSER = /\](?=\((?![ \t]*https?:\/\/))/gi;

/** A `<` that starts the server's own frame tags, which may not appear verbatim even in code. */
const FRAME_TAG = /<(?=\/?advisory_(?:summary|text))/gi;

/**
 * A line-leading `[` (after indentation and quote/list markers) that could open a link
 * reference definition: its label closes with `]:` on this line or continues onto the next.
 */
const REFERENCE_DEFINITION =
  /^([ \t]*(?:(?:>|[-+*]|\d{1,9}[.)])[ \t]*)*)\[(?=(?:[^\\\]]|\\.)*(?:\]:|\\?$))/s;

/**
 * A fenced-code opener run (three or more backticks or tildes) and its info string. The `s`
 * flag lets the info string hold U+2028/U+2029, which CommonMark does not treat as line breaks.
 */
const FENCE_OPENER = /^( {0,3})(`{3,}|~{3,})(.*)$/s;

/** An open fenced code block: its character and opener length. */
interface Fence {
  char: string;
  length: number;
}

/** Parse a fence opener line; a backtick run whose info string holds a backtick is not one. */
function parseFenceOpener(line: string): (Fence & { indent: number }) | null {
  const match = FENCE_OPENER.exec(line);
  if (!match) return null;
  const [, indent = '', run = '', info = ''] = match;
  const char = run.charAt(0);
  if (char === '`' && info.includes('`')) return null;
  return { char, length: run.length, indent: indent.length };
}

/** True when `line` closes `fence`: ≤3 spaces, a long-enough run of its character, then only whitespace. */
function closesFence(line: string, fence: Fence): boolean {
  let i = 0;
  while (i < 3 && line[i] === ' ') i++;
  let run = 0;
  while (line[i + run] === fence.char) run++;
  if (run < fence.length) return false;
  return /^[ \t]*$/.test(line.slice(i + run));
}

/**
 * Neutralize tag openers, non-http(s) links, and a line-leading reference definition on one
 * line. The definition check runs last: `[a](x]: javascript:…` only becomes a definition once
 * its `]` is escaped, so the check has to see the escaped line.
 */
function escapeTextLine(line: string): string {
  return line
    .replace(TAG_OPENER, '&lt;')
    .replace(UNSAFE_LINK_CLOSER, '\\]')
    .replace(REFERENCE_DEFINITION, '$1\\[');
}

/**
 * Escape an upstream string rendered inline (a summary, ID, version, URL, timestamp, …).
 * Line breaks become a space, so the value stays on its line; tag and autolink openers become
 * `&lt;`. Because a value may start a line, a leading reference-definition bracket and a
 * leading fence run are backslash-escaped too.
 */
export function escapeAdvisoryInline(value: string): string {
  const line = escapeTextLine(value.replace(LINE_BREAKS, ' '));
  const fence = parseFenceOpener(line);
  if (!fence) return line;
  return `${line.slice(0, fence.indent)}\\${line.slice(fence.indent)}`;
}

/**
 * Escape upstream Markdown rendered as a block (`details`). Outside fenced code, each line gets
 * the inline rules minus line joining. Inside a fence opened at column 0, code stays literal
 * except for the server's frame tags; text that ends inside such a fence gets a closing fence
 * so the server's own closer is not swallowed into code. A fence opened with 1–3 spaces of
 * indentation may sit in a list item that CommonMark closes without a closing fence, so after
 * one, no later fence is exempted and every line takes the text rule.
 */
export function escapeAdvisoryBlock(text: string): string {
  const out: string[] = [];
  let fence: Fence | null = null;
  let fencesTrusted = true;
  for (const line of text.split(/\r\n|\r|\n/)) {
    if (fence) {
      out.push(line.replace(FRAME_TAG, '&lt;'));
      if (closesFence(line, fence)) fence = null;
      continue;
    }
    const opener = parseFenceOpener(line);
    if (opener && opener.indent > 0) fencesTrusted = false;
    else if (opener && fencesTrusted) fence = opener;
    out.push(escapeTextLine(line));
  }
  if (fence) out.push(fence.char.repeat(fence.length));
  return out.join('\n');
}
