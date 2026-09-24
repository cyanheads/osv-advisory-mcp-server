/**
 * @fileoverview Parses rendered tool text with commonmark.js (the CommonMark reference
 * implementation) and reports the nodes a Markdown renderer would turn into live HTML.
 * @module tests/helpers/markdown
 */

import { Parser } from 'commonmark';

const parser = new Parser();

/** What a CommonMark renderer makes of one document. */
export interface MarkdownScan {
  /** Literals of `<…>` autolinks (URI and email). */
  autolinks: string[];
  /** Literals of fenced and indented code blocks, in document order. */
  codeBlocks: string[];
  /** Literals of raw HTML nodes (`html_inline`, `html_block`). */
  html: string[];
  /** Destinations of every link, autolinks included. */
  links: string[];
  /** Every text-node literal, concatenated — what a reader sees outside code. */
  text: string;
}

/** Parse Markdown and collect its HTML, link, code-block, and text nodes. */
export function scanMarkdown(markdown: string): MarkdownScan {
  const scan: MarkdownScan = { autolinks: [], codeBlocks: [], html: [], links: [], text: '' };
  const walker = parser.parse(markdown).walker();
  for (let step = walker.next(); step; step = walker.next()) {
    if (!step.entering) continue;
    const node = step.node;
    switch (node.type) {
      case 'html_inline':
      case 'html_block':
        scan.html.push(node.literal ?? '');
        break;
      case 'code_block':
        scan.codeBlocks.push(node.literal ?? '');
        break;
      case 'text':
        scan.text += node.literal ?? '';
        break;
      case 'link': {
        const destination = node.destination ?? '';
        const label = node.firstChild?.literal ?? '';
        scan.links.push(destination);
        if (destination === label || destination === `mailto:${label}`) scan.autolinks.push(label);
        break;
      }
    }
  }
  return scan;
}

/** Every text block of a tool result's `content[]`, joined — enrichment trailers included. */
export function contentText(result: { content: Array<{ type: string; text?: string }> }): string {
  return result.content
    .filter((block) => block.type === 'text')
    .map((block) => block.text ?? '')
    .join('\n');
}

/** Count frame closers (`</advisory_summary>`, `</advisory_text>`, any case) in raw text. */
export function countFrameClosers(text: string): number {
  return text.match(/<\/advisory_(?:summary|text)>/gi)?.length ?? 0;
}
