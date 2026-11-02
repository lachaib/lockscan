const IDENT_CHAR = /[A-Za-z0-9_]/;
const STRING_PREFIX = /^[rRbBuUfF]{1,2}$/;

const blank = (s: string): string => s.replace(/[^\n]/g, ' ');

export interface MaskedPython {
  /** Comments and non-f string contents blanked: only code tokens remain. */
  code: string;
  /** Comments and triple-quoted string contents blanked; short string literals kept. */
  text: string;
}

function isFString(src: string, quoteAt: number): boolean {
  for (let len = 2; len >= 1; len--) {
    const start = quoteAt - len;
    if (start < 0) continue;
    const prefix = src.slice(start, quoteAt);
    if (!STRING_PREFIX.test(prefix)) continue;
    if (start > 0 && IDENT_CHAR.test(src[start - 1])) continue;
    return /[fF]/.test(prefix);
  }
  return false;
}

/**
 * Blanks comments and string contents while keeping offsets and line breaks, so regexes can
 * run on code only. f-string bodies are kept because they hold executable expressions.
 */
export function maskPython(src: string): MaskedPython {
  const code: string[] = [];
  const text: string[] = [];
  const n = src.length;
  let i = 0;

  while (i < n) {
    const ch = src[i];

    if (ch === '#') {
      let end = src.indexOf('\n', i);
      if (end < 0) end = n;
      const blanked = blank(src.slice(i, end));
      code.push(blanked);
      text.push(blanked);
      i = end;
      continue;
    }

    if (ch === '"' || ch === "'") {
      const triple = src.startsWith(ch.repeat(3), i);
      const quote = triple ? ch.repeat(3) : ch;
      const bodyStart = i + quote.length;
      let j = bodyStart;
      while (j < n) {
        if (src[j] === '\\') j += 2;
        else if (triple ? src.startsWith(quote, j) : src[j] === ch) break;
        else if (!triple && src[j] === '\n') break;
        else j++;
      }
      const bodyEnd = Math.min(j, n);
      const closed = src.startsWith(quote, bodyEnd) && bodyEnd < n;
      const body = src.slice(bodyStart, bodyEnd);
      const close = closed ? quote : '';
      if (isFString(src, i)) {
        code.push(quote, body, close);
        text.push(quote, body, close);
      } else {
        code.push(quote, blank(body), close);
        text.push(quote, triple ? blank(body) : body, close);
      }
      i = bodyEnd + close.length;
      continue;
    }

    code.push(ch);
    text.push(ch);
    i++;
  }

  return { code: code.join(''), text: text.join('') };
}
