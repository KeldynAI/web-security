/**
 * A deliberately small, strict YAML subset parser.
 *
 * Why not a real YAML library?
 *   - The Action must run with zero runtime dependencies (no `npm install` on a
 *     runner), and vendoring a YAML implementation into a security tool means
 *     owning its supply-chain and CVE surface forever.
 *   - The only YAML this Action parses is its own ignore file, whose schema is
 *     small and fully under our control.
 *
 * Supported: block mappings, block sequences, compact sequence-of-mapping
 * entries, flow sequences/mappings of scalars, single/double quoted and plain
 * scalars, comments, and one optional leading `---`.
 *
 * Explicitly rejected with a clear error (rather than silently mis-parsed):
 * tabs used for indentation, anchors/aliases, explicit tags, block scalars
 * (`|`/`>`), multiple documents, complex keys and duplicate keys.
 */

export class YamlError extends Error {
  constructor(message, line) {
    super(line ? `${message} (line ${line})` : message);
    this.name = 'YamlError';
    this.line = line ?? null;
  }
}

const BOOLEAN_TRUE = new Set(['true', 'True', 'TRUE']);
const BOOLEAN_FALSE = new Set(['false', 'False', 'FALSE']);
const NULL_VALUES = new Set(['null', 'Null', 'NULL', '~', '']);
const NUMBER_PATTERN = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/;

/** Parses a YAML subset document. Returns `null` for an empty document. */
export function parseYaml(text) {
  if (typeof text !== 'string') {
    throw new YamlError('YAML input must be a string');
  }
  const lines = tokenize(text);
  const state = { lines, index: 0 };
  if (state.lines.length === 0) return null;

  const value = parseNode(state, state.lines[0].indent);
  if (state.index < state.lines.length) {
    throw new YamlError(
      `Unexpected content; check the indentation of "${state.lines[state.index].content}"`,
      state.lines[state.index].line,
    );
  }
  return value;
}

/** Splits the document into meaningful lines, rejecting unsupported syntax. */
function tokenize(text) {
  const rawLines = text.replace(/\r\n?/g, '\n').split('\n');
  const lines = [];
  let seenDocumentStart = false;

  for (let index = 0; index < rawLines.length; index += 1) {
    const raw = rawLines[index];
    const lineNumber = index + 1;

    const indentMatch = /^[ \t]*/.exec(raw)[0];
    if (indentMatch.includes('\t')) {
      throw new YamlError('Tabs cannot be used for indentation in YAML; use spaces', lineNumber);
    }

    const content = raw.slice(indentMatch.length);
    if (content.length === 0 || content.startsWith('#')) continue;

    if (content === '---' || content.startsWith('--- ')) {
      if (seenDocumentStart || lines.length > 0) {
        throw new YamlError('Multiple YAML documents are not supported', lineNumber);
      }
      seenDocumentStart = true;
      const inline = content.slice(3).trim();
      if (inline.length > 0 && !inline.startsWith('#')) {
        throw new YamlError('Inline content after "---" is not supported', lineNumber);
      }
      continue;
    }
    if (content === '...') {
      break;
    }
    if (content.startsWith('%')) {
      throw new YamlError('YAML directives are not supported', lineNumber);
    }

    lines.push({ indent: indentMatch.length, content, line: lineNumber });
  }

  return lines;
}

function peek(state) {
  return state.index < state.lines.length ? state.lines[state.index] : null;
}

function isSequenceEntry(line) {
  return line.content === '-' || line.content.startsWith('- ');
}

function parseNode(state, indent) {
  const line = peek(state);
  if (!line) return null;
  if (line.indent !== indent) {
    throw new YamlError(`Unexpected indentation for "${line.content}"`, line.line);
  }
  return isSequenceEntry(line) ? parseSequence(state, indent) : parseMapping(state, indent);
}

function parseSequence(state, indent) {
  const items = [];

  while (true) {
    const line = peek(state);
    if (!line || line.indent !== indent || !isSequenceEntry(line)) break;

    state.index += 1;
    const rest = line.content === '-' ? '' : line.content.slice(2);
    const restOffset = indent + 2;
    const trimmedRest = stripComment(rest, line.line);

    if (trimmedRest.length === 0) {
      items.push(parseChildBlock(state, indent, line));
      continue;
    }

    if (isMappingStart(trimmedRest, line.line)) {
      // Compact form: "- id: value" starts a mapping whose effective
      // indentation is the column the key begins at, so that following
      // sibling keys line up with it.
      const leading = /^[ ]*/.exec(rest)[0].length;
      state.lines.splice(state.index, 0, {
        indent: restOffset + leading,
        content: trimmedRest,
        line: line.line,
      });
      items.push(parseMapping(state, restOffset + leading));
      continue;
    }

    items.push(parseScalar(trimmedRest, line.line));
  }

  return items;
}

function parseMapping(state, indent) {
  const result = {};
  const seenKeys = new Set();

  while (true) {
    const line = peek(state);
    if (!line || line.indent !== indent) break;
    if (isSequenceEntry(line)) {
      throw new YamlError('Unexpected list item where a "key: value" pair was expected', line.line);
    }

    state.index += 1;
    const { key, rest } = splitKey(line.content, line.line);
    if (seenKeys.has(key)) {
      throw new YamlError(`Duplicate key "${key}"`, line.line);
    }
    seenKeys.add(key);

    const value = stripComment(rest, line.line);
    if (value.length === 0) {
      result[key] = parseChildBlock(state, indent, line);
    } else {
      result[key] = parseScalar(value, line.line);
    }
  }

  return result;
}

/**
 * Parses the block that belongs to a mapping key or sequence entry with no
 * inline value: either a more-indented block, or (for mappings) a sequence at
 * the same indentation, which YAML permits.
 */
function parseChildBlock(state, indent, parentLine) {
  const next = peek(state);
  if (!next) return null;
  if (next.indent > indent) return parseNode(state, next.indent);
  if (next.indent === indent && isSequenceEntry(next) && !isSequenceEntry(parentLine)) {
    return parseSequence(state, indent);
  }
  return null;
}

/** True when the text looks like the beginning of a `key: value` pair. */
function isMappingStart(text, lineNumber) {
  try {
    splitKey(text, lineNumber);
    return true;
  } catch {
    return false;
  }
}

function splitKey(content, lineNumber) {
  if (content.startsWith('?')) {
    throw new YamlError('Complex mapping keys ("?") are not supported', lineNumber);
  }

  let key;
  let rest;
  if (content.startsWith('"') || content.startsWith("'")) {
    const quoted = readQuoted(content, lineNumber);
    key = quoted.value;
    rest = content.slice(quoted.length);
    if (!rest.startsWith(':')) {
      throw new YamlError('Expected ":" after a quoted mapping key', lineNumber);
    }
    rest = rest.slice(1);
  } else {
    // A plain key ends at the first ":" that is followed by a space or the end
    // of the line; this keeps values such as "https://example.com" intact.
    const separator = /:(?:\s|$)/.exec(content);
    if (!separator) {
      throw new YamlError(`Expected "key: value" but found "${content}"`, lineNumber);
    }
    key = content.slice(0, separator.index).trim();
    rest = content.slice(separator.index + 1);
    if (key.length === 0) {
      throw new YamlError('Mapping key must not be empty', lineNumber);
    }
    if (key.startsWith('&') || key.startsWith('*') || key.startsWith('!')) {
      throw new YamlError('YAML anchors, aliases and tags are not supported', lineNumber);
    }
    if (key === '<<') {
      throw new YamlError('YAML merge keys ("<<") are not supported', lineNumber);
    }
  }

  return { key, rest: rest.trim() };
}

/** Removes a trailing `# comment` from a value, respecting quoted strings. */
function stripComment(text, lineNumber) {
  const trimmed = text.trim();
  if (trimmed.length === 0) return '';
  if (trimmed.startsWith('#')) return '';

  if (trimmed.startsWith('"') || trimmed.startsWith("'")) {
    const quoted = readQuoted(trimmed, lineNumber);
    const remainder = trimmed.slice(quoted.length).trim();
    if (remainder.length > 0 && !remainder.startsWith('#')) {
      throw new YamlError('Unexpected content after a quoted value', lineNumber);
    }
    return trimmed.slice(0, quoted.length);
  }

  if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
    return trimmed; // Flow collections are parsed (and comment-checked) later.
  }

  const commentIndex = findPlainCommentIndex(trimmed);
  return commentIndex === -1 ? trimmed : trimmed.slice(0, commentIndex).trim();
}

function findPlainCommentIndex(text) {
  for (let index = 0; index < text.length; index += 1) {
    if (text[index] === '#' && index > 0 && /\s/.test(text[index - 1])) return index;
  }
  return -1;
}

function parseScalar(text, lineNumber) {
  if (text.startsWith('|') || text.startsWith('>')) {
    throw new YamlError('Block scalars ("|" and ">") are not supported; use a quoted string', lineNumber);
  }
  if (text.startsWith('&') || text.startsWith('*')) {
    throw new YamlError('YAML anchors and aliases are not supported', lineNumber);
  }
  if (text.startsWith('!')) {
    throw new YamlError('Explicit YAML tags are not supported', lineNumber);
  }
  if (text.startsWith('[')) return parseFlowSequence(text, lineNumber);
  if (text.startsWith('{')) return parseFlowMapping(text, lineNumber);
  if (text.startsWith('"') || text.startsWith("'")) {
    const quoted = readQuoted(text, lineNumber);
    if (quoted.length !== text.length) {
      throw new YamlError('Unexpected content after a quoted value', lineNumber);
    }
    return quoted.value;
  }
  return interpretPlainScalar(text);
}

function interpretPlainScalar(text) {
  if (NULL_VALUES.has(text)) return null;
  if (BOOLEAN_TRUE.has(text)) return true;
  if (BOOLEAN_FALSE.has(text)) return false;
  if (NUMBER_PATTERN.test(text)) return Number(text);
  return text;
}

function readQuoted(text, lineNumber) {
  const quote = text[0];
  if (quote === "'") {
    let index = 1;
    let value = '';
    while (index < text.length) {
      if (text[index] === "'") {
        if (text[index + 1] === "'") {
          value += "'";
          index += 2;
          continue;
        }
        return { value, length: index + 1 };
      }
      value += text[index];
      index += 1;
    }
    throw new YamlError('Unterminated single-quoted string', lineNumber);
  }

  let index = 1;
  let value = '';
  while (index < text.length) {
    const char = text[index];
    if (char === '\\') {
      const escaped = text[index + 1];
      if (escaped === undefined) break;
      value += decodeEscape(escaped, lineNumber);
      index += 2;
      continue;
    }
    if (char === '"') return { value, length: index + 1 };
    value += char;
    index += 1;
  }
  throw new YamlError('Unterminated double-quoted string', lineNumber);
}

function decodeEscape(char, lineNumber) {
  switch (char) {
    case 'n':
      return '\n';
    case 't':
      return '\t';
    case 'r':
      return '\r';
    case '0':
      return '\0';
    case '"':
      return '"';
    case '\\':
      return '\\';
    case '/':
      return '/';
    default:
      throw new YamlError(`Unsupported escape sequence "\\${char}"`, lineNumber);
  }
}

function parseFlowSequence(text, lineNumber) {
  const body = requireFlowBody(text, '[', ']', lineNumber);
  return splitFlowItems(body, lineNumber).map((item) => parseScalar(item, lineNumber));
}

function parseFlowMapping(text, lineNumber) {
  const body = requireFlowBody(text, '{', '}', lineNumber);
  const result = {};
  for (const item of splitFlowItems(body, lineNumber)) {
    const { key, rest } = splitKey(item, lineNumber);
    if (Object.hasOwn(result, key)) {
      throw new YamlError(`Duplicate key "${key}"`, lineNumber);
    }
    result[key] = rest.length === 0 ? null : parseScalar(rest, lineNumber);
  }
  return result;
}

function requireFlowBody(text, open, close, lineNumber) {
  const trimmed = text.trim();
  if (!trimmed.startsWith(open)) {
    throw new YamlError(`Expected "${open}"`, lineNumber);
  }
  const closeIndex = trimmed.lastIndexOf(close);
  if (closeIndex !== trimmed.length - 1) {
    throw new YamlError(
      `Unterminated flow collection; expected "${close}" at the end of the line`,
      lineNumber,
    );
  }
  return trimmed.slice(1, -1).trim();
}

/** Splits `a, b, "c,d"` honouring quotes. Nested flow collections are rejected. */
function splitFlowItems(body, lineNumber) {
  if (body.length === 0) return [];
  const items = [];
  let current = '';
  let index = 0;

  while (index < body.length) {
    const char = body[index];
    if (char === '"' || char === "'") {
      const quoted = readQuoted(body.slice(index), lineNumber);
      current += body.slice(index, index + quoted.length);
      index += quoted.length;
      continue;
    }
    if (char === '[' || char === '{') {
      throw new YamlError('Nested flow collections are not supported', lineNumber);
    }
    if (char === ',') {
      items.push(current.trim());
      current = '';
      index += 1;
      continue;
    }
    current += char;
    index += 1;
  }

  items.push(current.trim());
  return items.filter((item) => item.length > 0);
}
