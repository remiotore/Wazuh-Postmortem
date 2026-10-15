/*
 * Minimal, dependency-free XML reader used by the offline build/verify tools.
 *
 * Wazuh ruleset files are NOT well-formed XML on their own: the project parses
 * them with its own config reader, so a few upstream files contain bare "&"
 * and stray "<" in element text.  This module therefore offers three things:
 *
 *   sanitize(text)  escape stray markup so the browser's DOMParser accepts it,
 *                   without changing the text the engines finally see.
 *   parse(text)     build a DOMParser-compatible tree (used by the headless
 *                   verification harness, which has no DOM).
 *   validate(text)  throw with file/line context if a document is still broken.
 *
 * It is intentionally small: the ruleset only uses elements, attributes, text
 * and comments, with no DTDs, namespaces or CDATA.
 */
"use strict";

var NAME_START = /[A-Za-z_:]/;
var NAME_CHAR = /[A-Za-z0-9_:.\-]/;
var WHITESPACE = /\s/;
var ENTITY = /^&(?:#[0-9]+|#x[0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]*);/;
var NAMED_ENTITIES = {
  amp: "&", lt: "<", gt: ">", quot: '"', apos: "'"
};

function decodeEntities(text) {
  return String(text).replace(/&(?:#[0-9]+|#x[0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]*);/g, function (ref) {
    if (ref.charAt(1) === "#") {
      var hex = /^&#x([0-9a-fA-F]+);$/.exec(ref);
      var code = hex ? parseInt(hex[1], 16) : parseInt(ref.slice(2, -1), 10);
      return isNaN(code) || code < 0 || code > 0x10ffff ? ref : String.fromCodePoint(code);
    }
    var name = ref.slice(1, -1);
    return Object.prototype.hasOwnProperty.call(NAMED_ENTITIES, name) ? NAMED_ENTITIES[name] : ref;
  });
}

/*
 * Returns the character reference starting at `index`, or null if the "&" does
 * not open one.  Only the five predefined entities plus numeric references
 * count: anything else is undefined, and a browser parser rejects the document
 * instead of resolving it.
 */
function entityAt(text, index) {
  var match = ENTITY.exec(text.slice(index));
  if (!match) return null;
  var named = /^&([A-Za-z][A-Za-z0-9]*);$/.exec(match[0]);
  if (named && !Object.prototype.hasOwnProperty.call(NAMED_ENTITIES, named[1])) return null;
  return match[0];
}

/**
 * Walk a document once, calling the visitor for every region.  The visitor
 * classifies each region so callers can escape or build nodes without needing
 * their own tokenizer.
 */
function scan(text, visitor) {
  var i = 0;
  var n = text.length;

  while (i < n) {
    var ch = text.charAt(i);

    if (ch === "<") {
      if (text.startsWith("<!--", i)) {
        var commentEnd = text.indexOf("-->", i + 4);
        if (commentEnd === -1) throw new XmlError("unterminated comment", text, i);
        visitor("comment", text.slice(i + 4, commentEnd), i);
        i = commentEnd + 3;
        continue;
      }
      if (text.startsWith("<![CDATA[", i)) {
        var cdataEnd = text.indexOf("]]>", i + 9);
        if (cdataEnd === -1) throw new XmlError("unterminated CDATA section", text, i);
        visitor("cdata", text.slice(i + 9, cdataEnd), i);
        i = cdataEnd + 3;
        continue;
      }
      if (text.startsWith("<?", i)) {
        var piEnd = text.indexOf("?>", i + 2);
        if (piEnd === -1) throw new XmlError("unterminated processing instruction", text, i);
        visitor("pi", text.slice(i + 2, piEnd), i);
        i = piEnd + 2;
        continue;
      }
      if (text.startsWith("<!", i)) {
        var declEnd = text.indexOf(">", i + 2);
        if (declEnd === -1) throw new XmlError("unterminated declaration", text, i);
        visitor("decl", text.slice(i + 2, declEnd), i);
        i = declEnd + 1;
        continue;
      }
      if (text.startsWith("</", i)) {
        var closeEnd = text.indexOf(">", i);
        if (closeEnd === -1) throw new XmlError("unterminated end tag", text, i);
        visitor("end", text.slice(i + 2, closeEnd).trim(), i);
        i = closeEnd + 1;
        continue;
      }
      if (NAME_START.test(text.charAt(i + 1))) {
        var tagEnd = findTagEnd(text, i);
        if (tagEnd === -1) throw new XmlError("unterminated start tag", text, i);
        visitor("start", text.slice(i + 1, tagEnd), i);
        i = tagEnd + 1;
        continue;
      }
      // A "<" that cannot begin a markup construct is literal text.
      visitor("literal-lt", "<", i);
      i++;
      continue;
    }

    if (ch === "&") {
      var reference = entityAt(text, i);
      if (reference) {
        visitor("text", reference, i);
        i += reference.length;
        continue;
      }
      if (ENTITY.test(text.slice(i))) {
        var end = text.indexOf(";", i);
        visitor("bad-entity", text.slice(i, end + 1), i);
        i = end + 1;
        continue;
      }
      visitor("bare-amp", "&", i);
      i++;
      continue;
    }

    var next = i;
    while (next < n) {
      var c = text.charAt(next);
      if (c === "<" || c === "&") break;
      if (c === "]" && text.startsWith("]]>", next)) {
        visitor("text", text.slice(i, next), i);
        visitor("cd-close", "]]>", next);
        i = next + 3;
        next = i;
        continue;
      }
      next++;
    }
    visitor("text", text.slice(i, next), i);
    i = next;
  }
}

function findTagEnd(text, start) {
  var quote = null;
  for (var i = start + 1; i < text.length; i++) {
    var ch = text.charAt(i);
    if (quote) {
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") { quote = ch; continue; }
    if (ch === ">") return i;
  }
  return -1;
}

function XmlError(message, text, index) {
  var upto = text.slice(0, index);
  var line = upto.split("\n").length;
  var column = index - upto.lastIndexOf("\n");
  this.name = "XmlError";
  this.message = message + " at line " + line + ", column " + column;
  this.line = line;
  this.column = column;
}
XmlError.prototype = Object.create(Error.prototype);

function position(text, index) {
  var upto = text.slice(0, index);
  return { line: upto.split("\n").length, column: index - upto.lastIndexOf("\n") };
}

function lineOf(text, index) {
  return position(text, index).line;
}

function parseAttributes(body) {
  var attrs = [];
  var re = /([^\s=/>]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
  var consumed = 0;
  var match;
  while ((match = re.exec(body)) !== null) {
    consumed = re.lastIndex;
    attrs.push({
      name: match[1],
      value: decodeEntities(match[2] !== undefined ? match[2] : match[3])
    });
  }
  return { attrs: attrs, consumed: consumed };
}

/**
 * Escape markup that upstream left unescaped.  "&" that does not already open
 * a character reference becomes "&amp;" and a "<" that cannot start a tag
 * becomes "&lt;", so element text decodes back to exactly the original bytes.
 */
function sanitize(text) {
  var fixes = [];
  var out = "";
  scan(String(text), function (type, value, index) {
    switch (type) {
      case "text":
        out += value;
        break;
      case "bare-amp":
        fixes.push({ offset: index, kind: "bare-amp", replacement: "&amp;" });
        out += "&amp;";
        break;
      case "bad-entity":
        fixes.push({ offset: index, kind: "undefined-entity", replacement: "&amp;" });
        out += "&amp;" + value.slice(1);
        break;
      case "cd-close":
        fixes.push({ offset: index, kind: "cdata-close", replacement: "&gt;" });
        out += "]]&gt;";
        break;
      case "literal-lt":
        fixes.push({ offset: index, kind: "literal-lt", replacement: "&lt;" });
        out += "&lt;";
        break;
      case "start":
        out += sanitizeStartTag(value, fixes, index);
        break;
      case "comment": {
        var safe = commentSafe(value);
        if (safe !== value) {
          fixes.push({ offset: index, kind: "comment-double-hyphen", replacement: "-=" });
        }
        out += "<!--" + safe + "-->";
        break;
      }
      case "cdata":
        out += "<![CDATA[" + value + "]]>";
        break;
      case "pi":
        out += "<?" + value + "?>";
        break;
      case "decl":
        out += "<!" + value + ">";
        break;
      case "end":
        out += "</" + value + ">";
        break;
      default:
        throw new XmlError("unknown region " + type, String(text), index);
    }
  });
  return { text: out, fixes: fixes };
}

/*
 * "--" may not appear inside an XML comment, and a comment may not end with
 * "-" because that would fuse with the closing delimiter.  Upstream is full of
 * example log lines and separator rules that contain them - nginx's "proxy
 * request -- speaking HTTP to HTTPS port!?" and a hundred-dash rule under
 * cylance - and a browser DOMParser rejects the whole document, taking the
 * entire ruleset down with it.  Separating each pair with "=" keeps the text
 * the same length and makes the substitution obvious.
 */
function commentSafe(value) {
  return value
    .replace(/-{2,}/g, function (run) {
      return new Array(Math.floor(run.length / 2) + 1).join("-=") + (run.length % 2 ? "-" : "");
    })
    .replace(/-$/, "");
}

function sanitizeStartTag(body, fixes, index) {
  var parsed = parseAttributes(body);
  var nameMatch = /^[^\s/>]+/.exec(body);
  var tail = body.slice(nameMatch ? nameMatch[0].length : 0, parsed.consumed);
  if (!tail.trim()) return "<" + body + ">";

  var rebuilt = "";
  var attrRe = /([^\s=/>]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
  var last = 0;
  var match;
  var end = parsed.consumed;
  while ((match = attrRe.exec(body.slice(0, end))) !== null) {
    rebuilt += body.slice(last, match.index);
    var quote = match[2] !== undefined ? '"' : "'";
    var value = match[2] !== undefined ? match[2] : match[3];
    var escaped = "";
    for (var c = 0; c < value.length; c++) {
      var ch = value.charAt(c);
      if (ch === "&") {
        var reference = entityAt(value, c);
        if (reference) {
          escaped += reference;
          c += reference.length - 1;
          continue;
        }
        fixes.push({ offset: index, kind: "bare-amp-in-attribute", replacement: "&amp;" });
        escaped += "&amp;";
      } else if (ch === "<") {
        fixes.push({ offset: index, kind: "literal-lt-in-attribute", replacement: "&lt;" });
        escaped += "&lt;";
      } else if (ch === '"' && quote === '"') {
        escaped += "&quot;";
      } else {
        escaped += ch;
      }
    }
    rebuilt += match[1] + "=" + quote + escaped + quote;
    last = attrRe.lastIndex;
  }
  rebuilt += body.slice(last);
  return "<" + rebuilt + ">";
}

// -- DOM shim ------------------------------------------------------------

var ELEMENT_NODE = 1;
var TEXT_NODE = 3;
var COMMENT_NODE = 8;
var DOCUMENT_NODE = 9;

function XmlNode(type) {
  this.nodeType = type;
  this.childNodes = [];
  this.parentNode = null;
}
Object.defineProperty(XmlNode.prototype, "children", {
  get: function () {
    return this.childNodes.filter(function (n) { return n.nodeType === ELEMENT_NODE; });
  }
});
Object.defineProperty(XmlNode.prototype, "textContent", {
  get: function () {
    if (this.nodeType === TEXT_NODE) return this.nodeValue;
    if (this.nodeType === COMMENT_NODE) return "";
    return this.childNodes.map(function (n) { return n.textContent; }).join("");
  },
  set: function (value) {
    this.childNodes = [new TextNode(String(value))];
    this.childNodes[0].parentNode = this;
  }
});

function TextNode(value) {
  XmlNode.call(this, TEXT_NODE);
  this.nodeValue = value;
}
TextNode.prototype = Object.create(XmlNode.prototype);

function ElementNode(name, attrs) {
  XmlNode.call(this, ELEMENT_NODE);
  this.tagName = name;
  this.nodeName = name;
  this.attributes = attrs;
  this.ownerDocument = null;
}
ElementNode.prototype = Object.create(XmlNode.prototype);

ElementNode.prototype.getAttribute = function (name) {
  for (var i = 0; i < this.attributes.length; i++) {
    if (this.attributes[i].name === name) return this.attributes[i].value;
  }
  return null;
};

ElementNode.prototype.hasAttribute = function (name) {
  return this.getAttribute(name) !== null;
};

ElementNode.prototype.getElementsByTagName = function (name) {
  var out = [];
  (function walk(node) {
    node.childNodes.forEach(function (child) {
      if (child.nodeType !== ELEMENT_NODE) return;
      if (child.tagName === name) out.push(child);
      walk(child);
    });
  })(this);
  return out;
};

function DocumentNode(root) {
  XmlNode.call(this, DOCUMENT_NODE);
  this.documentElement = root;
  this.nodeName = "#document";
  if (root) {
    this.childNodes = [root];
    root.parentNode = this;
  }
}
DocumentNode.prototype = Object.create(XmlNode.prototype);
DocumentNode.prototype.getElementsByTagName = function (name) {
  if (!this.documentElement) return [];
  return this.documentElement.getElementsByTagName(name);
};

var WRAPPER = "wazuh_ruleset";

/**
 * DOMParser-compatible entry point: a well-formed XML document must have
 * exactly one root element, which becomes documentElement.
 */
function parse(text) {
  var root = parseInto(text, null, null);
  if (!root) throw new XmlError("document has no root element", String(text), 0);
  if (root.next) {
    throw new XmlError("more than one root element <" + root.element.tagName +
      "> and <" + root.next.tagName + ">", String(text), root.offset);
  }
  return new DocumentNode(root.element);
}

/**
 * Parse a Wazuh ruleset fragment - several top-level elements, an optional
 * <?xml?> / <!DOCTYPE> header, no single root - and return the synthetic
 * wrapper that xml.js builds in the browser.
 */
function parseFragment(text) {
  return parse("<" + WRAPPER + ">" + String(text) + "</" + WRAPPER + ">").documentElement;
}

function parseRoots(text) {
  if (text == null) throw new XmlError("XML content is empty", "", 0);
  var roots = [];
  var stack = [];
  var top = new ElementNode(WRAPPER, []);

  function current() {
    return stack.length ? stack[stack.length - 1] : top;
  }

  scan(String(text), function (type, value, index) {
    var parent = current();
    switch (type) {
      case "text":
        appendText(parent, decodeEntities(value));
        break;
      case "literal-lt":
        if (text.startsWith("<![CDATA[", index)) {
          throw new XmlError("\"]]>\" is not allowed in character data", text, index);
        }
        appendText(parent, "<");
        break;
      case "bad-entity":
        throw new XmlError("undefined entity " + value, text, index);
      case "cd-close":
        throw new XmlError("\"]]>\" is not allowed in character data", text, index);
      case "cdata":
        appendText(parent, value);
        break;
      case "comment":
        if (value.indexOf("--") !== -1) {
          throw new XmlError("comment contains \"--\"", text, index);
        }
        if (value.charAt(value.length - 1) === "-") {
          throw new XmlError("comment ends with \"-\"", text, index);
        }
        appendComment(parent, value);
        break;
      case "start": {
        var element = new ElementNode(/^[^\s/>]+/.exec(value)[0], parseAttributes(value).attrs);
        if (!stack.length) element.__offset = index;
        parent.childNodes.push(element);
        element.parentNode = stack.length ? parent : null;
        if (!/\/\s*$/.test(value)) stack.push(element);
        break;
      }
      case "end": {
        if (!stack.length) {
          throw new XmlError("unexpected end tag </" + value + ">", text, index);
        }
        var open = stack.pop();
        if (open.tagName !== value) {
          throw new XmlError("end tag </" + value + "> does not match <" + open.tagName + ">",
            text, index);
        }
        if (!stack.length) roots.push(open);
        break;
      }
      default:
        break;
    }
  });

  if (stack.length) {
    throw new XmlError("unclosed element <" + stack[stack.length - 1].tagName + ">",
      text, text.length);
  }
  return roots;
}

function parse(text) {
  var roots = parseRoots(text);
  if (!roots.length) throw new XmlError("document has no root element", String(text), 0);
  if (roots.length > 1) {
    throw new XmlError("more than one root element (<" + roots[0].tagName + "> and <" +
      roots[1].tagName + ">)", String(text), roots[1].__offset || 0);
  }
  return new DocumentNode(roots[0]);
}

function parseFragment(text) {
  return parse("<" + WRAPPER + ">" + String(text) + "</" + WRAPPER + ">").documentElement;
}

function appendText(parent, value) {
  if (!value) return;
  var text = new TextNode(value);
  parent.childNodes.push(text);
  text.parentNode = parent;
}

function appendComment(parent, value) {
  var comment = new XmlNode(COMMENT_NODE);
  comment.nodeValue = value;
  parent.childNodes.push(comment);
  comment.parentNode = parent;
}

function validate(text, label) {
  try {
    parseFragment(text);
    return null;
  } catch (err) {
    if (err instanceof XmlError) {
      return (label ? label + ": " : "") + err.message;
    }
    throw err;
  }
}

module.exports = {
  sanitize: sanitize,
  parse: parse,
  parseFragment: parseFragment,
  validate: validate,
  decodeEntities: decodeEntities,
  XmlError: XmlError,
  position: position,
  lineOf: lineOf
};