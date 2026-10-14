/*
 * Wazuh Offline Analyzer - decoder stage.
 *
 * Loads classic (4.x) XML decoders, builds the parent/child decoder tree and
 * evaluates it with a "match once and cache the chain" optimisation: a cheap
 * signature (program name + normalised opening tokens) maps to the decoder
 * chain that decoded the line, so later lines skip root iteration.
 */
(function (Wz) {
  "use strict";

  var POSIX_CLASSES = [
    ["[[:alnum:]]", "[A-Za-z0-9]"],
    ["[[:alpha:]]", "[A-Za-z]"],
    ["[[:blank:]]", "[ \\t]"],
    ["[[:digit:]]", "[0-9]"],
    ["[[:lower:]]", "[a-z]"],
    ["[[:space:]]", "\\s"],
    ["[[:upper:]]", "[A-Z]"],
    ["[[:xdigit:]]", "[A-Fa-f0-9]"],
    ["[[:word:]]", "[A-Za-z0-9_]"],
    ["[[:punct:]]", "[!-/:-@\\[-`{-~]"]
  ];

  var AFTER_PARENT = "after_parent";
  var AFTER_PREMARK = "after_prematch";
  var AFTER_REGEX = "after_regex";

  function translatePosix(pattern) {
    for (var i = 0; i < POSIX_CLASSES.length; i++) {
      if (pattern.indexOf(POSIX_CLASSES[i][0]) !== -1) {
        pattern = pattern.split(POSIX_CLASSES[i][0]).join(POSIX_CLASSES[i][1]);
      }
    }
    return pattern;
  }

  function compileRegex(pattern) {
    try {
      return new RegExp(translatePosix(pattern));
    } catch (e) {
      if (window.console) console.warn("Invalid decoder regex", pattern, e.message);
      return null;
    }
  }

  function RegexSpec(pattern, offset) {
    this.pattern = pattern;
    this.offset = offset || null;
    this.regex = compileRegex(pattern);
    this.valid = this.regex !== null;
  }

  function DecoderNode(opts) {
    this.name = opts.name || "";
    this.index = opts.index || 0;
    this.programName = opts.programName || null;
    this.prematch = opts.prematch || null;
    this.regexes = opts.regexes || [];
    this.order = opts.order || [];
    this.parents = opts.parents || [];
    this.type = opts.type || null;
    this.pluginDecoder = opts.pluginDecoder || null;
    this.useOwnName = !!opts.useOwnName;
    this.sourceFile = opts.sourceFile || "";
    this.children = [];
    this.valid = true;
    this.programRe = this.programName ? compileRegex(this.programName) : null;
    this.prematchRe = this.prematch ? compileRegex(this.prematch) : null;
    if ((this.programName && !this.programRe) || (this.prematch && !this.prematchRe)) {
      this.valid = false;
    }
  }

  DecoderNode.prototype.isRoot = function () {
    return this.parents.length === 0;
  };

  DecoderNode.prototype.isJson = function () {
    var plugin = (this.pluginDecoder || "").toLowerCase();
    var kind = (this.type || "").toLowerCase();
    return plugin.indexOf("json") !== -1 || kind === "json";
  };

  function DecoderCache() {
    this.map = new Map();
    this.hits = 0;
    this.misses = 0;
    this.stores = 0;
  }
  DecoderCache.prototype.get = function (signature) {
    if (this.map.has(signature)) {
      this.hits++;
      return this.map.get(signature);
    }
    this.misses++;
    return null;
  };
  DecoderCache.prototype.put = function (signature, chain) {
    if (!chain || !chain.length) return;
    this.map.set(signature, chain);
    this.stores++;
  };
  DecoderCache.prototype.clear = function () {
    this.map.clear();
    this.hits = this.misses = this.stores = 0;
  };
  DecoderCache.prototype.stats = function () {
    var total = this.hits + this.misses;
    return {
      entries: this.map.size,
      hits: this.hits,
      misses: this.misses,
      stores: this.stores,
      hit_ratio: total ? Math.round((this.hits / total) * 10000) / 10000 : 0
    };
  };

  function DecoderEngine() {
    this.nodes = [];
    this.byName = new Map();
    this.roots = [];
    this.cache = new DecoderCache();
    this._index = 0;
  }

  DecoderEngine.prototype.loadXml = function (text, sourceName) {
    var root = Wz.Xml.parseWazuhXml(text);
    var elements = root.getElementsByTagName("decoder");
    var count = 0;
    for (var i = 0; i < elements.length; i++) {
      var node = this._readDecoder(elements[i], sourceName || "");
      if (node) {
        this.nodes.push(node);
        count++;
      }
    }
    this._buildTree();
    return count;
  };

  DecoderEngine.prototype.loadSources = function (sources) {
    var total = 0;
    for (var i = 0; i < sources.length; i++) {
      total += this.loadXml(sources[i].text, sources[i].name);
    }
    return total;
  };

  DecoderEngine.prototype._readDecoder = function (element, sourceName) {
    var programName = null;
    var prematch = null;
    var regexes = [];
    var order = [];
    var parents = [];

    for (var i = 0; i < element.children.length; i++) {
      var child = element.children[i];
      var tag = child.tagName;
      if (tag === "program_name") {
        programName = Wz.Xml.elementText(child) || null;
      } else if (tag === "prematch") {
        prematch = Wz.Xml.elementText(child) || null;
      } else if (tag === "regex") {
        regexes.push(new RegexSpec(Wz.Xml.elementText(child), child.getAttribute("offset")));
      } else if (tag === "order") {
        order = Wz.Xml.elementText(child).split(",").map(function (s) { return s.trim(); });
      } else if (tag === "parent") {
        var p = Wz.Xml.elementText(child);
        if (p) parents.push(p);
      }
    }

    var typeEl = Wz.Xml.firstChild(element, "type");
    var pluginEl = Wz.Xml.firstChild(element, "plugin_decoder");
    var ownEl = Wz.Xml.firstChild(element, "use_own_name");

    return new DecoderNode({
      name: element.getAttribute("name") || "",
      index: this._index++,
      programName: programName,
      prematch: prematch,
      regexes: regexes,
      order: order,
      parents: parents,
      type: Wz.Xml.elementText(typeEl) || null,
      pluginDecoder: Wz.Xml.elementText(pluginEl) || null,
      useOwnName: /^(yes|true|1)$/i.test(Wz.Xml.elementText(ownEl)),
      sourceFile: sourceName
    });
  };

  DecoderEngine.prototype._buildTree = function () {
    var self = this;
    this.byName = new Map();
    this.nodes.forEach(function (node) {
      if (!self.byName.has(node.name)) self.byName.set(node.name, []);
      self.byName.get(node.name).push(node);
      node.children = [];
    });

    this.roots = [];
    this.nodes.forEach(function (node) {
      if (node.isRoot()) {
        self.roots.push(node);
        return;
      }
      var attached = false;
      node.parents.forEach(function (parentName) {
        var all = self.byName.get(parentName) || [];
        var candidates = all.filter(function (c) { return c !== node && c.isRoot(); });
        if (!candidates.length) {
          candidates = all.filter(function (c) { return c !== node; });
        }
        candidates.forEach(function (parent) {
          parent.children.push(node);
          attached = true;
        });
      });
      if (!attached) {
        self.roots.push(node);
      }
    });
  };

  DecoderEngine.prototype.signature = function (event) {
    var base = event.programName || event.source || "-";
    var tokens = event.message.replace(/^\s+/, "").split(/\s+/).slice(0, 4);
    var joined = tokens.join(" ").replace(/\d+/g, "#");
    return (base + "|" + joined.slice(0, 80)).toLowerCase();
  };

  DecoderEngine.prototype.decode = function (event) {
    var signature = this.signature(event);
    var cached = this.cache.get(signature);
    if (cached) {
      var reused = this._runChain(cached, event);
      if (reused) {
        reused.cached = true;
        return reused;
      }
    }
    var result = this._scanRoots(event);
    if (result) {
      this.cache.put(signature, result.chainNodes);
      return result;
    }
    return { decoded: false, decoder: "", chain: [], fields: {}, cached: false, chainNodes: [] };
  };

  DecoderEngine.prototype._scanRoots = function (event) {
    for (var i = 0; i < this.roots.length; i++) {
      var result = this._matchFrom(this.roots[i], event, 0);
      if (result) return result;
    }
    return null;
  };

  DecoderEngine.prototype._runChain = function (chain, event) {
    var offset = 0;
    var fields = {};
    var names = [];
    for (var i = 0; i < chain.length; i++) {
      var match = this._matchNode(chain[i], event, offset);
      if (!match) return null;
      Object.assign(fields, match.fields);
      offset = match.endOffset;
      names.push(chain[i].name);
    }
    return {
      decoded: true,
      decoder: names[names.length - 1],
      chain: names,
      fields: fields,
      cached: true,
      chainNodes: chain.slice()
    };
  };

  DecoderEngine.prototype._matchFrom = function (node, event, offset) {
    var match = this._matchNode(node, event, offset);
    if (!match) return null;

    var chainNodes = [node];
    var names = [node.name];
    var fields = Object.assign({}, match.fields);
    var current = node;
    var currentMatch = match;

    while (true) {
      var kids = current.children || [];
      var chosen = null;
      for (var i = 0; i < kids.length; i++) {
        var childMatch = this._matchNode(kids[i], event, currentMatch.endOffset);
        if (childMatch) {
          chosen = { node: kids[i], match: childMatch };
          break;
        }
      }
      if (!chosen) break;
      chainNodes.push(chosen.node);
      names.push(chosen.node.name);
      Object.assign(fields, chosen.match.fields);
      current = chosen.node;
      currentMatch = chosen.match;
    }

    return {
      decoded: true,
      decoder: names[names.length - 1],
      chain: names,
      fields: fields,
      cached: false,
      chainNodes: chainNodes
    };
  };

  DecoderEngine.prototype._matchNode = function (node, event, inheritedOffset) {
    if (!node.valid) return null;
    for (var r = 0; r < node.regexes.length; r++) {
      if (!node.regexes[r].valid) return null;
    }

    var fields = {};
    var captures = [];
    var offset = inheritedOffset || 0;

    if (node.isJson()) {
      var parsed;
      try {
        parsed = JSON.parse(event.message);
      } catch (e) {
        return null;
      }
      Object.assign(fields, flattenJson(parsed));
      return { node: node, fields: fields, endOffset: offset, captures: [] };
    }

    if (node.programRe) {
      if (!event.programName) return null;
      if (!node.programRe.exec(event.programName)) return null;
    }

    var prematchEnd = null;
    if (node.prematchRe) {
      var region = event.message.slice(offset);
      var pm = node.prematchRe.exec(region);
      if (!pm) return null;
      prematchEnd = offset + pm.index + pm[0].length;
    }

    if (node.regexes.length === 0) {
      if (!node.programRe && !node.prematchRe) return null;
      return {
        node: node,
        fields: fields,
        endOffset: prematchEnd !== null ? prematchEnd : offset,
        captures: []
      };
    }

    var regexOffset = offset;
    var lastEnd = offset;
    for (var i = 0; i < node.regexes.length; i++) {
      var spec = node.regexes[i];
      var start = resolveOffset(spec.offset, inheritedOffset || 0, prematchEnd, regexOffset);
      var m = spec.regex.exec(event.message.slice(start));
      if (!m) return null;
      var groups = m.slice(1);
      for (var g = 0; g < groups.length; g++) {
        if (groups[g] != null) captures.push(groups[g]);
      }
      assignOrder(fields, node.order, groups);
      lastEnd = start + m.index + m[0].length;
      regexOffset = lastEnd;
    }

    return { node: node, fields: fields, endOffset: lastEnd, captures: captures };
  };

  function resolveOffset(specOffset, inherited, prematchEnd, regexOffset) {
    if (specOffset === AFTER_PREMARK) {
      return prematchEnd !== null ? prematchEnd : inherited;
    }
    if (specOffset === AFTER_REGEX) {
      return regexOffset;
    }
    if (specOffset === AFTER_PARENT) {
      return inherited;
    }
    if (prematchEnd !== null) {
      return prematchEnd;
    }
    return inherited;
  }

  function assignOrder(fields, order, groups) {
    for (var i = 0; i < groups.length; i++) {
      if (i >= order.length) break;
      var name = order[i];
      if (!name) continue;
      fields[name] = groups[i];
    }
  }

  function flattenJson(data, prefix, out) {
    out = out || {};
    prefix = prefix || "";
    if (data && typeof data === "object" && !Array.isArray(data)) {
      Object.keys(data).forEach(function (key) {
        var path = prefix ? prefix + "." + key : String(key);
        var value = data[key];
        if (value && typeof value === "object" && !Array.isArray(value)) {
          flattenJson(value, path, out);
        } else {
          out[path] = value;
        }
      });
    } else {
      out[prefix || "data"] = data;
    }
    return out;
  }

  Wz.DecoderEngine = DecoderEngine;
  Wz.translatePosix = translatePosix;
})(window.Wazuh = window.Wazuh || {});
