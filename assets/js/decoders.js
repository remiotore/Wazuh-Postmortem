/*
 * Wazuh Offline Analyzer - decoder stage.
 *
 * Loads classic (4.x) XML decoders and evaluates them the way analysisd does:
 * a decoder whose <parent> is the current end of the chain is applied when it
 * matches, and the walk continues down the tree, so every matching child
 * contributes and the last one to match owns the fields it overwrites.
 *
 * Matching the whole ruleset costs a scan of the parentless decoders, so the
 * chain that decoded a line is cached under a normalised signature and reused
 * for lines of the same shape.
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

  // Chains in the real ruleset are a handful deep; the cap only guards against
  // a parent cycle in a hand-written decoder.
  var MAX_CHAIN_DEPTH = 12;

  // Upstream default when a decoder declares no <type>.
  var DEFAULT_TYPE = "syslog";

  // "after_parent" is the default and is handled as the fallback in
  // resolveOffset(); only the two explicit alternatives need naming here.
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
    var root;
    try {
      root = Wz.Xml.parseWazuhXml(text);
    } catch (err) {
      // Name the file: one malformed ruleset document otherwise takes the
      // whole bundle down with an error that points nowhere.
      throw new Error((sourceName ? sourceName + ": " : "") + err.message);
    }
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
        programName = Wz.Xml.patternText(child) || null;
      } else if (tag === "prematch") {
        prematch = Wz.Xml.patternText(child) || null;
      } else if (tag === "regex") {
        regexes.push(new RegexSpec(Wz.Xml.patternText(child), child.getAttribute("offset")));
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

  /*
   * Cache key for a decoded shape: the program name plus the whole message with
   * digit runs collapsed, so a burst of identical attack lines hits the cache
   * while genuinely different lines do not collide.  An earlier version keyed on
   * the first four tokens only, which made "/app?id=1 union select ..." poison
   * the entry for every later access-log line from the same host.
   */
  DecoderEngine.prototype.signature = function (event) {
    var base = event.programName || event.source || "-";
    var normalized = event.message.replace(/[0-9]+/g, "#").replace(/\s+/g, " ");
    return (base + "|" + normalized.length + "|" + normalized.slice(0, 160)).toLowerCase();
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
    var result = this._bestMatch(event);
    if (result) {
      this.cache.put(signature, result.chainNodes);
      return result;
    }
    return { decoded: false, decoder: "", chain: [], type: "", fields: {}, cached: false, chainNodes: [] };
  };

  /*
   * Every root is tried and the deepest chain wins, ties going to the earliest
   * decoder in the ruleset.  Picking the first root that merely matches is not
   * good enough: the roundcube prematch is a character class that matches any
   * word character, so it accepts syslog, firewall and access-log lines alike
   * and would shadow sshd, apache and friends purely by file order.
   */
  DecoderEngine.prototype._bestMatch = function (event) {
    var best = null;
    for (var i = 0; i < this.roots.length; i++) {
      var result = this._matchFrom(this.roots[i], event, 0);
      if (!result) continue;
      if (best === null || result.chain.length > best.chain.length ||
        (result.chain.length === best.chain.length && result.rootIndex < best.rootIndex)) {
        best = result;
      }
    }
    return best;
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
      type: chainType(chain),
      fields: fields,
      cached: true,
      chainNodes: chain.slice()
    };
  };

  /*
   * The event's category is the <type> of the last decoder in the chain that
   * declares one; upstream defaults it to "syslog".  Rules select on it with
   * <category>, which is how the web, squid, ids, firewall, windows and ossec
   * rule sets keep from matching each other's events.
   */
  function chainType(chain) {
    for (var i = chain.length - 1; i >= 0; i--) {
      if (chain[i].type) return chain[i].type;
    }
    return DEFAULT_TYPE;
  }

  /*
   * Build the decoder chain for one event.
   *
   * analysisd walks its ordered decoder list and applies a decoder whose
   * <parent> is the current end of the chain; it does not stop at the first
   * child that matches, it keeps going.  That matters in practice: the web
   * access log decoder declares a domain, an ip-ip and a plain ip child whose
   * prematches all overlap, and the last one to match is the one whose fields
   * survive - which is how upstream ends up with the right srcip on a plain
   * combined-log line.
   */
  DecoderEngine.prototype._matchFrom = function (node, event, offset) {
    var match = this._matchNode(node, event, offset);
    if (!match) return null;

    var chainNodes = [node];
    var names = [node.name];
    var fields = Object.assign({}, match.fields);
    this._extendChain(node, match, event, chainNodes, names, fields, MAX_CHAIN_DEPTH);
    return {
      decoded: true,
      decoder: names[names.length - 1],
      chain: names,
      type: chainType(chainNodes),
      fields: fields,
      cached: false,
      chainNodes: chainNodes,
      rootIndex: node.index
    };
  };

  DecoderEngine.prototype._extendChain = function (node, match, event, chainNodes, names, fields, budget) {
    if (budget <= 0) return;
    var kids = node.children || [];
    for (var i = 0; i < kids.length; i++) {
      var childMatch = this._matchNode(kids[i], event, match.endOffset);
      if (!childMatch) continue;
      chainNodes.push(kids[i]);
      names.push(kids[i].name);
      Object.assign(fields, childMatch.fields);
      this._extendChain(kids[i], childMatch, event, chainNodes, names, fields, budget - 1);
    }
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
      return {
        node: node, fields: fields, endOffset: offset, captures: []
      };
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
      /*
       * A decoder that only gates on prematch has not consumed anything: the
       * offset handed to children is the inherited one, not the end of the
       * prematch.  Children that want to start after the prematch ask for it
       * explicitly with offset="after_prematch".  Getting this wrong makes
       * every web-accesslog line fall off the end of the decoder chain.
       */
      return {
        node: node,
        fields: fields,
        endOffset: offset,
        captures: []
      };
    }

    /*
     * <order> is one list per decoder, consumed left to right across every
     * regex the decoder owns - not restarted per regex.  Multi-regex decoders
     * such as the checkpoint syslog ones rely on this to name their second and
     * third capture groups.
     */
    var orderCursor = 0;
    var regexOffset = offset;
    var lastEnd = offset;
    for (var i = 0; i < node.regexes.length; i++) {
      var spec = node.regexes[i];
      var start = resolveOffset(spec.offset, inheritedOffset || 0, prematchEnd, regexOffset);
      var m = spec.regex.exec(event.message.slice(start));
      if (!m) return null;
      var groups = m.slice(1);
      for (var g = 0; g < groups.length; g++) {
        var field = orderCursor < node.order.length ? node.order[orderCursor] : null;
        orderCursor++;
        if (groups[g] == null) continue;
        captures.push(groups[g]);
        if (field) fields[field] = groups[g];
      }
      lastEnd = start + m.index + m[0].length;
      regexOffset = lastEnd;
    }

    return {
      node: node,
      fields: fields,
      endOffset: lastEnd,
      captures: captures
    };
  };

  /*
   * Upstream defaults <regex offset="..."> to after_parent: a decoder that also
   * has a prematch still matches its regex against the inherited offset unless
   * it explicitly asks for after_prematch.
   */
  function resolveOffset(specOffset, inherited, prematchEnd, regexOffset) {
    if (specOffset === AFTER_PREMARK) {
      return prematchEnd !== null ? prematchEnd : inherited;
    }
    if (specOffset === AFTER_REGEX) {
      return regexOffset;
    }
    return inherited;
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
