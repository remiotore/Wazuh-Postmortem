/*
 * Wazuh Offline Analyzer - rule stage.
 *
 * Classic Wazuh/OSSEC rule-chain semantics for offline analysis: if_sid /
 * if_group parent-child relationships, decoded_as / match / regex / field / ip
 * conditions (AND-ed, optional negate), frequency+timeframe aggregation, and
 * level-based alerting.
 *
 * Timeframe bookkeeping uses O(1) "most recent mark" indexes: because events
 * are processed in order, the latest occurrence of a rule/group/field value is
 * enough to answer any "within timeframe?" question.
 */
(function (Wz) {
  "use strict";

  var FIELD_TAGS = {
    srcip: true, dstip: true, srcport: true, dstport: true, srcuser: true,
    dstuser: true, user: true, id: true, url: true, status: true, action: true,
    extra_data: true, data: true, system_name: true, hostname: true,
    program_name: true, location: true, protocol: true, name: true,
    command: true, session: true
  };
  var IP_TAGS = { srcip: true, dstip: true };
  var SAME_FIELD_MAP = {
    same_source_ip: "srcip", same_dstip: "dstip", same_id: "id",
    same_srcuser: "srcuser", same_user: "user", same_agent: "agent",
    same_location: "location"
  };
  var WEEKDAYS = {
    sunday: 0, monday: 1, tuesday: 2, wednesday: 3,
    thursday: 4, friday: 5, saturday: 6
  };

  function toInt(value, def) {
    var n = parseInt(value, 10);
    return isNaN(n) ? def : n;
  }

  function splitCsv(text) {
    return String(text || "").split(",").map(function (s) { return s.trim(); })
      .filter(function (s) { return s.length; });
  }

  function toInts(text) {
    var out = [];
    String(text || "").replace(/,/g, " ").split(/\s+/).forEach(function (tok) {
      var n = parseInt(tok, 10);
      if (!isNaN(n)) out.push(n);
    });
    return out;
  }

  function parseIfLevel(text) {
    text = String(text || "").trim();
    var ops = [">=", "<=", ">", "<", "="];
    for (var i = 0; i < ops.length; i++) {
      if (text.indexOf(ops[i]) === 0) {
        var v = parseInt(text.slice(ops[i].length), 10);
        return isNaN(v) ? null : { op: ops[i], value: v };
      }
    }
    var n = parseInt(text, 10);
    return isNaN(n) ? null : { op: ">=", value: n };
  }

  function compareLevel(current, op, threshold) {
    if (op === ">=") return current >= threshold;
    if (op === "<=") return current <= threshold;
    if (op === ">") return current > threshold;
    if (op === "<") return current < threshold;
    return current === threshold;
  }

  function Condition(kind, value, opts) {
    opts = opts || {};
    this.kind = kind;
    this.value = value;
    this.name = opts.name || null;
    this.negate = !!opts.negate;
    this.matchType = opts.matchType || "osmatch";
    this.regex = null;
    this.network = null;
    try {
      if (kind === "regex" || kind === "field" || kind === "program_name") {
        this.regex = new RegExp(Wz.translatePosix(value));
      } else if (kind === "match" && this.matchType === "pcre2") {
        this.regex = new RegExp(Wz.translatePosix(value));
      } else if (kind === "ip") {
        this.network = parseNetwork(value);
      }
    } catch (e) {
      if (window.console) console.warn("Invalid rule regex", value, e.message);
      this.regex = null;
    }
  }

  function Rule(id) {
    this.id = id;
    this.level = 0;
    this.frequency = 0;
    this.timeframe = 0;
    this.noalert = false;
    this.description = "";
    this.groups = [];
    this.decodedAs = [];
    this.ifSid = [];
    this.ifGroup = [];
    this.ifLevel = null;
    this.ifMatchedSid = [];
    this.ifMatchedGroup = [];
    this.sameFields = [];
    this.conditions = [];
    this.timeConstraints = [];
    this.weekdays = {};
  }

  Rule.prototype.isRootRule = function () {
    return !(this.ifSid.length || this.ifGroup.length ||
      this.ifMatchedSid.length || this.ifMatchedGroup.length || this.ifLevel);
  };

  function parseWeekdays(text) {
    var out = {};
    String(text || "").replace(/,/g, " ").split(/\s+/).forEach(function (tok) {
      var key = tok.trim().toLowerCase();
      if (WEEKDAYS[key] !== undefined) out[WEEKDAYS[key]] = true;
    });
    return out;
  }

  function parseTimeRanges(text) {
    var out = [];
    String(text || "").split(",").forEach(function (part) {
      var m = /^(\d{1,2}):(\d{2})-(\d{1,2}):(\d{2})$/.exec(part.trim());
      if (m) {
        out.push({
          start: parseInt(m[1], 10) * 60 + parseInt(m[2], 10),
          end: parseInt(m[3], 10) * 60 + parseInt(m[4], 10)
        });
      }
    });
    return out;
  }

  function RuleEngine(alertLevel) {
    this.alertLevel = alertLevel || 3;
    this.rules = [];
    this.byId = new Map();
    this._recentRule = new Map();
    this._recentGroup = new Map();
    this._recentField = new Map();
    this._frequencyCounts = new Map();
  }

  RuleEngine.prototype.reset = function () {
    this._recentRule.clear();
    this._recentGroup.clear();
    this._recentField.clear();
    this._frequencyCounts.clear();
  };

  RuleEngine.prototype.loadXml = function (text, sourceName) {
    var root = Wz.Xml.parseWazuhXml(text);
    var entries = collectRules(root);
    var count = 0;
    for (var i = 0; i < entries.length; i++) {
      var rule = this._readRule(entries[i].el, sourceName || "", entries[i].groups);
      if (rule) {
        this.rules.push(rule);
        count++;
      }
    }
    this._reindex();
    return count;
  };

  RuleEngine.prototype.loadSources = function (sources) {
    var total = 0;
    for (var i = 0; i < sources.length; i++) {
      total += this.loadXml(sources[i].text, sources[i].name);
    }
    return total;
  };

  RuleEngine.prototype._reindex = function () {
    var self = this;
    this.byId = new Map();
    this.rules.forEach(function (rule) { self.byId.set(rule.id, rule); });
  };

  RuleEngine.prototype._readRule = function (element, sourceName, inheritedGroups) {
    var rawId = element.getAttribute("id");
    if (!rawId) return null;
    var id = parseInt(rawId, 10);
    if (isNaN(id)) return null;

    var rule = new Rule(id);
    rule.level = toInt(element.getAttribute("level"), 0);
    rule.frequency = toInt(element.getAttribute("frequency"), 0);
    rule.timeframe = toInt(element.getAttribute("timeframe"), 0);
    rule.noalert = /^(yes|1|true)$/i.test(element.getAttribute("noalert") || "");
    rule.groups = inheritedGroups.slice();

    for (var i = 0; i < element.children.length; i++) {
      var child = element.children[i];
      var tag = child.tagName;
      var text = Wz.Xml.elementText(child);
      var negate = /^(yes|1|true)$/i.test(child.getAttribute("negate") || "");
      var matchType = (child.getAttribute("type") || "osmatch").toLowerCase();

      if (tag === "description") {
        rule.description = text;
      } else if (tag === "group") {
        rule.groups = rule.groups.concat(splitCsv(text));
      } else if (tag === "decoded_as") {
        rule.decodedAs = rule.decodedAs.concat(text.split(/\s+/).filter(Boolean));
      } else if (tag === "if_sid") {
        rule.ifSid = rule.ifSid.concat(toInts(text));
      } else if (tag === "if_group") {
        rule.ifGroup = rule.ifGroup.concat(splitCsv(text));
      } else if (tag === "if_level") {
        rule.ifLevel = parseIfLevel(text);
      } else if (tag === "if_matched_sid") {
        rule.ifMatchedSid = rule.ifMatchedSid.concat(toInts(text));
      } else if (tag === "if_matched_group") {
        rule.ifMatchedGroup = rule.ifMatchedGroup.concat(splitCsv(text));
      } else if (SAME_FIELD_MAP[tag] || tag === "same_field") {
        var fieldName = tag === "same_field" ? child.getAttribute("name") : SAME_FIELD_MAP[tag];
        if (fieldName) rule.sameFields.push(fieldName);
      } else if (tag === "match") {
        rule.conditions.push(new Condition("match", text, { negate: negate, matchType: matchType }));
      } else if (tag === "regex") {
        rule.conditions.push(new Condition("regex", text, { negate: negate, matchType: "regex" }));
      } else if (tag === "field") {
        rule.conditions.push(new Condition("field", text, { name: child.getAttribute("name") || "data", negate: negate }));
      } else if (FIELD_TAGS[tag]) {
        rule.conditions.push(new Condition(IP_TAGS[tag] ? "ip" : "field", text, { name: tag, negate: negate }));
      } else if (tag === "time") {
        rule.timeConstraints = rule.timeConstraints.concat(parseTimeRanges(text));
      } else if (tag === "weekday") {
        var wd = parseWeekdays(text);
        Object.keys(wd).forEach(function (k) { rule.weekdays[k] = true; });
      } else if (tag === "options" && text.toLowerCase().indexOf("noalert") !== -1) {
        rule.noalert = true;
      }
    }
    return rule;
  };

  RuleEngine.prototype.matchEvent = function (decoded, event, index) {
    var firedSids = {};
    var firedGroups = {};
    var fired = [];
    var maxLevel = 0;
    var eventFields = Object.assign({}, Wz.eventFieldsSnapshot(event), decoded.fields);

    var changed = true;
    var guard = Math.max(1, Math.min(this.rules.length, 4096));
    for (var pass = 0; pass < guard && changed; pass++) {
      changed = false;
      for (var i = 0; i < this.rules.length; i++) {
        var rule = this.rules[i];
        if (firedSids[rule.id]) continue;
        if (!this._preconditionsOk(rule, firedSids, firedGroups, maxLevel, event, index, eventFields)) continue;
        if (!this._conditionsOk(rule, decoded, event)) continue;
        var firedRule = this._register(rule, event, index, eventFields);
        fired.push(firedRule);
        firedSids[rule.id] = true;
        for (var g = 0; g < rule.groups.length; g++) firedGroups[rule.groups[g]] = true;
        maxLevel = Math.max(maxLevel, rule.level);
        changed = true;
      }
    }
    return fired;
  };

  RuleEngine.prototype._preconditionsOk = function (rule, firedSids, firedGroups, maxLevel, event, index, eventFields) {
    var i;
    if (rule.ifSid.length && !anyIn(rule.ifSid, firedSids)) return false;
    if (rule.ifGroup.length && !anyIn(rule.ifGroup, firedGroups)) return false;
    if (rule.ifLevel && !compareLevel(maxLevel, rule.ifLevel.op, rule.ifLevel.value)) return false;
    if (rule.ifMatchedSid.length && !this._matchedSid(rule.ifMatchedSid, rule.timeframe, event, index)) return false;
    if (rule.ifMatchedGroup.length && !this._matchedGroup(rule.ifMatchedGroup, rule.timeframe, event, index)) return false;
    for (i = 0; i < rule.sameFields.length; i++) {
      if (!this._sameField(rule, rule.sameFields[i], event, index, eventFields)) return false;
    }
    if (!this._timeOk(rule, event)) return false;
    return true;
  };

  RuleEngine.prototype._conditionsOk = function (rule, decoded, event) {
    if (rule.decodedAs.length) {
      var chain = decoded.chain || [];
      if (!rule.decodedAs.some(function (name) { return chain.indexOf(name) !== -1; })) return false;
    }
    for (var i = 0; i < rule.conditions.length; i++) {
      var cond = rule.conditions[i];
      var result = this._evalCondition(cond, decoded, event);
      if (cond.negate) result = !result;
      if (!result) return false;
    }
    return true;
  };

  RuleEngine.prototype._evalCondition = function (condition, decoded, event) {
    var value;
    if (condition.kind === "match" || condition.kind === "regex") {
      return evalText(condition, event.raw);
    }
    if (condition.kind === "program_name") {
      value = (decoded.fields && decoded.fields.program_name) || event.programName || "";
      return condition.regex ? condition.regex.exec(value) !== null : false;
    }
    if (condition.kind === "field") {
      value = decoded.fields ? decoded.fields[condition.name] : undefined;
      if (value === undefined || value === null) return false;
      return evalText(condition, String(value));
    }
    if (condition.kind === "ip") {
      value = decoded.fields ? decoded.fields[condition.name] : undefined;
      if (value === undefined || value === null) return false;
      return evalIp(condition, String(value));
    }
    return false;
  };

  function evalText(condition, text) {
    if (condition.kind === "match" && condition.matchType !== "pcre2") {
      return osmatch(condition.value, text);
    }
    return condition.regex ? condition.regex.exec(text) !== null : false;
  }

  RuleEngine.prototype._register = function (rule, event, index, eventFields) {
    var mark = { index: index, ts: event.timestamp };
    this._recentRule.set(rule.id, mark);
    for (var g = 0; g < rule.groups.length; g++) this._recentGroup.set(rule.groups[g], mark);
    for (var field in eventFields) {
      if (!Object.prototype.hasOwnProperty.call(eventFields, field)) continue;
      var value = eventFields[field];
      if (value === null || value === undefined || typeof value === "object") continue;
      this._recentField.set(fieldKey(rule.id, field, value), mark);
      this._recentField.set(fieldKey(null, field, value), mark);
    }

    var fired = { rule: rule, suppressed: false, frequencyCount: 0, frequencyTriggered: false };
    if (rule.frequency && rule.frequency > 1) {
      var key = rule.id + "\u0000" + this._frequencyKey(rule, eventFields);
      var hits = this._frequencyCounts.get(key) || [];
      hits.push(mark);
      hits = this._pruneFrequency(rule, hits, event);
      this._frequencyCounts.set(key, hits);
      fired.frequencyCount = hits.length;
      if (hits.length >= rule.frequency) {
        fired.frequencyTriggered = true;
        this._frequencyCounts.set(key, []);
      } else {
        fired.suppressed = true;
      }
    }
    return fired;
  };

  RuleEngine.prototype._frequencyKey = function (rule, eventFields) {
    var names = ["srcip", "dstip", "srcuser", "dstuser", "id"];
    for (var i = 0; i < names.length; i++) {
      if (rule.sameFields.indexOf(names[i]) !== -1) {
        var value = eventFields[names[i]];
        if (value !== undefined && value !== null) return names[i] + "=" + value;
      }
    }
    return "";
  };

  RuleEngine.prototype._pruneFrequency = function (rule, hits, event) {
    if (!rule.timeframe || !event.timestamp) return hits;
    var cutoff = event.timestamp.getTime() - rule.timeframe * 1000;
    return hits.filter(function (h) {
      return !h.ts || h.ts.getTime() >= cutoff;
    });
  };

  RuleEngine.prototype._markWithin = function (mark, event, index, timeframe) {
    if (!timeframe) return true;
    if (mark.ts && event.timestamp) {
      return Math.abs(event.timestamp.getTime() - mark.ts.getTime()) <= timeframe * 1000;
    }
    return Math.abs(index - mark.index) <= timeframe;
  };

  RuleEngine.prototype._matchedSid = function (sids, timeframe, event, index) {
    for (var i = 0; i < sids.length; i++) {
      var mark = this._recentRule.get(sids[i]);
      if (mark && this._markWithin(mark, event, index, timeframe)) return true;
    }
    return false;
  };

  RuleEngine.prototype._matchedGroup = function (groups, timeframe, event, index) {
    for (var i = 0; i < groups.length; i++) {
      var mark = this._recentGroup.get(groups[i]);
      if (mark && this._markWithin(mark, event, index, timeframe)) return true;
    }
    return false;
  };

  RuleEngine.prototype._sameField = function (rule, fieldName, event, index, eventFields) {
    var current = eventFields[fieldName];
    if (current === undefined || current === null || typeof current === "object") return false;
    var targetSids = rule.ifMatchedSid.length ? rule.ifMatchedSid : rule.ifSid;
    var keys = [];
    if (targetSids.length) {
      for (var i = 0; i < targetSids.length; i++) keys.push(fieldKey(targetSids[i], fieldName, current));
    } else {
      keys.push(fieldKey(null, fieldName, current));
    }
    for (var k = 0; k < keys.length; k++) {
      var mark = this._recentField.get(keys[k]);
      if (mark && this._markWithin(mark, event, index, rule.timeframe)) return true;
    }
    return false;
  };

  RuleEngine.prototype._timeOk = function (rule, event) {
    if (!rule.timeConstraints.length && !Object.keys(rule.weekdays).length) return true;
    if (!event.timestamp) return true;
    var ts = event.timestamp;
    if (Object.keys(rule.weekdays).length && !rule.weekdays[ts.getDay()]) return false;
    if (rule.timeConstraints.length) {
      var minutes = ts.getHours() * 60 + ts.getMinutes();
      var ok = rule.timeConstraints.some(function (c) { return minutes >= c.start && minutes < c.end; });
      if (!ok) return false;
    }
    return true;
  };

  function fieldKey(sid, field, value) {
    return (sid === null ? "any" : sid) + "\u0000" + field + "\u0000" + value;
  }

  function anyIn(list, set) {
    for (var i = 0; i < list.length; i++) {
      if (set[list[i]]) return true;
    }
    return false;
  }

  function collectRules(root) {
    var out = [];
    function walk(element, groups) {
      for (var i = 0; i < element.children.length; i++) {
        var child = element.children[i];
        if (child.tagName === "group") {
          var name = child.getAttribute("name");
          var next = groups.slice();
          if (name) next = next.concat(splitCsv(name));
          if (child.children.length) walk(child, next);
        } else if (child.tagName === "rule") {
          out.push({ el: child, groups: groups.slice() });
        }
      }
    }
    walk(root, []);
    return out;
  }

  function osmatch(pattern, text) {
    if (pattern === "") return true;
    var alternatives = pattern.indexOf("|") !== -1 ? pattern.split("|") : [pattern];
    for (var i = 0; i < alternatives.length; i++) {
      var alt = alternatives[i];
      var aStart = alt.charAt(0) === "^";
      var aEnd = alt.length > 1 && alt.charAt(alt.length - 1) === "$";
      var core = aStart ? alt.slice(1) : alt;
      if (aEnd) core = core.slice(0, -1);
      if (aStart && aEnd) {
        if (text === core) return true;
      } else if (aStart) {
        if (text.indexOf(core) === 0) return true;
      } else if (aEnd) {
        if (text.length >= core.length && text.indexOf(core, text.length - core.length) !== -1) return true;
      } else if (text.indexOf(core) !== -1) {
        return true;
      }
    }
    return false;
  }

  function ipToInt(ip) {
    var parts = ip.split(".");
    if (parts.length !== 4) return null;
    var n = 0;
    for (var i = 0; i < 4; i++) {
      var v = parseInt(parts[i], 10);
      if (isNaN(v) || v < 0 || v > 255 || String(v) !== parts[i].replace(/^0+(?=\d)/, "")) return null;
      n = (n << 8) | v;
    }
    return n >>> 0;
  }

  function parseNetwork(text) {
    var parts = String(text).split("/");
    var base = ipToInt(parts[0]);
    if (base === null) return null;
    var bits = parts.length > 1 ? parseInt(parts[1], 10) : 32;
    if (isNaN(bits) || bits < 0 || bits > 32) return null;
    var mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
    return { base: (base & mask) >>> 0, mask: mask };
  }

  function evalIp(condition, value) {
    value = value.trim();
    if (condition.network) {
      var ip = ipToInt(value);
      if (ip === null) return false;
      return ((ip & condition.network.mask) >>> 0) === condition.network.base;
    }
    if (condition.regex) return condition.regex.exec(value) !== null;
    return value === condition.value;
  }

  Wz.RuleEngine = RuleEngine;
  Wz.osmatch = osmatch;
})(window.Wazuh = window.Wazuh || {});
