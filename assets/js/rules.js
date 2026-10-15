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
  /*
   * The same_ and different_ field family, per the rules syntax reference.
   * Upstream spells them inconsistently (same_source_ip next to same_srcip), so
   * both forms map onto the field they actually compare.
   */
  var SAME_FIELD_MAP = {
    same_source_ip: "srcip", same_srcip: "srcip",
    same_dstip: "dstip",
    same_srcport: "srcport", same_dstport: "dstport",
    same_srcuser: "srcuser", same_dstuser: "dstuser",
    same_user: "user", same_id: "id",
    same_url: "url", same_status: "status",
    same_action: "action", same_data: "data",
    same_extra_data: "extra_data",
    same_system_name: "system_name",
    same_protocol: "protocol", same_hostname: "hostname",
    same_location: "location", same_agent: "agent",
    same_srcgeoip: "srcgeoip", same_dstgeoip: "dstgeoip",
    same_name: "name"
  };
  var DIFFERENT_FIELD_MAP = {
    different_srcip: "srcip", different_source_ip: "srcip",
    different_dstip: "dstip",
    different_srcport: "srcport", different_dstport: "dstport",
    different_srcuser: "srcuser", different_dstuser: "dstuser",
    different_user: "user", different_id: "id",
    different_url: "url", different_status: "status",
    different_action: "action", different_data: "data",
    different_extra_data: "extra_data",
    different_system_name: "system_name",
    different_protocol: "protocol", different_hostname: "hostname",
    different_location: "location", different_agent: "agent",
    different_srcgeoip: "srcgeoip", different_dstgeoip: "dstgeoip",
    different_name: "name"
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
    this.maxsize = 0;
    this.ignore = 0;
    this.description = "";
    this.groups = [];
    this.decodedAs = [];
    this.ifSid = [];
    this.ifGroup = [];
    this.ifLevel = null;
    this.ifMatchedSid = [];
    this.ifMatchedGroup = [];
    this.sameFields = [];
    this.differentFields = [];
    this.category = null;
    this.conditions = [];
    this.timeConstraints = [];
    this.weekdays = {};
    this.needsFts = false;
    this.anchor = false;
  }

  /*
   * A rule is a candidate for every event when it hangs off nothing but the
   * event itself (no if_sid / if_group / if_matched_*).  Everything else is
   * only reachable once its parent fires, which is what lets the engine walk
   * the 3100-rule ruleset without testing all of it per event.
   */
  Rule.prototype.isRootRule = function () {
    return !(this.ifSid.length || this.ifGroup.length ||
      this.ifMatchedSid.length || this.ifMatchedGroup.length);
  };

  Rule.prototype.parentKeys = function () {
    return this.ifSid.concat(this.ifMatchedSid);
  };

  /*
   * A rule with nothing to match on cannot tell one event from another, so it
   * only groups: it still fires so that if_sid / if_group children resolve
   * through it, but it never alerts on its own.  Nothing in the bundled
   * ruleset needs this - every grouping anchor there is pinned by a
   * <category>, <decoded_as> or <maxsize> condition - but a hand-written rule
   * file without one would otherwise turn every line into an alert.
   */
  Rule.prototype.isAnchor = function () {
    return !(this.ifSid.length || this.ifGroup.length || this.ifMatchedSid.length ||
      this.ifMatchedGroup.length || this.ifLevel || this.decodedAs.length ||
      this.conditions.length || this.sameFields.length || this.maxsize || this.category);
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
    this.rootRules = [];
    this.childrenBySid = new Map();
    this.childrenByGroup = new Map();
    this._recentRule = new Map();
    this._recentGroup = new Map();
    this._recentField = new Map();
    this._frequencyCounts = new Map();
    this._ignored = new Map();
  }

  RuleEngine.prototype.reset = function () {
    this._recentRule.clear();
    this._recentGroup.clear();
    this._recentField.clear();
    this._frequencyCounts.clear();
    this._ignored.clear();
  };

  RuleEngine.prototype.loadXml = function (text, sourceName) {
    var root;
    try {
      root = Wz.Xml.parseWazuhXml(text);
    } catch (err) {
      // Name the file: one malformed ruleset document otherwise takes the
      // whole bundle down with an error that points nowhere.
      throw new Error((sourceName ? sourceName + ": " : "") + err.message);
    }
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
    this.rootRules = [];
    this.childrenBySid = new Map();
    this.childrenByGroup = new Map();

    this.rules.forEach(function (rule) {
      self.byId.set(rule.id, rule);
      if (rule.isRootRule()) {
        self.rootRules.push(rule);
        return;
      }
      rule.parentKeys().forEach(function (sid) {
        if (!self.childrenBySid.has(sid)) self.childrenBySid.set(sid, []);
        self.childrenBySid.get(sid).push(rule);
      });
      var groups = rule.ifGroup.concat(rule.ifMatchedGroup);
      groups.forEach(function (group) {
        if (!self.childrenByGroup.has(group)) self.childrenByGroup.set(group, []);
        self.childrenByGroup.get(group).push(rule);
      });
    });
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
    rule.maxsize = toInt(element.getAttribute("maxsize"), 0);
    rule.ignore = toInt(element.getAttribute("ignore"), 0);
    rule.noalert = /^(yes|1|true)$/i.test(element.getAttribute("noalert") || "");
    rule.groups = inheritedGroups.slice();

    for (var i = 0; i < element.children.length; i++) {
      var child = element.children[i];
      var tag = child.tagName;
      var text = Wz.Xml.elementText(child);
      // <match>, <regex> and <field> carry patterns: their leading and
      // trailing spaces are part of what upstream matches on.
      var pattern = Wz.Xml.patternText(child);
      var negate = /^(yes|1|true)$/i.test(child.getAttribute("negate") || "");
      var matchType = (child.getAttribute("type") || "osmatch").toLowerCase();

      if (tag === "description") {
        /*
         * Upstream appends repeated descriptions into one sentence - the web
         * "URL too long" rule splits its text across two lines - so join them
         * rather than silently keeping only the last.
         */
        rule.description = rule.description ? rule.description + " " + text : text;
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
      } else if (tag === "category") {
        rule.category = text;
      } else if (SAME_FIELD_MAP[tag]) {
        rule.sameFields.push(SAME_FIELD_MAP[tag]);
      } else if (DIFFERENT_FIELD_MAP[tag]) {
        rule.differentFields.push(DIFFERENT_FIELD_MAP[tag]);
      } else if (tag === "same_field") {
        var fieldName = child.getAttribute("name");
        if (fieldName) rule.sameFields.push(fieldName);
      } else if (tag === "match") {
        rule.conditions.push(new Condition("match", pattern, { negate: negate, matchType: matchType }));
      } else if (tag === "regex") {
        rule.conditions.push(new Condition("regex", pattern, { negate: negate, matchType: "regex" }));
      } else if (tag === "field") {
        rule.conditions.push(new Condition("field", pattern, { name: child.getAttribute("name") || "data", negate: negate }));
      } else if (tag === "program_name") {
        /*
         * <program_name> compares against the program name the pre-decoder
         * pulled out of the syslog header, not against a field some decoder
         * happened to order.
         */
        rule.conditions.push(new Condition("program_name", pattern, { negate: negate }));
      } else if (FIELD_TAGS[tag]) {
        rule.conditions.push(new Condition(IP_TAGS[tag] ? "ip" : "field", text, { name: tag, negate: negate }));
      } else if (tag === "time") {
        rule.timeConstraints = rule.timeConstraints.concat(parseTimeRanges(text));
      } else if (tag === "weekday") {
        var wd = parseWeekdays(text);
        Object.keys(wd).forEach(function (k) { rule.weekdays[k] = true; });
      } else if (tag === "if_fts") {
        /*
         * if_fts searches Wazuh's full-text index, which this offline analyzer
         * does not build, so such a rule can never be satisfied here.
         */
        rule.needsFts = true;
      } else if (tag === "options" && text.toLowerCase().indexOf("noalert") !== -1) {
        rule.noalert = true;
      }
    }
    rule.anchor = rule.isAnchor();
    return rule;
  };

  /*
   * Only rules that can still match are considered: the parentless rules plus
   * whatever the rules fired so far made reachable.  Scanning all 3000+ rules
   * per event is what the old flat loop did, and it dominated the runtime.
   */
  RuleEngine.prototype.matchEvent = function (decoded, event, index) {
    var firedSids = {};
    var firedGroups = {};
    var queued = {};
    var fired = [];
    var maxLevel = 0;
    var eventFields = Object.assign({}, Wz.eventFieldsSnapshot(event), decoded.fields);
    var queue = this.rootRules.slice();

    var self = this;

    function enqueue(rule) {
      if (queued[rule.id] || firedSids[rule.id]) return;
      queued[rule.id] = true;
      queue.push(rule);
    }

    function enqueueBySid(sid) {
      var children = self.childrenBySid.get(sid);
      if (!children) return;
      for (var i = 0; i < children.length; i++) enqueue(children[i]);
    }

    function enqueueByGroup(group) {
      var children = self.childrenByGroup.get(group);
      if (!children) return;
      for (var i = 0; i < children.length; i++) enqueue(children[i]);
    }

    var guard = this.rules.length + this.rootRules.length + 16;
    for (var cursor = 0; cursor < guard && queue.length; cursor++) {
      var rule = queue.pop();
      if (firedSids[rule.id]) continue;

      // maxsize only applies to events at least that many bytes long.
      if (rule.maxsize && (!event.raw || event.raw.length < rule.maxsize)) continue;
      if (!this._preconditionsOk(rule, firedSids, firedGroups, maxLevel, event, index, eventFields)) continue;
      if (!this._conditionsOk(rule, decoded, event)) continue;

      var firedRule = this._register(rule, event, index, eventFields);
      fired.push(firedRule);
      firedSids[rule.id] = true;
      if (rule.level > maxLevel) maxLevel = rule.level;

      // Children of the rule that just fired, plus anything keyed by the
      // groups it belongs to.
      enqueueBySid(rule.id);
      for (var g = 0; g < rule.groups.length; g++) {
        firedGroups[rule.groups[g]] = true;
        enqueueByGroup(rule.groups[g]);
      }
    }
    return fired;
  };

  RuleEngine.prototype._preconditionsOk = function (rule, firedSids, firedGroups, maxLevel, event, index, eventFields) {
    var i;
    if (rule.needsFts) return false;
    if (rule.ifSid.length && !anyIn(rule.ifSid, firedSids)) return false;
    if (rule.ifGroup.length && !anyIn(rule.ifGroup, firedGroups)) return false;
    if (rule.ifLevel && !compareLevel(maxLevel, rule.ifLevel.op, rule.ifLevel.value)) return false;
    if (rule.ifMatchedSid.length && !this._matchedSid(rule.ifMatchedSid, rule.timeframe, event, index)) return false;
    if (rule.ifMatchedGroup.length && !this._matchedGroup(rule.ifMatchedGroup, rule.timeframe, event, index)) return false;
    for (i = 0; i < rule.sameFields.length; i++) {
      if (!this._sameField(rule, rule.sameFields[i], event, index, eventFields)) return false;
    }
    for (i = 0; i < rule.differentFields.length; i++) {
      if (!this._differentField(rule, rule.differentFields[i], event, index, eventFields)) return false;
    }
    if (!this._timeOk(rule, event)) return false;
    if (rule.ignore && this._ignoreSuppressed(rule, event, index, eventFields)) return false;
    return true;
  };

  RuleEngine.prototype._conditionsOk = function (rule, decoded, event) {
    /*
     * <category> selects on the decoder's <type> - the same vocabulary upstream
     * uses to keep the web, squid, ids, firewall, windows and ossec rule sets
     * apart.  Without it the grouping anchors (31100 "access log messages
     * grouped", 35000 "squid messages grouped", 20101 "IDS event") would match
     * every event and drag unrelated children in with them.
     */
    if (rule.category && rule.category !== (decoded.type || "syslog")) return false;
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

    if (rule.anchor) fired.suppressed = true;

    /*
     * ignore="N" rate-limits the rule itself: once it has fired for a given
     * same_* key it stays quiet for N seconds.  Only rules carrying the
     * attribute need the extra bookkeeping.
     */
    if (rule.ignore) {
      this._ignored.set(rule.id + "\u0000" + this._frequencyKey(rule, eventFields), mark);
    }

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

  /*
   * True when the rule already fired inside its ignore window for the same
   * key.  Windows are measured on timestamps when the log carries them and on
   * event distance otherwise, like the timeframe checks.
   */
  RuleEngine.prototype._ignoreSuppressed = function (rule, event, index, eventFields) {
    var last = this._ignored.get(rule.id + "\u0000" + this._frequencyKey(rule, eventFields));
    if (!last) return false;
    return withinWindow(last, event, index, rule.ignore);
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
    return withinWindow(mark, event, index, timeframe);
  };

  /*
   * Events arrive in order, so "did this happen within N seconds / N events?"
   * only needs the previous mark.  Prefer real timestamps and fall back to
   * event distance when the log carries no clock.
   */
  function withinWindow(mark, event, index, seconds) {
    if (!seconds) return true;
    if (mark.ts && event.timestamp) {
      return Math.abs(event.timestamp.getTime() - mark.ts.getTime()) <= seconds * 1000;
    }
    return Math.abs(index - mark.index) <= seconds;
  }

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
    var current = comparableField(eventFields, fieldName);
    if (current === null) return false;
    return this._fieldSeenBefore(rule, fieldName, current, event, index);
  };

  RuleEngine.prototype._differentField = function (rule, fieldName, event, index, eventFields) {
    var current = comparableField(eventFields, fieldName);
    if (current === null) return false;
    return !this._fieldSeenBefore(rule, fieldName, current, event, index);
  };

  /*
   * Shared by same_* and different_*: has this exact value for this field been
   * seen inside the rule's timeframe, keyed by the rule's parent ids so that
   * two rules watching the same srcip do not share history.
   */
  RuleEngine.prototype._fieldSeenBefore = function (rule, fieldName, value, event, index) {
    var targetSids = rule.ifMatchedSid.length ? rule.ifMatchedSid : rule.ifSid;
    var keys = [];
    if (targetSids.length) {
      for (var i = 0; i < targetSids.length; i++) keys.push(fieldKey(targetSids[i], fieldName, value));
    } else {
      keys.push(fieldKey(null, fieldName, value));
    }
    for (var k = 0; k < keys.length; k++) {
      var mark = this._recentField.get(keys[k]);
      if (mark && withinWindow(mark, event, index, rule.timeframe)) return true;
    }
    return false;
  };

  function comparableField(eventFields, fieldName) {
    var value = eventFields[fieldName];
    if (value === undefined || value === null || typeof value === "object") return null;
    return value;
  }

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

  /*
   * sregex / OS_Match: substring search with ^, $ and | as the only special
   * characters.  OS_Match folds case, and the ruleset depends on it - rule 5710
   * matches "invalid user" while every sshd build logs "Invalid user", and
   * rules/log-entries/sshd is the upstream fixture for exactly that rule.
   */
  function osmatch(pattern, text) {
    if (pattern === "") return true;
    var haystack = String(text == null ? "" : text).toLowerCase();
    var alternatives = pattern.indexOf("|") !== -1 ? pattern.split("|") : [pattern];
    for (var i = 0; i < alternatives.length; i++) {
      var alt = alternatives[i].toLowerCase();
      var aStart = alt.charAt(0) === "^";
      var aEnd = alt.length > 1 && alt.charAt(alt.length - 1) === "$";
      var core = aStart ? alt.slice(1) : alt;
      if (aEnd) core = core.slice(0, -1);
      if (aStart && aEnd) {
        if (haystack === core) return true;
      } else if (aStart) {
        if (haystack.indexOf(core) === 0) return true;
      } else if (aEnd) {
        if (haystack.length >= core.length &&
          haystack.indexOf(core, haystack.length - core.length) !== -1) return true;
      } else if (haystack.indexOf(core) !== -1) {
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

  /*
   * Descriptions may interpolate decoded fields as $(name) - "Docker: Container
   * $(docker.Actor.Attributes.name) created".  The decoder already flattens
   * nested JSON and order lists into dotted paths, so a plain lookup does it.
   * Unknown names are left untouched rather than blanked.
   */
  function expandRuleVars(text, fields) {
    if (!fields || text.indexOf("$(") === -1) return text;
    return String(text).replace(/\$\(([^)]+)\)/g, function (match, name) {
      var value = fields[name.trim()];
      return value === undefined || value === null || typeof value === "object"
        ? match
        : String(value);
    });
  }

  Wz.expandRuleVars = expandRuleVars;
})(window.Wazuh = window.Wazuh || {});
