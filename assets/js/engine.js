/*
 * Wazuh Offline Analyzer - batch analysis engine.
 *
 * line -> predecode -> decode (cached) -> rule chain -> alert flag.
 * Emits a snake_case event structure the timeline renderer consumes.
 */
(function (Wz) {
  "use strict";

  function AnalyzerEngine(decoders, rules, options) {
    options = options || {};
    this.decoders = decoders;
    this.rules = rules;
    this.alertLevel = options.alertLevel != null ? options.alertLevel : 3;
    this.rules.alertLevel = this.alertLevel;
    this.predecoder = new Wz.Predecoder(options.defaultYear || null);
    this.yieldEvery = options.yieldEvery || 2000;
  }

  AnalyzerEngine.prototype.analyze = function (lines, options) {
    options = options || {};
    var self = this;
    var sourceHint = options.sourceHint || "";
    var onProgress = options.onProgress || null;
    this.rules.reset();

    var events = [];
    var stats = {
      lines_total: 0,
      lines_skipped: 0,
      decoded: 0,
      undecoded: 0,
      alerts: 0,
      by_level: {},
      sources: {},
      rules_fired: {}
    };

    var index = 0;
    function step() {
      var processedThisTick = 0;
      while (index < lines.length) {
        var line = String(lines[index]).replace(/\r?\n$/, "");
        if (!line.trim()) {
          stats.lines_skipped++;
          index++;
          continue;
        }
        stats.lines_total++;
        events.push(self._analyzeLine(line, index, sourceHint, stats));
        index++;
        processedThisTick++;
        if (self.yieldEvery && processedThisTick >= self.yieldEvery) {
          if (onProgress) onProgress(index, lines.length);
          return new Promise(function (resolve) { setTimeout(resolve, 0); }).then(step);
        }
      }
      if (onProgress) onProgress(index, lines.length);
      stats.decoder_cache = self.decoders.cache.stats();
      stats.decoders_loaded = self.decoders.nodes.length;
      stats.rules_loaded = self.rules.rules.length;
      stats.alert_level = self.alertLevel;
      return {
        generated_at: new Date().toISOString().replace(/\.\d+Z$/, ""),
        stats: stats,
        events: events
      };
    }

    return Promise.resolve().then(step);
  };

  AnalyzerEngine.prototype._analyzeLine = function (line, index, sourceHint, stats) {
    var pre = this.predecoder.predecode(line, sourceHint);
    var decoded = this.decoders.decode(pre);
    var fired = this.rules.matchEvent(decoded, pre, index);

    var matched = [];
    var maxLevel = 0;
    var alert = false;
    for (var i = 0; i < fired.length; i++) {
      var entry = fired[i];
      var rule = entry.rule;
      var isAlert = rule.level > 0 && !rule.noalert && rule.level >= this.alertLevel &&
        (entry.frequencyTriggered || !entry.suppressed);
      if (entry.suppressed && !entry.frequencyTriggered) isAlert = false;
      matched.push({
        id: rule.id,
        level: rule.level,
        description: Wz.expandRuleVars(rule.description, decoded.fields),
        groups: rule.groups,
        suppressed: entry.suppressed,
        frequency: rule.frequency,
        frequency_count: entry.frequencyCount,
        frequency_triggered: entry.frequencyTriggered,
        alert: isAlert
      });
      if (isAlert) {
        alert = true;
        maxLevel = Math.max(maxLevel, rule.level);
        stats.rules_fired[rule.id] = (stats.rules_fired[rule.id] || 0) + 1;
      }
    }

    if (decoded.decoded) stats.decoded++;
    else stats.undecoded++;
    if (alert) {
      stats.alerts++;
      stats.by_level[maxLevel] = (stats.by_level[maxLevel] || 0) + 1;
    }

    var source = pre.source || pre.programName || "-";
    stats.sources[source] = (stats.sources[source] || 0) + 1;

    return {
      index: index,
      timestamp: pre.timestamp ? pre.timestamp.toISOString() : null,
      epoch: pre.timestamp ? pre.timestamp.getTime() / 1000 : null,
      source: source,
      program: pre.programName,
      hostname: pre.hostname,
      raw: pre.raw,
      message: pre.message,
      decoded: decoded.decoded,
      decoder: decoded.decoder,
      decoder_chain: decoded.chain,
      fields: decoded.fields,
      cached: decoded.cached,
      matched_rules: matched,
      alert: alert,
      max_level: maxLevel
    };
  };

  AnalyzerEngine.prototype.stats = function () {
    return {
      decoders: { decoders_loaded: this.decoders.nodes.length, cache: this.decoders.cache.stats() },
      rules: { rules_loaded: this.rules.rules.length, alert_level: this.alertLevel }
    };
  };

  Wz.AnalyzerEngine = AnalyzerEngine;
})(window.Wazuh = window.Wazuh || {});
