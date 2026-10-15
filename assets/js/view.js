/*
 * Wazuh Offline Analyzer - result views.
 *
 * Two dependency-free SVG renderers over the same analysis payload: the
 * interactive Gantt timeline and the Indicators-of-Compromise panel.  They live
 * together because they share the time scale and the colour/escaping helpers,
 * and because the IoC "events over time" chart must agree with the Gantt chart
 * on every event's position and display time.
 */
(function (Wz) {
  "use strict";

  // -- shared helpers ------------------------------------------------------
  var LEVEL_COLORS = [
    { min: 12, color: "#ff2d55" },
    { min: 10, color: "#ff5c5c" },
    { min: 7, color: "#ff9f43" },
    { min: 4, color: "#ffd166" },
    { min: 0, color: "#4c8dff" }
  ];
  var MUTED = "#3d5a8c";

  function levelColor(level) {
    for (var i = 0; i < LEVEL_COLORS.length; i++) {
      if (level >= LEVEL_COLORS[i].min) return LEVEL_COLORS[i].color;
    }
    return "#4c8dff";
  }

  function esc(text) {
    return String(text == null ? "" : text).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function two(n) {
    return (n < 10 ? "0" : "") + n;
  }

  function timeOfDay(d) {
    return two(d.getHours()) + ":" + two(d.getMinutes());
  }

  function monthDay(d) {
    return two(d.getMonth() + 1) + "/" + two(d.getDate());
  }

  function crossesDay(minT, maxT) {
    var a = new Date(minT * 1000);
    var b = new Date(maxT * 1000);
    return a.getFullYear() !== b.getFullYear() ||
      a.getMonth() !== b.getMonth() ||
      a.getDate() !== b.getDate();
  }

  function truncate(text, max) {
    text = String(text == null ? "" : text);
    return text.length > max ? text.slice(0, max - 1) + "\u2026" : text;
  }

  function fieldValue(ev, names) {
    var fields = ev.fields || {};
    for (var i = 0; i < names.length; i++) {
      var value = fields[names[i]];
      if (value !== undefined && value !== null && value !== "") return String(value);
    }
    return null;
  }

  /*
   * Build a shared scale for a list of events.
   *
   * When at least one event carries a timestamp the axis is time-based and
   * events without one are interpolated by position between their nearest
   * timestamped neighbours (leading/trailing gaps clamp to the nearest known
   * time).  When no event has a timestamp the axis falls back to line order.
   * The same scale drives the Gantt chart and the "events over time" IoC chart
   * so both agree on every event's position and display time.
   */
  function buildTimeScale(events) {
    events = events || [];
    var n = events.length;
    var epochs = new Map();
    var minT = null;
    var maxT = null;
    var hasTime = false;
    var known = [];

    var i;
    for (i = 0; i < n; i++) {
      var t = events[i].epoch;
      if (t == null) continue;
      hasTime = true;
      if (minT === null || t < minT) minT = t;
      if (maxT === null || t > maxT) maxT = t;
      known.push(i);
    }

    if (hasTime) {
      for (var k = 0; k < known.length; k++) {
        var start = known[k];
        var t0 = events[start].epoch;
        epochs.set(events[start].index, t0);
        var nextPos = (k + 1 < known.length) ? known[k + 1] : -1;
        var t1 = nextPos === -1 ? t0 : events[nextPos].epoch;
        var span = nextPos === -1 ? 0 : nextPos - start;
        var stop = nextPos === -1 ? n - 1 : nextPos - 1;
        for (var j = start + 1; j <= stop; j++) {
          var frac = span ? (j - start) / span : 0;
          epochs.set(events[j].index, t0 + (t1 - t0) * frac);
        }
        if (k === 0 && start > 0) {
          for (var p = 0; p < start; p++) epochs.set(events[p].index, t0);
        }
      }
    }

    var maxIndex = Math.max(1, n - 1);
    var spansDays = hasTime && maxT !== minT && crossesDay(minT, maxT);

    function epochOf(ev) {
      return epochs.has(ev.index) ? epochs.get(ev.index) : null;
    }

    return {
      hasTime: hasTime,
      minT: minT,
      maxT: maxT,
      maxIndex: maxIndex,
      spansDays: spansDays,
      epochOf: epochOf,
      posOf: function (ev) {
        if (hasTime) {
          if (maxT === minT) return 0.5;
          var t = epochOf(ev);
          if (t == null) return 0.5;
          var pos = (t - minT) / (maxT - minT);
          return pos < 0 ? 0 : (pos > 1 ? 1 : pos);
        }
        return ev.index / maxIndex;
      },
      labelOf: function (ev) {
        if (hasTime) {
          var t = epochOf(ev);
          if (t != null) {
            var text = new Date(t * 1000).toLocaleString();
            return ev.epoch == null ? "~" + text : text;
          }
        }
        if (ev.timestamp) return new Date(ev.timestamp).toLocaleString();
        return "line " + ev.index;
      },
      tickLabel: function (frac) {
        if (hasTime && maxT !== minT) {
          var d = new Date((minT + frac * (maxT - minT)) * 1000);
          return spansDays ? monthDay(d) + " " + timeOfDay(d) : timeOfDay(d);
        }
        return "line " + Math.round(frac * maxIndex);
      }
    };
  }

  // -- Gantt timeline ------------------------------------------------------
  function Timeline(opts) {
    this.el = opts.el;
    this.payload = null;
    this.EVENTS = [];
    this.stats = {};
    this.state = {
      showAlertsOnly: false,
      groupBy: "source",
      viewStart: 0,
      viewEnd: 1,
      dragging: null
    };
    this.MARGIN = { top: 72, right: 64, bottom: 24, left: 210 };
    this.ROW_H = 26;
    this.hasTime = false;
    this.minT = null;
    this.maxT = null;
    this.maxIndex = 1;
    this._bound = false;
    this._bindStatics();
  }

  Timeline.prototype._bindStatics = function () {
    var self = this;

    function plotWidth() {
      return (self.el.wrap.clientWidth || 1000) - self.MARGIN.left - self.MARGIN.right;
    }

    // Scroll to zoom, anchored on the pointer so the time under the cursor
    // stays put.  At the zoom limits the event falls through so the page can
    // scroll normally.
    this.el.wrap.addEventListener("wheel", function (e) {
      var span = self.state.viewEnd - self.state.viewStart;
      var zoomIn = e.deltaY < 0;
      if ((zoomIn && span <= 0.02) || (!zoomIn && span >= 0.999)) return;
      e.preventDefault();
      var factor = zoomIn ? 0.85 : 1.18;
      var newSpan = Math.max(0.02, Math.min(1, span * factor));
      var plotW = plotWidth();
      var rect = self.el.wrap.getBoundingClientRect();
      var fx = plotW > 0 ? (e.clientX - rect.left - self.MARGIN.left) / plotW : 0.5;
      fx = fx < 0 ? 0 : (fx > 1 ? 1 : fx);
      var anchor = self.state.viewStart + fx * span;
      var s = anchor - fx * newSpan;
      if (s < 0) s = 0;
      if (s + newSpan > 1) s = 1 - newSpan;
      self.state.viewStart = s;
      self.state.viewEnd = s + newSpan;
      self.render();
    }, { passive: false });

    // Click and hold to pan left / right.
    this.el.svg.addEventListener("mousedown", function (e) {
      if (e.button !== 0) return;
      self._suppressClick = false;
      self._hideTooltip();
      self.state.dragging = { x: e.clientX, start: self.state.viewStart, end: self.state.viewEnd, moved: false };
      self.el.svg.classList.add("dragging");
    });
    window.addEventListener("mousemove", function (e) {
      var d = self.state.dragging;
      if (!d) return;
      var dx = e.clientX - d.x;
      if (!d.moved && Math.abs(dx) < 3) return;
      d.moved = true;
      var span = d.end - d.start;
      var plotW = plotWidth();
      var shift = plotW > 0 ? (dx / plotW) * span : 0;
      var s = d.start - shift;
      var en = d.end - shift;
      if (s < 0) { s = 0; en = span; }
      if (en > 1) { en = 1; s = 1 - span; }
      self.state.viewStart = s;
      self.state.viewEnd = en;
      self.render();
    });
    window.addEventListener("mouseup", function () {
      if (self.state.dragging) self._suppressClick = self.state.dragging.moved;
      self.state.dragging = null;
      self.el.svg.classList.remove("dragging");
    });

    // Double-click anywhere on the chart fits the full time range.
    this.el.svg.addEventListener("dblclick", function () { self.zoomReset(); });

    window.addEventListener("resize", function () { self.render(); });
  };

  Timeline.prototype.setData = function (payload) {
    this.payload = payload;
    this.EVENTS = payload.events || [];
    this.stats = payload.stats || {};
    var opts = payload.options || {};
    if (opts.group_by) this.state.groupBy = opts.group_by;
    this.state.showAlertsOnly = false;
    this.state.viewStart = 0;
    this.state.viewEnd = 1;

    this.scale = buildTimeScale(this.EVENTS);
    this.hasTime = this.scale.hasTime;
    this.minT = this.scale.minT;
    this.maxT = this.scale.maxT;
    this.maxIndex = this.scale.maxIndex;

    this.renderHeader();
    this.render();
  };

  Timeline.prototype._primaryRule = function (ev) {
    var best = null;
    (ev.matched_rules || []).forEach(function (r) {
      if (!best || r.level > best.level) best = r;
    });
    return best;
  };

  Timeline.prototype._groupKey = function (ev) {
    if (this.state.groupBy === "decoder") return ev.decoder || "(undecoded)";
    if (this.state.groupBy === "level") return "level " + (ev.max_level || 0);
    if (this.state.groupBy === "rule") {
      var r = this._primaryRule(ev);
      if (!r) return "(no rule)";
      return (r.groups && r.groups.length) ? r.groups[0] : "rule " + r.id;
    }
    return ev.source || ev.program || "(unknown)";
  };

  Timeline.prototype._currentEvents = function () {
    return this.state.showAlertsOnly ? this.EVENTS.filter(function (e) { return e.alert; }) : this.EVENTS;
  };

  Timeline.prototype._position = function (ev) {
    if (this.scale) return this.scale.posOf(ev);
    return ev.index / this.maxIndex;
  };

  Timeline.prototype._fmtTime = function (ev) {
    if (this.scale) return this.scale.labelOf(ev);
    if (ev.timestamp) return new Date(ev.timestamp).toLocaleString();
    if (ev.epoch != null) return new Date(ev.epoch * 1000).toLocaleString();
    return "line " + ev.index;
  };

  Timeline.prototype.render = function () {
    var svg = this.el.svg;
    var events = this._currentEvents();
    if (!events.length) {
      svg.innerHTML = '<text x="50%" y="60" fill="#8a99b8" text-anchor="middle">No events to display.</text>';
      this._renderLegend();
      return;
    }

    var groups = {};
    var self = this;
    events.forEach(function (e) {
      var key = self._groupKey(e);
      (groups[key] = groups[key] || []).push(e);
    });
    var rows = Object.keys(groups).sort();

    var width = this.el.wrap.clientWidth || 1000;
    var height = Math.max(this.el.wrap.clientHeight || 500, this.MARGIN.top + rows.length * this.ROW_H + this.MARGIN.bottom);
    svg.setAttribute("viewBox", "0 0 " + width + " " + height);
    svg.setAttribute("width", width);
    svg.setAttribute("height", height);

    var plotW = width - this.MARGIN.left - this.MARGIN.right;
    var totalW = plotW / (this.state.viewEnd - this.state.viewStart);
    var viewStart = this.state.viewStart;

    function xFor(pos) {
      return self.MARGIN.left + (pos - viewStart) * totalW;
    }

    var parts = [];
    parts.push('<line class="axis-line" x1="' + this.MARGIN.left + '" y1="' + (this.MARGIN.top - 6) +
      '" x2="' + (width - this.MARGIN.right) + '" y2="' + (this.MARGIN.top - 6) + '"/>');

    var TICKS = 8;
    for (var t = 0; t <= TICKS; t++) {
      var frac = viewStart + (this.state.viewEnd - viewStart) * (t / TICKS);
      var x = this.MARGIN.left + (t / TICKS) * plotW;
      var label;
      if (this.scale) {
        label = this.scale.tickLabel(frac);
      } else if (this.hasTime && this.maxT !== this.minT) {
        label = new Date((this.minT + frac * (this.maxT - this.minT)) * 1000).toLocaleTimeString();
      } else {
        label = "line " + Math.round(frac * this.maxIndex);
      }
      var labelY = this.MARGIN.top - 14;
      parts.push('<line class="tick-line" x1="' + x + '" y1="' + (this.MARGIN.top - 6) +
        '" x2="' + x + '" y2="' + (height - this.MARGIN.bottom) + '"/>');
      parts.push('<text class="tick-label" x="' + x + '" y="' + labelY +
        '" text-anchor="start" transform="rotate(-45 ' + x + ' ' + labelY + ')">' +
        esc(label) + '</text>');
    }

    rows.forEach(function (rowKey, ri) {
      var y = self.MARGIN.top + ri * self.ROW_H;
      var rowEvents = groups[rowKey];
      parts.push('<rect class="row-bg' + (ri % 2 ? " alt" : "") + '" x="' + self.MARGIN.left +
        '" y="' + y + '" width="' + plotW + '" height="' + self.ROW_H + '"/>');
      var label = rowKey.length > 30 ? rowKey.slice(0, 29) + "\u2026" : rowKey;
      parts.push('<text class="row-label" x="' + (self.MARGIN.left - 10) + '" y="' + (y + self.ROW_H / 2) +
        '" text-anchor="end"><title>' + esc(rowKey) + '</title>' + esc(label) + '</text>');
      parts.push('<text class="row-count" x="' + (self.MARGIN.left + 6) + '" y="' + (y + self.ROW_H / 2) +
        '">' + rowEvents.length + '</text>');

      rowEvents.forEach(function (ev) {
        var pos = self._position(ev);
        if (pos < self.state.viewStart || pos > self.state.viewEnd) return;
        var x = xFor(pos);
        var color = ev.alert ? levelColor(ev.max_level) : MUTED;
        var w = Math.max(4, Math.min(14, totalW / Math.max(1, rowEvents.length)));
        parts.push('<rect class="event" data-index="' + ev.index + '" x="' + (x - w / 2) +
          '" y="' + (y + 5) + '" width="' + w + '" height="' + (self.ROW_H - 10) +
          '" rx="2" fill="' + color + '" fill-opacity="' + (ev.alert ? 0.95 : 0.7) + '"/>');
      });
    });

    svg.innerHTML = parts.join("");
    this._bindEvents();
    this._renderLegend();
  };

  Timeline.prototype._renderLegend = function () {
    if (!this.el.legend) return;
    var items = [
      { c: MUTED, t: "Normal event" },
      { c: levelColor(4), t: "Low (4-6)" },
      { c: levelColor(7), t: "Medium (7-9)" },
      { c: levelColor(10), t: "High (10-11)" },
      { c: levelColor(12), t: "Critical (12+)" }
    ];
    this.el.legend.innerHTML = items.map(function (i) {
      return '<span><i style="background:' + i.c + '"></i>' + i.t + '</span>';
    }).join("");
  };

  Timeline.prototype._bindEvents = function () {
    var self = this;
    var nodes = this.el.svg.querySelectorAll(".event");
    Array.prototype.forEach.call(nodes, function (node) {
      var ev = self.EVENTS[+node.getAttribute("data-index")];
      node.addEventListener("mousemove", function (e) { self._showTooltip(e, ev); });
      node.addEventListener("mouseleave", function () { self._hideTooltip(); });
      node.addEventListener("click", function () {
        if (self._suppressClick) { self._suppressClick = false; return; }
        self._showDetail(ev);
      });
    });
  };

  Timeline.prototype._showTooltip = function (e, ev) {
    var wrap = this.el.wrap;
    var tooltip = this.el.tooltip;
    if (!tooltip) return;
    var r = wrap.getBoundingClientRect();
    var rule = this._primaryRule(ev);
    var html = '<div><b>' + esc(ev.source) + '</b> <span class="kv">#' + ev.index + '</span></div>' +
      '<div class="kv">' + esc(this._fmtTime(ev)) + '</div>' +
      '<div>' + esc(ev.decoder || "(undecoded)") + '</div>';
    if (rule) {
      html += '<div><span class="badge" style="background:' + levelColor(rule.level) +
        ';color:#08101f">L' + rule.level + '</span>' + esc(rule.id + " " + (rule.description || "")) + '</div>';
    }
    if (ev.alert) html += '<div style="color:#ff8a8a">ALERT</div>';
    tooltip.innerHTML = html;
    tooltip.style.display = "block";
    var x = e.clientX - r.left + 14;
    var y = e.clientY - r.top + 14;
    tooltip.style.left = Math.min(x, wrap.clientWidth - 480) + "px";
    tooltip.style.top = Math.min(y, wrap.clientHeight - 140) + "px";
  };

  Timeline.prototype._hideTooltip = function () {
    if (this.el.tooltip) this.el.tooltip.style.display = "none";
  };

  Timeline.prototype._showDetail = function (ev) {
    if (!this.el.detailBody) return;
    var self = this;
    var rulesHtml = (ev.matched_rules || []).map(function (r) {
      var flags = [];
      if (r.alert) flags.push('<span style="color:#ff8a8a">alert</span>');
      if (r.suppressed && !r.frequency_triggered) flags.push('<span class="muted">suppressed by frequency</span>');
      if (r.frequency > 1) flags.push('<span class="muted">freq ' + r.frequency_count + '/' + r.frequency + '</span>');
      return '<div class="rule-item">' +
        '<span class="badge" style="background:' + levelColor(r.level) + ';color:#08101f">L' + r.level + '</span>' +
        '<b>' + esc(r.id) + '</b> ' + esc(r.description || "") +
        (flags.length ? ' <span class="muted">(' + flags.join(", ") + ')</span>' : "") +
        (r.groups && r.groups.length ? '<div class="muted">' + esc(r.groups.join(", ")) + '</div>' : "") +
        '</div>';
    }).join("") || '<div class="muted">No rule matched.</div>';

    this.el.detailBody.innerHTML =
      '<h2>' + esc(ev.source) + ' <span class="muted">#' + ev.index + '</span></h2>' +
      '<div class="section"><h3>Time</h3><div>' + esc(self._fmtTime(ev)) + '</div></div>' +
      '<div class="section"><h3>Decoder chain</h3><div>' +
        esc((ev.decoder_chain || []).join(" \u2192 ") || "(none)") +
        (ev.cached ? ' <span class="muted">[cache hit]</span>' : '') + '</div></div>' +
      '<div class="section"><h3>Matched rules</h3>' + rulesHtml + '</div>' +
      '<div class="section"><h3>Decoded fields</h3><pre>' +
        esc(JSON.stringify(ev.fields || {}, null, 2)) + '</pre></div>' +
      '<div class="section"><h3>Raw log</h3><pre>' + esc(ev.raw) + '</pre></div>';
    if (this.el.detail) this.el.detail.classList.add("open");
  };

  Timeline.prototype.renderHeader = function () {
    var s = this.stats || {};
    if (this.el.subtitle) {
      this.el.subtitle.textContent =
        (this.payload && this.payload.generated_at ? this.payload.generated_at + " \u2022 " : "") +
        this.EVENTS.length + " lines \u2022 " + (s.decoded || 0) + " decoded \u2022 " + (s.alerts || 0) + " alerts";
    }
    if (this.el.stats) {
      var cells = [
        ["Lines", s.lines_total || this.EVENTS.length],
        ["Decoded", s.decoded || 0],
        ["Alerts", s.alerts || 0],
        ["Cache hits", (s.decoder_cache && s.decoder_cache.hits) || 0],
        ["Decoders", s.decoders_loaded || 0],
        ["Rules", s.rules_loaded || 0]
      ];
      this.el.stats.innerHTML = cells.map(function (c) {
        return '<div class="stat"><b>' + esc(c[1]) + '</b><span>' + esc(c[0]) + '</span></div>';
      }).join("");
    }
    if (this.el.groupBy) this.el.groupBy.value = this.state.groupBy;
  };

  Timeline.prototype.toggleAlerts = function () {
    this.state.showAlertsOnly = !this.state.showAlertsOnly;
    return this.state.showAlertsOnly;
  };
  Timeline.prototype.setGroupBy = function (value) {
    this.state.groupBy = value;
    this.render();
  };
  Timeline.prototype.zoomReset = function () {
    this.state.viewStart = 0;
    this.state.viewEnd = 1;
    this.render();
  };

  // -- Indicators of Compromise panel --------------------------------------
  /*
   * Every chart aggregates over all events: the muted bar is the total and the
   * coloured overlay is the alert subset.
   */
  function card(title, body) {
    return '<div class="ioc-card"><h3>' + esc(title) + "</h3>" +
      (body || '<div class="ioc-empty">No data</div>') + "</div>";
  }

  function barCard(title, items, opts) {
    opts = opts || {};
    var alertsOnly = !!opts.alertsOnly;
    items = items.slice(0, opts.maxItems || 6).filter(function (it) {
      return alertsOnly ? it.alert > 0 : it.total > 0;
    });
    if (!items.length) return card(title, "");

    var W = 340;
    var rowH = 20;
    var pad = 8;
    var labelW = 132;
    var gap = 8;
    var countW = 44;
    var chartW = W - labelW - gap - countW;
    var H = pad * 2 + items.length * rowH;
    var max = 1;
    items.forEach(function (it) {
      max = Math.max(max, alertsOnly ? it.alert : it.total);
    });

    var parts = [];
    items.forEach(function (it, i) {
      var y = pad + i * rowH;
      var cy = y + rowH / 2;
      var value = alertsOnly ? it.alert : it.total;
      var barW = Math.max(2, (value / max) * chartW);
      var trackW = Math.max(2, (it.total / max) * chartW);
      var alertW = Math.max(2, (it.alert / max) * chartW);
      var barY = y + 3;
      var barH = rowH - 6;

      parts.push('<text class="ioc-label" x="' + (labelW - 6) + '" y="' + cy +
        '" text-anchor="end" dominant-baseline="middle"><title>' + esc(it.full || it.label) +
        '</title>' + esc(truncate(it.label, 22)) + '</text>');
      if (!alertsOnly && it.total > 0) {
        parts.push('<rect x="' + (labelW + gap) + '" y="' + barY + '" width="' + trackW +
          '" height="' + barH + '" rx="2" fill="' + MUTED + '" fill-opacity="0.55"/>');
      }
      if (it.alert > 0) {
        var aw = alertsOnly ? barW : alertW;
        parts.push('<rect x="' + (labelW + gap) + '" y="' + barY + '" width="' + aw +
          '" height="' + barH + '" rx="2" fill="' + (it.color || levelColor(it.level)) + '"/>');
      }
      var countText = alertsOnly ? String(it.alert)
        : (it.alert > 0 ? it.alert + "/" + it.total : String(it.total));
      parts.push('<text class="ioc-count" x="' + (W - 4) + '" y="' + cy +
        '" text-anchor="end" dominant-baseline="middle">' + esc(countText) + '</text>');
    });

    return card(title, '<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="xMidYMid meet">' +
      parts.join("") + "</svg>");
  }

  function timeCard(title, scale, events, alertsOnly) {
    if (!events.length) return card(title, "");
    var W = 340;
    var H = 150;
    var padL = 10;
    var padR = 10;
    var padT = 12;
    var padB = 24;
    var bins = 32;
    var plotW = W - padL - padR;
    var plotH = H - padT - padB;
    var base = new Array(bins);
    var alert = new Array(bins);
    var i;
    for (i = 0; i < bins; i++) { base[i] = 0; alert[i] = 0; }

    events.forEach(function (ev) {
      var pos = scale.posOf(ev);
      var bin = Math.floor(pos * bins);
      if (bin < 0) bin = 0;
      if (bin >= bins) bin = bins - 1;
      base[bin]++;
      if (ev.alert) alert[bin]++;
    });

    var max = 1;
    for (i = 0; i < bins; i++) max = Math.max(max, alertsOnly ? alert[i] : base[i]);

    var slot = plotW / bins;
    var barW = Math.max(2, slot - 2);
    var parts = [];
    parts.push('<line class="ioc-axis" x1="' + padL + '" y1="' + (padT + plotH) +
      '" x2="' + (W - padR) + '" y2="' + (padT + plotH) + '"/>');
    for (i = 0; i < bins; i++) {
      var x = padL + i * slot + 1;
      if (!alertsOnly && base[i] > 0) {
        var bh = (base[i] / max) * plotH;
        parts.push('<rect x="' + x + '" y="' + (padT + plotH - bh) + '" width="' + barW +
          '" height="' + bh + '" rx="1" fill="' + MUTED + '" fill-opacity="0.55"/>');
      }
      if (alert[i] > 0) {
        var ah = (alert[i] / max) * plotH;
        parts.push('<rect x="' + x + '" y="' + (padT + plotH - ah) + '" width="' + barW +
          '" height="' + ah + '" rx="1" fill="' + levelColor(10) + '"/>');
      }
    }

    var labels = 4;
    for (var t = 0; t <= labels; t++) {
      var frac = t / labels;
      var lx = padL + frac * plotW;
      var anchor = t === 0 ? "start" : (t === labels ? "end" : "middle");
      parts.push('<text class="ioc-tick" x="' + lx + '" y="' + (H - 8) +
        '" text-anchor="' + anchor + '">' + esc(scale.tickLabel(frac)) + "</text>");
    }

    return card(title, '<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="xMidYMid meet">' +
      parts.join("") + "</svg>");
  }

  function topItems(counts) {
    return Object.keys(counts).map(function (key) {
      return counts[key];
    }).sort(function (a, b) {
      return b.total - a.total || b.alert - a.alert;
    });
  }

  function IoCCharts(opts) {
    this.el = (opts && opts.grid) || null;
    this.note = (opts && opts.note) || null;
    this.events = [];
    this.scale = null;
    this.alertsOnly = false;
  }

  IoCCharts.prototype.setData = function (payload) {
    this.events = (payload && payload.events) || [];
    this.scale = buildTimeScale(this.events);
    this.alertsOnly = false;
    this.render();
  };

  IoCCharts.prototype.setAlertsOnly = function (on) {
    this.alertsOnly = !!on;
    this.render();
  };

  IoCCharts.prototype.render = function () {
    if (!this.el) return;
    if (this.note) {
      this.note.innerHTML = this.alertsOnly
        ? "Showing alerts only"
        : "Base: all events &middot; Highlight: alerts";
    }
    if (!this.events.length) {
      this.el.innerHTML = '<div class="ioc-empty">No events analysed yet.</div>';
      return;
    }

    var events = this.events;
    var alertsOnly = this.alertsOnly;

    // severity distribution -------------------------------------------------
    var allLevels = {};
    var alertLevels = {};
    events.forEach(function (ev) {
      var lv = 0;
      (ev.matched_rules || []).forEach(function (r) { if (r.level > lv) lv = r.level; });
      var entry = allLevels[lv] || (allLevels[lv] = { label: "L" + lv, total: 0, alert: 0, level: lv });
      entry.total++;
      if (ev.alert) {
        alertLevels[ev.max_level] = (alertLevels[ev.max_level] || 0) + 1;
      }
    });
    Object.keys(alertLevels).forEach(function (lv) {
      var entry = allLevels[lv] || (allLevels[lv] = { label: "L" + lv, total: 0, alert: 0, level: +lv });
      entry.alert = alertLevels[lv];
    });
    var severityItems = Object.keys(allLevels).map(function (k) { return allLevels[k]; })
      .sort(function (a, b) { return b.level - a.level; });

    // top sources / users / ports ------------------------------------------
    var sources = {};
    var users = {};
    var ports = {};
    events.forEach(function (ev) {
      var isAlert = ev.alert;
      var srcip = fieldValue(ev, ["srcip", "src_ip"]);
      if (srcip) {
        var s = sources[srcip] || (sources[srcip] = { label: srcip, full: srcip, total: 0, alert: 0, color: levelColor(12) });
        s.total++; if (isAlert) s.alert++;
      }
      var user = fieldValue(ev, ["srcuser", "dstuser", "user"]);
      if (user) {
        var u = users[user] || (users[user] = { label: user, full: user, total: 0, alert: 0, color: levelColor(7) });
        u.total++; if (isAlert) u.alert++;
      }
      var port = fieldValue(ev, ["dstport"]);
      if (port) {
        var p = ports[port] || (ports[port] = { label: port, full: "port " + port, total: 0, alert: 0, color: levelColor(10) });
        p.total++; if (isAlert) p.alert++;
      }
    });

    // top rules -------------------------------------------------------------
    var rules = {};
    events.forEach(function (ev) {
      (ev.matched_rules || []).forEach(function (r) {
        var key = String(r.id);
        var entry = rules[key] || (rules[key] = {
          label: r.id + " " + truncate(r.description || "", 18),
          full: r.id + " " + (r.description || ""),
          total: 0, alert: 0, color: levelColor(r.level)
        });
        entry.total++;
        if (r.alert) entry.alert++;
      });
    });

    var html = [];
    html.push(barCard("Severity distribution", severityItems, { alertsOnly: alertsOnly }));
    html.push(barCard("Top source IPs", topItems(sources), { alertsOnly: alertsOnly }));
    html.push(barCard("Top users", topItems(users), { alertsOnly: alertsOnly }));
    html.push(barCard("Top destination ports", topItems(ports), { alertsOnly: alertsOnly }));
    html.push(barCard("Top rules fired", topItems(rules), { alertsOnly: alertsOnly }));
    html.push(timeCard("Events over time", this.scale, events, alertsOnly));

    this.el.innerHTML = html.join("");
  };

  Wz.Timeline = Timeline;
  Wz.IoCCharts = IoCCharts;
})(window.Wazuh = window.Wazuh || {});
