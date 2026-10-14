/*
 * Wazuh Offline Analyzer - Indicators of Compromise charts.
 *
 * Dependency-free SVG summary panels derived from the analysis payload.  Every
 * chart aggregates over all events: the muted bar is the total and the coloured
 * overlay is the alert subset.  The "events over time" panel reuses the exact
 * scale built by timeline.js so its positions match the Gantt chart.
 */
(function (Wz) {
  "use strict";

  var MUTED = "#3d5a8c";

  function esc(text) {
    return String(text == null ? "" : text).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function color(level) {
    return Wz.levelColor ? Wz.levelColor(level) : "#ff5c5c";
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

  // -- horizontal bar card -------------------------------------------------
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
          '" height="' + barH + '" rx="2" fill="' + (it.color || color(it.level)) + '"/>');
      }
      var countText = alertsOnly ? String(it.alert)
        : (it.alert > 0 ? it.alert + "/" + it.total : String(it.total));
      parts.push('<text class="ioc-count" x="' + (W - 4) + '" y="' + cy +
        '" text-anchor="end" dominant-baseline="middle">' + esc(countText) + '</text>');
    });

    return card(title, '<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="xMidYMid meet">' +
      parts.join("") + "</svg>");
  }

  // -- events over time (vertical bars) ------------------------------------
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
          '" height="' + ah + '" rx="1" fill="' + color(10) + '"/>');
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

  function card(title, body) {
    return '<div class="ioc-card"><h3>' + esc(title) + "</h3>" +
      (body || '<div class="ioc-empty">No data</div>') + "</div>";
  }

  function topItems(counts, opts) {
    opts = opts || {};
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
    this.scale = Wz.buildTimeScale(this.events);
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
        var s = sources[srcip] || (sources[srcip] = { label: srcip, full: srcip, total: 0, alert: 0, color: color(12) });
        s.total++; if (isAlert) s.alert++;
      }
      var user = fieldValue(ev, ["srcuser", "dstuser", "user"]);
      if (user) {
        var u = users[user] || (users[user] = { label: user, full: user, total: 0, alert: 0, color: color(7) });
        u.total++; if (isAlert) u.alert++;
      }
      var port = fieldValue(ev, ["dstport"]);
      if (port) {
        var p = ports[port] || (ports[port] = { label: port, full: "port " + port, total: 0, alert: 0, color: color(10) });
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
          total: 0, alert: 0, color: color(r.level)
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

  Wz.IoCCharts = IoCCharts;
})(window.Wazuh = window.Wazuh || {});
