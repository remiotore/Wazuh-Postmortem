/*
 * Wazuh Offline Analyzer - pre-decoding stage.
 *
 * Pulls the syslog header (timestamp, hostname, program, pid) out of a raw
 * line, understands ISO-8601 prefixed lines and pre-formatted JSON events, and
 * otherwise falls back to treating the whole line as the message.
 */
(function (Wz) {
  "use strict";

  var MONTHS = {
    jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5,
    jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11
  };

  var SYSLOG_RE = /^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\s\[:]+)(?:\[(\d+)\])?:\s?([\s\S]*)$/;
  var ISO_RE = /^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(\S+)\s+([^\s\[:]+)(?:\[(\d+)\])?:\s?([\s\S]*)$/;
  // Apache/NGINX common & combined log format: [dd/Mon/yyyy:HH:MM:SS +zzzz]
  var CLF_RE = /\[(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-]\d{2}:?\d{2})\]/;
  // A bare date-time prefix with no host/program (e.g. "2026-01-12 10:00:00 msg").
  var NUMERIC_TS_RE = /^(\d{4})[-\/](\d{2})[-\/](\d{2}) (\d{2}):(\d{2}):(\d{2})/;

  function Predecoder(defaultYear) {
    this.defaultYear = defaultYear || new Date().getFullYear();
  }

  Predecoder.prototype.predecode = function (line, sourceHint) {
    line = String(line == null ? "" : line).replace(/\r?\n$/, "");
    sourceHint = sourceHint || "";
    if (!line) {
      return this._empty(line, sourceHint);
    }
    var stripped = line.replace(/^\s+/, "");
    if (stripped.charAt(0) === "{") {
      var jsonEvent = this._tryJson(line, sourceHint);
      if (jsonEvent) return jsonEvent;
    }
    var isoEvent = this._tryIso(line, sourceHint);
    if (isoEvent) return isoEvent;
    var syslogEvent = this._trySyslog(line, sourceHint);
    if (syslogEvent) return syslogEvent;
    var clfEvent = this._tryClf(line, sourceHint);
    if (clfEvent) return clfEvent;
    var numericEvent = this._tryNumeric(line, sourceHint);
    if (numericEvent) return numericEvent;
    var ev = this._empty(line, sourceHint);
    ev.source = sourceHint || "-";
    return ev;
  };

  Predecoder.prototype._empty = function (line, sourceHint) {
    return {
      raw: line,
      message: line,
      timestamp: null,
      hostname: "",
      programName: "",
      pid: "",
      source: sourceHint || "-",
      kind: "raw",
      jsonFields: {}
    };
  };

  Predecoder.prototype._tryJson = function (line, sourceHint) {
    var data;
    try {
      data = JSON.parse(line);
    } catch (e) {
      return null;
    }
    if (!data || typeof data !== "object" || Array.isArray(data)) {
      return null;
    }
    var message = data.full_log != null ? data.full_log
      : (data.message != null ? data.message
        : (data.data != null ? data.data : line));
    var ev = {
      raw: data.full_log != null ? data.full_log : line,
      message: String(message),
      timestamp: parseTimestamp(data.timestamp),
      hostname: String(data.hostname || data.host || ""),
      programName: String(data.program_name || data.program || ""),
      pid: String(data.pid || ""),
      source: String(data.location || sourceHint || data.program_name || data.program || "-"),
      kind: "json",
      jsonFields: data
    };
    return ev;
  };

  Predecoder.prototype._tryIso = function (line, sourceHint) {
    var m = ISO_RE.exec(line);
    if (!m) return null;
    var ts = parseIsoTimestamp(m[1]);
    if (!ts) return null;
    return {
      raw: line,
      message: m[5],
      timestamp: ts,
      hostname: m[2],
      programName: m[3],
      pid: m[4] || "",
      source: m[3] || sourceHint || "-",
      kind: "iso",
      jsonFields: {}
    };
  };

  Predecoder.prototype._trySyslog = function (line, sourceHint) {
    var m = SYSLOG_RE.exec(line);
    if (!m) return null;
    var month = MONTHS[m[1].toLowerCase()];
    if (month === undefined) return null;
    var parts = m[3].split(":");
    var ts = new Date(
      this.defaultYear, month, parseInt(m[2], 10),
      parseInt(parts[0], 10), parseInt(parts[1], 10), parseInt(parts[2], 10)
    );
    if (isNaN(ts.getTime())) return null;
    return {
      raw: line,
      message: m[7],
      timestamp: ts,
      hostname: m[4],
      programName: m[5],
      pid: m[6] || "",
      source: m[5] || sourceHint || "-",
      kind: "syslog",
      jsonFields: {}
    };
  };

  // Apache/NGINX access logs: the timestamp sits in brackets and the message
  // stays the whole line so the web decoder anchor still matches.
  Predecoder.prototype._tryClf = function (line, sourceHint) {
    var m = CLF_RE.exec(line);
    if (!m) return null;
    var month = MONTHS[m[2].toLowerCase()];
    if (month === undefined) return null;
    var offset = parseUtcOffset(m[7]);
    var ts = new Date(Date.UTC(
      parseInt(m[3], 10), month, parseInt(m[1], 10),
      parseInt(m[4], 10), parseInt(m[5], 10), parseInt(m[6], 10)
    ) - offset * 60000);
    if (isNaN(ts.getTime())) return null;
    return {
      raw: line,
      message: line,
      timestamp: ts,
      hostname: "",
      programName: "",
      pid: "",
      source: sourceHint || "-",
      kind: "clf",
      jsonFields: {}
    };
  };

  // A bare date-time prefix, useful for logs without a syslog/ISO header.
  Predecoder.prototype._tryNumeric = function (line, sourceHint) {
    var m = NUMERIC_TS_RE.exec(line);
    if (!m) return null;
    var ts = new Date(
      parseInt(m[1], 10), parseInt(m[2], 10) - 1, parseInt(m[3], 10),
      parseInt(m[4], 10), parseInt(m[5], 10), parseInt(m[6], 10)
    );
    if (isNaN(ts.getTime())) return null;
    return {
      raw: line,
      message: line,
      timestamp: ts,
      hostname: "",
      programName: "",
      pid: "",
      source: sourceHint || "-",
      kind: "timestamp",
      jsonFields: {}
    };
  };

  function parseUtcOffset(text) {
    var m = /^([+-])(\d{2}):?(\d{2})$/.exec(text || "");
    if (!m) return 0;
    var minutes = parseInt(m[2], 10) * 60 + parseInt(m[3], 10);
    return m[1] === "-" ? -minutes : minutes;
  }

  function parseIsoTimestamp(value) {
    if (!value) return null;
    var text = String(value).trim();
    if (text.charAt(text.length - 1) === "Z") {
      text = text.slice(0, -1) + "+00:00";
    }
    var m = /([+-]\d{2})(\d{2})$/.exec(text);
    if (m) {
      text = text.slice(0, m.index) + m[1] + ":" + m[2];
    }
    var date = new Date(text);
    return isNaN(date.getTime()) ? null : date;
  }

  function parseTimestamp(value) {
    if (value == null) return null;
    if (typeof value === "number") {
      var date = new Date(value * 1000);
      return isNaN(date.getTime()) ? null : date;
    }
    return parseIsoTimestamp(value);
  }

  Wz.Predecoder = Predecoder;
  Wz.parseIsoTimestamp = parseIsoTimestamp;

  // Fields derived purely from pre-decoding, available to rules' same_* checks.
  Wz.eventFieldsSnapshot = function (event) {
    return {
      hostname: event.hostname,
      program_name: event.programName,
      location: event.source,
      agent: event.hostname
    };
  };
})(window.Wazuh = window.Wazuh || {});
