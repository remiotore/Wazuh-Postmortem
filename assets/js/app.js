/*
 * Wazuh Offline Analyzer - application controller.
 *
 * The decoder/rule ruleset is built in, so the user only supplies logs: by
 * dropping files, browsing, pasting text, or picking one of the demo samples.
 * Everything runs client side: no server, no network calls.
 */
(function (Wz) {
  "use strict";

  function $(id) { return document.getElementById(id); }

  function readFiles(fileList) {
    var files = Array.prototype.slice.call(fileList || []);
    return Promise.all(files.map(function (file) {
      return file.text().then(function (text) {
        return { name: file.name, text: text };
      });
    }));
  }

  function splitLines(text) {
    return String(text == null ? "" : text).split(/\r?\n/);
  }

  function boot() {
    var timeline = new Wz.Timeline({
      el: {
        svg: $("gantt"),
        wrap: $("chartWrap"),
        tooltip: $("tooltip"),
        detail: $("detail"),
        detailBody: $("detailBody"),
        legend: $("legend"),
        stats: $("stats"),
        subtitle: $("subtitle"),
        groupBy: $("groupBy")
      }
    });

    var builtin = Wz.SAMPLE || { decoders: [], rules: [], samples: [] };
    var state = { files: [], busy: false, lastRunKey: null };

    var charts = new Wz.IoCCharts({ grid: $("iocGrid"), note: $("iocNote") });

    function setStatus(message, kind) {
      var el = $("status");
      el.textContent = message || "";
      el.className = "status" + (kind ? " " + kind : "");
    }

    // -- sample picker ------------------------------------------------
    var select = $("sampleSelect");
    (builtin.samples || []).forEach(function (s) {
      var opt = document.createElement("option");
      opt.value = s.id;
      opt.textContent = s.name;
      select.appendChild(opt);
    });

    function updateDropzone() {
      var dz = $("dropzone");
      var text = dz.querySelector(".dz-text");
      if (state.files.length) {
        dz.classList.add("loaded");
        text.innerHTML = "<b>" + state.files.length + " file" +
          (state.files.length > 1 ? "s" : "") + " loaded</b> " +
          state.files.map(function (f) { return f.name; }).join(", ");
      } else {
        dz.classList.remove("loaded");
        text.innerHTML = "<b>Drop log files</b> or <u>browse</u>";
      }
    }

    // -- analysis -----------------------------------------------------
    function run() {
      if (state.busy) return;
      var decoderSources = [];
      var ruleSources = [];
      var logLines = [];
      var note = [];

      state.busy = true;
      $("run").disabled = true;
      setStatus("Reading inputs\u2026");

      Promise.all([
        readFiles($("decoderFiles").files),
        readFiles($("ruleFiles").files)
      ]).then(function (custom) {
        decoderSources = custom[0].length ? custom[0] : builtin.decoders;
        ruleSources = custom[1].length ? custom[1] : builtin.rules;

        state.files.forEach(function (f) { logLines = logLines.concat(splitLines(f.text)); });
        logLines = logLines.concat(splitLines($("logText").value));
        logLines = logLines.filter(function (l, idx, arr) { return !(idx === arr.length - 1 && l === ""); });

        if (!decoderSources.length || !ruleSources.length) {
          throw new Error("No decoders or rules are available.");
        }
        if (!logLines.length) {
          throw new Error("No logs provided. Drop a file, paste lines, or pick a sample.");
        }

        var alertLevel = parseInt($("alertLevel").value, 10);
        if (isNaN(alertLevel)) alertLevel = 3;
        var defaultYear = parseInt($("defaultYear").value, 10);
        if (isNaN(defaultYear)) defaultYear = undefined;
        var sourceHint = $("sourceHint").value || "";

        if (!custom[0].length) note.push("built-in decoders");
        if (!custom[1].length) note.push("built-in rules");

        var decoders = new Wz.DecoderEngine();
        var nd = decoders.loadSources(decoderSources);
        var rules = new Wz.RuleEngine(alertLevel);
        var nr = rules.loadSources(ruleSources);
        var engine = new Wz.AnalyzerEngine(decoders, rules, {
          alertLevel: alertLevel,
          defaultYear: defaultYear
        });

        setStatus("Analysing " + logLines.length + " lines with " + nd + " decoders / " +
          nr + " rules\u2026");

        return engine.analyze(logLines, {
          sourceHint: sourceHint,
          onProgress: function (done, total) {
            if (done < total) setStatus("Analysing " + done + "/" + total + " lines\u2026");
          }
        });
      }).then(function (payload) {
        payload.options = { group_by: $("groupBy").value };
        timeline.setData(payload);
        charts.setData(payload);
        $("toggleAlerts").textContent = "Show Alerts Only";
        $("toggleAlerts").classList.remove("active");
        var s = payload.stats;
        setStatus("Done: " + s.lines_total + " lines, " + s.decoded + " decoded, " +
          s.alerts + " alerts" + (note.length ? " (" + note.join(", ") + ")" : "") + ".",
          "ok");
        state.busy = false;
        $("run").disabled = false;
      }).catch(function (err) {
        if (window.console) console.error(err);
        setStatus("Error: " + (err && err.message ? err.message : err), "error");
        state.busy = false;
        $("run").disabled = false;
      });
    }

    // -- log intake ---------------------------------------------------
    function loadSample(id) {
      var sample = (builtin.samples || []).filter(function (s) { return s.id === id; })[0];
      if (!sample) return;
      state.files = [];
      $("logFiles").value = "";
      updateDropzone();
      $("logText").value = sample.log;
      setStatus("Loaded sample: " + sample.name);
      run();
    }

    $("run").addEventListener("click", run);
    select.addEventListener("change", function () {
      if (this.value) loadSample(this.value);
    });

    $("logFiles").addEventListener("change", function () {
      readFiles(this.files).then(function (files) {
        state.files = files;
        updateDropzone();
        if (files.length) run();
      });
    });

    $("logText").addEventListener("keydown", function (e) {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") run();
    });

    var dz = $("dropzone");
    ["dragenter", "dragover"].forEach(function (evt) {
      dz.addEventListener(evt, function (e) {
        e.preventDefault();
        dz.classList.add("over");
      });
    });
    ["dragleave", "dragend"].forEach(function (evt) {
      dz.addEventListener(evt, function () { dz.classList.remove("over"); });
    });
    dz.addEventListener("drop", function (e) {
      e.preventDefault();
      dz.classList.remove("over");
      var files = e.dataTransfer && e.dataTransfer.files;
      if (files && files.length) {
        state.files = [];
        readFiles(files).then(function (read) {
          state.files = read;
          updateDropzone();
          run();
        });
      }
    });

    // -- view controls ------------------------------------------------
    $("groupBy").addEventListener("change", function () { timeline.setGroupBy(this.value); });
    $("toggleAlerts").addEventListener("click", function () {
      var on = timeline.toggleAlerts();
      this.classList.toggle("active", on);
      this.textContent = on ? "Showing Alerts Only" : "Show Alerts Only";
      timeline.render();
      charts.setAlertsOnly(on);
    });
    $("detailClose").addEventListener("click", function () {
      $("detail").classList.remove("open");
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})(window.Wazuh = window.Wazuh || {});
