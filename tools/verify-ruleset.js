#!/usr/bin/env node
/*
 * Wazuh Offline Analyzer - headless ruleset check.
 *
 * Loads the browser modules in a bare V8 context (there is no DOM here, so the
 * harness supplies a DOMParser built on tools/lib/xml-dom.js) and runs the
 * bundled ruleset through the real decoders and rules.  It answers three
 * questions the browser can only answer by hand:
 *
 *   1. does every bundled decoder/rule file load, and are the counts the
 *      build reported?
 *   2. do the rule chains resolve - i.e. is every if_sid/if_matched_sid target
 *      actually present in the bundle?
 *   3. do the demo samples still surface their alerts, and how fast?
 *
 * Usage:
 *   node tools/verify-ruleset.js               check counts, chains and samples
 *   node tools/verify-ruleset.js --perf 20      re-analyse the mixed sample 20x
 */
"use strict";

var fs = require("fs");
var path = require("path");
var vm = require("vm");

var xmlDom = require("./lib/xml-dom.js");

var ROOT = path.resolve(__dirname, "..");
var JS_DIR = path.join(ROOT, "assets", "js");

var ENGINE_MODULES = ["xml.js", "predecoder.js", "decoders.js", "rules.js", "engine.js"];
var DATA_MODULES = ["ruleset-data.js", "sample-data.js"];

function parseArgs(argv) {
  var options = { perf: 0 };
  for (var i = 0; i < argv.length; i++) {
    if (argv[i] === "--perf") options.perf = Number(argv[++i]) || 1;
    else throw new Error("Unknown option: " + argv[i]);
  }
  return options;
}

/*
 * A minimal browser-ish global for the engine modules.  They only need
 * `window` as their module namespace plus a real XML parser.
 */
function createSandbox() {
  var sandbox = { console: console, setTimeout: setTimeout, clearTimeout: clearTimeout };
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.document = { readyState: "complete" };
  sandbox.DOMParser = function () {
    this.parseFromString = function (text) {
      return xmlDom.parse(text);
    };
  };
  vm.createContext(sandbox);
  return sandbox;
}

function loadModules(sandbox, files) {
  files.forEach(function (file) {
    var full = path.join(JS_DIR, file);
    if (!fs.existsSync(full)) throw new Error("Missing module: " + file);
    vm.runInContext(fs.readFileSync(full, "utf8"), sandbox, { filename: full });
  });
  return sandbox.Wazuh;
}

function fail(message) {
  console.error("FAIL  " + message);
  process.exitCode = 1;
}

function pass(message) {
  console.log("ok    " + message);
}

function checkRuleGraph(Wz, rules) {
  var danglingSids = {};
  var total = 0;
  rules.rules.forEach(function (rule) {
    total++;
    rule.ifSid.concat(rule.ifMatchedSid).forEach(function (sid) {
      if (!rules.byId.has(sid)) danglingSids[sid] = true;
    });
  });
  var ids = Object.keys(danglingSids).map(Number).sort(function (a, b) { return a - b; });
  return { total: total, dangling: ids };
}

function runSamples(Wz) {
  var samples = (Wz.SAMPLE && Wz.SAMPLE.samples) || [];
  var decoders = new Wz.DecoderEngine();
  var decodersLoaded = decoders.loadSources(Wz.RULESET.decoders);
  var rules = new Wz.RuleEngine(3);
  var rulesLoaded = rules.loadSources(Wz.RULESET.rules);

  console.log("loaded " + decodersLoaded + " decoders from " + Wz.RULESET.decoders.length +
    " files, " + rulesLoaded + " rules from " + Wz.RULESET.rules.length + " files");

  var results = [];
  var chain = Promise.resolve();
  samples.forEach(function (sample) {
    chain = chain.then(function () {
      var engine = new Wz.AnalyzerEngine(decoders, rules, { alertLevel: 3, defaultYear: 2026 });
      return engine.analyze(sample.log.split(/\r?\n/)).then(function (payload) {
        results.push({ sample: sample, payload: payload });
      });
    });
  });

  return chain.then(function () {
    results.forEach(function (result) {
      var s = result.payload.stats;
      console.log("  " + pad(result.sample.id, 10) +
        pad(s.lines_total + " lines", 11) +
        pad(s.decoded + " decoded", 13) +
        pad(s.alerts + " alerts", 13) +
        topRule(result.payload));
    });
    return { decoders: decoders, rules: rules, results: results };
  });
}

function topRule(payload) {
  var best = null;
  payload.events.forEach(function (event) {
    event.matched_rules.forEach(function (match) {
      if (match.alert && (!best || match.level > best.level)) best = match;
    });
  });
  if (!best) return "";
  return "peak L" + best.level + " rule " + best.id + " " + truncate(best.description, 52);
}

function pad(value, width) {
  var text = String(value);
  while (text.length < width) text += " ";
  return text;
}

function truncate(text, max) {
  text = String(text || "").replace(/\s+/g, " ").trim();
  return text.length > max ? text.slice(0, max - 1) + "\u2026" : text;
}

function benchmark(Wz, iterations) {
  var sample = (Wz.SAMPLE.samples || [])[0];
  if (!sample) return Promise.resolve();
  var lines = sample.log.split(/\r?\n/);
  var start = Date.now();
  var chain = Promise.resolve();
  for (var i = 0; i < iterations; i++) {
    (function () {
      chain = chain.then(function () {
        var decoders = new Wz.DecoderEngine();
        decoders.loadSources(Wz.RULESET.decoders);
        var rules = new Wz.RuleEngine(3);
        rules.loadSources(Wz.RULESET.rules);
        var engine = new Wz.AnalyzerEngine(decoders, rules, { alertLevel: 3, defaultYear: 2026 });
        return engine.analyze(lines);
      });
    })();
  }
  return chain.then(function () {
    var elapsed = Date.now() - start;
    var total = lines.length * iterations;
    console.log("perf: " + iterations + " runs over " + lines.length + " lines = " +
      total + " lines in " + elapsed + " ms (" + Math.round(total / (elapsed / 1000)) +
      " lines/s)");
  });
}

function main(argv) {
  var options = parseArgs(argv);
  var sandbox = createSandbox();
  var Wz = loadModules(sandbox, ENGINE_MODULES);
  loadModules(sandbox, DATA_MODULES);

  if (!Wz.RULESET) {
    fail("window.Wazuh.RULESET is missing - run: node tools/build-ruleset.js");
    return Promise.resolve(1);
  }

  var expectedDecoders = Wz.RULESET.decoders.reduce(function (sum, e) { return sum + e.text.length; }, 0);
  if (expectedDecoders === 0) fail("bundled ruleset is empty");

  var graphCheck;
  runSamples(Wz).then(function (ctx) {
    graphCheck = checkRuleGraph(Wz, ctx.rules);
    if (graphCheck.dangling.length) {
      console.log("warn  " + graphCheck.dangling.length + " if_sid targets missing from bundle: " +
        graphCheck.dangling.slice(0, 12).join(", ") +
        (graphCheck.dangling.length > 12 ? " ..." : ""));
    } else {
      pass("every if_sid / if_matched_sid target resolves within the bundle");
    }

    var silent = ctx.results.filter(function (r) { return r.payload.stats.alerts === 0; });
    if (silent.length === ctx.results.length) {
      fail("no sample produced a single alert");
    } else if (silent.length) {
      console.log("warn  samples without alerts: " + silent.map(function (r) {
        return r.sample.id;
      }).join(", "));
    } else {
      pass("all " + ctx.results.length + " samples produced alerts");
    }

    if (options.perf > 1) return benchmark(Wz, options.perf);
    return null;
  }).catch(function (err) {
    fail(err && err.stack ? err.stack : String(err));
    process.exitCode = 1;
  });
}

if (require.main === module) {
  main(process.argv.slice(2));
}

module.exports = { createSandbox: createSandbox, loadModules: loadModules };