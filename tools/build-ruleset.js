#!/usr/bin/env node
/*
 * Wazuh Offline Analyzer - ruleset bundler.
 *
 * The analyzer ships with its decoders and rules compiled into a JS file so the
 * page works straight off the filesystem: the browser cannot fetch the ruleset
 * over file://, and re-parsing 230 XML documents per run would be wasteful.
 *
 * This script walks the vendored Wazuh ruleset, normalises the handful of files
 * that upstream leaves as non-well-formed XML, applies the correctness patches
 * listed below, verifies every document still parses, and writes
 * assets/js/ruleset-data.js.
 *
 * Usage:
 *   node tools/build-ruleset.js            rebuild assets/js/ruleset-data.js
 *   node tools/build-ruleset.js --check    fail if the checked-in bundle is stale
 *   node tools/build-ruleset.js --stats    print the inventory without writing
 *
 * Excluded on purpose:
 *   rules/translated/**  alternate-language copies of the same rule ids; the
 *                        upstream manager loads exactly one per run, so bundling
 *                        all of them would give every id a dozen descriptions.
 *   rules/log-entries/** sample log data, not rules.
 *   anything that is not *.xml in the decoders/ and rules/ directories.
 */
"use strict";

var fs = require("fs");
var path = require("path");

var xmlDom = require("./lib/xml-dom.js");

var ROOT = path.resolve(__dirname, "..");
var RULESET_DIR = path.join(ROOT, "wazuh-ruleset");
var DEFAULT_OUT = path.join(ROOT, "assets", "js", "ruleset-data.js");

var EXCLUDED_DIRS = ["translated", "log-entries"];

/*
 * Correctness patches applied to the vendored ruleset on the way in.
 *
 * These are upstream data bugs, not analyzer bugs: the ruleset is read by
 * Wazuh's own config parser, so nothing stops a pattern from being nonsense -
 * and in these cases it is.  The vendored XML is left untouched; the bundle is
 * what gets corrected, and every patch is reported by --stats so it can be
 * dropped once upstream ships a fix.
 *
 * 1. Escaped-dot quantifiers.  954 patterns across 60 files write "\\.*" or
 *    "\\.+" where ".*" / ".+" was meant, i.e. "zero or more literal dots" for
 *    what is really "anything here".  The web access log decoder is the known
 *    upstream report (wazuh/wazuh#352); the same typo makes every iptables
 *    firewall line lose its action/srcport/dstport, and it recurs in the
 *    checkpoint, cisco, paloalto, windows and panda decoders.  Bare "\\." is
 *    left alone: four genuine literal dots exist.
 *
 * 2. The roundcube prematch wraps a regex sequence in a character class:
 *    "^[\d\d-\w\w\w-\d\d\d\d \d\d:\d\d:\d\d \S+]" matches exactly one word
 *    character, so the decoder accepts every syslog-shaped line in the ruleset
 *    and mislabels them.  Read as a sequence - which is plainly what was
 *    meant, and what the four worked examples in that file's own header show -
 *    it is a bracketed date, restored below.
 *
 * 3. Unescaped brackets around a capture group.  59 patterns write
 *    "[(\S+)]" where "[\S+]" is read as a character class rather than a
 *    literal bracket around a group, which silently drops the capture the
 *    rule's <order> is waiting for.  The <order> lists prove the intent:
 *    identity_guard-generic orders three fields and has exactly three of them.
 *
 * 4. Reserved for further upstream corrections, same shape:
 *      { file: "rules/0100-example_rules.xml", find: /old/, replace: "new",
 *        why: "..." }
 */
var PATCHES = [
  {
    file: null,
    find: /\\\.[*+]/g,
    replace: function (match) { return "." + match.charAt(2); },
    why: "\\.* and \\.+ are \"literal dots\", not wildcards: they silently " +
      "disable 954 patterns across 60 files, including the whole NCSA access " +
      "log decoder (wazuh/wazuh#352) and every iptables field."
  },
  {
    file: null,
    find: /\[(\([^()]*\))\]/g,
    replace: function (match, group) { return "\\[" + group + "\\]"; },
    why: "[(\\\\S+)] is a character class, not a bracketed capture group, so " +
      "the capture its <order> names never happens."
  },
  {
    file: "decoders/0255-roundcube_decoders.xml",
    find: /\^\[\\d\\d-\\w\\w\\w-\\d\\d\\d\\d \\d\\d:\\d\\d:\\d\\d \\S\+\]/,
    replace: "^\\[\\d\\d-\\w\\w\\w-\\d\\d\\d\\d \\d\\d:\\d\\d:\\d\\d [+-]\\d\\d\\d\\d\\]",
    why: "the prematch is a pattern wrapped in a character class, so it " +
      "matches any single word character and claims every syslog line."
  }
];

function applyPatches(relativeToRuleset, text, report) {
  var out = text;
  PATCHES.forEach(function (patch) {
    if (patch.file !== null && patch.file !== relativeToRuleset) return;
    var pattern = new RegExp(patch.find.source, patch.find.flags);
    var found = out.match(pattern);
    if (!found || !found.length) {
      if (patch.file !== null) {
        report.problems.push(relativeToRuleset + ": expected patch no longer applies (" +
          patch.why + ") - drop it from PATCHES if upstream fixed this.");
      }
      return;
    }
    report.patches.push({
      file: patch.file === null ? "wazuh-ruleset/**" : relativeToRuleset,
      key: patch.why,
      count: found.length,
      why: patch.why
    });
    out = out.replace(pattern, patch.replace);
  });
  return out;
}

function parseArgs(argv) {
  var options = { out: DEFAULT_OUT, ruleset: RULESET_DIR, check: false, stats: false };
  for (var i = 0; i < argv.length; i++) {
    var arg = argv[i];
    if (arg === "--check") options.check = true;
    else if (arg === "--stats") options.stats = true;
    else if (arg === "--out") options.out = path.resolve(process.cwd(), argv[++i]);
    else if (arg === "--ruleset") options.ruleset = path.resolve(process.cwd(), argv[++i]);
    else if (arg === "-h" || arg === "--help") options.help = true;
    else throw new Error("Unknown option: " + arg);
  }
  return options;
}

/*
 * Ruleset files are loaded in numeric prefix order, exactly like the upstream
 * manager does, because parent decoders and if_sid rule chains rely on it.
 */
function orderKey(file) {
  var base = path.basename(file);
  var match = /^(\d+)[-_]/.exec(base);
  return match ? [Number(match[1]), base] : [Number.MAX_SAFE_INTEGER, base];
}

function listXmlFiles(dir, label) {
  var entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (err) {
    throw new Error("Cannot read " + label + " directory " + dir + ": " + err.message);
  }
  var files = entries
    .filter(function (entry) { return entry.isFile() && /\.xml$/i.test(entry.name); })
    .map(function (entry) { return path.join(dir, entry.name); });

  var skipped = entries
    .filter(function (entry) { return entry.isDirectory() && EXCLUDED_DIRS.indexOf(entry.name) !== -1; })
    .map(function (entry) { return entry.name; });

  files.sort(function (a, b) {
    var ka = orderKey(a);
    var kb = orderKey(b);
    return ka[0] - kb[0] || (ka[1] < kb[1] ? -1 : ka[1] > kb[1] ? 1 : 0);
  });
  return { files: files, skipped: skipped };
}

function countElements(doc, tagName) {
  return doc.getElementsByTagName(tagName).length;
}

function loadRuleset(rulesetDir) {
  var decoders = listXmlFiles(path.join(rulesetDir, "decoders"), "decoders");
  var rules = listXmlFiles(path.join(rulesetDir, "rules"), "rules");

  var report = {
    decoders: [],
    rules: [],
    repairs: [],
    patches: [],
    problems: []
  };

  function readGroup(files, groupName, entryTag) {
    files.forEach(function (file) {
      var relative = path.relative(ROOT, file);
      var relativeToRuleset = path.relative(rulesetDir, file).split(path.sep).join("/");
      var source = fs.readFileSync(file, "utf8");

      var before = xmlDom.validate(source, relative);
      var cleaned = xmlDom.sanitize(source);

      cleaned.fixes.forEach(function (fix) {
        report.repairs.push({
          file: relative,
          line: xmlDom.position(source, fix.offset).line,
          kind: fix.kind,
          replacement: fix.replacement
        });
      });

      var after = xmlDom.validate(cleaned.text, relative);
      if (after) {
        report.problems.push(after);
        return;
      }
      if (before) {
        report.repairs.push({
          file: relative,
          line: 1,
          kind: "not-well-formed-upstream",
          replacement: "normalised at build time"
        });
      }

      var patched = applyPatches(relativeToRuleset, cleaned.text, report);
      var patchedProblem = xmlDom.validate(patched, relative);
      if (patchedProblem) {
        report.problems.push(patchedProblem);
        return;
      }

      report[groupName].push({
        name: path.basename(file),
        path: relative,
        entries: countElements(xmlDom.parseFragment(patched), entryTag),
        text: patched
      });
    });
  }

  readGroup(decoders.files, "decoders", "decoder");
  readGroup(rules.files, "rules", "rule");

  report.excluded = decoders.skipped.concat(rules.skipped);
  report.version = readVersion(rulesetDir);
  return report;
}

function readVersion(rulesetDir) {
  try {
    var text = fs.readFileSync(path.join(rulesetDir, "VERSION"), "utf8");
    var match = /RULESET_VERSION\s*=\s*"?([^"\s]+)"?/.exec(text);
    return match ? match[1] : "unknown";
  } catch (err) {
    return "unknown";
  }
}

/*
 * JSON.stringify gives us the escaping for free, and the result is stable
 * across runs, so `build && diff` is a meaningful drift check.
 */
function render(report) {
  var payload = {
    ruleset_version: report.version,
    decoders: report.decoders.map(function (entry) {
      return { name: entry.name, text: entry.text };
    }),
    rules: report.rules.map(function (entry) {
      return { name: entry.name, text: entry.text };
    })
  };

  var lines = [];
  lines.push("/*");
  lines.push(" * GENERATED FILE - do not edit by hand.");
  lines.push(" * Rebuild with: node tools/build-ruleset.js");
  lines.push(" *");
  lines.push(" * Every decoder and rule from wazuh-ruleset/ (" + report.version + "), embedded as");
  lines.push(" * text so the page works from file:// with no network access.");
  lines.push(" */");
  lines.push("window.Wazuh = window.Wazuh || {};");
  lines.push("window.Wazuh.RULESET = " + JSON.stringify(payload, null, 2) + ";");
  return lines.join("\n") + "\n";
}

function summarize(report) {
  var decoders = report.decoders.reduce(function (sum, e) { return sum + e.entries; }, 0);
  var rules = report.rules.reduce(function (sum, e) { return sum + e.entries; }, 0);
  return {
    files: report.decoders.length + report.rules.length,
    decoders: decoders,
    rules: rules
  };
}

function printStats(report) {
  var totals = summarize(report);
  console.log("ruleset " + report.version);
  console.log("  decoders: " + report.decoders.length + " files, " + totals.decoders + " definitions");
  console.log("  rules:    " + report.rules.length + " files, " + totals.rules + " definitions");
  if (report.excluded.length) {
    console.log("  excluded: " + report.excluded.join(", "));
  }
  if (report.repairs.length) {
    console.log("  repaired " + report.repairs.length + " malformed constructs:");
    report.repairs.forEach(function (repair) {
      console.log("    " + repair.file + ":" + repair.line + "  " + repair.kind +
        " -> " + repair.replacement);
    });
  }
  if (report.patches.length) {
    // One entry per rule, with the files it touched, not one per file.
    var byPatch = new Map();
    report.patches.forEach(function (hit) {
      if (!byPatch.has(hit.key)) byPatch.set(hit.key, { why: hit.why, count: 0, files: 0 });
      var entry = byPatch.get(hit.key);
      entry.count += hit.count;
      entry.files++;
    });
    console.log("  patched " + byPatch.size + " upstream bug(s):");
    byPatch.forEach(function (entry) {
      console.log("    " + entry.files + " file(s), " + entry.count + " pattern(s)");
      console.log("      " + entry.why);
    });
  }
  if (report.problems.length) {
    console.log("  UNPARSABLE FILES:");
    report.problems.forEach(function (problem) { console.log("    " + problem); });
  }
}

function main(argv) {
  var options = parseArgs(argv);
  if (options.help) {
    var source = fs.readFileSync(__filename, "utf8");
    var header = source.slice(source.indexOf("/*"), source.indexOf("*/") + 2);
    var body = header
      .replace(/^\/\*+/, "")
      .replace(/\*\/\s*$/, "")
      .split("\n")
      .map(function (line) { return line.replace(/^ \* ?/, ""); })
      .join("\n");
    console.log(body.trim());
    return 0;
  }

  var report = loadRuleset(options.ruleset);
  var totals = summarize(report);

  if (report.problems.length) {
    printStats(report);
    console.error("\nBuild failed: " + report.problems.length + " file(s) could not be parsed.");
    return 1;
  }

  if (options.stats) {
    printStats(report);
    return 0;
  }

  var output = render(report);

  if (options.check) {
    var existing = fs.existsSync(options.out) ? fs.readFileSync(options.out, "utf8") : null;
    if (existing === output) {
      console.log("ruleset-data.js is up to date (" + totals.files + " files, " +
        totals.decoders + " decoders, " + totals.rules + " rules).");
      return 0;
    }
    console.error("ruleset-data.js is stale. Run: node tools/build-ruleset.js");
    return 1;
  }

  fs.mkdirSync(path.dirname(options.out), { recursive: true });
  fs.writeFileSync(options.out, output);
  printStats(report);
  console.log("\nwrote " + path.relative(ROOT, options.out) + " (" +
    (Buffer.byteLength(output) / 1024).toFixed(0) + " KiB)");
  return 0;
}

if (require.main === module) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (err) {
    console.error("build-ruleset: " + (err && err.message ? err.message : err));
    process.exitCode = 1;
  }
}

module.exports = { loadRuleset: loadRuleset, render: render, summarize: summarize };