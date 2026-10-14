/*
 * Wazuh Offline Analyzer - XML utilities
 *
 * Wazuh ruleset files contain several top-level <decoder>/<rule> elements and
 * optional <?xml?> / <!DOCTYPE> headers, so they are not well-formed XML on
 * their own.  We wrap the content in a synthetic root and parse with DOMParser.
 * Simple <var name="X">value</var> / $X substitution is also supported.
 */
(function (Wz) {
  "use strict";

  var VAR_RE = /\$([A-Za-z_][A-Za-z0-9_]*)/g;

  function stripHeaders(content) {
    return content
      .replace(/<\?xml[^>]*\?>/, "")
      .replace(/<!DOCTYPE[^>]*>/, "");
  }

  function substituteVars(root) {
    var vars = {};
    var varNodes = root.getElementsByTagName("var");
    var i;
    for (i = 0; i < varNodes.length; i++) {
      var name = varNodes[i].getAttribute("name");
      if (name) {
        vars[name] = (varNodes[i].textContent || "").trim();
      }
    }
    if (!Object.keys(vars).length) {
      return;
    }
    var replacer = function (match, key) {
      return Object.prototype.hasOwnProperty.call(vars, key) ? vars[key] : match;
    };

    function walk(node) {
      if (node.nodeType === 3) {
        node.nodeValue = node.nodeValue.replace(VAR_RE, replacer);
        return;
      }
      if (node.tagName === "var") {
        return;
      }
      if (node.attributes) {
        for (var a = 0; a < node.attributes.length; a++) {
          var attr = node.attributes[a];
          attr.value = attr.value.replace(VAR_RE, replacer);
        }
      }
      var children = node.childNodes || [];
      for (var c = 0; c < children.length; c++) {
        walk(children[c]);
      }
    }
    walk(root);
  }

  function parseWazuhXml(text) {
    if (text == null) {
      throw new Error("XML content is empty");
    }
    var wrapped = "<wazuh_ruleset>" + stripHeaders(String(text)) + "</wazuh_ruleset>";
    var doc = new DOMParser().parseFromString(wrapped, "application/xml");
    var errors = doc.getElementsByTagName("parsererror");
    if (errors && errors.length) {
      throw new Error("XML parse error: " + (errors[0].textContent || "").trim());
    }
    substituteVars(doc.documentElement);
    return doc.documentElement;
  }

  function elementText(el) {
    if (!el) return "";
    return (el.textContent || "").trim();
  }

  function childElements(el, name) {
    var out = [];
    if (!el) return out;
    for (var i = 0; i < el.children.length; i++) {
      if (el.children[i].tagName === name) out.push(el.children[i]);
    }
    return out;
  }

  function firstChild(el, name) {
    var kids = childElements(el, name);
    return kids.length ? kids[0] : null;
  }

  Wz.Xml = {
    parseWazuhXml: parseWazuhXml,
    elementText: elementText,
    childElements: childElements,
    firstChild: firstChild
  };
})(window.Wazuh = window.Wazuh || {});
