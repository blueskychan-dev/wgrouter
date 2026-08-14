/* wgrouter's only JavaScript.
 *
 * Everything here is progressive enhancement: every page works with scripting
 * disabled. The device list renders live state server-side and this merely
 * keeps it fresh; the source-mode help is all visible by default and this only
 * narrows it to the relevant one. Nothing is submitted from here, so no CSRF
 * token is involved.
 *
 * Served from the binary's own embedded assets -- there is no CDN, because a
 * router admin panel that needs the internet to render is a router admin panel
 * you cannot use when the internet is what is broken.
 */
(function () {
  "use strict";

  // --- Live device state, over Server-Sent Events -------------------------

  function initEvents() {
    var table = document.getElementById("devtable");
    if (!table || typeof EventSource === "undefined") {
      return;
    }

    var source = new EventSource("/events");

    source.addEventListener("peers", function (e) {
      var peers;
      try {
        peers = JSON.parse(e.data);
      } catch (err) {
        return;
      }
      peers.forEach(function (p) {
        var row = table.querySelector('tr[data-device="' + p.id + '"]');
        if (!row || row.classList.contains("row-disabled")) {
          // A disabled peer has no kernel state to show; leave its row alone.
          return;
        }
        var dot = row.querySelector(".cell-presence .dot");
        if (dot) {
          dot.className = "dot dot-" + p.presence;
        }
        var label = row.querySelector(".presence-label");
        if (label) {
          label.textContent = p.presenceLabel;
        }
        var hs = row.querySelector(".cell-handshake");
        if (hs) {
          hs.textContent = p.lastHandshake;
        }
        var tx = row.querySelector(".cell-transfer");
        if (tx) {
          tx.innerHTML = "";
          tx.appendChild(document.createTextNode("↓ " + p.rx));
          tx.appendChild(document.createElement("br"));
          tx.appendChild(document.createTextNode("↑ " + p.tx));
        }
      });
    });

    // The browser reconnects on its own after an error, so there is nothing to
    // do here but avoid noisy console output on a normal navigation away.
    source.addEventListener("error", function () {});

    window.addEventListener("pagehide", function () {
      source.close();
    });
  }

  // --- Copy the one-time configuration ------------------------------------

  function initCopy() {
    var btn = document.getElementById("copyconf");
    if (!btn) {
      return;
    }
    // The clipboard API is unavailable over plain HTTP on a non-localhost
    // origin. Rather than offering a button that silently does nothing, say
    // why -- the text is selectable either way.
    var usable = navigator.clipboard && window.isSecureContext;
    if (!usable) {
      btn.disabled = true;
      btn.title =
        "Copying needs a secure context. Select the text manually, or use the download link.";
      return;
    }
    btn.addEventListener("click", function () {
      var pre = document.getElementById(btn.getAttribute("data-target"));
      if (!pre) {
        return;
      }
      navigator.clipboard.writeText(pre.textContent).then(
        function () {
          var original = btn.textContent;
          btn.textContent = "Copied";
          setTimeout(function () {
            btn.textContent = original;
          }, 1500);
        },
        function () {
          btn.textContent = "Copy failed";
        }
      );
    });
  }

  // --- Source-mode help ---------------------------------------------------

  function initForwardForm() {
    var mode = document.getElementById("fwd-mode");
    if (!mode) {
      return;
    }
    var helps = Array.prototype.slice.call(
      document.querySelectorAll(".mode-help")
    );

    function showHelp() {
      helps.forEach(function (h) {
        h.hidden = h.getAttribute("data-mode") !== mode.value;
      });
    }

    // A port range forwards every port straight through, so the target port
    // field does not apply. Hiding it beats showing a box whose value is
    // silently discarded.
    var listen = document.getElementById("fwd-listen");
    var targetRow = document.getElementById("fwd-target-row");

    function syncTarget() {
      if (!listen || !targetRow) {
        return;
      }
      targetRow.hidden = listen.value.indexOf("-") > 0;
    }

    // The source list is only meaningful for a policy that has one.
    var policy = document.getElementById("fwd-policy");
    var sourcesRow = document.getElementById("fwd-sources-row");
    var policyHelps = Array.prototype.slice.call(
      document.querySelectorAll(".policy-help")
    );

    function syncPolicy() {
      if (!policy) {
        return;
      }
      policyHelps.forEach(function (h) {
        h.hidden = h.getAttribute("data-policy") !== policy.value;
      });
      if (sourcesRow) {
        sourcesRow.hidden = policy.value === "any";
      }
    }

    mode.addEventListener("change", showHelp);
    if (listen) {
      listen.addEventListener("input", syncTarget);
    }
    if (policy) {
      policy.addEventListener("change", syncPolicy);
    }
    showHelp();
    syncTarget();
    syncPolicy();
  }

  // --- Diagnostics console -------------------------------------------------

  function initDiagForm() {
    var tool = document.getElementById("diag-tool");
    var portRow = document.getElementById("diag-port-row");
    if (!tool) {
      return;
    }
    var helps = Array.prototype.slice.call(
      document.querySelectorAll(".diag-help")
    );

    function sync() {
      helps.forEach(function (h) {
        h.hidden = h.getAttribute("data-tool") !== tool.value;
      });
      if (portRow) {
        // Only the TCP check takes a port. Hiding the field for the others
        // stops it looking like an option that was ignored.
        var opt = tool.options[tool.selectedIndex];
        portRow.hidden = !(opt && opt.getAttribute("data-need-port") === "1");
      }
    }

    tool.addEventListener("change", sync);
    sync();
  }

  // --- Device routing help -------------------------------------------------

  function initDeviceForm() {
    var routing = document.getElementById("dev-routing");
    if (!routing) {
      return;
    }
    var helps = Array.prototype.slice.call(
      document.querySelectorAll(".routing-help")
    );

    function sync() {
      helps.forEach(function (h) {
        h.hidden = h.getAttribute("data-routing") !== routing.value;
      });
    }

    routing.addEventListener("change", sync);
    sync();
  }

  function init() {
    initDeviceForm();
    initEvents();
    initCopy();
    initForwardForm();
    initDiagForm();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
