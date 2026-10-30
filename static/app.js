/* bash-guard-forge - vanilla JS front end */
(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };
  var state = { result: null, filter: "all", rating: null, sid: null };

  function esc(s) {
    return String(s === undefined || s === null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function colorFor(score) {
    if (score >= 80) return "#3fb950";
    if (score >= 60) return "#d29922";
    if (score >= 40) return "#db6d28";
    return "#f85149";
  }

  function verdictColor(v) {
    if (v === "deploy_ready") return "#3fb950";
    if (v === "mostly_safe") return "#7ee787";
    if (v === "needs_review") return "#d29922";
    if (v === "tight_but_usable") return "#db6d28";
    return "#f85149";
  }

  function setStatus(txt, isErr) {
    var s = $("status");
    s.textContent = txt || "";
    s.style.color = isErr ? "#ff8b82" : "#8b98a9";
  }

  /* ------------------------------------------------------------------ analyze */

  function run() {
    var script = $("script").value;
    if (!script.trim()) { setStatus("Paste a script first.", true); return; }
    setStatus("Reviewing...");
    $("run").disabled = true;
    fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        script: script,
        env: $("env").value,
        shell: $("shell").value,
        intent: $("intent").value
      })
    }).then(function (r) { return r.json(); }).then(function (data) {
      $("run").disabled = false;
      if (data.error) { setStatus(data.error, true); return; }
      state.result = data;
      state.sid = data.session_id;
      state.rating = null;
      render(data);
      setStatus("");
      loadHistory();
    }).catch(function (e) {
      $("run").disabled = false;
      setStatus("Request failed: " + e, true);
    });
  }

  /* ------------------------------------------------------------------ render */

  function render(d) {
    $("empty").classList.add("hidden");
    $("results").classList.remove("hidden");

    $("score").textContent = d.score;
    $("score").style.color = colorFor(d.score);
    var vp = $("verdictPill");
    vp.textContent = d.verdict_label;
    vp.style.color = verdictColor(d.verdict);
    vp.style.borderColor = verdictColor(d.verdict);
    $("verdictNote").textContent = d.verdict_note;

    var counts = $("counts");
    counts.innerHTML = "";
    ["critical", "high", "medium", "low"].forEach(function (k) {
      var sp = document.createElement("span");
      sp.className = "count-pill";
      sp.textContent = d.counts[k] + " " + k;
      sp.style.color = k === "critical" ? "#ff8b82" : k === "high" ? "#f0a868" : k === "medium" ? "#e3b341" : "#8b98a9";
      counts.appendChild(sp);
    });

    var ax = $("axes");
    ax.innerHTML = "";
    d.axes.forEach(function (a) {
      var row = document.createElement("div");
      row.className = "axis";
      var name = document.createElement("div");
      name.className = "axis-name";
      name.textContent = a.label;
      var w = document.createElement("span");
      w.className = "axis-weight";
      w.textContent = " (" + Math.round(a.weight * 100) + "%)";
      name.appendChild(w);
      var bar = document.createElement("div");
      bar.className = "bar";
      var fill = document.createElement("span");
      fill.style.width = Math.max(2, a.score) + "%";
      fill.style.background = colorFor(a.score);
      bar.appendChild(fill);
      var sc = document.createElement("div");
      sc.className = "axis-score";
      sc.textContent = a.score;
      row.appendChild(name);
      row.appendChild(bar);
      row.appendChild(sc);
      ax.appendChild(row);
    });

    var steps = $("steps");
    steps.innerHTML = "";
    d.steps.forEach(function (s) {
      var li = document.createElement("li");
      li.className = "step";
      var num = document.createElement("div");
      num.className = "stepnum";
      num.textContent = s.n + ".";
      var body = document.createElement("div");
      var code = document.createElement("div");
      code.className = "stepcode";
      code.innerHTML = '<span class="sevdot" style="background:' + (s.severity === "ok" ? "#3fb950" : verdictColor(s.severity === "critical" ? "dangerous_do_not_run" : s.severity === "high" ? "tight_but_usable" : s.severity === "medium" ? "needs_review" : "mostly_safe")) + '"></span>' + esc(s.raw);
      var desc = document.createElement("div");
      desc.className = "stepdesc";
      desc.textContent = "line " + s.line + " - " + s.description;
      body.appendChild(code);
      body.appendChild(desc);
      li.appendChild(num);
      li.appendChild(body);
      steps.appendChild(li);
    });

    var bl = $("blast");
    bl.innerHTML = "";
    var b = d.blast;
    function blastRow(label, items, cls) {
      if (!items || !items.length) return;
      var row = document.createElement("div");
      row.className = "blastrow";
      var l = document.createElement("span");
      l.className = "blastlabel";
      l.textContent = label;
      row.appendChild(l);
      items.forEach(function (it) {
        var t = document.createElement("span");
        t.className = "tag" + (cls ? " " + cls : "");
        t.textContent = it;
        row.appendChild(t);
      });
      bl.appendChild(row);
    }
    blastRow("System paths", b.system_paths, "tag-bad");
    blastRow("Paths touched", b.paths);
    blastRow("Hosts contacted", b.hosts, "tag-warn");
    blastRow("Packages", b.packages);
    blastRow("Databases", b.databases);
    if (b.escalates_to_root) {
      var row = document.createElement("div");
      row.className = "blastrow";
      var l = document.createElement("span");
      l.className = "blastlabel";
      l.textContent = "Privilege";
      row.appendChild(l);
      var t = document.createElement("span");
      t.className = "tag tag-bad";
      t.textContent = "escalates to root (sudo)";
      row.appendChild(t);
      bl.appendChild(row);
    }
    if (!bl.children.length) {
      var p = document.createElement("p");
      p.className = "hint";
      p.textContent = "No paths, hosts or packages detected.";
      bl.appendChild(p);
    }

    renderFindings(d.findings);

    var patch = d.patch || {};
    if (patch.available) {
      $("patchCard").classList.remove("hidden");
      $("patch").textContent = patch.diff;
      $("dlPatch").href = "/api/export/" + d.session_id + "?fmt=patch";
    } else {
      $("patchCard").classList.add("hidden");
    }

    $("dlMd").href = "/api/export/" + d.session_id + "?fmt=md";
    $("dlJson").href = "/api/export/" + d.session_id + "?fmt=json";
    $("notes").value = "";
    setStars(0);
    $("saved").textContent = "Saved as review " + d.session_id;
  }

  /* ------------------------------------------------------------------ findings */

  function renderFindings(findings) {
    var box = $("findings");
    box.innerHTML = "";
    var list = findings.filter(function (f) {
      return state.filter === "all" || f.severity === state.filter;
    });
    if (!list.length) {
      var p = document.createElement("p");
      p.className = "hint";
      p.textContent = "Nothing at this severity.";
      box.appendChild(p);
      return;
    }
    list.forEach(function (f) {
      var card = document.createElement("div");
      card.className = "finding " + f.severity;
      var head = document.createElement("div");
      head.className = "fhead";
      var sev = document.createElement("span");
      sev.className = "sev " + f.severity;
      sev.textContent = f.severity;
      var title = document.createElement("span");
      title.className = "ftitle";
      title.textContent = f.title;
      var meta = document.createElement("span");
      meta.className = "fmeta";
      meta.textContent = f.axis_label + " - line " + f.line + " - " + f.id;
      head.appendChild(sev);
      head.appendChild(title);
      head.appendChild(meta);
      card.appendChild(head);
      if (f.evidence) {
        var ev = document.createElement("div");
        ev.className = "evidence";
        ev.textContent = f.evidence;
        card.appendChild(ev);
      }
      var why = document.createElement("p");
      why.className = "why";
      why.textContent = f.why;
      card.appendChild(why);
      var fix = document.createElement("p");
      fix.className = "fix";
      fix.innerHTML = "<b>Fix:</b> " + esc(f.fix);
      card.appendChild(fix);
      box.appendChild(card);
    });
  }

  /* ------------------------------------------------------------------ stars */

  function setStars(n) {
    var stars = document.querySelectorAll("#stars .star");
    for (var i = 0; i < stars.length; i++) {
      if (i < n) stars[i].classList.add("on");
      else stars[i].classList.remove("on");
    }
  }

  function saveRating(n) {
    setStars(n);
    state.rating = n;
    if (!state.sid) return;
    fetch("/api/sessions/" + state.sid, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rating: n, notes: $("notes").value })
    }).then(function () { loadHistory(); });
  }

  function saveNotes() {
    if (!state.sid) return;
    fetch("/api/sessions/" + state.sid, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rating: state.rating, notes: $("notes").value })
    }).then(function () { loadHistory(); });
  }

  /* ------------------------------------------------------------------ history */

  function loadHistory() {
    fetch("/api/sessions").then(function (r) { return r.json(); }).then(function (rows) {
      var box = $("history");
      box.innerHTML = "";
      if (!rows.length) {
        var p = document.createElement("p");
        p.className = "hint";
        p.textContent = "No reviews saved yet.";
        box.appendChild(p);
        return;
      }
      rows.forEach(function (row) {
        var div = document.createElement("div");
        div.className = "hrow";
        var sc = document.createElement("span");
        sc.className = "hscore";
        sc.textContent = row.score;
        sc.style.color = colorFor(row.score);
        var ti = document.createElement("span");
        ti.className = "htitle";
        ti.textContent = row.title;
        var me = document.createElement("span");
        me.className = "hmeta";
        me.textContent = row.created_at + " - " + row.env + " - " + row.findings_count + " findings";
        var btn = document.createElement("button");
        btn.className = "btn hbtn";
        btn.textContent = "open";
        btn.addEventListener("click", function () { openSession(row.id); });
        div.appendChild(sc);
        div.appendChild(ti);
        div.appendChild(me);
        div.appendChild(btn);
        box.appendChild(div);
      });
    });
  }

  function openSession(id) {
    fetch("/api/sessions/" + id).then(function (r) { return r.json(); }).then(function (d) {
      if (d.error) return;
      state.result = d;
      state.sid = d.session_id;
      state.rating = d.rating;
      $("script").value = d.script || "";
      $("intent").value = d.intent || "";
      $("env").value = d.env || "default";
      render(d);
      $("notes").value = d.notes || "";
      setStars(d.rating || 0);
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  }

  /* ------------------------------------------------------------------ samples */

  function wireSamples() {
    document.querySelectorAll(".samples .chip").forEach(function (btn) {
      var id = btn.getAttribute("data-sample");
      btn.addEventListener("click", function () {
        fetch("/api/sample/" + id).then(function (r) { return r.json(); }).then(function (d) {
          if (d.error) { setStatus("Could not load the sample.", true); return; }
          $("script").value = d.script;
          $("env").value = d.env;
          $("shell").value = d.shell;
          $("intent").value = d.intent;
          document.querySelectorAll(".samples .chip").forEach(function (x) { x.classList.remove("active"); });
          btn.classList.add("active");
          setStatus("Loaded " + id + " - press Review script.");
        });
      });
    });
  }

  /* ------------------------------------------------------------------ wire up */

  document.addEventListener("DOMContentLoaded", function () {
    $("run").addEventListener("click", run);
    $("clear").addEventListener("click", function () {
      $("script").value = "";
      $("intent").value = "";
      setStatus("");
    });
    $("notes").addEventListener("change", saveNotes);

    document.querySelectorAll("#filters .chip").forEach(function (c) {
      c.addEventListener("click", function () {
        document.querySelectorAll("#filters .chip").forEach(function (x) { x.classList.remove("active"); });
        c.classList.add("active");
        state.filter = c.getAttribute("data-sev");
        if (state.result) renderFindings(state.result.findings);
      });
    });

    document.querySelectorAll("#stars .star").forEach(function (s) {
      s.addEventListener("click", function () {
        saveRating(parseInt(s.getAttribute("data-rating"), 10));
      });
    });

    $("copyPatch").addEventListener("click", function () {
      var text = $("patch").textContent;
      if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(function () { setStatus("Patch copied."); });
      } else {
        setStatus("Copy failed - select the diff manually.");
      }
    });

    wireSamples();
    loadHistory();
  });
})();
