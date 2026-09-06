// =====================================================
// OWASP-ML SOC dashboard -- charts + interactions
// Chart payloads come from app.py via <script type="application/json">
// blocks, so this file stays dumb: read JSON, draw what exists, wire up
// the reports table + detail drawer. No framework, no build step.
// =====================================================

document.addEventListener("DOMContentLoaded", function () {

    // ---------- Chart.js dark defaults ----------
    if (window.Chart) {
        Chart.defaults.font.family = "'Inter', 'Poppins', sans-serif";
        Chart.defaults.font.size = 11.5;
        Chart.defaults.color = "#94a3b8";
        Chart.defaults.borderColor = "rgba(148, 163, 184, 0.12)";
    }

    const SEV_COLORS = {
        "Critical": "#f43f5e",
        "High": "#ef4444",
        "Medium": "#f59e0b",
        "Low": "#34d399",
        "Informational": "#64748b"
    };
    const CYAN = "#22d3ee";
    const GREEN = "#34d399";

    // ---------- Read every JSON payload block on the page ----------
    const data = {};
    document.querySelectorAll('script[type="application/json"]').forEach(function (el) {
        try {
            const parsed = JSON.parse(el.textContent);
            Object.assign(data, parsed);
        } catch (err) {
            console.warn("chart-data block was not valid JSON", err);
        }
    });

    function baseBarOptions(horizontal) {
        return {
            indexAxis: horizontal ? "y" : "x",
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: "#0D1321",
                    titleColor: "#e2e8f0",
                    bodyColor: "#94a3b8",
                    borderColor: "rgba(34,211,238,0.25)",
                    borderWidth: 1,
                    padding: 10,
                    cornerRadius: 8,
                    titleFont: { family: "'JetBrains Mono', monospace", size: 11 },
                    bodyFont: { family: "'JetBrains Mono', monospace", size: 11 },
                }
            },
            scales: {
                x: { grid: { color: "rgba(148,163,184,0.08)", display: !horizontal }, ticks: { color: "#64748b", font: { family: "'JetBrains Mono', monospace", size: 10 } } },
                y: { grid: { color: "rgba(148,163,184,0.08)", display: horizontal }, beginAtZero: true, ticks: { color: "#94a3b8", font: { family: "'JetBrains Mono', monospace", size: 10 } } }
            }
        };
    }

    // ---------- Dashboard: risk doughnut ----------
    const riskCanvas = document.getElementById("riskChart");
    if (riskCanvas && data.risk) {
        new Chart(riskCanvas, {
            type: "doughnut",
            data: {
                labels: data.risk.labels,
                datasets: [{
                    data: data.risk.values,
                    backgroundColor: data.risk.labels.map(l => SEV_COLORS[l] || "#64748b"),
                    borderColor: "#0D1321",
                    borderWidth: 3,
                    hoverOffset: 6
                }]
            },
            options: {
                responsive: true, maintainAspectRatio: false, cutout: "62%",
                plugins: {
                    legend: { position: "bottom", labels: { color: "#94a3b8", font: { family: "'JetBrains Mono', monospace", size: 11 }, padding: 12, usePointStyle: true, pointStyle: "rectRounded" } },
                    tooltip: { backgroundColor: "#0D1321", titleColor: "#e2e8f0", bodyColor: "#94a3b8", borderColor: "rgba(34,211,238,0.25)", borderWidth: 1, padding: 10, cornerRadius: 8 }
                }
            }
        });
    }

    // ---------- Dashboard: top attack types ----------
    const attackCanvas = document.getElementById("attackChart");
    if (attackCanvas && data.attack) {
        new Chart(attackCanvas, {
            type: "bar",
            data: { labels: data.attack.labels, datasets: [{ data: data.attack.values, backgroundColor: CYAN, borderRadius: 5 }] },
            options: baseBarOptions(true)
        });
    }

    // ---------- Dashboard: OWASP categories (full labels in tooltip) ----------
    const owaspCanvas = document.getElementById("owaspChart");
    if (owaspCanvas && data.owasp) {
        var owaspFull = data.owasp.full_labels || data.owasp.labels;
        new Chart(owaspCanvas, {
            type: "bar",
            data: { labels: data.owasp.labels, datasets: [{ data: data.owasp.values, backgroundColor: GREEN, borderRadius: 5 }] },
            options: Object.assign({}, baseBarOptions(true), {
                plugins: Object.assign({}, baseBarOptions(true).plugins, {
                    tooltip: Object.assign({}, (baseBarOptions(true).plugins || {}).tooltip || {}, {
                        callbacks: { title: function (ctx) { return owaspFull[ctx[0].dataIndex] || ctx[0].label; } }
                    })
                })
            })
        });
    }

    // ---------- Dashboard: HTTP methods ----------
    const methodCanvas = document.getElementById("methodChart");
    if (methodCanvas && data.method) {
        new Chart(methodCanvas, {
            type: "bar",
            data: { labels: data.method.labels, datasets: [{ data: data.method.values, backgroundColor: "#64748b", borderRadius: 5 }] },
            options: baseBarOptions(true)
        });
    }

    // ---------- Dashboard: hybrid score buckets ----------
    const bucketCanvas = document.getElementById("scoreBucketChart");
    if (bucketCanvas && data.score_buckets) {
        new Chart(bucketCanvas, {
            type: "bar",
            data: {
                labels: data.score_buckets.labels,
                datasets: [{ data: data.score_buckets.values, backgroundColor: ["#64748b", "#34d399", "#f59e0b", "#f43f5e"], borderRadius: 5 }]
            },
            options: baseBarOptions(false)
        });
    }

    // ---------- Gauge arc animation ----------
    const gaugeArc = document.getElementById("gaugeArc");
    const gaugeNum = document.getElementById("gaugeNum");
    if (gaugeArc && gaugeNum) {
        const pct = Math.max(0, Math.min(100, parseFloat(gaugeNum.textContent) || 0));
        // Arc path length for the 200x120 viewBox (radius 84, sweep ~263px).
        // Computed once via getTotalLength() so a viewBox change never desyncs.
        let total = 263;
        try { total = gaugeArc.getTotalLength(); } catch (e) { /* keep fallback */ }
        const offset = total - (total * pct / 100);
        requestAnimationFrame(() => {
            gaugeArc.style.transition = "stroke-dashoffset 1.1s cubic-bezier(.2,.8,.2,1)";
            gaugeArc.style.strokeDashoffset = offset;
        });
    }

    // ---------- Footer freshness label ----------
    const freshLabel = document.getElementById("freshLabel");
    if (freshLabel) {
        // The dashboard route already computed the freshness server-side via
        // _freshness(); we re-fetch the summary API every 60s so the label
        // stays fresh without a full page reload.
        function refreshFreshness() {
            fetch("/api/summary" + (window.location.search ? window.location.search + "&" : "?") + "_=" + Date.now())
                .then(r => r.json()).then(d => {
                    if (d && d.status) {
                        freshLabel.textContent = "ok";
                    }
                }).catch(() => { freshLabel.textContent = "—"; });
        }
        freshLabel.textContent = "ok";
        setInterval(refreshFreshness, 60000);
    }

    // ---------- Feed copy-to-clipboard ----------
    document.querySelectorAll(".feed .copy-btn[data-copy]").forEach(function (btn) {
        btn.addEventListener("click", function (e) {
            e.stopPropagation();
            const url = btn.getAttribute("data-copy") || "";
            if (!url) return;
            const done = function () {
                const orig = btn.textContent;
                btn.textContent = "✓"; btn.style.color = "var(--green)";
                setTimeout(() => { btn.textContent = orig; btn.style.color = ""; }, 1200);
            };
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(url).then(done).catch(() => {});
            } else {
                const ta = document.createElement("textarea"); ta.value = url;
                document.body.appendChild(ta); ta.select();
                try { document.execCommand("copy"); done(); } catch (e2) {}
                document.body.removeChild(ta);
            }
        });
    });

    // =====================================================
    // REPORTS PAGE -- search + filters + sort + drawer
    // =====================================================
    const searchBox = document.getElementById("reportSearch");
    const sevFilter = document.getElementById("filterSeverity");
    const attackFilter = document.getElementById("filterAttack");
    const owaspFilter = document.getElementById("filterOwasp");
    const clearBtn = document.getElementById("clearFilters");
    const noResults = document.getElementById("noResults");
    const reportBody = document.getElementById("reportBody");
    const rowNote = document.getElementById("rowNote");

    function applyReportFilters() {
        if (!reportBody) return;
        const needle = (searchBox && searchBox.value.trim().toLowerCase()) || "";
        const sev = sevFilter ? sevFilter.value : "";
        const atk = attackFilter ? attackFilter.value : "";
        const ows = owaspFilter ? owaspFilter.value : "";
        let visible = 0;
        reportBody.querySelectorAll("tr").forEach(function (row) {
            const text = row.textContent.toLowerCase();
            const matchText = !needle || text.indexOf(needle) !== -1;
            const matchSev = !sev || row.dataset.severity === sev;
            const matchAtk = !atk || row.dataset.attack === atk;
            const matchOws = !ows || row.dataset.owasp === ows;
            const show = matchText && matchSev && matchAtk && matchOws;
            row.style.display = show ? "" : "none";
            if (show) visible++;
        });
        if (rowNote) {
            rowNote.textContent = visible + " shown (of " + (reportBody.querySelectorAll("tr").length) + ")";
        }
        if (noResults) {
            noResults.style.display = visible === 0 ? "block" : "none";
        }
    }
    [searchBox, sevFilter, attackFilter, owaspFilter].forEach(function (el) {
        if (el) el.addEventListener("input", applyReportFilters);
        if (el) el.addEventListener("change", applyReportFilters);
    });
    if (clearBtn) {
        clearBtn.addEventListener("click", function () {
            if (searchBox) searchBox.value = "";
            if (sevFilter) sevFilter.value = "";
            if (attackFilter) attackFilter.value = "";
            if (owaspFilter) owaspFilter.value = "";
            applyReportFilters();
            // also drop any ?rule= query so "clear" fully resets
            if (window.location.search.indexOf("rule=") !== -1) {
                window.location.href = window.location.pathname;
            }
        });
    }
    // '/' focuses the search box (unless the user is already typing in a field)
    document.addEventListener("keydown", function (e) {
        if (e.key === "/" && document.activeElement.tagName !== "INPUT" &&
            document.activeElement.tagName !== "SELECT" && document.activeElement.tagName !== "TEXTAREA") {
            if (searchBox) { e.preventDefault(); searchBox.focus(); }
        }
    });
    if (reportBody) applyReportFilters();

    // ---------- sortable columns ----------
    const table = document.getElementById("reportTable");
    if (table) {
        const headers = table.querySelectorAll("th.sortable");
        let sortState = { col: null, dir: 1 };
        // map data-sort value -> the row data attribute that holds the sort key
        const colToAttr = {
            "severity": "severityRank",
            "alert_name": "sortAlert",
            "attack_type": "sortAttack",
            "owasp": "sortOwasp",
            "cwe": "sortCwe",
            "method": "sortMethod",
            "confidence": "sortConfidence",
            "ml_prediction": "sortMlRank",
            "anomaly_score": "sortAnomaly",
            "hybrid_score": "sortHybrid",
        };
        headers.forEach(function (th) {
            th.addEventListener("click", function () {
                const col = th.dataset.sort;
                if (sortState.col === col) sortState.dir = -sortState.dir;
                else { sortState.col = col; sortState.dir = 1; }
                headers.forEach(h => h.querySelector(".arrow").textContent = "");
                th.querySelector(".arrow").textContent = sortState.dir > 0 ? "▲" : "▼";

                const attr = colToAttr[col] || col;
                const rows = Array.from(reportBody.querySelectorAll("tr"));
                rows.sort(function (a, b) {
                    let av = a.dataset[attr] || "";
                    let bv = b.dataset[attr] || "";
                    // numeric for the score columns
                    if (col === "anomaly_score" || col === "hybrid_score" || col === "cwe" ||
                        col === "severity" || col === "ml_prediction") {
                        av = parseFloat(av) || 0; bv = parseFloat(bv) || 0;
                    } else {
                        av = String(av).toLowerCase(); bv = String(bv).toLowerCase();
                    }
                    if (av < bv) return -1 * sortState.dir;
                    if (av > bv) return 1 * sortState.dir;
                    return 0;
                });
                rows.forEach(r => reportBody.appendChild(r));
                applyReportFilters();
            });
        });
    }

    // ---------- detail drawer ----------
    const drawer = document.getElementById("findingDrawer");
    const backdrop = document.getElementById("drawerBackdrop");
    const drawerTitle = document.getElementById("drawerTitle");
    const drawerSub = document.getElementById("drawerSub");
    const drawerBody = document.getElementById("drawerBody");
    const drawerClose = document.getElementById("drawerClose");

    function openDrawer(row) {
        let f = {};
        try { f = JSON.parse(row.dataset.finding || "{}"); } catch (e) { f = {}; }
        drawerTitle.textContent = f.alert_name || "Finding";
        drawerSub.textContent = f.finding_id ? (f.finding_id + " · " + (f.url || "")) : (f.url || "");

        const sev = f.severity || "Informational";
        const remediation = f.remediation || {};
        drawerBody.innerHTML = `
            <div class="drawer-section">
                <span class="badge ${f.sev || 'sev-unknown'}">${sev}</span>
                <span class="badge ${String(f.attack_type||'').toLowerCase().replace(/[^a-z]/g,'') || 'sev-unknown'}" style="margin-left:6px;">${f.attack_type || 'Other'}</span>
                <span class="chip" style="margin-left:6px;">${f.owasp || 'Uncategorized'}</span>
            </div>
            <div class="drawer-section">
                <h4>Endpoint</h4>
                <p class="mono small" style="word-break:break-all;">${f.url || '(unknown)'}</p>
                <div class="kv" style="margin-top:8px;">
                    <span class="k">Method</span><span class="v">${f.method || '—'}</span>
                    <span class="k">CWE</span><span class="v">${f.cwe || '0'}</span>
                    <span class="k">Scanner risk</span><span class="v">${f.scanner_risk || '—'}</span>
                    <span class="k">Scanner conf.</span><span class="v">${f.confidence || '—'}</span>
                    <span class="k">ML prediction</span><span class="v">${f.ml_prediction || '—'}</span>
                    <span class="k">Detection rule</span><span class="v">${f.detection_rule || 'None'}</span>
                    <span class="k">Correlation</span><span class="v">${f.correlation_id || 'None'}</span>
                </div>
            </div>
            <div class="drawer-section">
                <h4>Risk Calculation</h4>
                <div class="score-grid">
                    <div class="score-tile"><div class="k">Classifier conf.</div><div class="v">${(f.classifier_confidence || 0).toFixed(3)}</div></div>
                    <div class="score-tile"><div class="k">Anomaly score</div><div class="v">${(f.anomaly_score || 0).toFixed(3)}</div></div>
                    <div class="score-tile"><div class="k">Hybrid score</div><div class="v">${(f.hybrid_score || 0).toFixed(3)}</div></div>
                    <div class="score-tile"><div class="k">Final risk</div><div class="v">${sev}</div></div>
                </div>
                <p class="small muted" style="margin-top:8px;">hybrid = 0.6×classifier + 0.3×anomaly + 0.1×static (not a probability)</p>
            </div>
            <div class="drawer-section">
                <h4>Explanation</h4>
                <p>${f.explanation || 'Standard vulnerability pattern detected.'}</p>
            </div>
            <div class="drawer-section">
                <h4>Remediation</h4>
                <div class="kv">
                    <span class="k">Why it matters</span><span class="v">${(remediation.why_it_matters || '—')}</span>
                </div>
                <p style="margin-top:8px;"><strong>Impact:</strong> ${remediation.impact || '—'}</p>
                <p><strong>Fix:</strong></p>
                <ol>${(remediation.fix || 'Refer to OWASP guidelines.').split('\n').filter(s=>s.trim()).map(s=>`<li>${s.replace(/^\d+\)\s*/,'')}</li>`).join('')}</ol>
                <p class="small muted" style="margin-top:6px;"><strong>Best practice:</strong> ${remediation.best_practice || '—'}</p>
            </div>
        `;
        drawer.classList.add("open");
        backdrop.classList.add("open");
        document.body.style.overflow = "hidden";
    }
    function closeDrawer() {
        drawer.classList.remove("open");
        backdrop.classList.remove("open");
        document.body.style.overflow = "";
    }
    if (reportBody && drawer) {
        reportBody.addEventListener("click", function (e) {
            const row = e.target.closest("tr.report-row");
            if (row) openDrawer(row);
        });
    }
    if (drawerClose) drawerClose.addEventListener("click", closeDrawer);
    if (backdrop) backdrop.addEventListener("click", closeDrawer);
    document.addEventListener("keydown", function (e) {
        if (e.key === "Escape" && drawer && drawer.classList.contains("open")) closeDrawer();
    });

    // =====================================================
    // DETECTION RULE ROW -> scroll reports filtered by rule (lightweight)
    // =====================================================
    document.querySelectorAll(".rule-row[data-rule]").forEach(function (row) {
        row.addEventListener("click", function () {
            const ruleId = row.dataset.rule;
            // surface the rule description in an alert-free way: toggle a class
            row.classList.toggle("expanded");
            const existing = row.querySelector(".rule-detail");
            if (existing) { existing.remove(); return; }
            const detail = document.createElement("div");
            detail.className = "rule-desc rule-detail";
            const desc = row.querySelector(".rule-desc");
            detail.textContent = row.dataset.action || desc ? (desc ? desc.textContent + " — click again to collapse." : "") : "";
            const name = row.querySelector(".rule-name");
            if (name) {
                const d = document.createElement("div");
                d.className = "rule-desc";
                d.style.color = "var(--cyan)";
                d.style.marginTop = "6px";
                d.textContent = "See the Findings page — detection column shows " + ruleId + " on affected rows.";
                name.parentElement.appendChild(d);
                setTimeout(() => d.remove(), 3500);
            }
        });
    });

});

    // =====================================================
    // KPI COUNT-UP ANIMATION
    // =====================================================
    document.querySelectorAll(".kpi-count[data-count]").forEach(function (el) {
        var target = parseInt(el.getAttribute("data-count"), 10) || 0;
        if (target === 0) { el.textContent = "0"; return; }
        var start = 0, dur = 900, t0 = null;
        function tick(ts) {
            if (!t0) t0 = ts;
            var p = Math.min((ts - t0) / dur, 1);
            // easeOutCubic
            var eased = 1 - Math.pow(1 - p, 3);
            el.textContent = Math.round(start + (target - start) * eased).toString();
            if (p < 1) requestAnimationFrame(tick);
            else el.textContent = target.toString();
        }
        requestAnimationFrame(tick);
    });

    // =====================================================
    // ATTACK MATRIX CELL -> jump to filtered reports
    // =====================================================
    document.querySelectorAll(".matrix-cell[data-href]").forEach(function (cell) {
        cell.addEventListener("click", function () {
            window.location.href = cell.getAttribute("data-href");
        });
    });

    // =====================================================
    // STYLED TOOLTIP (replaces browser title for data-tip elements)
    // =====================================================
    var tip = document.getElementById("styledTip");
    if (tip) {
        function showTip(e, text) {
            tip.textContent = text;
            tip.classList.add("show");
            var r = e.target.getBoundingClientRect();
            var x = r.left + 10, y = r.bottom + 8;
            if (x + 340 > window.innerWidth) x = window.innerWidth - 350;
            tip.style.left = x + "px"; tip.style.top = y + "px";
        }
        function hideTip() { tip.classList.remove("show"); }
        document.addEventListener("mouseover", function (e) {
            var t = e.target.closest("[title]");
            if (!t) return;
            var txt = t.getAttribute("title");
            if (!txt) return;
            // hide the native title tooltip by stashing + clearing it
            t.dataset.tip = txt;
            showTip(e, txt);
        });
        document.addEventListener("mouseout", function (e) {
            var t = e.target.closest("[data-tip]");
            if (t && t.dataset.tip) { hideTip(); }
        });
    }

    // =====================================================
    // RE-RUN PIPELINE MODAL
    // =====================================================
    var rerunBtn = document.getElementById("rerunBtn");
    var rerunBackdrop = document.getElementById("rerunBackdrop");
    var rerunClose = document.getElementById("rerunClose");
    var rerunCancel = document.getElementById("rerunCancel");
    var rerunConfirm = document.getElementById("rerunConfirm");
    var rerunLog = document.getElementById("rerunLog");
    var rerunPoll = null;

    function openRerun() {
        if (!rerunBackdrop) return;
        rerunBackdrop.classList.add("open");
        // poll current status in case a run is already going
        pollRerun();
    }
    function closeRerun() {
        if (!rerunBackdrop) return;
        rerunBackdrop.classList.remove("open");
        if (rerunPoll) { clearInterval(rerunPoll); rerunPoll = null; }
    }
    function appendLine(text, cls) {
        if (!rerunLog) return;
        var line = document.createElement("div");
        line.className = "rerun-line " + (cls || "");
        var mark = document.createElement("span"); mark.className = "mark"; mark.textContent = "›";
        var txt = document.createElement("span"); txt.textContent = text;
        line.appendChild(mark); line.appendChild(txt);
        rerunLog.appendChild(line);
        rerunLog.scrollTop = rerunLog.scrollHeight;
    }
    function gatewayPort() {
        var m = window.location.search.match(/XTransformPort=(\d+)/);
        return m ? m[1] : null;
    }
    function withGateway(path) {
        var p = gatewayPort();
        return path + (p ? (path.indexOf("?") !== -1 ? "&" : "?") + "XTransformPort=" + p : "");
    }
    function pollRerun() {
        if (rerunPoll) clearInterval(rerunPoll);
        rerunPoll = setInterval(function () {
            fetch(withGateway("/api/rerun/status")).then(function (r) { return r.json(); }).then(function (d) {
                if (!d) return;
                if (rerunLog) rerunLog.innerHTML = "";
                (d.lines || []).forEach(function (l) {
                    var cls = "ok";
                    if (/\bFAILED|error|Traceback\b/i.test(l)) cls = "err";
                    else if (/^\[\d\/\d\]|====|PIPELINE COMPLETE/.test(l)) cls = "ok";
                    else if (/Running|Hybrid|Training|Spider/i.test(l)) cls = "active";
                    appendLine(l, cls);
                });
                if (!d.running) {
                    if (rerunPoll) { clearInterval(rerunPoll); rerunPoll = null; }
                    if (rerunConfirm) { rerunConfirm.disabled = false; rerunConfirm.textContent = "Run demo pipeline"; }
                    if (d.status === "ok") {
                        appendLine("✓ pipeline complete — reloading dashboard…", "done");
                        setTimeout(function () { window.location.href = withGateway("/"); }, 1200);
                    } else if (d.status === "error") {
                        appendLine("✗ pipeline failed — see log above", "err");
                    }
                } else {
                    if (rerunConfirm) { rerunConfirm.disabled = true; rerunConfirm.textContent = "Running…"; }
                }
            }).catch(function () {});
        }, 1200);
    }
    if (rerunBtn) rerunBtn.addEventListener("click", openRerun);
    if (rerunClose) rerunClose.addEventListener("click", closeRerun);
    if (rerunCancel) rerunCancel.addEventListener("click", closeRerun);
    if (rerunBackdrop) rerunBackdrop.addEventListener("click", function (e) { if (e.target === rerunBackdrop) closeRerun(); });
    if (rerunConfirm) rerunConfirm.addEventListener("click", function () {
        rerunConfirm.disabled = true; rerunConfirm.textContent = "Starting…";
        if (rerunLog) rerunLog.innerHTML = "";
        appendLine("starting demo pipeline…", "active");
        fetch(withGateway("/api/rerun"), { method: "POST" })
            .then(function (r) { return r.json(); })
            .then(function (d) {
                if (!d.ok) { appendLine("✗ " + (d.error || "could not start"), "err"); rerunConfirm.disabled = false; rerunConfirm.textContent = "Run demo pipeline"; return; }
                pollRerun();
            }).catch(function (e) {
                appendLine("✗ request failed: " + e, "err");
                rerunConfirm.disabled = false; rerunConfirm.textContent = "Run demo pipeline";
            });
    });

    // =====================================================
    // COMMAND PALETTE (Ctrl/Cmd+K)
    // =====================================================
    var cmdkTrigger = document.getElementById("cmdkTrigger");
    var cmdkBackdrop = document.getElementById("cmdkBackdrop");
    var cmdkInput = document.getElementById("cmdkInput");
    var cmdkList = document.getElementById("cmdkList");
    var cmdkActive = 0;

    function cmdkItems() {
        var qp = gatewayPort();
        var ap = qp ? "&XTransformPort=" + qp : "";
        var qpOnly = qp ? "?XTransformPort=" + qp : "";
        var items = [
            { label: "Command Center", hint: "dashboard", href: "/" + qpOnly, ico: "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2'><rect x='3' y='3' width='7' height='9'/><rect x='14' y='3' width='7' height='5'/><rect x='14' y='12' width='7' height='9'/><rect x='3' y='16' width='7' height='5'/></svg>" },
            { label: "ML Insights", hint: "model eval", href: "/ml-insights" + qpOnly, ico: "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2'><path d='M3 3v18h18'/><path d='M7 14l4-4 3 3 5-6'/></svg>" },
            { label: "Findings", hint: "all findings", href: "/reports" + qpOnly, ico: "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2'><path d='M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z'/><path d='M14 2v6h6'/></svg>" },
            { label: "Critical findings", hint: "severity", href: "/reports?severity=Critical" + ap, ico: "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2'><path d='M12 2 L20 5 V11 C20 16.5 16.7 20.6 12 22 C7.3 20.6 4 16.5 4 11 V5 Z'/></svg>" },
            { label: "High findings", hint: "severity", href: "/reports?severity=High" + ap, ico: "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2'><path d='M12 2 L20 5 V11 C20 16.5 16.7 20.6 12 22 C7.3 20.6 4 16.5 4 11 V5 Z'/></svg>" },
            { label: "SQL Injection findings", hint: "attack", href: "/reports?attack=SQL+Injection" + ap, ico: "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2'><ellipse cx='12' cy='6' rx='8' ry='3'/><path d='M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6'/></svg>" },
        ];
        // add detection rules from the page payload
        var payload = document.getElementById("cmdk-data");
        if (payload) {
            try {
                var d = JSON.parse(payload.textContent);
                (d.rules || []).forEach(function (r) {
                    items.push({
                        label: r.name + " (" + r.rule_id + ")",
                        hint: "detection · " + r.severity,
                        href: r.href,
                        ico: "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2'><path d='M9 11l3 3 8-8'/><path d='M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11'/></svg>",
                    });
                });
            } catch (e) {}
        }
        // top vulnerable endpoints
        document.querySelectorAll(".url-item").forEach(function (li) {
            var url = li.getAttribute("title") || li.querySelector(".url-path") && li.querySelector(".url-path").getAttribute("title");
            if (url) items.push({
                label: "Endpoint: " + (li.querySelector(".url-path") ? li.querySelector(".url-path").textContent : url),
                hint: "top vulnerable",
                href: "#",
                ico: "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2'><path d='M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1'/><path d='M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1'/></svg>",
            });
        });
        return items;
    }

    function renderCmdk(q) {
        if (!cmdkList) return;
        var items = cmdkItems();
        q = (q || "").toLowerCase().trim();
        var filtered = !q ? items : items.filter(function (it) {
            return (it.label + " " + it.hint).toLowerCase().indexOf(q) !== -1;
        });
        cmdkActive = 0;
        cmdkList.innerHTML = "";
        if (!filtered.length) {
            var empty = document.createElement("li");
            empty.className = "cmdk-empty";
            empty.textContent = "No matches";
            cmdkList.appendChild(empty);
            return;
        }
        filtered.slice(0, 8).forEach(function (it, i) {
            var li = document.createElement("li");
            li.className = "cmdk-item" + (i === 0 ? " active" : "");
            li.innerHTML = '<span class="cm-ico">' + it.ico + '</span>' +
                '<span class="cm-label">' + it.label + '</span>' +
                '<span class="cm-hint">' + it.hint + '</span>';
            li.addEventListener("click", function () { if (it.href && it.href !== "#") window.location.href = it.href; closeCmdk(); });
            li.addEventListener("mouseenter", function () {
                cmdkActive = i;
                Array.prototype.forEach.call(cmdkList.querySelectorAll(".cmdk-item"), function (el, idx) {
                    el.classList.toggle("active", idx === cmdkActive);
                });
            });
            cmdkList.appendChild(li);
        });
        cmdkList._items = filtered;
    }
    function openCmdk() {
        if (!cmdkBackdrop) return;
        cmdkBackdrop.classList.add("open");
        if (cmdkInput) { cmdkInput.value = ""; setTimeout(function () { cmdkInput.focus(); }, 50); }
        renderCmdk("");
    }
    function closeCmdk() {
        if (!cmdkBackdrop) return;
        cmdkBackdrop.classList.remove("open");
    }
    if (cmdkTrigger) cmdkTrigger.addEventListener("click", openCmdk);
    if (cmdkBackdrop) cmdkBackdrop.addEventListener("click", function (e) { if (e.target === cmdkBackdrop) closeCmdk(); });
    if (cmdkInput) {
        cmdkInput.addEventListener("input", function () { renderCmdk(cmdkInput.value); });
    }
    // global Ctrl/Cmd+K + Esc handling
    document.addEventListener("keydown", function (e) {
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
            e.preventDefault();
            if (cmdkBackdrop && cmdkBackdrop.classList.contains("open")) closeCmdk(); else openCmdk();
            return;
        }
        if (e.key === "Escape") {
            if (cmdkBackdrop && cmdkBackdrop.classList.contains("open")) { closeCmdk(); return; }
            if (rerunBackdrop && rerunBackdrop.classList.contains("open")) { closeRerun(); return; }
        }
        if (cmdkBackdrop && cmdkBackdrop.classList.contains("open")) {
            var items = cmdkList && cmdkList._items || [];
            if (e.key === "ArrowDown") {
                e.preventDefault();
                cmdkActive = Math.min(cmdkActive + 1, items.length - 1);
                updateCmdkActive();
            } else if (e.key === "ArrowUp") {
                e.preventDefault();
                cmdkActive = Math.max(cmdkActive - 1, 0);
                updateCmdkActive();
            } else if (e.key === "Enter") {
                e.preventDefault();
                var it = items[cmdkActive];
                if (it && it.href && it.href !== "#") window.location.href = it.href;
                closeCmdk();
            }
        }
    });
    function updateCmdkActive() {
        if (!cmdkList) return;
        Array.prototype.forEach.call(cmdkList.querySelectorAll(".cmdk-item"), function (el, idx) {
            el.classList.toggle("active", idx === cmdkActive);
        });
    }
