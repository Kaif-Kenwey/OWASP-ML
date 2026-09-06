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

    // ---------- Value-labels plugin (shows the number at the end of each bar) ----------
    // Registered once globally so every horizontal bar chart gets data labels.
    const valueLabelsPlugin = {
        id: "owaspValueLabels",
        afterDatasetsDraw: function (chart) {
            var ds = chart.data.datasets;
            if (!ds || !ds.length) return;
            var ctx = chart.ctx;
            var meta = chart.getDatasetMeta(0);
            ctx.save();
            ctx.font = "600 10px 'JetBrains Mono', monospace";
            ctx.fillStyle = "#e2e8f0";
            ctx.textAlign = chart.config.options.indexAxis === "y" ? "left" : "center";
            ctx.textBaseline = "middle";
            meta.data.forEach(function (el, i) {
                var v = ds[0].data[i];
                if (v === undefined || v === null || v === 0) return;
                var pos = el.tooltipPosition();
                var x = chart.config.options.indexAxis === "y" ? pos.x + 6 : pos.x;
                var y = pos.y;
                ctx.fillText(String(v), x, y);
            });
            ctx.restore();
        }
    };
    if (window.Chart && !Chart.registry.plugins.get("owaspValueLabels")) {
        Chart.register(valueLabelsPlugin);
    }

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

    // ---------- Dashboard: risk doughnut (clickable -> reports?severity=) ----------
    const riskCanvas = document.getElementById("riskChart");
    if (riskCanvas && data.risk) {
        // wrap the canvas in a relative div so we can overlay a center label
        var riskWrap = document.createElement("div");
        riskWrap.className = "donut-wrap-rel";
        riskWrap.style.cssText = "position:relative;flex:1;min-height:260px;";
        riskCanvas.parentNode.insertBefore(riskWrap, riskCanvas);
        riskWrap.appendChild(riskCanvas);
        var riskCenter = document.createElement("div");
        riskCenter.className = "donut-center";
        var riskTotal = data.risk.values.reduce(function (a, b) { return a + b; }, 0);
        riskCenter.innerHTML = '<span class="dc-num">' + riskTotal + '</span><span class="dc-lbl">findings</span>';
        riskWrap.appendChild(riskCenter);

        var riskChart = new Chart(riskCanvas, {
            type: "doughnut",
            data: {
                labels: data.risk.labels,
                datasets: [{
                    data: data.risk.values,
                    backgroundColor: data.risk.labels.map(l => SEV_COLORS[l] || "#64748b"),
                    borderColor: "#0D1321",
                    borderWidth: 3,
                    hoverOffset: 8
                }]
            },
            options: {
                responsive: true, maintainAspectRatio: false, cutout: "62%",
                plugins: {
                    legend: { position: "bottom", labels: { color: "#94a3b8", font: { family: "'JetBrains Mono', monospace", size: 11 }, padding: 12, usePointStyle: true, pointStyle: "rectRounded" } },
                    tooltip: {
                        backgroundColor: "#0D1321", titleColor: "#e2e8f0", bodyColor: "#94a3b8",
                        borderColor: "rgba(34,211,238,0.25)", borderWidth: 1, padding: 10, cornerRadius: 8,
                        callbacks: {
                            label: function (ctx) {
                                var v = ctx.parsed, pct = riskTotal ? (100 * v / riskTotal).toFixed(1) : 0;
                                return " " + ctx.label + ": " + v + " (" + pct + "%)";
                            }
                        }
                    }
                },
                onClick: function (evt, items) {
                    if (!items.length) return;
                    var label = data.risk.labels[items[0].index];
                    if (label) {
                        var port = (window.location.search.match(/XTransformPort=(\d+)/) || [])[1];
                        var ap = port ? "&XTransformPort=" + port : "";
                        window.location.href = "/reports?severity=" + encodeURIComponent(label) + ap;
                    }
                },
                onHover: function (evt, items) {
                    riskCanvas.style.cursor = items.length ? "pointer" : "default";
                }
            }
        });
    }

    // ---------- Dashboard: top attack types (full labels in tooltip) ----------
    const attackCanvas = document.getElementById("attackChart");
    if (attackCanvas && data.attack) {
        var attackFull = data.attack.full_labels || data.attack.labels;
        new Chart(attackCanvas, {
            type: "bar",
            data: { labels: data.attack.labels, datasets: [{ data: data.attack.values, backgroundColor: CYAN, borderRadius: 5 }] },
            options: Object.assign({}, baseBarOptions(true), {
                plugins: Object.assign({}, baseBarOptions(true).plugins, {
                    tooltip: Object.assign({}, (baseBarOptions(true).plugins || {}).tooltip || {}, {
                        callbacks: { title: function (ctx) { return attackFull[ctx[0].dataIndex] || ctx[0].label; } }
                    })
                })
            })
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
        // notify the pagination module (outside this closure) that filters changed
        document.dispatchEvent(new CustomEvent("reportFiltersChanged", { detail: { visible: visible } }));
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

    // ---------- sortable columns (with localStorage persistence) ----------
    const table = document.getElementById("reportTable");
    if (table) {
        const headers = table.querySelectorAll("th.sortable");
        // restore persisted sort
        let savedSort = null;
        try { savedSort = JSON.parse(localStorage.getItem("owasp_ml_sort") || "null"); } catch (e) {}
        let sortState = savedSort || { col: null, dir: 1 };
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
        function persistSort() {
            try { localStorage.setItem("owasp_ml_sort", JSON.stringify(sortState)); } catch (e) {}
        }
        function runSort(col, dir) {
            sortState.col = col; sortState.dir = dir;
            headers.forEach(function (h) {
                var a = h.querySelector(".arrow"); if (a) a.textContent = "";
            });
            var activeTh = Array.prototype.find.call(headers, function (h) { return h.dataset.sort === col; });
            if (activeTh) {
                var a = activeTh.querySelector(".arrow");
                if (a) a.textContent = dir > 0 ? "▲" : "▼";
            }
            const attr = colToAttr[col] || col;
            const rows = Array.from(reportBody.querySelectorAll("tr"));
            rows.sort(function (a, b) {
                let av = a.dataset[attr] || "";
                let bv = b.dataset[attr] || "";
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
            persistSort();
        }
        // restore visual indicator on load
        if (savedSort && savedSort.col) {
            var a = Array.prototype.find.call(headers, function (h) { return h.dataset.sort === savedSort.col; });
            if (a) { var arr = a.querySelector(".arrow"); if (arr) arr.textContent = savedSort.dir > 0 ? "▲" : "▼"; }
        }
        headers.forEach(function (th) {
            th.addEventListener("click", function () {
                const col = th.dataset.sort;
                if (sortState.col === col) sortState.dir = -sortState.dir;
                else { sortState.col = col; sortState.dir = 1; }
                runSort(sortState.col, sortState.dir);
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
        // expose for the inline 'view' action button (delegated click handler)
        window._openFindingDrawer = openDrawer;
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
        var cntEl = document.getElementById("cmdkCount");
        if (cntEl) cntEl.textContent = Math.min(filtered.length, 8) + (filtered.length > 8 ? "+" : "");
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

    // =====================================================
    // REPORTS: COLUMN TOGGLE DROPDOWN
    // =====================================================
    var colToggleBtn = document.getElementById("colToggleBtn");
    var colToggleMenu = document.getElementById("colToggleMenu");
    if (colToggleBtn && colToggleMenu) {
        colToggleBtn.addEventListener("click", function (e) {
            e.stopPropagation();
            colToggleMenu.classList.toggle("open");
            colToggleMenu.setAttribute("aria-hidden", colToggleMenu.classList.contains("open") ? "false" : "true");
        });
        document.addEventListener("click", function (e) {
            if (!colToggleMenu.contains(e.target) && e.target !== colToggleBtn) {
                colToggleMenu.classList.remove("open");
                colToggleMenu.setAttribute("aria-hidden", "true");
            }
        });
        colToggleMenu.querySelectorAll("input[data-col]").forEach(function (cb) {
            cb.addEventListener("change", function () {
                var col = cb.getAttribute("data-col");
                var hidden = !cb.checked;
                document.querySelectorAll(".col-" + col).forEach(function (cell) {
                    cell.classList.toggle("col-hidden", hidden);
                });
            });
        });
    }

    // =====================================================
    // REPORTS: PAGINATION
    // =====================================================
    // Pagination state. visibleRows() returns the currently-filtered + sorted
    // rows (those with display!=='none'). The page size + current page drive
    // which rows are shown; rows outside the current page get display:none.
    var pageSizeSel = document.getElementById("pageSize");
    var pageFirst = document.getElementById("pageFirst");
    var pagePrev = document.getElementById("pagePrev");
    var pageNext = document.getElementById("pageNext");
    var pageLast = document.getElementById("pageLast");
    var pageNumEl = document.getElementById("pageNum");
    var pageInfoEl = document.getElementById("pageInfo");
    var currentPage = 1;
    var pageSize = 50;

    function _visibleReportRows() {
        var rb = document.getElementById("reportBody");
        if (!rb) return [];
        return Array.prototype.filter.call(rb.querySelectorAll("tr"), function (r) {
            return r.style.display !== "none";
        });
    }
    function applyPagination() {
        var rb = document.getElementById("reportBody");
        var vis = Array.prototype.filter.call(rb ? rb.querySelectorAll("tr") : [], function (r) {
            return r.dataset._filterShow === "true";
        });
        var total = vis.length;
        var size = pageSize;
        var pages = Math.max(1, Math.ceil(total / size));
        if (currentPage > pages) currentPage = pages;
        if (currentPage < 1) currentPage = 1;
        var start = (currentPage - 1) * size;
        vis.forEach(function (row, i) {
            // keep the search/filter visibility (already set), only override
            // for pagination hide
            var inPage = (i >= start && i < start + size);
            // row.style.display was set by applyReportFilters to "" or "none"
            // we re-derive: if filter hid it, keep hidden; else page-hide
            // we stored filter visibility in dataset._filterShow
            var filterShow = row.dataset._filterShow !== "false";
            row.style.display = (filterShow && inPage) ? "" : "none";
        });
        if (pageNumEl) pageNumEl.textContent = currentPage;
        if (pageInfoEl) pageInfoEl.textContent = "page " + currentPage + " of " + pages + " · " + total + " rows";
        if (pageFirst) pageFirst.disabled = currentPage <= 1;
        if (pagePrev) pagePrev.disabled = currentPage <= 1;
        if (pageNext) pageNext.disabled = currentPage >= pages;
        if (pageLast) pageLast.disabled = currentPage >= pages;
    }
    if (pageSizeSel) {
        pageSizeSel.addEventListener("change", function () {
            pageSize = parseInt(pageSizeSel.value, 10) || 50;
            currentPage = 1;
            applyPagination();
        });
    }
    [pageFirst, pagePrev, pageNext, pageLast].forEach(function (btn) {
        if (!btn) return;
        btn.addEventListener("click", function () {
            if (btn === pageFirst) currentPage = 1;
            else if (btn === pagePrev) currentPage = Math.max(1, currentPage - 1);
            else if (btn === pageNext) currentPage = currentPage + 1;
            else if (btn === pageLast) {
                var vis = _visibleReportRows().length;
                currentPage = Math.max(1, Math.ceil(vis / pageSize));
            }
            applyPagination();
        });
    });

    // hook pagination into the filter pipeline via a custom event dispatched by
    // applyReportFilters (which lives in the DOMContentLoaded closure above).
    // This avoids the fragile function-wrapper that broke when this code ran
    // outside DOMContentLoaded and couldn't see the closure variable.
    document.addEventListener("reportFiltersChanged", function () {
        var rb = document.getElementById("reportBody");
        if (rb) {
            rb.querySelectorAll("tr").forEach(function (r) {
                r.dataset._filterShow = (r.style.display !== "none") ? "true" : "false";
            });
        }
        currentPage = 1;
        applyPagination();
    });

    // =====================================================
    // REPORTS: EXPORT FILTERED CSV
    // =====================================================
    var exportFilteredBtn = document.getElementById("exportFilteredBtn");
    if (exportFilteredBtn) {
        exportFilteredBtn.addEventListener("click", function () {
            // collect the finding JSON from each currently-visible (filter+page) row
            var rows = [];
            // Use the filter-visible rows (not just the current page) so the
            // export respects the active filters but ignores pagination.
            var rb = document.getElementById("reportBody");
            if (rb) {
                rb.querySelectorAll("tr").forEach(function (r) {
                    if (r.dataset._filterShow === "true" && r.dataset.finding) {
                        try { rows.push(JSON.parse(r.dataset.finding)); } catch (e) {}
                    }
                });
            }
            if (!rows.length) {
                alert("No visible rows to export. Adjust your filters and try again.");
                return;
            }
            // build a CSV from the finding dicts (stable column order)
            var cols = ["finding_id", "severity", "scanner_risk", "ml_prediction",
                        "classifier_confidence", "anomaly_score", "hybrid_score",
                        "attack_type", "owasp", "cwe", "method", "path", "url",
                        "alert_name", "confidence", "detection_rule", "correlation_id",
                        "explanation"];
            var esc = function (v) {
                v = (v === null || v === undefined) ? "" : String(v);
                if (/[",\n]/.test(v)) v = '"' + v.replace(/"/g, '""') + '"';
                return v;
            };
            var lines = [cols.join(",")];
            rows.forEach(function (r) {
                lines.push(cols.map(function (c) {
                    if (c === "path") return esc(r["path"]);
                    return esc(r[c]);
                }).join(","));
            });
            var csv = lines.join("\n");
            var blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
            var url = URL.createObjectURL(blob);
            var a = document.createElement("a");
            a.href = url;
            a.download = "owasp_ml_findings_filtered_" + rows.length + "rows.csv";
            document.body.appendChild(a); a.click(); document.body.removeChild(a);
            setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
        });
    }

    // =====================================================
    // ML INSIGHTS: CROSS-TARGET BAR CHART
    // =====================================================
    var crossTargetCanvas = document.getElementById("crossTargetChart");
    var crossTargetPayload = document.getElementById("cross-target-data");
    if (crossTargetCanvas && crossTargetPayload && window.Chart) {
        try {
            var ct = JSON.parse(crossTargetPayload.textContent);
            var folds = (ct.folds || []).filter(function (f) { return f.accuracy !== null; });
            if (folds.length) {
                new Chart(crossTargetCanvas, {
                    type: "bar",
                    data: {
                        labels: folds.map(function (f) { return f.host.length > 18 ? f.host.slice(0, 16) + "…" : f.host; }),
                        datasets: [
                            { label: "Accuracy", data: folds.map(function (f) { return f.accuracy; }), backgroundColor: "#22d3ee", borderRadius: 4 },
                            { label: "Weighted F1", data: folds.map(function (f) { return f.weighted_f1; }), backgroundColor: "#34d399", borderRadius: 4 },
                            { label: "Macro F1", data: folds.map(function (f) { return f.macro_f1; }), backgroundColor: "#f59e0b", borderRadius: 4 }
                        ]
                    },
                    options: {
                        responsive: true, maintainAspectRatio: false,
                        plugins: {
                            legend: { position: "bottom", labels: { color: "#94a3b8", font: { family: "'JetBrains Mono', monospace", size: 10 }, usePointStyle: true, boxWidth: 8 } },
                            tooltip: { backgroundColor: "#0D1321", titleColor: "#e2e8f0", bodyColor: "#94a3b8", borderColor: "rgba(34,211,238,0.25)", borderWidth: 1, padding: 10, cornerRadius: 8 }
                        },
                        scales: {
                            x: { grid: { color: "rgba(148,163,184,0.08)" }, ticks: { color: "#64748b", font: { family: "'JetBrains Mono', monospace", size: 10 } } },
                            y: { beginAtZero: true, max: 1.0, grid: { color: "rgba(148,163,184,0.08)" }, ticks: { color: "#64748b", font: { family: "'JetBrains Mono', monospace", size: 10 }, callback: function (v) { return v.toFixed(2); } } }
                        }
                    }
                });
            }
        } catch (e) { console.warn("cross-target chart failed", e); }
    }

    // =====================================================
    // DASHBOARD: ATTACK-SURFACE HOST DONUT
    // =====================================================
    var hostDonut = document.getElementById("hostDonut");
    if (hostDonut && data.host_donut && window.Chart) {
        var hd = data.host_donut;
        var palette = ["#22d3ee", "#34d399", "#f59e0b", "#f43f5e", "#a78bfa", "#94a3b8", "#475569"];
        new Chart(hostDonut, {
            type: "doughnut",
            data: {
                labels: hd.labels,
                datasets: [{
                    data: hd.values,
                    backgroundColor: hd.labels.map(function (_, i) { return palette[i % palette.length]; }),
                    borderColor: "#0D1321", borderWidth: 3, hoverOffset: 6
                }]
            },
            options: {
                responsive: true, maintainAspectRatio: false, cutout: "62%",
                plugins: {
                    legend: { position: "right", labels: { color: "#94a3b8", font: { family: "'JetBrains Mono', monospace", size: 9.5 }, boxWidth: 8, padding: 6, usePointStyle: true } },
                    tooltip: { backgroundColor: "#0D1321", titleColor: "#e2e8f0", bodyColor: "#94a3b8", borderColor: "rgba(34,211,238,0.25)", borderWidth: 1, padding: 9, cornerRadius: 7,
                        callbacks: { label: function (ctx) { return " " + ctx.label + ": " + ctx.parsed + " findings"; } } }
                }
            }
        });
    }

    // =====================================================
    // REPORTS: FILTER CHIPS (active filters as removable pills)
    // =====================================================
    var filterChipsEl = document.getElementById("filterChips");
    function renderFilterChips() {
        if (!filterChipsEl) return;
        var chips = [];
        var sb = document.getElementById("reportSearch");
        var sf = document.getElementById("filterSeverity");
        var af = document.getElementById("filterAttack");
        var of = document.getElementById("filterOwasp");
        if (sb && sb.value.trim()) chips.push({ k: "search", v: sb.value.trim(), clear: function () { sb.value = ""; } });
        if (sf && sf.value) chips.push({ k: "severity", v: sf.value, clear: function () { sf.value = ""; } });
        if (af && af.value) chips.push({ k: "attack", v: af.value, clear: function () { af.value = ""; } });
        if (of && of.value) chips.push({ k: "owasp", v: of.value, clear: function () { of.value = ""; } });
        filterChipsEl.innerHTML = "";
        if (!chips.length) return;
        chips.forEach(function (c) {
            var chip = document.createElement("span");
            chip.className = "fchip";
            chip.innerHTML = '<span class="fchip-k">' + c.k + '</span><span class="fchip-v">' + c.v + '</span><button class="fchip-x" aria-label="remove ' + c.k + ' filter">×</button>';
            chip.querySelector(".fchip-x").addEventListener("click", function () {
                c.clear();
                // trigger the filter
                if (c.k === "search" && sb) sb.dispatchEvent(new Event("input"));
                else if (sf) sf.dispatchEvent(new Event("change"));
                if (af) af.dispatchEvent(new Event("change"));
                if (of) of.dispatchEvent(new Event("change"));
            });
            filterChipsEl.appendChild(chip);
        });
    }
    // re-render chips whenever filters change
    document.addEventListener("reportFiltersChanged", renderFilterChips);
    // also render once on load
    renderFilterChips();

    // =====================================================
    // REPORTS: COLUMN-TOGGLE localStorage PERSISTENCE
    // =====================================================
    var COL_STORE_KEY = "owasp_ml_report_cols";
    function loadColState() {
        try {
            var s = localStorage.getItem(COL_STORE_KEY);
            return s ? JSON.parse(s) : null;
        } catch (e) { return null; }
    }
    function saveColState(state) {
        try { localStorage.setItem(COL_STORE_KEY, JSON.stringify(state)); } catch (e) {}
    }
    var colMenu = document.getElementById("colToggleMenu");
    if (colMenu) {
        var saved = loadColState();
        if (saved) {
            colMenu.querySelectorAll("input[data-col]").forEach(function (cb) {
                var col = cb.getAttribute("data-col");
                if (saved[col] === false) {
                    cb.checked = false;
                    document.querySelectorAll(".col-" + col).forEach(function (cell) {
                        cell.classList.add("col-hidden");
                    });
                }
            });
        }
        // override the earlier change handler with one that also persists
        colMenu.querySelectorAll("input[data-col]").forEach(function (cb) {
            cb.addEventListener("change", function () {
                var col = cb.getAttribute("data-col");
                var hidden = !cb.checked;
                document.querySelectorAll(".col-" + col).forEach(function (cell) {
                    cell.classList.toggle("col-hidden", hidden);
                });
                // persist
                var st = loadColState() || {};
                st[col] = cb.checked;
                saveColState(st);
            });
        });
    }

    // =====================================================
    // ML INSIGHTS: CONFUSION MATRIX CELL CLICK -> drill-down
    // =====================================================
    // Cells carry data-actual / data-predicted. Clicking a cell jumps to
    // /reports and (visually) the user can verify the misclassifications.
    // We can't filter by both actual+predicted in the reports UI yet, so
    // we jump to the predicted-severity filter + a search hint.
    document.querySelectorAll(".cm-cell[data-actual]").forEach(function (cell) {
        cell.style.cursor = "pointer";
        cell.title = "click to inspect findings predicted as " + cell.dataset.predicted;
        cell.addEventListener("click", function () {
            var pred = cell.dataset.predicted;
            var port = (window.location.search.match(/XTransformPort=(\d+)/) || [])[1];
            var ap = port ? "&XTransformPort=" + port : "";
            window.location.href = "/reports?severity=" + encodeURIComponent(pred) + ap;
        });
    });

    // =====================================================
    // REPORTS: SUMMARY STATS + DENSITY TOGGLE + JSON EXPORT
    // =====================================================
    function updateReportSummary() {
        var rb = document.getElementById("reportBody");
        if (!rb) return;
        var rows = Array.prototype.filter.call(rb.querySelectorAll("tr"), function (r) {
            return r.dataset._filterShow === "true";
        });
        var sev = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
        var scoreSum = 0, scoreN = 0;
        rows.forEach(function (r) {
            var s = r.dataset.severity;
            if (sev.hasOwnProperty(s)) sev[s]++;
            var f = r.dataset.finding;
            if (f) {
                try {
                    var d = JSON.parse(f);
                    var sc = parseFloat(d.hybrid_score);
                    if (!isNaN(sc)) { scoreSum += sc; scoreN++; }
                } catch (e) {}
            }
        });
        var set = function (id, val) { var el = document.getElementById(id); if (el) el.textContent = val; };
        set("rsCrit", sev.Critical); set("rsHigh", sev.High); set("rsMed", sev.Medium);
        set("rsLow", sev.Low); set("rsInfo", sev.Informational);
        set("rsTotal", rows.length);
        set("rsAvg", scoreN ? (scoreSum / scoreN).toFixed(2) : "0.00");
    }
    document.addEventListener("reportFiltersChanged", updateReportSummary);
    updateReportSummary();

    // density toggle
    var densComfort = document.getElementById("densComfort");
    var densCompact = document.getElementById("densCompact");
    var reportTableEl = document.getElementById("reportTable");
    function setDensity(compact) {
        if (!reportTableEl) return;
        reportTableEl.classList.toggle("compact", compact);
        if (densComfort) densComfort.classList.toggle("active", !compact);
        if (densCompact) densCompact.classList.toggle("active", compact);
        try { localStorage.setItem("owasp_ml_density", compact ? "compact" : "comfort"); } catch (e) {}
    }
    if (densComfort) densComfort.addEventListener("click", function () { setDensity(false); });
    if (densCompact) densCompact.addEventListener("click", function () { setDensity(true); });
    // restore persisted density
    try {
        var savedDens = localStorage.getItem("owasp_ml_density");
        if (savedDens === "compact") setDensity(true);
    } catch (e) {}

    // JSON export (filtered)
    var exportJsonBtn = document.getElementById("exportJsonBtn");
    if (exportJsonBtn) {
        exportJsonBtn.addEventListener("click", function () {
            var rb = document.getElementById("reportBody");
            if (!rb) return;
            var rows = [];
            rb.querySelectorAll("tr").forEach(function (r) {
                if (r.dataset._filterShow === "true" && r.dataset.finding) {
                    try { rows.push(JSON.parse(r.dataset.finding)); } catch (e) {}
                }
            });
            if (!rows.length) { alert("No visible rows to export."); return; }
            var blob = new Blob([JSON.stringify(rows, null, 2)], { type: "application/json;charset=utf-8" });
            var url = URL.createObjectURL(blob);
            var a = document.createElement("a");
            a.href = url; a.download = "owasp_ml_findings_" + rows.length + "rows.json";
            document.body.appendChild(a); a.click(); document.body.removeChild(a);
            setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
        });
    }

    // =====================================================
    // DASHBOARD: URL-DECODE TOP-VULNERABLE-ENDPOINTS PATHS
    // The visible textContent is the path+query (percent-encoded by ZAP).
    // Decode it for readability; leave the title (tooltip) as the full raw
    // URL so copy-paste stays accurate.
    // Uses requestAnimationFrame + a micro-delay because the dashboard is
    // reached through a gateway redirect and the URL list can render a
    // tick after the script first runs.
    function decodeUrlPaths() {
        document.querySelectorAll(".url-path").forEach(function (el) {
            var raw = el.textContent;
            if (!raw || raw === "(unknown)") return;
            if (el.dataset.decoded === "1") return;  // idempotent
            try {
                var decoded = decodeURIComponent(raw);
                if (decoded !== raw) { el.textContent = decoded; el.dataset.decoded = "1"; }
            } catch (e) { /* leave as-is if malformed */ }
        });
    }
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", function () { requestAnimationFrame(decodeUrlPaths); });
    } else {
        requestAnimationFrame(function () { setTimeout(decodeUrlPaths, 50); });
    }

    // =====================================================
    // DASHBOARD: RISK DONUT LEGEND CLICK-TO-FILTER
    // =====================================================
    // Chart.js legend items get a click handler that jumps to reports?severity=
    // (extends the donut-segment click added earlier)
    setTimeout(function () {
        document.querySelectorAll("#riskChart").forEach(function (canvas) {
            var inst = Chart.getChart(canvas);
            if (!inst || !inst.legend) return;
            inst.options.plugins.legend.onClick = function (e, legendItem, legend) {
                var label = legendItem.text;
                var port = (window.location.search.match(/XTransformPort=(\d+)/) || [])[1];
                var ap = port ? "&XTransformPort=" + port : "";
                window.location.href = "/reports?severity=" + encodeURIComponent(label) + ap;
            };
            inst.update();
        });
    }, 200);

    // =====================================================
    // REPORTS: GROUP-BY SELECTOR
    // =====================================================
    // Groups the table rows by the selected dimension. Inserts a sticky
    // group-header row before each group's rows, with a count + collapse toggle.
    // Grouping is applied AFTER filtering + sorting, and re-applies pagination.
    var groupBySel = document.getElementById("groupBy");
    function applyGroupBy() {
        var rb = document.getElementById("reportBody");
        if (!rb) return;
        var dim = groupBySel ? groupBySel.value : "";
        // remove old group headers
        rb.querySelectorAll("tr.group-header").forEach(function (r) { r.remove(); });
        if (!dim) { return; }
        // map dim -> the row attribute to group by
        var attr = { severity: "severity", attack: "attack", owasp: "owasp",
                     method: "method", detection: "detectionRule" }[dim];
        if (!attr) return;
        // collect rows in current DOM order (already sorted)
        var rows = Array.prototype.slice.call(rb.querySelectorAll("tr.report-row"));
        var groups = {};
        var groupOrder = [];
        rows.forEach(function (r) {
            var key = r.dataset[attr] || r.dataset[dim] || "(none)";
            if (dim === "detection") {
                key = r.dataset.finding ? (function () {
                    try { return JSON.parse(r.dataset.finding).detection_rule || "—"; } catch (e) { return "—"; }
                })() : "—";
            }
            if (!groups[key]) { groups[key] = []; groupOrder.push(key); }
            groups[key].push(r);
        });
        // re-insert: for each group, add a header row + its members
        groupOrder.forEach(function (key) {
            var members = groups[key];
            var header = document.createElement("tr");
            header.className = "group-header";
            header.innerHTML = '<td colspan="12">' + key + '<span class="gh-count">' + members.length + '</span>' +
                '<span class="gh-toggle" title="collapse group">▼</span></td>';
            var collapsed = false;
            header.querySelector(".gh-toggle").addEventListener("click", function (e) {
                e.stopPropagation();
                collapsed = !collapsed;
                members.forEach(function (m) { m.style.display = collapsed ? "none" : ""; });
                header.querySelector(".gh-toggle").textContent = collapsed ? "▶" : "▼";
            });
            rb.insertBefore(header, members[0]);
        });
    }
    if (groupBySel) {
        groupBySel.addEventListener("change", function () {
            applyGroupBy();
            // re-mark filter visibility + re-paginate
            document.dispatchEvent(new CustomEvent("reportFiltersChanged"));
        });
        // restore persisted group-by
        try {
            var savedGb = localStorage.getItem("owasp_ml_groupby");
            if (savedGb && groupBySel.querySelector('option[value="' + savedGb + '"]')) {
                groupBySel.value = savedGb;
            }
        } catch (e) {}
        groupBySel.addEventListener("change", function () {
            try { localStorage.setItem("owasp_ml_groupby", groupBySel.value); } catch (e) {}
        });
    }
    // re-apply grouping after sorting (sort reorders rows)
    document.addEventListener("reportFiltersChanged", function () {
        // grouping survives filtering (rows just get hidden), but sorting reorders
        // so we re-group after a sort. The sort handler calls applyReportFilters ->
        // dispatches this event. Re-apply only if a group dim is selected.
        if (groupBySel && groupBySel.value) {
            // defer so the sort's row reordering completes first
            setTimeout(applyGroupBy, 0);
        }
    });

    // =====================================================
    // REPORTS: INLINE 'VIEW' ACTION BUTTON
    // =====================================================
    // Delegate clicks so it works after re-ordering / grouping.
    document.addEventListener("click", function (e) {
        var btn = e.target.closest(".row-action[data-finding-id]");
        if (!btn) return;
        e.stopPropagation();
        // find the parent row + open its drawer
        var row = btn.closest("tr.report-row");
        if (row && row.dataset.finding) {
            // trigger the same drawer-open logic the row click uses
            var evt = new MouseEvent("click", { bubbles: true });
            // the row click handler reads data-finding; simulate it
            var drawer = document.getElementById("findingDrawer");
            if (drawer && typeof window._openFindingDrawer === "function") {
                window._openFindingDrawer(row);
            } else {
                row.dispatchEvent(evt);
            }
        }
    });

    // =====================================================
    // ML INSIGHTS: PER-CLASS TABLE SORTABLE
    // =====================================================
    var classPerfTable = document.getElementById("classPerfTable");
    if (classPerfTable) {
        var cpHeaders = classPerfTable.querySelectorAll("th.sortable");
        var cpSortState = { col: null, dir: 1 };
        cpHeaders.forEach(function (th) {
            th.addEventListener("click", function () {
                var col = th.dataset.sort;
                if (cpSortState.col === col) cpSortState.dir = -cpSortState.dir;
                else { cpSortState.col = col; cpSortState.dir = 1; }
                cpHeaders.forEach(function (h) { var a = h.querySelector(".arrow"); if (a) a.textContent = ""; });
                var arrow = th.querySelector(".arrow");
                if (arrow) arrow.textContent = cpSortState.dir > 0 ? "▲" : "▼";
                var tbody = classPerfTable.querySelector("tbody");
                var rows = Array.prototype.slice.call(tbody.querySelectorAll("tr"));
                rows.sort(function (a, b) {
                    var av = a.dataset[col] || "", bv = b.dataset[col] || "";
                    var an = parseFloat(av), bn = parseFloat(bv);
                    if (!isNaN(an) && !isNaN(bn)) { av = an; bv = bn; }
                    else { av = String(av).toLowerCase(); bv = String(bv).toLowerCase(); }
                    if (av < bv) return -1 * cpSortState.dir;
                    if (av > bv) return 1 * cpSortState.dir;
                    return 0;
                });
                rows.forEach(function (r) { tbody.appendChild(r); });
            });
        });
    }

    // =====================================================
    // KEYBOARD SHORTCUTS HELP OVERLAY + g-d/g-m/g-f NAVIGATION
    // =====================================================
    var shortcutsBtn = document.getElementById("shortcutsBtn");
    var shortcutsBackdrop = document.getElementById("shortcutsBackdrop");
    var shortcutsClose = document.getElementById("shortcutsClose");
    function openShortcuts() { if (shortcutsBackdrop) shortcutsBackdrop.classList.add("open"); }
    function closeShortcuts() { if (shortcutsBackdrop) shortcutsBackdrop.classList.remove("open"); }
    if (shortcutsBtn) shortcutsBtn.addEventListener("click", openShortcuts);
    if (shortcutsClose) shortcutsClose.addEventListener("click", closeShortcuts);
    if (shortcutsBackdrop) shortcutsBackdrop.addEventListener("click", function (e) {
        if (e.target === shortcutsBackdrop) closeShortcuts();
    });

    // g-then-d/m/f navigation (vim-style)
    var gPending = false, gTimer = null;
    function navTo(path) {
        var port = (window.location.search.match(/XTransformPort=(\d+)/) || [])[1];
        var qp = port ? "?" + "XTransformPort=" + port : "";
        window.location.href = path + qp;
    }
    document.addEventListener("keydown", function (e) {
        // ignore when typing in a field
        var tag = document.activeElement.tagName;
        if (tag === "INPUT" || tag === "SELECT" || tag === "TEXTAREA") return;
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") return; // handled by cmdk
        if (e.key === "?" && !e.ctrlKey && !e.metaKey) {
            e.preventDefault();
            if (shortcutsBackdrop && shortcutsBackdrop.classList.contains("open")) closeShortcuts();
            else openShortcuts();
            return;
        }
        if (e.key === "Escape") {
            if (shortcutsBackdrop && shortcutsBackdrop.classList.contains("open")) { closeShortcuts(); return; }
        }
        // g-then-X navigation
        if (e.key.toLowerCase() === "g" && !e.ctrlKey && !e.metaKey) {
            if (gPending) return;
            gPending = true;
            clearTimeout(gTimer);
            gTimer = setTimeout(function () { gPending = false; }, 800);
            return;
        }
        if (gPending) {
            gPending = false;
            clearTimeout(gTimer);
            var k = e.key.toLowerCase();
            if (k === "d") { e.preventDefault(); navTo("/"); }
            else if (k === "m") { e.preventDefault(); navTo("/ml-insights"); }
            else if (k === "f") { e.preventDefault(); navTo("/reports"); }
        }
    });

    // =====================================================
    // REPORTS: COPY-FINDING-ID BUTTON (in the drawer header)
    // =====================================================
    // The drawer is built dynamically by openDrawer; we expose a copy helper
    // and add a copy button to the drawer sub on open.
    var origOpenDrawer = window._openFindingDrawer;
    if (typeof origOpenDrawer === "function") {
        window._openFindingDrawer = function (row) {
            origOpenDrawer(row);
            var sub = document.getElementById("drawerSub");
            if (sub && !sub.querySelector(".copy-id-btn")) {
                var btn = document.createElement("button");
                btn.className = "copy-id-btn"; btn.textContent = "⧉ copy ID";
                btn.style.cssText = "margin-left:8px;background:var(--panel-3);border:1px solid var(--line);color:var(--cyan);font-family:var(--mono);font-size:10px;padding:2px 8px;border-radius:5px;cursor:pointer;";
                btn.addEventListener("click", function () {
                    var fid = sub.dataset.fid || "";
                    if (!fid) return;
                    if (navigator.clipboard && navigator.clipboard.writeText) {
                        navigator.clipboard.writeText(fid).then(function () {
                            btn.textContent = "✓ copied"; setTimeout(function () { btn.textContent = "⧉ copy ID"; }, 1200);
                        });
                    } else {
                        var ta = document.createElement("textarea"); ta.value = fid; document.body.appendChild(ta); ta.select();
                        try { document.execCommand("copy"); btn.textContent = "✓ copied"; setTimeout(function () { btn.textContent = "⧉ copy ID"; }, 1200); } catch (e2) {}
                        document.body.removeChild(ta);
                    }
                });
                sub.appendChild(btn);
            }
            // store the finding_id on the sub for the copy button
            try {
                var f = JSON.parse(row.dataset.finding || "{}");
                if (sub) sub.dataset.fid = f.finding_id || "";
            } catch (e) {}
        };
    }

    // =====================================================
    // ML INSIGHTS: CONFUSION MATRIX NORMALIZED/RAW TOGGLE
    // =====================================================
    var cmTable = document.querySelector(".cm-table");
    if (cmTable) {
        // add a toggle button in the card head
        var cmCard = cmTable.closest(".card");
        if (cmCard) {
            var cmHead = cmCard.querySelector(".card-head");
            if (cmHead) {
                var toggle = document.createElement("button");
                toggle.className = "btn btn-ghost"; toggle.textContent = "raw counts";
                toggle.style.cssText = "padding:5px 11px;font-size:11px;";
                var normalized = false;
                // capture the raw values once
                var rawCells = Array.prototype.map.call(cmTable.querySelectorAll("td.cm-cell"), function (td) {
                    return { el: td, val: parseInt(td.textContent, 10) || 0 };
                });
                // row totals (actual counts) for normalization
                var rowTotals = [];
                Array.prototype.forEach.call(cmTable.querySelectorAll("tbody tr"), function (tr) {
                    var sum = 0;
                    tr.querySelectorAll("td.cm-cell").forEach(function (td) {
                        sum += parseInt(td.textContent, 10) || 0;
                    });
                    rowTotals.push(sum);
                });
                toggle.addEventListener("click", function () {
                    normalized = !normalized;
                    toggle.textContent = normalized ? "normalized %" : "raw counts";
                    var ri = 0, ci = 0;
                    rawCells.forEach(function (c, i) {
                        // determine row index for this cell
                        var cellRow = Math.floor(i / (Math.sqrt(rawCells.length) || 1));
                        var total = rowTotals[cellRow] || 1;
                        if (normalized) {
                            c.el.textContent = ((c.val / total) * 100).toFixed(0) + "%";
                        } else {
                            c.el.textContent = String(c.val);
                        }
                    });
                });
                cmHead.appendChild(toggle);
            }
        }
    }
