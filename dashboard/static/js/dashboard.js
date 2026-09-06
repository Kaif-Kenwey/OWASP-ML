// =====================================================
// OWASP-ML dashboard charts + small page helpers
// Chart payloads come from app.py via <script
// type="application/json" id="chart-data"> blocks, so this
// file stays dumb: read JSON, draw what exists, nothing else.
// =====================================================

document.addEventListener("DOMContentLoaded", function () {

    // ---------- Chart.js defaults (Poppins + muted grid) ----------
    if (window.Chart) {
        Chart.defaults.font.family = "'Poppins', sans-serif";
        Chart.defaults.font.size = 12;
        Chart.defaults.color = "#64748b";
        Chart.defaults.borderColor = "rgba(148, 163, 184, 0.18)";
    }

    // ---------- Severity palette (matches style.css) ----------
    var SEV_COLORS = {
        "Critical": "#dc2626",
        "High": "#ea580c",
        "Medium": "#eab308",
        "Low": "#16a34a",
        "Informational": "#94a3b8"
    };

    // ---------- Read the JSON payload(s) rendered by Jinja ----------
    var data = {};
    document.querySelectorAll('script[type="application/json"]').forEach(function (el) {
        try {
            var parsed = JSON.parse(el.textContent);
            Object.assign(data, parsed);
        } catch (err) {
            console.warn("chart-data block was not valid JSON", err);
        }
    });

    // ---------- Shared option helpers ----------
    function baseBarOptions(horizontal) {
        return {
            indexAxis: horizontal ? "y" : "x",
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { display: !horizontal } },
                y: { grid: { display: horizontal }, beginAtZero: true }
            }
        };
    }

    // ---------- Dashboard: risk doughnut ----------
    var riskCanvas = document.getElementById("riskChart");
    if (riskCanvas && data.risk) {
        new Chart(riskCanvas, {
            type: "doughnut",
            data: {
                labels: data.risk.labels,
                datasets: [{
                    data: data.risk.values,
                    backgroundColor: data.risk.labels.map(function (l) { return SEV_COLORS[l] || "#94a3b8"; }),
                    borderColor: "#ffffff",
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: "58%",
                plugins: { legend: { position: "bottom" } }
            }
        });
    }

    // ---------- Dashboard: top attack types ----------
    var attackCanvas = document.getElementById("attackChart");
    if (attackCanvas && data.attack) {
        new Chart(attackCanvas, {
            type: "bar",
            data: {
                labels: data.attack.labels,
                datasets: [{
                    data: data.attack.values,
                    backgroundColor: "#0e9488",
                    borderRadius: 6
                }]
            },
            options: baseBarOptions(true)
        });
    }

    // ---------- Dashboard: OWASP categories ----------
    var owaspCanvas = document.getElementById("owaspChart");
    if (owaspCanvas && data.owasp) {
        new Chart(owaspCanvas, {
            type: "bar",
            data: {
                labels: data.owasp.labels,
                datasets: [{
                    data: data.owasp.values,
                    backgroundColor: "#0f766e",
                    borderRadius: 6
                }]
            },
            options: baseBarOptions(true)
        });
    }

    // ---------- Dashboard: HTTP methods ----------
    var methodCanvas = document.getElementById("methodChart");
    if (methodCanvas && data.method) {
        new Chart(methodCanvas, {
            type: "bar",
            data: {
                labels: data.method.labels,
                datasets: [{
                    data: data.method.values,
                    backgroundColor: "#64748b",
                    borderRadius: 6
                }]
            },
            options: baseBarOptions(true)
        });
    }

    // ---------- ML Insights: confidence buckets ----------
    var bucketCanvas = document.getElementById("confBucketChart");
    if (bucketCanvas && data.conf_buckets) {
        new Chart(bucketCanvas, {
            type: "bar",
            data: {
                labels: data.conf_buckets.labels,
                datasets: [{
                    data: data.conf_buckets.values,
                    backgroundColor: ["#94a3b8", "#eab308", "#0e9488", "#0f766e"],
                    borderRadius: 6
                }]
            },
            options: baseBarOptions(false)
        });
    }

    // ---------- ML Insights: original vs predicted risk ----------
    var origPredCanvas = document.getElementById("origPredChart");
    if (origPredCanvas && data.orig_pred) {
        new Chart(origPredCanvas, {
            type: "bar",
            data: {
                labels: data.orig_pred.labels,
                datasets: [
                    {
                        label: "Scanner risk",
                        data: data.orig_pred.original,
                        backgroundColor: "#94a3b8",
                        borderRadius: 5
                    },
                    {
                        label: "ML / final prediction",
                        data: data.orig_pred.predicted,
                        backgroundColor: "#0e9488",
                        borderRadius: 5
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: "bottom" } },
                scales: {
                    x: { grid: { display: false } },
                    y: { beginAtZero: true }
                }
            }
        });
    }

    // ---------- Reports page: client-side row filter ----------
    var searchBox = document.getElementById("reportSearch");
    var reportBody = document.getElementById("reportBody");
    if (searchBox && reportBody) {
        searchBox.addEventListener("input", function () {
            var needle = searchBox.value.trim().toLowerCase();
            reportBody.querySelectorAll("tr").forEach(function (row) {
                var text = row.textContent.toLowerCase();
                row.style.display = text.indexOf(needle) !== -1 ? "" : "none";
            });
        });
    }

});
