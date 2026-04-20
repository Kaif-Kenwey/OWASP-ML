document.addEventListener("DOMContentLoaded", function () {

    console.log("JS Loaded Successfully");

    // Sidebar active highlight
    document.querySelectorAll(".nav-item").forEach(item => {
        if (item.href === window.location.href) {
            item.classList.add("active");
        }
    });

    // Live clock
    function updateClock() {
        const now = new Date();
        const clock = document.getElementById("clock");
        if (clock) {
            clock.innerText = now.toLocaleTimeString();
        }
    }
    setInterval(updateClock, 1000);
    updateClock();

    // Refresh button
    const refreshBtn = document.getElementById("refreshBtn");
    if (refreshBtn) {
        refreshBtn.addEventListener("click", () => location.reload());
    }

    // Dark mode toggle
    const darkToggle = document.getElementById("darkToggle");
    if (darkToggle) {
        darkToggle.addEventListener("click", () => {
            document.body.classList.toggle("dark");
        });
    }

    // Animated counters
    document.querySelectorAll(".counter").forEach(counter => {
        const target = parseInt(counter.dataset.target || 0);
        let count = 0;
        const increment = Math.ceil(target / 40);

        const update = () => {
            count += increment;
            if (count >= target) {
                counter.innerText = target;
            } else {
                counter.innerText = count;
                setTimeout(update, 20);
            }
        };

        update();
    });

    // ===============================
    // CHARTS
    // ===============================
    if (window.dashboardData) {

        const riskCtx = document.getElementById("riskChart");
        const confCtx = document.getElementById("confChart");
        const cweCtx = document.getElementById("cweChart");

        // ===============================
        // RISK CHART (4 LEVEL SUPPORT)
        // ===============================
        if (riskCtx) {
            window.riskChart = new Chart(riskCtx, {
                type: "doughnut",
                data: {
                    labels: dashboardData.riskLabels,
                    datasets: [{
                        data: dashboardData.riskValues,
                        backgroundColor: [
                            "#22c55e",   // Low
                            "#f97316",   // Medium
                            "#ef4444",   // High
                            "#8b0000"    // Critical
                        ]
                    }]
                },
                options: {
                    responsive: true
                }
            });
        }

        // ===============================
        // CONFIDENCE CHART
        // ===============================
        if (confCtx) {
            new Chart(confCtx, {
                type: "pie",
                data: {
                    labels: dashboardData.confLabels,
                    datasets: [{
                        data: dashboardData.confValues,
                        backgroundColor: [
                            "#6366f1",
                            "#06b6d4",
                            "#94a3b8"
                        ]
                    }]
                },
                options: {
                    responsive: true
                }
            });
        }

        // ===============================
        // CWE CHART
        // ===============================
        if (cweCtx) {
            new Chart(cweCtx, {
                type: "bar",
                data: {
                    labels: dashboardData.cweLabels,
                    datasets: [{
                        label: "Occurrences",
                        data: dashboardData.cweValues,
                        backgroundColor: "#8b5cf6"
                    }]
                },
                options: {
                    responsive: true
                }
            });
        }
    }

});
