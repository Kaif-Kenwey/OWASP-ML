document.addEventListener("DOMContentLoaded", function () {

    // Sidebar active highlight
    document.querySelectorAll(".nav-item").forEach(item => {
        if (item.href === window.location.href) {
            item.classList.add("active");
        }
    });

    // Live clock
    function updateClock() {
        const now = new Date();
        document.getElementById("clock").innerText =
            now.toLocaleTimeString();
    }
    setInterval(updateClock, 1000);
    updateClock();

    // Refresh
    document.getElementById("refreshBtn")?.addEventListener("click", () => {
        location.reload();
    });

    // Dark mode
    document.getElementById("darkToggle")?.addEventListener("click", () => {
        document.body.classList.toggle("dark");
    });

    // Counter animation
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

    // Charts
    if (window.dashboardData) {

        window.riskChart = new Chart(
            document.getElementById('riskChart'),
            {
                type: 'doughnut',
                data: {
                    labels: dashboardData.riskLabels,
                    datasets: [{
                        data: dashboardData.riskValues,
                        backgroundColor: ['#ef4444','#f97316','#22c55e','#3b82f6']
                    }]
                },
                options: { responsive: true }
            }
        );

        new Chart(
            document.getElementById('confChart'),
            {
                type: 'pie',
                data: {
                    labels: dashboardData.confLabels,
                    datasets: [{
                        data: dashboardData.confValues,
                        backgroundColor: ['#6366f1','#06b6d4','#94a3b8']
                    }]
                },
                options: { responsive: true }
            }
        );

        new Chart(
            document.getElementById('cweChart'),
            {
                type: 'bar',
                data: {
                    labels: dashboardData.cweLabels,
                    datasets: [{
                        label: 'Occurrences',
                        data: dashboardData.cweValues,
                        backgroundColor: '#8b5cf6'
                    }]
                },
                options: { responsive: true }
            }
        );

        // Filtering
        document.querySelectorAll(".filter-btn").forEach(btn => {
            btn.addEventListener("click", function () {
                const selected = this.dataset.risk;

                if (selected === "All") {
                    riskChart.data.labels = dashboardData.riskLabels;
                    riskChart.data.datasets[0].data = dashboardData.riskValues;
                } else {
                    const index = dashboardData.riskLabels.indexOf(selected);
                    if (index !== -1) {
                        riskChart.data.labels = [selected];
                        riskChart.data.datasets[0].data = [dashboardData.riskValues[index]];
                    }
                }
                riskChart.update();
            });
        });
    }

});
