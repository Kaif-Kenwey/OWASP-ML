window.riskChart = new Chart(...)
// Sidebar Active Highlight
const navItems = document.querySelectorAll(".nav-item");
navItems.forEach(item => {
    if (item.href === window.location.href) {
        item.classList.add("active");
    }
});

// Live Clock
function updateClock() {
    const now = new Date();
    document.getElementById("clock").innerText =
        now.toLocaleTimeString();
}
setInterval(updateClock, 1000);
updateClock();

// Refresh Button
document.getElementById("refreshBtn")?.addEventListener("click", () => {
    location.reload();
});

// Dark Mode Toggle
document.getElementById("darkToggle")?.addEventListener("click", () => {
    document.body.classList.toggle("dark");
});

// Animated Counters
const counters = document.querySelectorAll(".counter");

counters.forEach(counter => {
    const target = +counter.getAttribute("data-target");
    let count = 0;

    const updateCount = () => {
        const increment = target / 50;
        if (count < target) {
            count += increment;
            counter.innerText = Math.ceil(count);
            setTimeout(updateCount, 20);
        } else {
            counter.innerText = target;
        }
    };

    updateCount();
});

// Charts
if (window.dashboardData) {

    new Chart(document.getElementById('riskChart'), {
        type: 'doughnut',
        data: {
            labels: dashboardData.riskLabels,
            datasets: [{
                data: dashboardData.riskValues,
                backgroundColor: ['#ef4444','#f97316','#22c55e','#3b82f6']
            }]
        },
        options: { responsive: true }
    });

    new Chart(document.getElementById('confChart'), {
        type: 'pie',
        data: {
            labels: dashboardData.confLabels,
            datasets: [{
                data: dashboardData.confValues,
                backgroundColor: ['#6366f1','#06b6d4','#94a3b8']
            }]
        },
        options: { responsive: true }
    });

    new Chart(document.getElementById('cweChart'), {
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
    });
}

document.addEventListener("DOMContentLoaded", function() {
const filterButtons = document.querySelectorAll(".filter-btn");

filterButtons.forEach(btn => {
    btn.addEventListener("click", function() {
        const selected = this.dataset.risk;

        if (!window.dashboardData) return;

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
});
