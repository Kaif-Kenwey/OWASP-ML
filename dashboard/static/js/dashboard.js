async function loadData() {
    const response = await fetch("/api/data");
    const data = await response.json();

    if (!data.risk_distribution) return;

    document.getElementById("totalAlerts").innerText = data.total;
    document.getElementById("avgConfidence").innerText = data.average_confidence + "%";

    renderRiskChart(data.risk_distribution);
    renderAttackChart(data.attack_distribution);
}

function renderRiskChart(riskData) {
    const ctx = document.getElementById('riskChart').getContext('2d');

    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(riskData),
            datasets: [{
                data: Object.values(riskData),
                backgroundColor: [
                    '#dc2626',
                    '#f59e0b',
                    '#10b981',
                    '#3b82f6'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false
        }
    });
}

function renderAttackChart(attackData) {
    const ctx = document.getElementById('attackChart').getContext('2d');

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: Object.keys(attackData),
            datasets: [{
                label: 'Number of Alerts',
                data: Object.values(attackData),
                backgroundColor: '#6366f1'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false
        }
    });
}

loadData();
