/**
 * QUANTUM-SHIELD // CHART.JS INITIALIZATION & TELEMETRY VISUALIZATION
 * Renders dark cybersecurity-themed charts backed by real database records.
 */

let trendsChart = null;
let scoreDistChart = null;
let categoryChart = null;

// Dark Cyber Theme Configuration for Chart.js
const cyberChartDefaults = {
    color: '#94a3b8',
    borderColor: '#192744',
    font: {
        family: "'Inter', sans-serif",
        size: 11
    }
};

document.addEventListener('DOMContentLoaded', () => {
    if (typeof Chart !== 'undefined') {
        Chart.defaults.color = cyberChartDefaults.color;
        Chart.defaults.borderColor = cyberChartDefaults.borderColor;
        Chart.defaults.font.family = cyberChartDefaults.font.family;
        
        const dashboardCanvas = document.getElementById('chart-trends');
        if (dashboardCanvas) {
            initDashboardCharts();
        }
    }
});

async function initDashboardCharts() {
    try {
        const response = await fetch('/api/dashboard/stats');
        const json = await response.json();
        if (json.status !== 'success') return;

        const data = json.data;
        renderTrendsChart(data.weekly_trends);
        renderScoreDistributionChart(data.score_distribution);
        renderCategoryChart(data.category_breakdown);
    } catch (err) {
        console.error('Failed to load dashboard telemetry stats:', err);
    }
}

function renderTrendsChart(trends) {
    const ctx = document.getElementById('chart-trends');
    if (!ctx) return;

    if (trendsChart) trendsChart.destroy();

    trendsChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: trends.labels,
            datasets: [
                {
                    label: 'Valid Signatures',
                    data: trends.valid,
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    borderWidth: 2.5,
                    tension: 0.35,
                    fill: true,
                    pointBackgroundColor: '#10b981',
                    pointRadius: 4,
                    pointHoverRadius: 6,
                },
                {
                    label: 'Invalid / Mismatch',
                    data: trends.invalid,
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.08)',
                    borderWidth: 2,
                    tension: 0.35,
                    borderDash: [4, 4],
                    pointBackgroundColor: '#ef4444',
                    pointRadius: 4,
                    pointHoverRadius: 6,
                },
                {
                    label: 'High/Critical Anomalies',
                    data: trends.anomalies,
                    borderColor: '#00f0ff',
                    backgroundColor: 'rgba(0, 240, 255, 0.05)',
                    borderWidth: 2,
                    tension: 0.35,
                    pointBackgroundColor: '#00f0ff',
                    pointRadius: 4,
                    pointHoverRadius: 6,
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top',
                    labels: { boxWidth: 12, padding: 16 }
                },
                tooltip: {
                    backgroundColor: '#111c35',
                    titleColor: '#00f0ff',
                    bodyColor: '#f8fafc',
                    borderColor: '#263c68',
                    borderWidth: 1,
                    padding: 12,
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: { precision: 0 },
                    grid: { color: 'rgba(25, 39, 68, 0.6)' }
                },
                x: {
                    grid: { display: false }
                }
            }
        }
    });
}

function renderScoreDistributionChart(dist) {
    const ctx = document.getElementById('chart-score-dist');
    if (!ctx) return;

    if (scoreDistChart) scoreDistChart.destroy();

    scoreDistChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: dist.labels,
            datasets: [{
                label: 'Verification Count',
                data: dist.counts,
                backgroundColor: [
                    'rgba(16, 185, 129, 0.6)',
                    'rgba(0, 112, 243, 0.6)',
                    'rgba(245, 158, 11, 0.6)',
                    'rgba(249, 115, 22, 0.7)',
                    'rgba(239, 68, 68, 0.8)'
                ],
                borderColor: [
                    '#10b981',
                    '#0070f3',
                    '#f59e0b',
                    '#f97316',
                    '#ef4444'
                ],
                borderWidth: 1.5,
                borderRadius: 4,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#111c35',
                    borderColor: '#263c68',
                    borderWidth: 1
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: { precision: 0 },
                    grid: { color: 'rgba(25, 39, 68, 0.6)' }
                },
                x: {
                    grid: { display: false }
                }
            }
        }
    });
}

function renderCategoryChart(cat) {
    const ctx = document.getElementById('chart-category');
    if (!ctx) return;

    if (categoryChart) categoryChart.destroy();

    categoryChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: cat.labels,
            datasets: [{
                data: cat.counts,
                backgroundColor: [
                    '#10b981',
                    '#ef4444',
                    '#f97316',
                    '#00f0ff'
                ],
                borderColor: '#111c35',
                borderWidth: 2,
                hoverOffset: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { boxWidth: 12, padding: 12 }
                },
                tooltip: {
                    backgroundColor: '#111c35',
                    borderColor: '#263c68',
                    borderWidth: 1
                }
            },
            cutout: '68%'
        }
    });
}
