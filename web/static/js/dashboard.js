let severityChart = null;
let typeChart = null;

// Chart Color Palette Configuration
const CHART_COLORS = {
    high: '#EF4444',     // Red
    medium: '#F59E0B',   // Amber
    low: '#3B82F6',      // Blue
    ml: '#A855F7',       // Purple
    rule: '#0EA5E9',     // Cyan
    grid: '#1F2937'
};

async function fetchAlerts() {
    try {
        const response = await fetch('/api/alerts');
        const data = await response.json();

        // Counter Aggregation
        let counts = {
            total: data.length,
            high: 0,
            medium: 0,
            low: 0,
            ml: 0,
            rule: 0
        };

        const tbody = document.getElementById('alertTable');
        tbody.innerHTML = '';

        if (data.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="7" class="py-8 text-center text-slate-500 font-sans">
                        No security threats or suspicious activity detected in the network stream.
                    </td>
                </tr>`;
            updateKPIs(counts);
            return;
        }

        data.forEach(alert => {
            // Count Severities
            if (alert.severity === 'HIGH') counts.high++;
            else if (alert.severity === 'MEDIUM') counts.medium++;
            else counts.low++;

            // Count Engines
            if (alert.detection_type === 'ML-DETECTION') counts.ml++;
            else counts.rule++;

            // Format Badge Design
            const severityBadge = getSeverityBadge(alert.severity);
            const engineBadge = getEngineBadge(alert.detection_type);

            const row = `
                <tr class="hover:bg-slate-800/40 transition-colors">
                    <td class="py-3 px-4 text-slate-400 whitespace-nowrap">${alert.timestamp}</td>
                    <td class="py-3 px-4 text-emerald-400 font-semibold">${alert.src_ip}:${alert.src_port}</td>
                    <td class="py-3 px-4 text-slate-300">${alert.dst_ip}:${alert.dst_port}</td>
                    <td class="py-3 px-4"><span class="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 font-semibold text-[10px]">${alert.protocol}</span></td>
                    <td class="py-3 px-4">${engineBadge}</td>
                    <td class="py-3 px-4 font-sans font-medium text-slate-200">${alert.alert_name}</td>
                    <td class="py-3 px-4">${severityBadge}</td>
                </tr>`;
            tbody.innerHTML += row;
        });

        updateKPIs(counts);
        renderOrUpdateCharts(counts);

    } catch (error) {
        console.error('Error fetching alerts from SIEM API:', error);
    }
}

function updateKPIs(counts) {
    document.getElementById('kpi-total').innerText = counts.total;
    document.getElementById('kpi-high').innerText = counts.high;
    document.getElementById('kpi-ml').innerText = counts.ml;
    document.getElementById('kpi-rules').innerText = counts.rule;
}

function getSeverityBadge(severity) {
    if (severity === 'HIGH') {
        return `<span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-rose-500/10 border border-rose-500/20 text-rose-400 font-semibold text-[10px]">
            <span class="h-1.5 w-1.5 rounded-full bg-rose-500"></span> HIGH
        </span>`;
    } else if (severity === 'MEDIUM') {
        return `<span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-amber-500/10 border border-amber-500/20 text-amber-400 font-semibold text-[10px]">
            <span class="h-1.5 w-1.5 rounded-full bg-amber-500"></span> MEDIUM
        </span>`;
    }
    return `<span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 font-semibold text-[10px]">
        <span class="h-1.5 w-1.5 rounded-full bg-blue-500"></span> LOW
    </span>`;
}

function getEngineBadge(engine) {
    if (engine === 'ML-DETECTION') {
        return `<span class="px-2 py-0.5 rounded bg-purple-500/10 border border-purple-500/20 text-purple-400 font-semibold text-[10px]">ML Model</span>`;
    }
    return `<span class="px-2 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400 font-semibold text-[10px]">Rule Signature</span>`;
}

function renderOrUpdateCharts(counts) {
    // 1. Doughnut Chart — Severity
    if (!severityChart) {
        const ctx1 = document.getElementById('severityChart').getContext('2d');
        severityChart = new Chart(ctx1, {
            type: 'doughnut',
            data: {
                labels: ['High', 'Medium', 'Low'],
                datasets: [{
                    data: [counts.high, counts.medium, counts.low],
                    backgroundColor: [CHART_COLORS.high, CHART_COLORS.medium, CHART_COLORS.low],
                    borderWidth: 0,
                    hoverOffset: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#94A3B8', font: { family: 'sans-serif', size: 11 }, padding: 15 }
                    }
                },
                cutout: '75%'
            }
        });
    } else {
        severityChart.data.datasets[0].data = [counts.high, counts.medium, counts.low];
        severityChart.update();
    }

    // 2. Bar Chart — Detection Engine
    if (!typeChart) {
        const ctx2 = document.getElementById('typeChart').getContext('2d');
        typeChart = new Chart(ctx2, {
            type: 'bar',
            data: {
                labels: ['Rule Signature Engine', 'Machine Learning Engine'],
                datasets: [{
                    label: 'Alert Counts',
                    data: [counts.rule, counts.ml],
                    backgroundColor: [CHART_COLORS.rule, CHART_COLORS.ml],
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { color: '#94A3B8', font: { size: 11 } }
                    },
                    y: {
                        grid: { color: CHART_COLORS.grid },
                        ticks: { color: '#94A3B8', precision: 0 }
                    }
                }
            }
        });
    } else {
        typeChart.data.datasets[0].data = [counts.rule, counts.ml];
        typeChart.update();
    }
}

// Initial Fetch & Poll every 3 seconds
fetchAlerts();
setInterval(fetchAlerts, 3000);