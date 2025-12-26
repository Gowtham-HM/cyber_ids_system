let cpuChart, memoryChart, networkChart, threatChart;
let updateInterval;

// Initialize Charts
function initCharts() {
    const chartConfig = {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
            legend: {
                labels: {
                    color: '#00ff41',
                    font: { family: 'Orbitron' }
                }
            }
        },
        scales: {
            y: {
                grid: { color: 'rgba(0,255,65,0.1)' },
                ticks: { color: '#00d4ff' }
            },
            x: {
                grid: { color: 'rgba(0,255,65,0.1)' },
                ticks: { color: '#00d4ff' }
            }
        }
    };

    // CPU Chart
    cpuChart = new Chart(document.getElementById('cpuChart'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Before Attack',
                data: [],
                borderColor: '#00ff41',
                backgroundColor: 'rgba(0,255,65,0.1)',
                tension: 0.4
            }, {
                label: 'After Attack',
                data: [],
                borderColor: '#ff0055',
                backgroundColor: 'rgba(255,0,85,0.1)',
                tension: 0.4
            }]
        },
        options: chartConfig
    });

    // Memory Chart
    memoryChart = new Chart(document.getElementById('memoryChart'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Before Attack',
                data: [],
                borderColor: '#00d4ff',
                backgroundColor: 'rgba(0,212,255,0.1)',
                tension: 0.4
            }, {
                label: 'After Attack',
                data: [],
                borderColor: '#ffaa00',
                backgroundColor: 'rgba(255,170,0,0.1)',
                tension: 0.4
            }]
        },
        options: chartConfig
    });

    // Network Chart
    networkChart = new Chart(document.getElementById('networkChart'), {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Network Traffic',
                data: [],
                backgroundColor: 'rgba(0,255,65,0.5)',
                borderColor: '#00ff41',
                borderWidth: 2
            }]
        },
        options: chartConfig
    });

    // Threat Distribution Chart
    threatChart = new Chart(document.getElementById('threatChart'), {
        type: 'doughnut',
        data: {
            labels: ['Normal', 'DoS', 'Probe', 'R2L', 'U2R'],
            datasets: [{
                data: [0, 0, 0, 0, 0],
                backgroundColor: [
                    'rgba(0,255,65,0.7)',
                    'rgba(255,0,85,0.7)',
                    'rgba(255,170,0,0.7)',
                    'rgba(0,212,255,0.7)',
                    'rgba(138,43,226,0.7)'
                ],
                borderColor: '#00ff41',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    labels: {
                        color: '#00ff41',
                        font: { family: 'Orbitron' }
                    }
                }
            }
        }
    });
}

// Update System Metrics
function updateSystemMetrics() {
    fetch('/api/system-metrics')
        .then(response => response.json())
        .then(data => {
            const current = data.current;

            // Update status display
            if (data.attack_detected) {
                document.getElementById('systemStatus').innerHTML = `
                    <div class="status-icon">🚨</div>
                    <div class="status-info">
                        <h3>System Status</h3>
                        <p class="status-text" style="color: #ff0055;">UNDER ATTACK</p>
                    </div>
                `;
            }

            // Update CPU Chart
            const timeLabel = new Date().toLocaleTimeString();
            if (cpuChart.data.labels.length > 20) {
                cpuChart.data.labels.shift();
                cpuChart.data.datasets[0].data.shift();
                cpuChart.data.datasets[1].data.shift();
            }
            cpuChart.data.labels.push(timeLabel);

            const avgBefore = data.before_attack.cpu.length > 0
                ? data.before_attack.cpu.reduce((a, b) => a + b, 0) / data.before_attack.cpu.length
                : current.cpu;
            const avgAfter = data.after_attack.cpu.length > 0
                ? data.after_attack.cpu.reduce((a, b) => a + b, 0) / data.after_attack.cpu.length
                : 0;

            cpuChart.data.datasets[0].data.push(avgBefore);
            cpuChart.data.datasets[1].data.push(avgAfter);
            cpuChart.update('none');

            // Update Memory Chart
            if (memoryChart.data.labels.length > 20) {
                memoryChart.data.labels.shift();
                memoryChart.data.datasets[0].data.shift();
                memoryChart.data.datasets[1].data.shift();
            }
            memoryChart.data.labels.push(timeLabel);

            const memBefore = data.before_attack.memory.length > 0
                ? data.before_attack.memory.reduce((a, b) => a + b, 0) / data.before_attack.memory.length
                : current.memory;
            const memAfter = data.after_attack.memory.length > 0
                ? data.after_attack.memory.reduce((a, b) => a + b, 0) / data.after_attack.memory.length
                : 0;

            memoryChart.data.datasets[0].data.push(memBefore);
            memoryChart.data.datasets[1].data.push(memAfter);
            memoryChart.update('none');

            // Update Network Chart
            if (networkChart.data.labels.length > 15) {
                networkChart.data.labels.shift();
                networkChart.data.datasets[0].data.shift();
            }
            networkChart.data.labels.push(timeLabel);
            networkChart.data.datasets[0].data.push(current.network_sent / 1024 / 1024);
            networkChart.update('none');
        })
        .catch(error => console.error('Error updating metrics:', error));
}

// Update Traffic Monitor
function updateTrafficMonitor() {
    fetch('/api/traffic-monitor')
        .then(response => response.json())
        .then(data => {
            const log = data.log_entry;
            const logsContainer = document.getElementById('logsContainer');

            const logClass = log.prediction !== 'Normal' ? 'log-entry threat' : 'log-entry';
            const statusClass = log.prediction !== 'Normal' ? 'log-threat' : 'log-normal';

            const logHTML = `
                <div class="${logClass}">
                    <span class="log-timestamp">[${new Date(log.timestamp).toLocaleTimeString()}]</span>
                    <span class="${statusClass}">${log.prediction}</span> | 
                    ${log.src_ip} → ${log.dst_ip} | 
                    Protocol: ${log.protocol} | 
                    <span style="color: var(--neon-purple)">Fusion Score: ${(log.confidence * 100).toFixed(1)}%</span> | 
                    <span style="color: var(--neon-blue)">RQA: DET ${log.rqa_det}% / RR ${log.rqa_rr}%</span> |
                    ${log.blocked ? '<span class="log-threat">⛔ BLOCKED</span>' : '✅ ALLOWED'}
                </div>
            `;

            logsContainer.insertAdjacentHTML('afterbegin', logHTML);

            // Keep only last 50 logs
            while (logsContainer.children.length > 50) {
                logsContainer.removeChild(logsContainer.lastChild);
            }
        })
        .catch(error => console.error('Error updating traffic:', error));
}

// Update Statistics
function updateStatistics() {
    fetch('/api/statistics')
        .then(response => response.json())
        .then(data => {
            document.getElementById('totalTraffic').textContent = data.total_traffic;
            document.getElementById('threatsDetected').textContent = data.malicious_count;
            document.getElementById('ipsBlocked').textContent = data.blocked_ips;

            // Update threat distribution chart
            const distribution = data.threat_distribution;
            threatChart.data.datasets[0].data = [
                distribution['Normal'] || 0,
                distribution['DoS'] || 0,
                distribution['Probe'] || 0,
                distribution['R2L'] || 0,
                distribution['U2R'] || 0
            ];
            threatChart.update('none');

            // Update blocked IPs list
            const blockedList = document.getElementById('blockedIpsList');
            if (data.blocked_ip_list.length > 0) {
                blockedList.innerHTML = data.blocked_ip_list
                    .map(ip => `<div class="blocked-ip">${ip}</div>`)
                    .join('');
            }
        })
        .catch(error => console.error('Error updating statistics:', error));
}

// Generate Report
function generateReport() {
    fetch('/api/generate-report')
        .then(response => response.json())
        .then(data => {
            alert(`Report generated successfully!\n\nSaved to: ${data.saved_to}\n\nThreats Detected: ${data.report.summary.threats_detected}\nIPs Blocked: ${data.report.summary.ips_blocked}`);

            // Download report
            const dataStr = JSON.stringify(data.report, null, 2);
            const dataBlob = new Blob([dataStr], { type: 'application/json' });
            const url = URL.createObjectURL(dataBlob);
            const link = document.createElement('a');
            link.href = url;
            link.download = `security_report_${new Date().toISOString()}.json`;
            link.click();
        })
        .catch(error => console.error('Error generating report:', error));
}

// Reset System
function resetSystem() {
    if (confirm('Are you sure you want to reset the system? All data will be cleared.')) {
        fetch('/api/reset')
            .then(response => response.json())
            .then(data => {
                alert(data.message);
                location.reload();
            })
            .catch(error => console.error('Error resetting system:', error));
    }
}

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function () {
    initCharts();

    // Start updates
    updateSystemMetrics();
    updateTrafficMonitor();
    updateStatistics();

    // Set intervals for real-time updates
    setInterval(updateSystemMetrics, 2000);
    setInterval(updateTrafficMonitor, 1500);
    setInterval(updateStatistics, 3000);

    console.log('🚀 CyberShield IDS Dashboard Initialized');
});