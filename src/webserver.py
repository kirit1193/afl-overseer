"""Web server for AFL Overseer dashboard."""

import asyncio
import logging
import threading
from pathlib import Path

from aiohttp import web

from .models import MonitorConfig
from .monitor import AFLMonitor
from .process import ProcessMonitor


# Embedded HTML dashboard template
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AFL Overseer Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root[data-theme="dark"] {
            --bg-primary: #0f0f0f;
            --bg-secondary: #1a1a1a;
            --bg-tertiary: #252525;
            --text-primary: #e0e0e0;
            --text-secondary: #a0a0a0;
            --accent: #00d4aa;
            --accent-hover: #00f5c4;
            --danger: #ff4444;
            --warning: #ffaa00;
            --success: #00cc66;
            --border: #333;
            --shadow: rgba(0, 0, 0, 0.3);
        }

        :root[data-theme="light"] {
            --bg-primary: #ffffff;
            --bg-secondary: #f5f5f5;
            --bg-tertiary: #e0e0e0;
            --text-primary: #1a1a1a;
            --text-secondary: #666666;
            --accent: #00a87e;
            --accent-hover: #00c494;
            --danger: #d63031;
            --warning: #e17055;
            --success: #00b894;
            --border: #ddd;
            --shadow: rgba(0, 0, 0, 0.1);
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            font-size: 14px;
            line-height: 1.5;
            transition: background-color 0.3s, color 0.3s;
        }

        .header {
            background: var(--bg-secondary);
            border-bottom: 2px solid var(--accent);
            padding: 10px 20px 12px 20px;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: 0 2px 8px var(--shadow);
        }

        .header-top {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }

        .header h1 {
            font-size: 18px;
            font-weight: 600;
            color: var(--accent);
            margin: 0;
        }

        .header-info {
            display: flex;
            gap: 12px;
            align-items: center;
            font-size: 12px;
        }

        .system-metrics {
            display: flex;
            gap: 20px;
            align-items: center;
            font-size: 11px;
            color: var(--text-secondary);
        }

        .sys-metric {
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .sys-metric-label {
            font-weight: 500;
            min-width: 30px;
        }

        .sys-metric-bar {
            width: 60px;
            height: 6px;
            background: var(--bg-tertiary);
            border-radius: 3px;
            overflow: hidden;
            position: relative;
        }

        .sys-metric-fill {
            height: 100%;
            background: var(--accent);
            transition: width 0.3s ease;
        }

        .sys-metric-value {
            min-width: 45px;
            text-align: right;
        }

        .status-badge {
            padding: 4px 12px;
            border-radius: 12px;
            background: var(--bg-tertiary);
            font-weight: 500;
        }

        .status-badge.live {
            background: var(--success);
            color: #000;
        }

        .theme-toggle {
            background: var(--bg-tertiary);
            border: none;
            color: var(--text-primary);
            padding: 6px 12px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.2s;
        }

        .theme-toggle:hover {
            background: var(--accent);
            color: #000;
        }

        .container {
            max-width: 1800px;
            margin: 0 auto;
            padding: 15px;
        }

        .alerts {
            margin-bottom: 20px;
        }

        .alert {
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 12px;
            animation: slideIn 0.3s ease;
        }

        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .alert.danger {
            background: rgba(255, 68, 68, 0.15);
            border-left: 4px solid var(--danger);
        }

        .alert.warning {
            background: rgba(255, 170, 0, 0.15);
            border-left: 4px solid var(--warning);
        }

        .alert-icon {
            font-size: 20px;
        }

        .tabs {
            display: flex;
            gap: 2px;
            background: var(--bg-secondary);
            padding: 4px;
            border-radius: 8px;
            margin-bottom: 20px;
        }

        .tab {
            padding: 10px 20px;
            background: transparent;
            border: none;
            color: var(--text-secondary);
            cursor: pointer;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.2s;
        }

        .tab:hover {
            background: var(--bg-tertiary);
            color: var(--text-primary);
        }

        .tab.active {
            background: var(--accent);
            color: #000;
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 10px;
            margin-bottom: 20px;
        }

        .metric-card {
            background: var(--bg-secondary);
            padding: 10px 12px;
            border-radius: 6px;
            border: 1px solid var(--border);
            transition: all 0.2s;
        }

        .metric-card:hover {
            transform: translateY(-1px);
            box-shadow: 0 2px 8px var(--shadow);
            border-color: var(--accent);
        }

        .metric-card.warning {
            border-color: var(--warning);
            background: rgba(255, 170, 0, 0.08);
        }

        .metric-card.danger {
            border-color: var(--danger);
            background: rgba(255, 68, 68, 0.08);
        }

        .metric-label {
            font-size: 10px;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 4px;
            font-weight: 500;
        }

        .metric-value {
            font-size: 20px;
            font-weight: 600;
            color: var(--text-primary);
            line-height: 1.2;
        }

        .metric-subvalue {
            font-size: 11px;
            color: var(--text-secondary);
            margin-top: 2px;
        }

        .metric-trend {
            font-size: 11px;
            margin-top: 6px;
        }

        .metric-trend.up {
            color: var(--success);
        }

        .metric-trend.down {
            color: var(--danger);
        }

        .chart-container {
            background: var(--bg-secondary);
            padding: 20px;
            border-radius: 8px;
            border: 1px solid var(--border);
            margin-bottom: 20px;
        }

        .chart-title {
            font-size: 14px;
            font-weight: 600;
            margin-bottom: 15px;
            color: var(--text-primary);
        }

        .chart-wrapper {
            position: relative;
            height: 250px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-secondary);
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid var(--border);
        }

        th {
            background: var(--bg-tertiary);
            padding: 12px;
            text-align: left;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-secondary);
            font-weight: 600;
            border-bottom: 1px solid var(--border);
        }

        td {
            padding: 12px;
            border-bottom: 1px solid var(--border);
        }

        tr:last-child td {
            border-bottom: none;
        }

        tr:hover {
            background: var(--bg-tertiary);
        }

        tr.dead {
            opacity: 0.6;
        }

        tr.warning {
            background: rgba(255, 170, 0, 0.05);
        }

        .status {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 10px;
            font-size: 11px;
            font-weight: 600;
        }

        .status.alive {
            background: rgba(0, 204, 102, 0.2);
            color: var(--success);
        }

        .status.dead {
            background: rgba(255, 68, 68, 0.2);
            color: var(--danger);
        }

        .status.starting {
            background: rgba(255, 170, 0, 0.2);
            color: var(--warning);
        }

        .progress-bar {
            height: 6px;
            background: var(--bg-tertiary);
            border-radius: 3px;
            overflow: hidden;
            margin-top: 4px;
        }

        .progress-fill {
            height: 100%;
            background: var(--accent);
            transition: width 0.3s ease;
        }

        .warning-badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 8px;
            font-size: 10px;
            font-weight: 600;
            margin-left: 8px;
            background: var(--warning);
            color: #000;
        }

        @media (max-width: 768px) {
            .metrics-grid {
                grid-template-columns: repeat(2, 1fr);
            }

            .header-top {
                flex-wrap: wrap;
            }

            .header-info {
                gap: 8px;
                font-size: 11px;
            }

            .system-metrics {
                gap: 12px;
                font-size: 10px;
            }

            .sys-metric-bar {
                width: 50px;
            }

            .container {
                padding: 10px;
            }

            table {
                font-size: 12px;
            }

            th, td {
                padding: 8px;
            }
        }

        @media (max-width: 480px) {
            .metrics-grid {
                grid-template-columns: 1fr;
            }

            .header h1 {
                font-size: 16px;
            }

            .header-top {
                margin-bottom: 6px;
            }

            .system-metrics {
                gap: 8px;
                flex-wrap: wrap;
            }

            .sys-metric {
                gap: 4px;
            }

            .sys-metric-bar {
                width: 40px;
            }

            .sys-metric-value {
                min-width: 35px;
                font-size: 10px;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-top">
            <h1>AFL Overseer Dashboard</h1>
            <div class="header-info">
                <select id="refreshSelect" onchange="changeRefreshInterval()" style="background: var(--bg-tertiary); border: none; color: var(--text-primary); padding: 6px 10px; border-radius: 6px; cursor: pointer; font-size: 12px;">
                    <option value="1">1s</option>
                    <option value="2">2s</option>
                    <option value="5">5s</option>
                    <option value="10">10s</option>
                    <option value="30">30s</option>
                </select>
                <button class="theme-toggle" onclick="toggleTheme()" title="Toggle theme">
                    <span id="themeIcon">☀</span>
                </button>
                <div class="status-badge live">● LIVE</div>
                <div id="lastUpdate" style="font-size: 11px;">Last update: --:--:--</div>
            </div>
        </div>
        <div class="system-metrics">
            <div class="sys-metric">
                <span class="sys-metric-label">CPU:</span>
                <div class="sys-metric-bar"><div class="sys-metric-fill" id="cpuBar" style="width: 0%"></div></div>
                <span class="sys-metric-value" id="cpuText">0%</span>
            </div>
            <div class="sys-metric">
                <span class="sys-metric-label">RAM:</span>
                <div class="sys-metric-bar"><div class="sys-metric-fill" id="ramBar" style="width: 0%"></div></div>
                <span class="sys-metric-value" id="ramText">0/0 GB</span>
            </div>
            <div class="sys-metric">
                <span class="sys-metric-label">Disk:</span>
                <div class="sys-metric-bar"><div class="sys-metric-fill" id="diskBar" style="width: 0%"></div></div>
                <span class="sys-metric-value" id="diskText">0/0 GB</span>
            </div>
        </div>
    </div>

    <div class="container">
        <div id="alerts" class="alerts"></div>

        <div class="tabs">
            <button class="tab active" onclick="switchTab('overview')">Overview</button>
            <button class="tab" onclick="switchTab('fuzzers')">Fuzzers</button>
            <button class="tab" onclick="switchTab('graphs')">Graphs</button>
        </div>

        <div id="overview" class="tab-content active">
            <div class="metrics-grid" style="grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px;">
                <!-- Fuzzer Status -->
                <div class="metric-card" id="aliveFuzzersCard">
                    <div class="metric-label">Fuzzers</div>
                    <div class="metric-value" id="aliveFuzzers">0</div>
                    <div class="metric-subvalue" id="fuzzerStatus">0 total</div>
                </div>

                <!-- Runtime -->
                <div class="metric-card">
                    <div class="metric-label">Runtime</div>
                    <div class="metric-value" id="totalRuntime">0s</div>
                    <div class="metric-subvalue" style="opacity: 0.6;">cumulative</div>
                </div>

                <!-- Execution Speed -->
                <div class="metric-card">
                    <div class="metric-label">Speed</div>
                    <div class="metric-value" id="totalSpeed">0</div>
                    <div class="metric-subvalue"><span id="avgSpeedPerCore">0</span> /core</div>
                </div>

                <!-- Total Executions -->
                <div class="metric-card">
                    <div class="metric-label">Execs</div>
                    <div class="metric-value" id="totalExecs">0</div>
                    <div class="metric-subvalue" style="opacity: 0.6;">total</div>
                </div>

                <!-- Coverage -->
                <div class="metric-card">
                    <div class="metric-label">Coverage</div>
                    <div class="metric-value" id="coverage">0%</div>
                    <div class="progress-bar"><div class="progress-fill" id="coverageBar" style="width: 0%"></div></div>
                </div>

                <!-- Crashes & Hangs -->
                <div class="metric-card">
                    <div class="metric-label">Crashes</div>
                    <div class="metric-value" id="crashes">0</div>
                    <div class="metric-subvalue"><span id="hangs">0</span> hangs <span id="newFindings"></span></div>
                </div>

                <!-- Corpus -->
                <div class="metric-card">
                    <div class="metric-label">Corpus</div>
                    <div class="metric-value" id="corpusAll">0</div>
                    <div class="metric-subvalue" style="opacity: 0.6;">paths</div>
                </div>

                <!-- Pending Paths -->
                <div class="metric-card">
                    <div class="metric-label">Pending</div>
                    <div class="metric-value" id="pendingAll">0</div>
                    <div class="metric-subvalue"><span id="pendingFavs">0</span> favs</div>
                </div>

                <!-- Last Find -->
                <div class="metric-card">
                    <div class="metric-label">Last Find</div>
                    <div class="metric-value" id="lastFind" style="font-size: 16px;">never</div>
                    <div class="metric-subvalue" style="opacity: 0.6;">ago</div>
                </div>

                <!-- Cycles -->
                <div class="metric-card">
                    <div class="metric-label">Cycles</div>
                    <div class="metric-value" id="avgCycle">0</div>
                    <div class="metric-subvalue">max: <span id="maxCycle">0</span></div>
                </div>

                <!-- Stability -->
                <div class="metric-card">
                    <div class="metric-label">Stability</div>
                    <div class="metric-value" id="stability">0%</div>
                    <div class="metric-subvalue" id="stabilityRange">N/A</div>
                </div>
            </div>
        </div>

        <div id="fuzzers" class="tab-content">
            <table>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Status</th>
                        <th>Runtime</th>
                        <th>Execs</th>
                        <th>Speed</th>
                        <th>Coverage</th>
                        <th>Crashes</th>
                        <th>Corpus</th>
                        <th>Stability</th>
                    </tr>
                </thead>
                <tbody id="fuzzersTable">
                    <tr><td colspan="9" style="text-align: center; padding: 40px; color: var(--text-secondary);">Loading...</td></tr>
                </tbody>
            </table>
        </div>

        <div id="graphs" class="tab-content">
            <div style="margin-bottom: 15px; display: flex; align-items: center; gap: 10px;">
                <label style="font-size: 12px; color: var(--text-secondary);">Time Period:</label>
                <select id="timePeriodSelect" onchange="changeTimePeriod()" style="background: var(--bg-tertiary); border: none; color: var(--text-primary); padding: 6px 10px; border-radius: 6px; cursor: pointer; font-size: 12px;">
                    <option value="all">All (Session)</option>
                    <option value="60">Last 1 min</option>
                    <option value="300">Last 5 min</option>
                    <option value="600">Last 10 min</option>
                    <option value="1800">Last 30 min</option>
                    <option value="3600">Last 1 hour</option>
                </select>
            </div>
            <div class="chart-container">
                <div class="chart-title">Execution Speed Over Time</div>
                <div class="chart-wrapper">
                    <canvas id="speedChart"></canvas>
                </div>
            </div>
            <div class="chart-container">
                <div class="chart-title">Coverage Over Time</div>
                <div class="chart-wrapper">
                    <canvas id="coverageChart"></canvas>
                </div>
            </div>
            <div class="chart-container">
                <div class="chart-title">Paths & Crashes Over Time</div>
                <div class="chart-wrapper">
                    <canvas id="pathsChart"></canvas>
                </div>
            </div>
            <div class="chart-container">
                <div class="chart-title">Pending Paths Over Time</div>
                <div class="chart-wrapper">
                    <canvas id="pendingChart"></canvas>
                </div>
            </div>
        </div>

    </div>

    <script>
        let refreshInterval = REFRESH_INTERVAL;
        let speedData = [];
        let coverageData = [];
        let pathsData = [];
        let crashesData = [];
        let pendingData = [];
        let timestamps = []; // Track data timestamps
        let maxDataPoints = 60;
        let timePeriod = 'all'; // Default to showing all data

        // Refresh interval management
        let refreshIntervalId = null;

        function changeTimePeriod() {
            const select = document.getElementById('timePeriodSelect');
            timePeriod = select.value;
            localStorage.setItem('timePeriod', timePeriod);
            updateChartsWithFilter();
        }

        function filterDataByTime(dataArray, timestampArray) {
            if (timePeriod === 'all') {
                return dataArray;
            }

            const period = parseInt(timePeriod);
            const now = Date.now() / 1000;
            const cutoff = now - period;

            const filtered = [];
            for (let i = 0; i < timestampArray.length; i++) {
                if (timestampArray[i] >= cutoff) {
                    filtered.push(dataArray[i]);
                }
            }
            return filtered;
        }

        function updateChartsWithFilter() {
            const filteredSpeed = filterDataByTime(speedData, timestamps);
            const filteredCoverage = filterDataByTime(coverageData, timestamps);
            const filteredPaths = filterDataByTime(pathsData, timestamps);
            const filteredCrashes = filterDataByTime(crashesData, timestamps);
            const filteredPending = filterDataByTime(pendingData, timestamps);

            // Update chart data
            speedChart.data.datasets[0].data = filteredSpeed;
            speedChart.data.labels = Array(filteredSpeed.length).fill('');
            speedChart.update('none');

            coverageChart.data.datasets[0].data = filteredCoverage;
            coverageChart.data.labels = Array(filteredCoverage.length).fill('');
            coverageChart.update('none');

            pathsChart.data.datasets[0].data = filteredPaths;
            pathsChart.data.datasets[1].data = filteredCrashes;
            pathsChart.data.labels = Array(filteredPaths.length).fill('');
            pathsChart.update('none');

            pendingChart.data.datasets[0].data = filteredPending;
            pendingChart.data.labels = Array(filteredPending.length).fill('');
            pendingChart.update('none');
        }

        function changeRefreshInterval() {
            const select = document.getElementById('refreshSelect');
            refreshInterval = parseInt(select.value);
            localStorage.setItem('refreshInterval', refreshInterval);

            // Clear and restart interval
            if (refreshIntervalId) {
                clearInterval(refreshIntervalId);
            }
            refreshIntervalId = setInterval(fetchData, refreshInterval * 1000);
        }

        // Theme management
        function toggleTheme() {
            const root = document.documentElement;
            const currentTheme = root.getAttribute('data-theme') || 'dark';
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            root.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);

            // Update icon
            document.getElementById('themeIcon').textContent = newTheme === 'dark' ? '☀' : '☾';

            // Update chart colors
            updateChartTheme(newTheme);
        }

        function loadTheme() {
            const savedTheme = localStorage.getItem('theme') || 'dark';
            document.documentElement.setAttribute('data-theme', savedTheme);
            // Update icon based on loaded theme
            document.getElementById('themeIcon').textContent = savedTheme === 'dark' ? '☀' : '☾';
        }

        function getComputedColor(variable) {
            return getComputedStyle(document.documentElement).getPropertyValue(variable).trim();
        }

        function updateChartTheme(theme) {
            const borderColor = theme === 'dark' ? '#333' : '#ddd';
            const textColor = theme === 'dark' ? '#a0a0a0' : '#666';

            [speedChart, coverageChart, pathsChart, pendingChart].forEach(chart => {
                chart.options.scales.x.grid.color = borderColor;
                chart.options.scales.y.grid.color = borderColor;
                chart.options.scales.x.ticks.color = textColor;
                chart.options.scales.y.ticks.color = textColor;
                chart.update('none');
            });
        }

        loadTheme();

        // Initialize charts
        const chartConfig = {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                intersect: false,
                mode: 'index'
            },
            plugins: {
                legend: { display: true },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    padding: 12,
                    titleFont: { size: 14 },
                    bodyFont: { size: 13 }
                }
            },
            scales: {
                x: {
                    grid: { color: '#333' },
                    ticks: { color: '#a0a0a0', maxTicksLimit: 10 }
                },
                y: {
                    grid: { color: '#333' },
                    ticks: { color: '#a0a0a0' }
                }
            }
        };

        const speedChart = new Chart(document.getElementById('speedChart'), {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Execs/sec',
                    data: [],
                    borderColor: '#00d4aa',
                    backgroundColor: 'rgba(0, 212, 170, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: chartConfig
        });

        const coverageChart = new Chart(document.getElementById('coverageChart'), {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Coverage %',
                    data: [],
                    borderColor: '#00cc66',
                    backgroundColor: 'rgba(0, 204, 102, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: chartConfig
        });

        const pathsChart = new Chart(document.getElementById('pathsChart'), {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Total Paths',
                    data: [],
                    borderColor: '#ffaa00',
                    backgroundColor: 'rgba(255, 170, 0, 0.1)',
                    tension: 0.4,
                    fill: true,
                    yAxisID: 'y'
                }, {
                    label: 'Crashes',
                    data: [],
                    borderColor: '#ff4444',
                    backgroundColor: 'rgba(255, 68, 68, 0.1)',
                    tension: 0.4,
                    fill: true,
                    yAxisID: 'y1'
                }]
            },
            options: {
                ...chartConfig,
                scales: {
                    x: chartConfig.scales.x,
                    y: {
                        ...chartConfig.scales.y,
                        type: 'linear',
                        position: 'left'
                    },
                    y1: {
                        ...chartConfig.scales.y,
                        type: 'linear',
                        position: 'right',
                        grid: { drawOnChartArea: false }
                    }
                }
            }
        });

        const pendingChart = new Chart(document.getElementById('pendingChart'), {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Pending Paths',
                    data: [],
                    borderColor: '#9b59b6',
                    backgroundColor: 'rgba(155, 89, 182, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: chartConfig
        });

        function switchTab(tabName) {
            // Update tab buttons
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            event.target.classList.add('active');

            // Update tab content
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            document.getElementById(tabName).classList.add('active');

            // Resize charts when graphs tab is shown
            if (tabName === 'graphs') {
                setTimeout(() => {
                    speedChart.resize();
                    coverageChart.resize();
                    pathsChart.resize();
                    pendingChart.resize();
                }, 50);
            }
        }

        function formatNumber(num) {
            if (num >= 1000000000) return (num / 1000000000).toFixed(2) + 'B';
            if (num >= 1000000) return (num / 1000000).toFixed(2) + 'M';
            if (num >= 1000) return (num / 1000).toFixed(2) + 'K';
            return num.toString();
        }

        function formatTime(seconds) {
            const h = Math.floor(seconds / 3600);
            const m = Math.floor((seconds % 3600) / 60);
            const s = seconds % 60;
            if (h > 0) return `${h}h ${m}m`;
            if (m > 0) return `${m}m ${s}s`;
            return `${s}s`;
        }

        function formatTimeAgo(timestamp) {
            if (!timestamp || timestamp <= 0) return 'never';

            const now = Math.floor(Date.now() / 1000);
            const elapsed = now - timestamp;

            if (elapsed < 0) return 'in future';
            if (elapsed < 60) return `${elapsed}s`;
            if (elapsed < 3600) return `${Math.floor(elapsed / 60)}m`;
            if (elapsed < 86400) return `${Math.floor(elapsed / 3600)}h`;
            return `${Math.floor(elapsed / 86400)}d`;
        }

        function updateAlerts(data) {
            const alertsDiv = document.getElementById('alerts');
            const alerts = [];

            const summary = data.summary;
            const deadCount = summary.total_fuzzers - summary.alive_fuzzers;

            // Dead fuzzers alert
            if (deadCount > 0) {
                alerts.push({
                    type: 'danger',
                    icon: '!',
                    message: `${deadCount} fuzzer${deadCount > 1 ? 's' : ''} not responding (dead)`
                });
            }

            // Low stability alert
            data.fuzzers.forEach(f => {
                if (f.status === 'ALIVE' && f.stability < 80) {
                    alerts.push({
                        type: 'warning',
                        icon: '!',
                        message: `${f.name}: Low stability (${f.stability.toFixed(1)}%)`
                    });
                }
            });

            // High timeout alert
            data.fuzzers.forEach(f => {
                if (f.status === 'ALIVE' && f.slowest_exec_ms > 100) {
                    alerts.push({
                        type: 'warning',
                        icon: '!',
                        message: `${f.name}: High execution timeout (${f.slowest_exec_ms}ms)`
                    });
                }
            });

            // Render alerts
            if (alerts.length > 0) {
                alertsDiv.innerHTML = alerts.map(alert => `
                    <div class="alert ${alert.type}">
                        <span class="alert-icon">${alert.icon}</span>
                        <div>${alert.message}</div>
                    </div>
                `).join('');
            } else {
                alertsDiv.innerHTML = '';
            }
        }

        function updateDashboard(data) {
            const summary = data.summary;
            const system = data.system;

            // Update alerts
            updateAlerts(data);

            // Fuzzer status with warnings
            const deadCount = summary.dead_fuzzers || 0;
            const startingCount = summary.starting_fuzzers || 0;
            const aliveFuzzersCard = document.getElementById('aliveFuzzersCard');

            if (deadCount > 0) {
                aliveFuzzersCard.classList.add('danger');
            } else {
                aliveFuzzersCard.classList.remove('danger');
            }

            document.getElementById('aliveFuzzers').textContent = summary.alive_fuzzers;
            let statusText = `${summary.total_fuzzers} total`;
            if (deadCount > 0) statusText += `, ${deadCount} dead`;
            if (startingCount > 0) statusText += `, ${startingCount} starting`;
            document.getElementById('fuzzerStatus').textContent = statusText;

            // Runtime
            document.getElementById('totalRuntime').textContent = formatTime(summary.total_runtime || 0);

            // Execution speed
            document.getElementById('totalSpeed').textContent = formatNumber(summary.total_speed.toFixed(0)) + '/s';
            document.getElementById('avgSpeedPerCore').textContent = (summary.avg_speed_per_core || 0).toFixed(0) + '/s';

            // Total executions
            document.getElementById('totalExecs').textContent = formatNumber(summary.total_execs);

            // Coverage
            document.getElementById('coverage').textContent = summary.max_coverage.toFixed(1) + '%';
            document.getElementById('coverageBar').style.width = Math.min(summary.max_coverage, 100) + '%';

            // Crashes & Hangs with new findings
            document.getElementById('crashes').textContent = summary.total_crashes;
            document.getElementById('hangs').textContent = summary.total_hangs;
            let newFindingsText = '';
            if (summary.new_crashes > 0) newFindingsText += `(+${summary.new_crashes}!)`;
            if (summary.new_hangs > 0) newFindingsText += ` (+${summary.new_hangs} hangs!)`;
            document.getElementById('newFindings').innerHTML = newFindingsText ?
                `<span style="color: var(--danger); font-weight: 600;">${newFindingsText}</span>` : '';

            // Corpus
            document.getElementById('corpusAll').textContent = formatNumber(summary.total_corpus);

            // Pending paths
            document.getElementById('pendingAll').textContent = formatNumber(summary.total_pending);
            document.getElementById('pendingFavs').textContent = summary.total_pending_favs;

            // Last find
            const lastFindText = formatTimeAgo(summary.last_find_time);
            document.getElementById('lastFind').textContent = lastFindText === 'never' ? 'never' : lastFindText;

            // Cycles
            document.getElementById('avgCycle').textContent = summary.avg_cycle.toFixed(1);
            document.getElementById('maxCycle').textContent = summary.max_cycle;

            // Stability
            document.getElementById('stability').textContent = summary.avg_stability.toFixed(1) + '%';
            document.getElementById('stabilityRange').textContent =
                `${summary.min_stability.toFixed(1)}%-${summary.max_stability.toFixed(1)}%`;

            // Header system metrics with progress bars
            const cpuPercent = Math.min(system.cpu_percent, 100);
            document.getElementById('cpuBar').style.width = cpuPercent + '%';
            document.getElementById('cpuText').textContent = system.cpu_percent.toFixed(1) + '%';

            const memPercent = Math.min(system.memory_percent || 0, 100);
            document.getElementById('ramBar').style.width = memPercent + '%';
            document.getElementById('ramText').textContent =
                `${system.memory_used_gb.toFixed(1)}/${system.memory_total_gb.toFixed(1)} GB`;

            const diskPercent = Math.min(system.disk_percent || 0, 100);
            document.getElementById('diskBar').style.width = diskPercent + '%';
            document.getElementById('diskText').textContent =
                `${(system.disk_used_gb || 0).toFixed(0)}/${(system.disk_total_gb || 0).toFixed(0)} GB`;

            // Fuzzers table
            const tbody = document.getElementById('fuzzersTable');
            tbody.innerHTML = data.fuzzers.map(f => {
                const rowClass = f.status === 'DEAD' ? 'dead' : (f.stability < 80 ? 'warning' : '');
                const warnings = [];
                if (f.stability < 80) warnings.push(`!${f.stability.toFixed(1)}%`);
                if (f.slowest_exec_ms > 100) warnings.push(`slow:${f.slowest_exec_ms}ms`);

                return `
                <tr class="${rowClass}">
                    <td>${f.name}${warnings.length > 0 ? `<span class="warning-badge">${warnings.join(' ')}</span>` : ''}</td>
                    <td><span class="status ${f.status.toLowerCase()}">${f.status}</span></td>
                    <td>${formatTime(f.run_time)}</td>
                    <td>${formatNumber(f.execs_done)}</td>
                    <td>${f.exec_speed.toFixed(0)}/s</td>
                    <td>${f.bitmap_cvg.toFixed(1)}%</td>
                    <td>${f.saved_crashes}</td>
                    <td>${f.corpus_count}</td>
                    <td>${f.stability ? f.stability.toFixed(1) + '%' : 'N/A'}</td>
                </tr>
            `}).join('');

            // Update charts with timestamp tracking
            const timestamp = new Date().toLocaleTimeString();
            const unixTime = Math.floor(Date.now() / 1000);

            if (speedData.length >= maxDataPoints) {
                speedData.shift();
                coverageData.shift();
                pathsData.shift();
                crashesData.shift();
                pendingData.shift();
                timestamps.shift();
            }

            speedData.push(summary.total_speed);
            coverageData.push(summary.max_coverage);
            pathsData.push(summary.total_corpus);
            crashesData.push(summary.total_crashes);
            pendingData.push(summary.total_pending);
            timestamps.push(unixTime);

            // Apply time period filter and update charts
            updateChartsWithFilter();

            // Update last update time
            document.getElementById('lastUpdate').textContent = 'Last update: ' + timestamp;
        }

        async function fetchData() {
            try {
                const response = await fetch('/api/stats');
                const data = await response.json();
                updateDashboard(data);
            } catch (error) {
                console.error('Error fetching data:', error);
            }
        }

        // Load saved preferences
        const savedInterval = localStorage.getItem('refreshInterval');
        if (savedInterval) {
            refreshInterval = parseInt(savedInterval);
            document.getElementById('refreshSelect').value = refreshInterval;
        } else {
            // Set default from server
            document.getElementById('refreshSelect').value = refreshInterval;
        }

        const savedTimePeriod = localStorage.getItem('timePeriod');
        if (savedTimePeriod) {
            timePeriod = savedTimePeriod;
            document.getElementById('timePeriodSelect').value = timePeriod;
        }

        // Initial fetch
        fetchData();

        // Auto-refresh
        refreshIntervalId = setInterval(fetchData, refreshInterval * 1000);
    </script>
</body>
</html>
"""


class WebServer:
    """Web server for AFL Overseer dashboard with thread-safe request handling."""

    def __init__(self, findings_dir: Path, refresh_interval: int = 5):
        self.findings_dir = findings_dir
        self.refresh_interval = refresh_interval
        self.app = web.Application()
        self.setup_routes()

        # Create monitor config
        self.config = MonitorConfig(
            findings_dir=findings_dir,
            output_format=['terminal'],
            verbose=False,
            no_color=False,
            watch_mode=False,
            watch_interval=refresh_interval,
            execute_command=None,
            show_dead=True,  # Always include dead fuzzers in API
            minimal=False,
            html_dir=None,
            json_file=None,
        )

        self.monitor = AFLMonitor(self.config)

        # Async lock for thread-safe request handling (prevents concurrent stats collection)
        self._stats_lock = asyncio.Lock()

    def setup_routes(self):
        """Setup web server routes."""
        self.app.router.add_get('/', self.handle_index)
        self.app.router.add_get('/api/stats', self.handle_stats)

    async def handle_index(self, request):
        """Serve the main dashboard HTML."""
        html = HTML_TEMPLATE.replace('REFRESH_INTERVAL', str(self.refresh_interval))
        return web.Response(text=html, content_type='text/html')

    async def handle_stats(self, request):
        """
        API endpoint for fuzzer statistics with thread-safe handling.
        Uses async lock to prevent concurrent request interference.
        """
        # Acquire lock to prevent concurrent stats collection
        async with self._stats_lock:
            try:
                # Load previous state (non-critical)
                try:
                    self.monitor.load_previous_state()
                except Exception:
                    pass  # State loading is non-critical

                # Collect statistics (runs in thread pool, but protected by async lock)
                try:
                    loop = asyncio.get_event_loop()
                    all_stats, summary = await loop.run_in_executor(
                        None, self.monitor.collect_stats
                    )
                except Exception as e:
                    logging.error(f"Failed to collect stats: {e}")
                    return web.json_response(
                        {'error': 'Failed to collect statistics', 'detail': str(e)},
                        status=500
                    )

                # Get system info with fallback (run in executor to avoid blocking)
                try:
                    system_info = await loop.run_in_executor(
                        None, ProcessMonitor.get_system_info
                    )
                except Exception as e:
                    logging.warning(f"Failed to get system info: {e}")
                    system_info = {
                        'cpu_count': 0, 'cpu_percent': 0,
                        'memory_total_gb': 0, 'memory_used_gb': 0, 'memory_percent': 0
                    }

                # Save state (non-critical)
                try:
                    self.monitor.save_current_state(summary)
                except Exception:
                    pass  # State saving is non-critical

                # Format response with FULL suite of information
                response_data = {
                    'summary': {
                        # Fuzzer counts
                        'total_fuzzers': summary.total_fuzzers,
                        'alive_fuzzers': summary.alive_fuzzers,
                        'dead_fuzzers': summary.dead_fuzzers,
                        'starting_fuzzers': summary.starting_fuzzers,

                        # Runtime
                        'total_runtime': summary.total_runtime,

                        # Execution stats
                        'total_execs': summary.total_execs,
                        'total_speed': summary.total_speed,
                        'avg_speed_per_core': summary.avg_speed_per_core,
                        'current_avg_speed': summary.current_avg_speed,

                        # Coverage
                        'max_coverage': summary.max_coverage,

                        # Findings
                        'total_crashes': summary.total_crashes,
                        'total_hangs': summary.total_hangs,
                        'new_crashes': summary.new_crashes,
                        'new_hangs': summary.new_hangs,

                        # Corpus stats
                        'total_corpus': summary.total_corpus,
                        'total_pending': summary.total_pending,
                        'total_pending_favs': summary.total_pending_favs,

                        # Last activity
                        'last_find_time': summary.last_find_time,
                        'last_crash_time': summary.last_crash_time,
                        'last_hang_time': summary.last_hang_time,

                        # Cycles
                        'max_cycle': summary.max_cycle,
                        'avg_cycle': summary.avg_cycle,
                        'cycles_wo_finds': summary.cycles_wo_finds,

                        # Stability
                        'avg_stability': summary.avg_stability,
                        'min_stability': summary.min_stability,
                        'max_stability': summary.max_stability,

                        # Advanced metrics
                        'total_edges_found': summary.total_edges_found,
                        'max_total_edges': summary.max_total_edges,
                    },
                    'system': {
                        'cpu_count': system_info.get('cpu_count', 0),
                        'cpu_percent': system_info.get('cpu_percent', 0),
                        'memory_total_gb': system_info.get('memory_total_gb', 0),
                        'memory_used_gb': system_info.get('memory_used_gb', 0),
                        'memory_percent': system_info.get('memory_percent', 0),
                        'disk_total_gb': system_info.get('disk_total_gb', 0),
                        'disk_used_gb': system_info.get('disk_used_gb', 0),
                        'disk_percent': system_info.get('disk_percent', 0),
                    },
                    'fuzzers': [
                        {
                            'name': stats.fuzzer_name,
                            'status': stats.status.value if hasattr(stats.status, 'value') else str(stats.status),
                            'run_time': stats.run_time,
                            'execs_done': stats.execs_done,
                            'exec_speed': stats.execs_per_sec,
                            'bitmap_cvg': stats.bitmap_cvg,
                            'saved_crashes': stats.saved_crashes,
                            'saved_hangs': stats.saved_hangs,
                            'corpus_count': stats.corpus_count,
                            'stability': stats.stability,
                            'cpu_percent': stats.cpu_usage,
                            'memory_percent': stats.memory_usage,
                            'slowest_exec_ms': stats.slowest_exec_ms,
                            'exec_timeout': stats.exec_timeout,
                        }
                        for stats in all_stats
                    ]
                }

                return web.json_response(response_data)

            except Exception as e:
                logging.error(f"Unexpected error in stats endpoint: {e}")
                return web.json_response(
                    {'error': 'Internal server error', 'detail': str(e)},
                    status=500
                )


def _run_web_server_in_thread(findings_dir: Path, port: int, refresh_interval: int):
    """Run web server in background thread with its own event loop."""
    # Create new event loop for this thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    server = WebServer(findings_dir, refresh_interval)

    async def _start_server():
        runner = web.AppRunner(server.app)
        await runner.setup()

        try:
            site = web.TCPSite(runner, '0.0.0.0', port)
            await site.start()

            print(f"\nAFL Overseer Dashboard")
            print(f"   Local:    http://localhost:{port}")
            print(f"   Network:  http://0.0.0.0:{port}")
            print(f"   Mode:     With TUI")
            print(f"   Refresh:  {refresh_interval}s\n")

            # Keep running until interrupted
            await asyncio.Event().wait()
        except OSError as e:
            if "Address already in use" in str(e) or "Errno 98" in str(e):
                print(f"\nError: Port {port} is already in use")
                print(f"   Try a different port with: -p <port_number>")
                print(f"   Or stop the process using port {port}\n")
            else:
                print(f"\nError starting server: {e}\n")
        finally:
            await runner.cleanup()

    try:
        loop.run_until_complete(_start_server())
    except Exception as e:
        logging.error(f"Web server error: {e}")
    finally:
        loop.close()


def start_web_server_background(
    findings_dir: Path,
    port: int = 8080,
    refresh_interval: int = 5
) -> threading.Thread:
    """
    Start web server in a background thread.

    Returns the thread object so caller can manage it.
    """
    web_thread = threading.Thread(
        target=_run_web_server_in_thread,
        args=(findings_dir, port, refresh_interval),
        daemon=True
    )
    web_thread.start()
    # Give web server a moment to start
    import time
    time.sleep(1)
    return web_thread


async def run_web_server(
    findings_dir: Path,
    port: int = 8080,
    headless: bool = False,
    refresh_interval: int = 5
):
    """
    Run the web server for AFL Monitor dashboard.

    Args:
        findings_dir: Path to AFL sync directory
        port: Port to run server on
        headless: If True, run without TUI. If False, start web in background and signal to run TUI
        refresh_interval: Data refresh interval in seconds
    """
    # If not headless, we can't run TUI from here due to async/signal issues
    # Signal back to caller to handle TUI in main thread
    if not headless:
        # This should not be called - CLI should handle non-headless mode differently
        raise RuntimeError(
            "Non-headless mode must be handled by starting web server in background "
            "and TUI in main thread. Use start_web_server_background() instead."
        )

    # Headless mode - run web server in main async context
    server = WebServer(findings_dir, refresh_interval)

    try:
        runner = web.AppRunner(server.app)
        await runner.setup()

        try:
            site = web.TCPSite(runner, '0.0.0.0', port)
            await site.start()
        except OSError as e:
            if "Address already in use" in str(e) or "Errno 98" in str(e):
                print(f"\nError: Port {port} is already in use")
                print(f"   Try a different port with: -p <port_number>")
                print(f"   Or stop the process using port {port}\n")
            else:
                print(f"\nError starting server: {e}\n")
            await runner.cleanup()
            return

        print(f"\nAFL Overseer Dashboard")
        print(f"   Local:    http://localhost:{port}")
        print(f"   Network:  http://0.0.0.0:{port}")
        print(f"   Mode:     Headless")
        print(f"   Refresh:  {refresh_interval}s\n")
        print("Press Ctrl+C to stop...\n")

        # Keep server running in headless mode
        try:
            await asyncio.Event().wait()
        except KeyboardInterrupt:
            print("\n\nShutting down...\n")
        finally:
            await runner.cleanup()

    except Exception as e:
        logging.error(f"Failed to start web server: {e}")
        print(f"\nFatal error: {e}\n")
        raise
