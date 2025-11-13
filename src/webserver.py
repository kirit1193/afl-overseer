"""Web server for AFL Overseer dashboard."""

import asyncio
import json
import logging
from pathlib import Path
from typing import Optional
import threading

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
            padding: 12px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: 0 2px 8px var(--shadow);
        }

        .header h1 {
            font-size: 18px;
            font-weight: 600;
            color: var(--accent);
        }

        .header-info {
            display: flex;
            gap: 20px;
            align-items: center;
            font-size: 12px;
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
            max-width: 1600px;
            margin: 0 auto;
            padding: 20px;
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
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }

        .metric-card {
            background: var(--bg-secondary);
            padding: 15px;
            border-radius: 8px;
            border: 1px solid var(--border);
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .metric-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px var(--shadow);
        }

        .metric-card.warning {
            border-color: var(--warning);
            background: rgba(255, 170, 0, 0.05);
        }

        .metric-card.danger {
            border-color: var(--danger);
            background: rgba(255, 68, 68, 0.05);
        }

        .metric-label {
            font-size: 11px;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
        }

        .metric-value {
            font-size: 24px;
            font-weight: 600;
            color: var(--text-primary);
        }

        .metric-subvalue {
            font-size: 12px;
            color: var(--text-secondary);
            margin-top: 4px;
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

            .header-info {
                flex-direction: column;
                gap: 8px;
                align-items: flex-end;
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
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>⚡ AFL Overseer Dashboard</h1>
        <div class="header-info">
            <button class="theme-toggle" onclick="toggleTheme()">🌓 Theme</button>
            <div class="status-badge live">● LIVE</div>
            <div id="lastUpdate">Last update: --:--:--</div>
            <div>Refresh: <span id="refreshInterval">5</span>s</div>
        </div>
    </div>

    <div class="container">
        <div id="alerts" class="alerts"></div>

        <div class="tabs">
            <button class="tab active" onclick="switchTab('overview')">Overview</button>
            <button class="tab" onclick="switchTab('fuzzers')">Fuzzers</button>
            <button class="tab" onclick="switchTab('graphs')">Graphs</button>
            <button class="tab" onclick="switchTab('system')">System</button>
        </div>

        <div id="overview" class="tab-content active">
            <div class="metrics-grid">
                <div class="metric-card" id="aliveFuzzersCard">
                    <div class="metric-label">Active Fuzzers</div>
                    <div class="metric-value" id="aliveFuzzers">0</div>
                    <div class="metric-subvalue">of <span id="totalFuzzers">0</span> total</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Total Executions</div>
                    <div class="metric-value" id="totalExecs">0</div>
                    <div class="metric-subvalue"><span id="execsPerSec">0</span>/sec</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Coverage</div>
                    <div class="metric-value" id="coverage">0%</div>
                    <div class="progress-bar"><div class="progress-fill" id="coverageBar" style="width: 0%"></div></div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Crashes Found</div>
                    <div class="metric-value" id="crashes">0</div>
                    <div class="metric-subvalue"><span id="hangs">0</span> hangs</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Corpus Size</div>
                    <div class="metric-value" id="corpusAll">0</div>
                    <div class="metric-subvalue"><span id="corpusFavs">0</span> favored</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Pending Paths</div>
                    <div class="metric-value" id="pendingAll">0</div>
                    <div class="metric-subvalue"><span id="pendingFavs">0</span> favored</div>
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

        <div id="system" class="tab-content">
            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-label">CPU Cores</div>
                    <div class="metric-value" id="cpuCores">0</div>
                    <div class="metric-subvalue"><span id="cpuUsage">0</span>% used</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Memory</div>
                    <div class="metric-value" id="memoryUsed">0 GB</div>
                    <div class="metric-subvalue">of <span id="memoryTotal">0 GB</span></div>
                    <div class="progress-bar"><div class="progress-fill" id="memoryBar" style="width: 0%"></div></div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Avg Cycle</div>
                    <div class="metric-value" id="avgCycle">0</div>
                    <div class="metric-subvalue">Max: <span id="maxCycle">0</span></div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Avg Stability</div>
                    <div class="metric-value" id="stability">0%</div>
                    <div class="metric-subvalue">Range: <span id="stabilityRange">N/A</span></div>
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
        let maxDataPoints = 60;

        // Theme management
        function toggleTheme() {
            const root = document.documentElement;
            const currentTheme = root.getAttribute('data-theme') || 'dark';
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            root.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);

            // Update chart colors
            updateChartTheme(newTheme);
        }

        function loadTheme() {
            const savedTheme = localStorage.getItem('theme') || 'dark';
            document.documentElement.setAttribute('data-theme', savedTheme);
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

        function updateAlerts(data) {
            const alertsDiv = document.getElementById('alerts');
            const alerts = [];

            const summary = data.summary;
            const deadCount = summary.total_fuzzers - summary.alive_fuzzers;

            // Dead fuzzers alert
            if (deadCount > 0) {
                alerts.push({
                    type: 'danger',
                    icon: '⚠️',
                    message: `${deadCount} fuzzer${deadCount > 1 ? 's' : ''} not responding (dead)`
                });
            }

            // Low stability alert
            data.fuzzers.forEach(f => {
                if (f.status === 'ALIVE' && f.stability < 80) {
                    alerts.push({
                        type: 'warning',
                        icon: '⚡',
                        message: `${f.name}: Low stability (${f.stability.toFixed(1)}%)`
                    });
                }
            });

            // High timeout alert
            data.fuzzers.forEach(f => {
                if (f.status === 'ALIVE' && f.slowest_exec_ms > 100) {
                    alerts.push({
                        type: 'warning',
                        icon: '🐌',
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

            // Overview metrics
            const deadCount = summary.total_fuzzers - summary.alive_fuzzers;
            const aliveFuzzersCard = document.getElementById('aliveFuzzersCard');

            if (deadCount > 0) {
                aliveFuzzersCard.classList.add('danger');
            } else {
                aliveFuzzersCard.classList.remove('danger');
            }

            document.getElementById('aliveFuzzers').textContent = summary.alive_fuzzers;
            document.getElementById('totalFuzzers').textContent = summary.total_fuzzers;
            document.getElementById('totalExecs').textContent = formatNumber(summary.total_execs);
            document.getElementById('execsPerSec').textContent = summary.current_speed.toFixed(0);
            document.getElementById('coverage').textContent = summary.max_coverage.toFixed(1) + '%';
            document.getElementById('coverageBar').style.width = summary.max_coverage + '%';
            document.getElementById('crashes').textContent = summary.total_crashes;
            document.getElementById('hangs').textContent = summary.total_hangs;
            document.getElementById('corpusAll').textContent = summary.corpus_count;
            document.getElementById('corpusFavs').textContent = summary.corpus_favored;
            document.getElementById('pendingAll').textContent = summary.pending_total;
            document.getElementById('pendingFavs').textContent = summary.pending_favored;

            // System metrics
            document.getElementById('cpuCores').textContent = system.cpu_cores;
            document.getElementById('cpuUsage').textContent = system.cpu_percent.toFixed(1);
            document.getElementById('memoryUsed').textContent = system.memory_used_gb.toFixed(1);
            document.getElementById('memoryTotal').textContent = system.memory_total_gb.toFixed(1);
            document.getElementById('memoryBar').style.width = system.memory_percent + '%';
            document.getElementById('avgCycle').textContent = summary.avg_cycle.toFixed(1);
            document.getElementById('maxCycle').textContent = summary.max_cycle;
            document.getElementById('stability').textContent = summary.avg_stability.toFixed(1) + '%';
            document.getElementById('stabilityRange').textContent =
                `${summary.min_stability || 0}% - ${summary.max_stability || 0}%`;

            // Fuzzers table
            const tbody = document.getElementById('fuzzersTable');
            tbody.innerHTML = data.fuzzers.map(f => {
                const rowClass = f.status === 'DEAD' ? 'dead' : (f.stability < 80 ? 'warning' : '');
                const warnings = [];
                if (f.stability < 80) warnings.push(`⚡${f.stability.toFixed(1)}%`);
                if (f.slowest_exec_ms > 100) warnings.push(`🐌${f.slowest_exec_ms}ms`);

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

            // Update charts
            const timestamp = new Date().toLocaleTimeString();
            if (speedData.length >= maxDataPoints) {
                speedData.shift();
                coverageData.shift();
                pathsData.shift();
                crashesData.shift();
                pendingData.shift();
                speedChart.data.labels.shift();
            }

            speedData.push(summary.current_speed);
            coverageData.push(summary.max_coverage);
            pathsData.push(summary.corpus_count);
            crashesData.push(summary.total_crashes);
            pendingData.push(summary.pending_total);

            speedChart.data.labels.push(timestamp);
            speedChart.data.datasets[0].data = speedData;
            speedChart.update('none');

            coverageChart.data.labels = speedChart.data.labels;
            coverageChart.data.datasets[0].data = coverageData;
            coverageChart.update('none');

            pathsChart.data.labels = speedChart.data.labels;
            pathsChart.data.datasets[0].data = pathsData;
            pathsChart.data.datasets[1].data = crashesData;
            pathsChart.update('none');

            pendingChart.data.labels = speedChart.data.labels;
            pendingChart.data.datasets[0].data = pendingData;
            pendingChart.update('none');

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

        // Initial fetch
        fetchData();

        // Auto-refresh
        document.getElementById('refreshInterval').textContent = refreshInterval;
        setInterval(fetchData, refreshInterval * 1000);
    </script>
</body>
</html>
"""


class WebServer:
    """Web server for AFL Overseer dashboard."""

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

    def setup_routes(self):
        """Setup web server routes."""
        self.app.router.add_get('/', self.handle_index)
        self.app.router.add_get('/api/stats', self.handle_stats)

    async def handle_index(self, request):
        """Serve the main dashboard HTML."""
        html = HTML_TEMPLATE.replace('REFRESH_INTERVAL', str(self.refresh_interval))
        return web.Response(text=html, content_type='text/html')

    async def handle_stats(self, request):
        """API endpoint for fuzzer statistics."""
        # Load previous state
        self.monitor.load_previous_state()

        # Collect statistics
        all_stats, summary = self.monitor.collect_stats()
        system_info = ProcessMonitor.get_system_info()

        # Save state
        self.monitor.save_current_state(summary)

        # Format response
        response_data = {
            'summary': {
                'alive_fuzzers': summary.alive_fuzzers,
                'total_fuzzers': summary.total_fuzzers,
                'total_execs': summary.total_execs,
                'current_speed': summary.total_speed,
                'avg_speed': summary.current_avg_speed,
                'max_coverage': summary.max_coverage,
                'avg_coverage': summary.max_coverage,
                'total_crashes': summary.total_crashes,
                'total_hangs': summary.total_hangs,
                'corpus_count': summary.total_corpus,
                'corpus_favored': 0,  # Calculate from all_stats
                'pending_total': summary.total_pending,
                'pending_favored': summary.total_pending_favs,
                'avg_stability': summary.avg_stability,
                'min_stability': summary.min_stability,
                'max_stability': summary.max_stability,
                'avg_cycle': summary.avg_cycle,
                'max_cycle': summary.max_cycle,
            },
            'system': {
                'cpu_cores': system_info['cpu_count'],
                'cpu_percent': system_info['cpu_percent'],
                'memory_total_gb': system_info['memory_total_gb'],
                'memory_used_gb': system_info['memory_used_gb'],
                'memory_percent': system_info['memory_percent'],
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
        headless: If True, run without TUI. If False, run TUI in background thread
        refresh_interval: Data refresh interval in seconds
    """
    server = WebServer(findings_dir, refresh_interval)

    # Start TUI in background thread if not headless
    tui_thread = None
    if not headless:
        def run_tui():
            try:
                from .tui import run_interactive_tui
                run_interactive_tui(findings_dir, refresh_interval)
            except Exception as e:
                logging.error(f"TUI error: {e}")

        tui_thread = threading.Thread(target=run_tui, daemon=True)
        tui_thread.start()

    # Start web server
    runner = web.AppRunner(server.app)
    await runner.setup()

    site = web.TCPSite(runner, '0.0.0.0', port)
    await site.start()

    print(f"\n🌐 AFL Overseer Dashboard")
    print(f"   Local:    http://localhost:{port}")
    print(f"   Network:  http://0.0.0.0:{port}")
    print(f"   Mode:     {'Headless' if headless else 'With TUI'}")
    print(f"   Refresh:  {refresh_interval}s\n")
    print("Press Ctrl+C to stop...\n")

    # Keep server running
    try:
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        await runner.cleanup()
