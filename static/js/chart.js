// PhantomStrike - Chart Utilities

document.addEventListener('DOMContentLoaded', function() {
    // Configure global chart.js settings
    if (typeof Chart !== 'undefined') {
        // Set default colors to match the theme
        Chart.defaults.color = '#A0AEC0';
        Chart.defaults.borderColor = '#4A5568';
        
        // Override the default tooltip styles 
        Chart.defaults.plugins.tooltip.backgroundColor = '#1A202C';
        Chart.defaults.plugins.tooltip.titleColor = '#E2E8F0';
        Chart.defaults.plugins.tooltip.bodyColor = '#E2E8F0';
        Chart.defaults.plugins.tooltip.borderColor = '#4A5568';
        Chart.defaults.plugins.tooltip.borderWidth = 1;
        
        // Custom tooltip title formatter
        Chart.defaults.plugins.tooltip.callbacks.title = function(tooltipItems) {
            return tooltipItems[0].label;
        };
        
        // Custom tooltip label formatter
        Chart.defaults.plugins.tooltip.callbacks.label = function(context) {
            let label = context.dataset.label || '';
            if (label) {
                label += ': ';
            }
            
            if (context.parsed.y !== null) {
                label += context.parsed.y;
            }
            
            return label;
        };
    }
    
    // Initialize all charts on the page
    initializeCharts();
});

/**
 * Initialize all charts on the page
 */
function initializeCharts() {
    // Vulnerability Distribution Charts
    const vulnerabilityCharts = document.querySelectorAll('[id^="vulnerabilityChart"]');
    
    vulnerabilityCharts.forEach(chartCanvas => {
        // Get data from data attributes or from parent element
        let highCount = parseInt(chartCanvas.dataset.high || 0);
        let mediumCount = parseInt(chartCanvas.dataset.medium || 0);
        let lowCount = parseInt(chartCanvas.dataset.low || 0);
        
        // If no data attributes, try to find elements in the DOM with these counts
        if (!chartCanvas.dataset.high) {
            const parent = chartCanvas.closest('.chart-container') || document;
            const highElement = parent.querySelector('.high-count, [data-severity="high"]');
            const mediumElement = parent.querySelector('.medium-count, [data-severity="medium"]');
            const lowElement = parent.querySelector('.low-count, [data-severity="low"]');
            
            if (highElement) highCount = parseInt(highElement.textContent || '0');
            if (mediumElement) mediumCount = parseInt(mediumElement.textContent || '0');
            if (lowElement) lowCount = parseInt(lowElement.textContent || '0');
        }
        
        // Create the chart
        createVulnerabilityChart(chartCanvas, highCount, mediumCount, lowCount);
    });
    
    // Timeline Charts for scan history
    const timelineCharts = document.querySelectorAll('[id^="timelineChart"]');
    
    timelineCharts.forEach(chartCanvas => {
        // Check if there's a data source element
        const dataSourceId = chartCanvas.dataset.source;
        let timelineData = [];
        
        if (dataSourceId) {
            const dataSource = document.getElementById(dataSourceId);
            if (dataSource && dataSource.value) {
                try {
                    timelineData = JSON.parse(dataSource.value);
                } catch (e) {
                    console.error('Invalid JSON data for timeline chart:', e);
                }
            }
        }
        
        createTimelineChart(chartCanvas, timelineData);
    });
    
    // Scan Progress Charts
    const progressCharts = document.querySelectorAll('[id^="progressChart"]');
    
    progressCharts.forEach(chartCanvas => {
        const progress = parseInt(chartCanvas.dataset.progress || 0);
        createProgressChart(chartCanvas, progress);
    });
}

/**
 * Create a doughnut chart for vulnerability distribution
 */
function createVulnerabilityChart(canvas, highCount, mediumCount, lowCount) {
    if (!canvas || typeof Chart === 'undefined') return;
    
    // Clear any existing chart
    if (canvas.chart) {
        canvas.chart.destroy();
    }
    
    // Create the chart
    canvas.chart = new Chart(canvas, {
        type: 'doughnut',
        data: {
            labels: ['High', 'Medium', 'Low'],
            datasets: [{
                data: [highCount, mediumCount, lowCount],
                backgroundColor: [
                    '#F56565', // red for high
                    '#ED8936', // orange for medium
                    '#48BB78'  // green for low
                ],
                borderColor: '#2D3748',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        fontColor: '#E2E8F0',
                        fontSize: 12,
                        padding: 20
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.raw || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = Math.round((value / total) * 100);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            },
            cutout: '70%'
        }
    });
}

/**
 * Create a line chart for scan history timeline
 */
function createTimelineChart(canvas, data) {
    if (!canvas || typeof Chart === 'undefined') return;
    
    // Clear any existing chart
    if (canvas.chart) {
        canvas.chart.destroy();
    }
    
    // Format the data
    const labels = data.map(item => item.date || item.timestamp || '');
    const highData = data.map(item => item.high || 0);
    const mediumData = data.map(item => item.medium || 0);
    const lowData = data.map(item => item.low || 0);
    
    // Create the chart
    canvas.chart = new Chart(canvas, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'High',
                    data: highData,
                    borderColor: '#F56565',
                    backgroundColor: 'rgba(245, 101, 101, 0.2)',
                    tension: 0.2,
                    fill: true
                },
                {
                    label: 'Medium',
                    data: mediumData,
                    borderColor: '#ED8936',
                    backgroundColor: 'rgba(237, 137, 54, 0.2)',
                    tension: 0.2,
                    fill: true
                },
                {
                    label: 'Low',
                    data: lowData,
                    borderColor: '#48BB78',
                    backgroundColor: 'rgba(72, 187, 120, 0.2)',
                    tension: 0.2,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'top',
                },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                }
            },
            scales: {
                x: {
                    display: true,
                    title: {
                        display: true,
                        text: 'Date'
                    }
                },
                y: {
                    display: true,
                    title: {
                        display: true,
                        text: 'Vulnerabilities'
                    },
                    min: 0,
                    suggestedMax: 10
                }
            }
        }
    });
}

/**
 * Create a progress gauge chart
 */
function createProgressChart(canvas, progress) {
    if (!canvas || typeof Chart === 'undefined') return;
    
    // Ensure progress is between 0 and 100
    progress = Math.min(100, Math.max(0, progress));
    
    // Clear any existing chart
    if (canvas.chart) {
        canvas.chart.destroy();
    }
    
    // Create the chart
    canvas.chart = new Chart(canvas, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [progress, 100 - progress],
                backgroundColor: [
                    '#4FD1C5', // teal for completed
                    '#2D3748'  // dark for remaining
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            circumference: 180,
            rotation: 270,
            cutout: '80%',
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    enabled: false
                }
            }
        }
    });
    
    // Add center text
    const ctx = canvas.getContext('2d');
    ctx.font = 'bold 24px Arial';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = '#E2E8F0';
    ctx.fillText(`${progress}%`, canvas.width / 2, canvas.height / 2 + 20);
}

/**
 * Update a vulnerability chart with new data
 */
function updateVulnerabilityChart(chartId, highCount, mediumCount, lowCount) {
    const canvas = document.getElementById(chartId);
    if (!canvas || !canvas.chart) return;
    
    canvas.chart.data.datasets[0].data = [highCount, mediumCount, lowCount];
    canvas.chart.update();
}

/**
 * Update a progress chart with new percentage
 */
function updateProgressChart(chartId, progress) {
    const canvas = document.getElementById(chartId);
    if (!canvas || !canvas.chart) return;
    
    // Ensure progress is between 0 and 100
    progress = Math.min(100, Math.max(0, progress));
    
    canvas.chart.data.datasets[0].data = [progress, 100 - progress];
    canvas.chart.update();
    
    // Update center text
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    canvas.chart.draw();
    
    ctx.font = 'bold 24px Arial';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = '#E2E8F0';
    ctx.fillText(`${progress}%`, canvas.width / 2, canvas.height / 2 + 20);
}

/**
 * Create a simple bar chart for comparing multiple values
 */
function createBarChart(canvas, labels, data, colors) {
    if (!canvas || typeof Chart === 'undefined') return;
    
    // Clear any existing chart
    if (canvas.chart) {
        canvas.chart.destroy();
    }
    
    // Default colors if not provided
    if (!colors) {
        colors = [
            '#4FD1C5', // phantom-accent
            '#48BB78', // phantom-success
            '#4299E1', // phantom-info
            '#ED8936', // phantom-warning
            '#F56565'  // phantom-danger
        ];
    }
    
    // Create background colors array
    const backgroundColor = data.map((_, index) => colors[index % colors.length]);
    
    // Create the chart
    canvas.chart = new Chart(canvas, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: backgroundColor,
                borderColor: '#2D3748',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}
