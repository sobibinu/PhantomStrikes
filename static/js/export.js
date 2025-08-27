// PhantomStrike - Export Functionality

document.addEventListener('DOMContentLoaded', function() {
    // Initialize export dropdowns
    initExportDropdowns();
    
    // Add event listeners for export buttons
    setupExportButtons();
});

/**
 * Initialize export dropdowns
 */
function initExportDropdowns() {
    const exportDropdowns = document.querySelectorAll('.dropdown-container');
    
    exportDropdowns.forEach(dropdown => {
        const button = dropdown.querySelector('button');
        const menu = dropdown.querySelector('.dropdown-menu');
        
        if (button && menu) {
            // Toggle menu on button click
            button.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                menu.classList.toggle('hidden');
            });
            
            // Close when clicking outside
            document.addEventListener('click', function(e) {
                if (!dropdown.contains(e.target)) {
                    menu.classList.add('hidden');
                }
            });
        }
    });
}

/**
 * Set up export buttons functionality
 */
function setupExportButtons() {
    // JSON Export
    const jsonExportButtons = document.querySelectorAll('[data-export="json"]');
    jsonExportButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            const scanId = this.dataset.scanId;
            if (scanId) {
                exportScanResult(scanId, 'json');
            }
        });
    });
    
    // CSV Export
    const csvExportButtons = document.querySelectorAll('[data-export="csv"]');
    csvExportButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            const scanId = this.dataset.scanId;
            if (scanId) {
                exportScanResult(scanId, 'csv');
            }
        });
    });
    
    // PDF Export
    const pdfExportButtons = document.querySelectorAll('[data-export="pdf"]');
    pdfExportButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            const scanId = this.dataset.scanId;
            if (scanId) {
                exportScanResult(scanId, 'pdf');
            }
        });
    });
}

/**
 * Export scan result in the specified format
 */
function exportScanResult(scanId, format) {
    // Show loading state
    const exportButton = document.querySelector(`[data-export="${format}"][data-scan-id="${scanId}"]`);
    if (exportButton) {
        const originalContent = exportButton.innerHTML;
        exportButton.innerHTML = `<i class="fas fa-spinner fa-spin mr-2"></i> Exporting...`;
        exportButton.disabled = true;
        
        // Restore button state after export complete or failed
        const restoreButton = () => {
            exportButton.innerHTML = originalContent;
            exportButton.disabled = false;
        };
        
        // Timeout to reset button if export takes too long
        setTimeout(restoreButton, 10000);
    }
    
    // Create export URL
    const exportUrl = `/export/${scanId}/${format}`;
    
    // For different export types
    if (format === 'json' || format === 'csv' || format === 'pdf') {
        // Create hidden iframe or use file download
        try {
            // Create a hidden link and click it
            const link = document.createElement('a');
            link.href = exportUrl;
            link.download = `scan_result_${scanId}.${format}`;
            link.target = '_blank';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            
            // Show success message
            createToast(`Export successful. Download starting...`, 'success');
            
            // Reset button
            if (exportButton) setTimeout(() => {
                exportButton.innerHTML = originalContent;
                exportButton.disabled = false;
            }, 1000);
        } catch (e) {
            console.error('Export failed:', e);
            createToast('Export failed. Please try again.', 'error');
            
            // Reset button immediately on error
            if (exportButton) {
                exportButton.innerHTML = originalContent;
                exportButton.disabled = false;
            }
        }
    }
}

/**
 * Export all scan results for a user
 */
function exportAllScanResults(format = 'json') {
    // Show loading message
    createToast('Preparing export of all scan results...', 'info');
    
    // Get all scan IDs
    fetch('/api/scan/all')
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to fetch scan list');
            }
            return response.json();
        })
        .then(data => {
            if (data && data.length > 0) {
                // For simplicity, just redirect to export the most recent scan
                // In a real implementation, this would need to support multiple scan exports
                const mostRecentScanId = data[0].id;
                window.location.href = `/export/${mostRecentScanId}/${format}`;
            } else {
                createToast('No scan results found to export', 'warning');
            }
        })
        .catch(error => {
            console.error('Export all failed:', error);
            createToast('Failed to export scan results. Please try again.', 'error');
        });
}

/**
 * Create a CSV from scan data
 */
function createCSVFromScanData(scanData) {
    // CSV header
    let csv = 'Type,Severity,Location,Description,Evidence,Remediation\n';
    
    // Add vulnerabilities to CSV
    if (scanData.vulnerabilities && scanData.vulnerabilities.length > 0) {
        scanData.vulnerabilities.forEach(vuln => {
            // Escape fields that might have commas
            const escapeCsvField = (field) => {
                field = field ? String(field).replace(/"/g, '""') : '';
                // If field contains comma, newline or double-quote, enclose in double quotes
                if (field.includes(',') || field.includes('\n') || field.includes('"')) {
                    return `"${field}"`;
                }
                return field;
            };
            
            // Add row to CSV
            csv += [
                escapeCsvField(vuln.vulnerability_type),
                escapeCsvField(vuln.severity),
                escapeCsvField(vuln.location),
                escapeCsvField(vuln.description),
                escapeCsvField(vuln.evidence),
                escapeCsvField(vuln.remediation)
            ].join(',') + '\n';
        });
    }
    
    return csv;
}

/**
 * Create a download link for a string
 */
function createDownloadLink(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    
    // Trigger the download
    document.body.appendChild(link);
    link.click();
    
    // Clean up
    setTimeout(() => {
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    }, 100);
}

/**
 * Create a toast notification
 */
function createToast(message, type = 'info', duration = 3000) {
    // Create toast container if it doesn't exist
    let toastContainer = document.getElementById('toast-container');
    
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.id = 'toast-container';
        toastContainer.className = 'fixed bottom-5 right-5 z-50 flex flex-col space-y-2';
        document.body.appendChild(toastContainer);
    }
    
    // Set color based on type
    let bgColor, textColor, icon;
    switch (type) {
        case 'success':
            bgColor = 'bg-phantom-success';
            textColor = 'text-white';
            icon = '<i class="fas fa-check-circle mr-2"></i>';
            break;
        case 'error':
            bgColor = 'bg-phantom-danger';
            textColor = 'text-white';
            icon = '<i class="fas fa-exclamation-circle mr-2"></i>';
            break;
        case 'warning':
            bgColor = 'bg-phantom-warning';
            textColor = 'text-white';
            icon = '<i class="fas fa-exclamation-triangle mr-2"></i>';
            break;
        default:
            bgColor = 'bg-phantom-info';
            textColor = 'text-white';
            icon = '<i class="fas fa-info-circle mr-2"></i>';
    }
    
    // Create toast element
    const toast = document.createElement('div');
    toast.className = `${bgColor} ${textColor} flex items-center p-3 rounded-lg shadow-lg transform transition-all duration-300 opacity-0 translate-x-full`;
    toast.innerHTML = `
        <div>
            ${icon}
        </div>
        <div>${message}</div>
        <button class="ml-4 text-white focus:outline-none">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    // Add to container
    toastContainer.appendChild(toast);
    
    // Trigger animation
    setTimeout(() => {
        toast.classList.remove('opacity-0', 'translate-x-full');
    }, 10);
    
    // Add close button functionality
    const closeButton = toast.querySelector('button');
    closeButton.addEventListener('click', () => {
        removeToast(toast);
    });
    
    // Auto-remove after duration
    setTimeout(() => {
        removeToast(toast);
    }, duration);
}

/**
 * Remove a toast with animation
 */
function removeToast(toast) {
    toast.classList.add('opacity-0', 'translate-x-full');
    setTimeout(() => {
        if (toast.parentNode) {
            toast.parentNode.removeChild(toast);
        }
    }, 300);
}
