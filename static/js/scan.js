// PhantomStrike - Scan Page Functionality

document.addEventListener('DOMContentLoaded', function() {
    // Scan type selection
    const scanTypeRadios = document.querySelectorAll('input[name="scan_type"]');
    const scanOptionsContainers = document.querySelectorAll('.scan-options');
    
    // Function to show the correct options based on scan type
    function showScanOptions(scanType) {
        // Hide all options
        scanOptionsContainers.forEach(container => {
            container.classList.remove('active');
        });
        
        // Show the relevant options
        const targetContainer = document.getElementById(`${scanType}ScanOptions`);
        if (targetContainer) {
            targetContainer.classList.add('active');
        }
    }
    
    // Set up event listeners for scan type selection
    scanTypeRadios.forEach(radio => {
        radio.addEventListener('change', function() {
            showScanOptions(this.value);
        });
    });
    
    // Initialize with the correct options displayed
    const initialScanType = document.querySelector('input[name="scan_type"]:checked');
    if (initialScanType) {
        showScanOptions(initialScanType.value);
    }
    
    // URL Validation
    const targetUrlInput = document.getElementById('target_url');
    const validateUrlButton = document.getElementById('validateUrl');
    
    if (validateUrlButton && targetUrlInput) {
        validateUrlButton.addEventListener('click', function() {
            const url = targetUrlInput.value.trim();
            
            if (!url) {
                showValidationError(targetUrlInput, 'Please enter a URL');
                return;
            }
            
            // Simple URL validation
            try {
                // Add http:// if not present
                let fullUrl = url;
                if (!url.match(/^https?:\/\//i)) {
                    fullUrl = 'http://' + url;
                    targetUrlInput.value = fullUrl;
                }
                
                // Attempt to create a URL object (will throw if invalid)
                new URL(fullUrl);
                
                showValidationSuccess(targetUrlInput, 'URL format is valid');
            } catch (e) {
                showValidationError(targetUrlInput, 'Invalid URL format');
            }
        });
    }
    
    // Form validation before submission
    const scanForm = document.getElementById('scanForm');
    const startScanButton = document.getElementById('startScanButton');
    
    if (scanForm) {
        scanForm.addEventListener('submit', function(e) {
            // Validate URL
            const url = targetUrlInput.value.trim();
            
            if (!url) {
                e.preventDefault();
                showValidationError(targetUrlInput, 'Please enter a URL');
                return;
            }
            
            try {
                // Add http:// if not present
                let fullUrl = url;
                if (!url.match(/^https?:\/\//i)) {
                    fullUrl = 'http://' + url;
                    targetUrlInput.value = fullUrl;
                }
                
                // Attempt to create a URL object (will throw if invalid)
                new URL(fullUrl);
            } catch (error) {
                e.preventDefault();
                showValidationError(targetUrlInput, 'Invalid URL format');
                return;
            }
            
            // Show loading state
            if (startScanButton) {
                startScanButton.disabled = true;
                startScanButton.innerHTML = `
                    <svg class="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Starting Scan...
                `;
            }
        });
    }
    
    // Load recent scans for authenticated users
    loadRecentScans();
    
    // Visual highlighting for scan cards on selection
    const scanCards = document.querySelectorAll('.scan-card');
    
    scanCards.forEach(card => {
        const radioInput = card.querySelector('input[type="radio"]');
        
        if (radioInput) {
            // Set initial state
            if (radioInput.checked) {
                card.classList.add('border-phantom-accent');
            }
            
            // Update on change
            radioInput.addEventListener('change', function() {
                // Remove highlight from all cards
                scanCards.forEach(c => {
                    c.classList.remove('border-phantom-accent');
                });
                
                // Add highlight to the selected card
                if (this.checked) {
                    card.classList.add('border-phantom-accent');
                }
            });
        }
    });
});

/**
 * Show a validation error on an input field
 */
function showValidationError(inputElement, message) {
    // Remove any existing validation messages
    removeValidationMessages(inputElement);
    
    // Add error styling
    inputElement.classList.add('border-red-500');
    
    // Create error message
    const errorDiv = document.createElement('div');
    errorDiv.className = 'text-red-500 text-xs mt-1 validation-message';
    errorDiv.innerText = message;
    
    // Add after the input
    inputElement.parentNode.insertBefore(errorDiv, inputElement.nextSibling);
}

/**
 * Show a validation success on an input field
 */
function showValidationSuccess(inputElement, message) {
    // Remove any existing validation messages
    removeValidationMessages(inputElement);
    
    // Add success styling
    inputElement.classList.remove('border-red-500');
    inputElement.classList.add('border-green-500');
    
    // Create success message
    const successDiv = document.createElement('div');
    successDiv.className = 'text-green-500 text-xs mt-1 validation-message';
    successDiv.innerText = message;
    
    // Add after the input
    inputElement.parentNode.insertBefore(successDiv, inputElement.nextSibling);
    
    // Remove the success styling after a delay
    setTimeout(() => {
        inputElement.classList.remove('border-green-500');
        removeValidationMessages(inputElement);
    }, 3000);
}

/**
 * Remove any validation messages for an input
 */
function removeValidationMessages(inputElement) {
    // Remove styling
    inputElement.classList.remove('border-red-500', 'border-green-500');
    
    // Remove any existing validation messages
    const parent = inputElement.parentNode;
    const validationMessages = parent.querySelectorAll('.validation-message');
    validationMessages.forEach(el => el.remove());
}

/**
 * Load recent scans for the user
 */
function loadRecentScans() {
    const recentScansContainer = document.getElementById('recentScans');
    if (!recentScansContainer) return;
    
    // Try to fetch recent scans from the API
    fetch('/api/scan/result/0')
        .then(response => {
            if (response.ok) {
                return response.json();
            }
            throw new Error('Failed to load recent scans');
        })
        .then(data => {
            // If there are scans to display
            if (data && data.length > 0) {
                const scansList = document.createElement('ul');
                scansList.className = 'divide-y divide-phantom-primary';
                
                // Create list items for each scan
                data.forEach(scan => {
                    const li = document.createElement('li');
                    li.className = 'py-2';
                    
                    // Determine status badge class
                    let statusBadgeClass = 'bg-blue-800 text-blue-100';
                    if (scan.status === 'completed') {
                        statusBadgeClass = 'bg-green-800 text-green-100';
                    } else if (scan.status === 'failed') {
                        statusBadgeClass = 'bg-red-800 text-red-100';
                    }
                    
                    // Format the scan item
                    li.innerHTML = `
                        <a href="/scan_result/${scan.id}" class="block hover:bg-phantom-primary p-2 rounded transition duration-200">
                            <div class="flex justify-between items-center">
                                <div class="text-sm text-white truncate max-w-xs">
                                    ${scan.target_url}
                                </div>
                                <span class="px-2 py-1 text-xs rounded-full ${statusBadgeClass}">
                                    ${scan.status}
                                </span>
                            </div>
                            <div class="mt-1 flex justify-between text-xs text-gray-400">
                                <div>
                                    ${scan.scan_type} scan
                                </div>
                                <div class="flex space-x-1">
                                    <span class="text-red-400">H:${scan.high_severity || 0}</span>
                                    <span class="text-yellow-400">M:${scan.medium_severity || 0}</span>
                                    <span class="text-green-400">L:${scan.low_severity || 0}</span>
                                </div>
                            </div>
                        </a>
                    `;
                    
                    scansList.appendChild(li);
                });
                
                // Clear and append to container
                recentScansContainer.innerHTML = '';
                recentScansContainer.appendChild(scansList);
            } else {
                // No scans to display
                recentScansContainer.innerHTML = `
                    <p class="text-gray-400 text-center py-4">
                        No recent scans found. Start a new scan to see results here.
                    </p>
                `;
            }
        })
        .catch(error => {
            // Show error state
            recentScansContainer.innerHTML = `
                <p class="text-gray-400 text-center py-4">
                    <i class="fas fa-exclamation-circle text-phantom-warning mr-2"></i>
                    Could not load recent scans
                </p>
            `;
            console.error('Error loading recent scans:', error);
        });
}

/**
 * Start a new scan via API
 */
function startScanViaApi(targetUrl, scanType, customOptions = {}) {
    // Create request payload
    const payload = {
        target_url: targetUrl,
        scan_type: scanType,
        custom_options: customOptions
    };
    
    // Make API request
    return fetch('/api/scan/start', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${getAuthToken()}`
        },
        body: JSON.stringify(payload)
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Failed to start scan');
        }
        return response.json();
    });
}

/**
 * Get authentication token from session storage or cookie
 */
function getAuthToken() {
    // Try to get from sessionStorage
    const token = sessionStorage.getItem('jwt_token');
    if (token) return token;
    
    // Try to get from cookie
    return getCookie('jwt_token');
}

/**
 * Get cookie value by name
 */
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return null;
}
