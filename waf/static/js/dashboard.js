// WAF Dashboard JavaScript

// Global variables
let socket;
let attackChart;
let analyticsChart;
let currentPage = 1;
let currentSettings = {};
let currentFilters = {
    ip: '',
    method: '',
    path: '',
    blocked_only: false
};

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    initializeSocket();
    loadSettings();
    loadRules();
    loadMLModels();
    loadBlockedIPs();
    loadAnalytics();
    
    // Set up event listeners
    setupEventListeners();
    
    // Initial load
    refreshStats();
    loadRequests();
    
    // Auto-refresh every 30 seconds
    setInterval(refreshStats, 30000);
});

// Initialize WebSocket connection
function initializeSocket() {
    socket = io();
    
    socket.on('connect', function() {
        updateConnectionStatus(true);
        showNotification('Connected to WAF Dashboard', 'success');
    });
    
    socket.on('disconnect', function() {
        updateConnectionStatus(false);
        showNotification('Disconnected from WAF Dashboard', 'warning');
    });
    
    socket.on('stats_update', function(data) {
        updateDashboardStats(data);
    });
}

// Update connection status
function updateConnectionStatus(connected) {
    const indicator = document.getElementById('status-indicator');
    const icon = indicator.querySelector('i');
    
    if (connected) {
        indicator.textContent = 'Connected';
        indicator.className = 'status-indicator connected';
        icon.className = 'fas fa-circle text-success me-1';
    } else {
        indicator.textContent = 'Disconnected';
        indicator.className = 'status-indicator disconnected';
        icon.className = 'fas fa-circle text-danger me-1';
    }
}

// Setup event listeners
function setupEventListeners() {
    // Tab navigation
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Remove active class from all links
            document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
            
            // Add active class to clicked link
            this.classList.add('active');
            
            // Show corresponding tab
            const target = this.getAttribute('href');
            document.querySelectorAll('.tab-pane').forEach(pane => {
                pane.classList.remove('show', 'active');
            });
            document.querySelector(target).classList.add('show', 'active');
        });
    });
    
    // Settings form listeners
    document.getElementById('confidence-threshold').addEventListener('input', function() {
        document.getElementById('confidence-value').textContent = this.value;
    });
    
    // Blocked only filter
    document.getElementById('blocked-only').addEventListener('change', function() {
        currentFilters.blocked_only = this.checked;
        currentPage = 1;
        loadRequests();
    });
    
    // Filter inputs
    document.getElementById('ip-filter').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            applyFilters();
        }
    });
    
    document.getElementById('path-filter').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            applyFilters();
        }
    });
}

// Load and display statistics
function refreshStats() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            updateDashboardStats(data);
        })
        .catch(error => {
            console.error('Error loading stats:', error);
            showNotification('Error loading statistics', 'error');
        });
}

// Update dashboard statistics
function updateDashboardStats(data) {
    // Update stat cards
    document.getElementById('total-requests').textContent = data.total_requests;
    document.getElementById('allowed-requests').textContent = data.allowed_requests;
    document.getElementById('blocked-requests').textContent = data.blocked_requests;
    document.getElementById('block-rate').textContent = data.block_rate.toFixed(1) + '%';
    
    // Update new stat cards
    if (data.blocked_ips_count !== undefined) {
        document.getElementById('currently-blocked-ips').textContent = data.blocked_ips_count;
    }
    if (data.total_blocked_ips !== undefined) {
        document.getElementById('total-blocked-ips').textContent = data.total_blocked_ips;
    }
    if (data.expired_blocked_ips !== undefined) {
        document.getElementById('expired-blocked-ips').textContent = data.expired_blocked_ips;
    }
    
    // Update attack chart
    updateAttackChart(data.attack_reasons);
    
    // Update recent activity
    updateRecentActivity(data.recent_requests);
}

// Update attack types chart
function updateAttackChart(attackReasons) {
    const ctx = document.getElementById('attackChart');
    
    if (attackChart) {
        attackChart.destroy();
    }
    
    const labels = Object.keys(attackReasons);
    const values = Object.values(attackReasons);
    
    attackChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: [
                    '#e74a3b',
                    '#f6c23e',
                    '#36b9cc',
                    '#1cc88a',
                    '#4e73df',
                    '#858796'
                ],
                borderWidth: 2,
                borderColor: '#fff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });
}

// Update recent activity feed
function updateRecentActivity(requests) {
    const container = document.getElementById('recent-activity');
    container.innerHTML = '';
    
    requests.slice(0, 10).forEach(request => {
        const item = document.createElement('div');
        item.className = 'activity-item fade-in';
        
        const iconClass = request.blocked ? 'danger' : 'success';
        const icon = request.blocked ? 'fa-ban' : 'fa-check';
        
        item.innerHTML = `
            <div class="activity-icon ${iconClass}">
                <i class="fas ${icon}"></i>
            </div>
            <div class="activity-content">
                <div class="fw-bold">${request.remote_addr}</div>
                <div class="text-muted">${request.method} ${request.path}</div>
                <div class="activity-time">${formatTime(request.timestamp)}</div>
            </div>
        `;
        
        container.appendChild(item);
    });
}

// Load requests with pagination and filters
function loadRequests() {
    const url = new URL('/api/requests', window.location.origin);
    url.searchParams.set('page', currentPage);
    url.searchParams.set('per_page', 50);
    url.searchParams.set('blocked_only', currentFilters.blocked_only);
    url.searchParams.set('ip', currentFilters.ip);
    url.searchParams.set('method', currentFilters.method);
    url.searchParams.set('path', currentFilters.path);
    
    fetch(url)
        .then(response => response.json())
        .then(data => {
            displayRequests(data.requests);
            displayPagination(data);
        })
        .catch(error => {
            console.error('Error loading requests:', error);
            showNotification('Error loading requests', 'error');
        });
}

// Apply filters
function applyFilters() {
    currentFilters.ip = document.getElementById('ip-filter').value;
    currentFilters.method = document.getElementById('method-filter').value;
    currentFilters.path = document.getElementById('path-filter').value;
    currentPage = 1;
    loadRequests();
}

// Refresh requests
function refreshRequests() {
    loadRequests();
}

// Display requests in table
function displayRequests(requests) {
    const tbody = document.getElementById('requests-table');
    tbody.innerHTML = '';
    
    if (requests.length === 0) {
        const row = document.createElement('tr');
        row.innerHTML = '<td colspan="8" class="text-center text-muted">No requests found</td>';
        tbody.appendChild(row);
        return;
    }
    
    requests.forEach(request => {
        const row = document.createElement('tr');
        const statusClass = request.blocked ? 'blocked' : 'allowed';
        const statusText = request.blocked ? 'Blocked' : 'Allowed';
        
        // Truncate user agent if too long
        const userAgent = request.user_agent || 'N/A';
        const truncatedUserAgent = userAgent.length > 50 ? userAgent.substring(0, 50) + '...' : userAgent;
        
        row.innerHTML = `
            <td>${formatTime(request.timestamp)}</td>
            <td><code>${request.remote_addr}</code></td>
            <td><span class="badge bg-secondary">${request.method}</span></td>
            <td><code>${request.path}</code></td>
            <td title="${userAgent}">${truncatedUserAgent}</td>
            <td><span class="status-badge ${statusClass}">${statusText}</span></td>
            <td>${request.reason || 'N/A'}</td>
            <td>
                <button class="btn btn-sm btn-outline-primary" onclick="viewRequestDetails('${request._id}')">
                    <i class="fas fa-eye"></i>
                </button>
            </td>
        `;
        
        tbody.appendChild(row);
    });
}

// Display pagination
function displayPagination(data) {
    const pagination = document.getElementById('requests-pagination');
    pagination.innerHTML = '';
    
    const totalPages = data.pages;
    const currentPageNum = data.page;
    
    if (totalPages <= 1) {
        return;
    }
    
    // Previous button
    const prevLi = document.createElement('li');
    prevLi.className = `page-item ${currentPageNum === 1 ? 'disabled' : ''}`;
    prevLi.innerHTML = `<a class="page-link" href="#" onclick="changePage(${currentPageNum - 1})">Previous</a>`;
    pagination.appendChild(prevLi);
    
    // Page numbers
    for (let i = 1; i <= totalPages; i++) {
        if (i === 1 || i === totalPages || (i >= currentPageNum - 2 && i <= currentPageNum + 2)) {
            const li = document.createElement('li');
            li.className = `page-item ${i === currentPageNum ? 'active' : ''}`;
            li.innerHTML = `<a class="page-link" href="#" onclick="changePage(${i})">${i}</a>`;
            pagination.appendChild(li);
        } else if (i === currentPageNum - 3 || i === currentPageNum + 3) {
            const li = document.createElement('li');
            li.className = 'page-item disabled';
            li.innerHTML = '<span class="page-link">...</span>';
            pagination.appendChild(li);
        }
    }
    
    // Next button
    const nextLi = document.createElement('li');
    nextLi.className = `page-item ${currentPageNum === totalPages ? 'disabled' : ''}`;
    nextLi.innerHTML = `<a class="page-link" href="#" onclick="changePage(${currentPageNum + 1})">Next</a>`;
    pagination.appendChild(nextLi);
}

// Change page
function changePage(page) {
    currentPage = page;
    loadRequests();
}

// Load settings
function loadSettings() {
    fetch('/api/settings')
        .then(response => response.json())
        .then(data => {
            currentSettings = data;
            populateSettingsForm(data);
        })
        .catch(error => {
            console.error('Error loading settings:', error);
            showNotification('Error loading settings', 'error');
        });
}

// Populate settings form
function populateSettingsForm(settings) {
    // Rate limiting
    document.getElementById('rate-limiting-enabled').checked = settings.rate_limiting.enabled;
    document.getElementById('max-requests').value = settings.rate_limiting.max_requests;
    document.getElementById('window-seconds').value = settings.rate_limiting.window_seconds;
    document.getElementById('block-time').value = settings.rate_limiting.block_time;
    
    // ML model
    document.getElementById('ml-enabled').checked = settings.ml_model.enabled;
    document.getElementById('confidence-threshold').value = settings.ml_model.confidence_threshold;
    document.getElementById('confidence-value').textContent = settings.ml_model.confidence_threshold;
    
    // Plugins
    document.getElementById('plugin-block-admin').checked = settings.plugins.block_admin;
    document.getElementById('plugin-block-ip').checked = settings.plugins.block_ip;
    document.getElementById('plugin-block-user-agent').checked = settings.plugins.block_user_agent;
}

// Save settings
function saveSettings() {
    const settings = {
        rate_limiting: {
            enabled: document.getElementById('rate-limiting-enabled').checked,
            max_requests: parseInt(document.getElementById('max-requests').value),
            window_seconds: parseInt(document.getElementById('window-seconds').value),
            block_time: parseInt(document.getElementById('block-time').value)
        },
        ml_model: {
            enabled: document.getElementById('ml-enabled').checked,
            confidence_threshold: parseFloat(document.getElementById('confidence-threshold').value)
        },
        plugins: {
            block_admin: document.getElementById('plugin-block-admin').checked,
            block_ip: document.getElementById('plugin-block-ip').checked,
            block_user_agent: document.getElementById('plugin-block-user-agent').checked
        }
    };
    
    fetch('/api/settings', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(settings)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('Settings saved successfully', 'success');
            currentSettings = settings;
        } else {
            showNotification('Error saving settings', 'error');
        }
    })
    .catch(error => {
        console.error('Error saving settings:', error);
        showNotification('Error saving settings', 'error');
    });
}

// Load rules
function loadRules() {
    fetch('/api/rules')
        .then(response => response.json())
        .then(data => {
            updateRulesStats(data);
            displayRules(data.rules);
        })
        .catch(error => {
            console.error('Error loading rules:', error);
            showNotification('Error loading rules', 'error');
        });
}

// Refresh rules
function refreshRules() {
    loadRules();
}

// Update rules statistics
function updateRulesStats(data) {
    document.getElementById('total-rules').textContent = data.total_rules;
    document.getElementById('block-rules').textContent = data.block_rules;
    document.getElementById('log-rules').textContent = data.log_rules;
    document.getElementById('rules-last-modified').textContent = formatTime(data.last_modified);
}

// Display rules
function displayRules(rules) {
    const container = document.getElementById('rules-editor');
    container.innerHTML = '';
    
    if (rules.length === 0) {
        container.innerHTML = '<div class="text-center text-muted">No rules found</div>';
        return;
    }
    
    rules.forEach((rule, index) => {
        const ruleDiv = document.createElement('div');
        ruleDiv.className = 'rule-item';
        
        ruleDiv.innerHTML = `
            <div class="rule-header">
                <span class="rule-id">${rule.id}</span>
                <span class="rule-action ${rule.action}">${rule.action}</span>
            </div>
            <div class="mb-3">
                <label class="form-label">Pattern</label>
                <input type="text" class="form-control rule-pattern" value="${rule.pattern}" data-index="${index}">
                <div class="form-text">Regular expression pattern to match</div>
            </div>
            <div class="mb-3">
                <label class="form-label">Description</label>
                <input type="text" class="form-control rule-description" value="${rule.description}" data-index="${index}">
                <div class="form-text">Human-readable description of the rule</div>
            </div>
            <div class="mb-3">
                <label class="form-label">Action</label>
                <select class="form-select rule-action-select" data-index="${index}">
                    <option value="block" ${rule.action === 'block' ? 'selected' : ''}>Block</option>
                    <option value="log" ${rule.action === 'log' ? 'selected' : ''}>Log</option>
                </select>
                <div class="form-text">Action to take when pattern matches</div>
            </div>
            <button class="btn btn-sm btn-danger" onclick="deleteRule(${index})">
                <i class="fas fa-trash"></i> Delete
            </button>
        `;
        
        container.appendChild(ruleDiv);
    });
    
    // Add new rule button
    const addButton = document.createElement('button');
    addButton.className = 'btn btn-success mt-3';
    addButton.innerHTML = '<i class="fas fa-plus"></i> Add New Rule';
    addButton.onclick = addNewRule;
    container.appendChild(addButton);
}

// Add new rule
function addNewRule() {
    const container = document.getElementById('rules-editor');
    const ruleItems = container.querySelectorAll('.rule-item');
    const index = ruleItems.length;
    
    const ruleDiv = document.createElement('div');
    ruleDiv.className = 'rule-item';
    
    ruleDiv.innerHTML = `
        <div class="rule-header">
            <span class="rule-id">NEW-RULE-${index + 1}</span>
            <span class="rule-action block">block</span>
        </div>
        <div class="mb-3">
            <label class="form-label">Pattern</label>
            <input type="text" class="form-control rule-pattern" value="" data-index="${index}">
            <div class="form-text">Regular expression pattern to match</div>
        </div>
        <div class="mb-3">
            <label class="form-label">Description</label>
            <input type="text" class="form-control rule-description" value="" data-index="${index}">
            <div class="form-text">Human-readable description of the rule</div>
        </div>
        <div class="mb-3">
            <label class="form-label">Action</label>
            <select class="form-select rule-action-select" data-index="${index}">
                <option value="block" selected>Block</option>
                <option value="log">Log</option>
            </select>
            <div class="form-text">Action to take when pattern matches</div>
        </div>
        <button class="btn btn-sm btn-danger" onclick="deleteRule(${index})">
            <i class="fas fa-trash"></i> Delete
        </button>
    `;
    
    container.insertBefore(ruleDiv, container.lastElementChild);
}

// Delete rule
function deleteRule(index) {
    const container = document.getElementById('rules-editor');
    const rules = container.querySelectorAll('.rule-item');
    
    if (rules[index]) {
        rules[index].remove();
    }
}

// Save rules
function saveRules() {
    const container = document.getElementById('rules-editor');
    const ruleItems = container.querySelectorAll('.rule-item');
    const rules = [];
    
    ruleItems.forEach((item, index) => {
        const pattern = item.querySelector('.rule-pattern').value;
        const description = item.querySelector('.rule-description').value;
        const action = item.querySelector('.rule-action-select').value;
        
        if (pattern && description) {
            rules.push({
                id: `RULE-${index + 1}`,
                pattern: pattern,
                action: action,
                description: description
            });
        }
    });
    
    fetch('/api/rules', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ rules: rules })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification(data.message, 'success');
            loadRules(); // Refresh rules display
        } else {
            showNotification(data.error, 'error');
        }
    })
    .catch(error => {
        console.error('Error saving rules:', error);
        showNotification('Error saving rules', 'error');
    });
}

// Load blocked IPs
function loadBlockedIPs() {
    fetch('/api/blocked-ips')
        .then(response => response.json())
        .then(data => {
            displayBlockedIPs(data);
        })
        .catch(error => {
            console.error('Error loading blocked IPs:', error);
            showNotification('Error loading blocked IPs', 'error');
        });
}

// Display blocked IPs
function displayBlockedIPs(ips) {
    const tbody = document.getElementById('blocked-ips-table');
    tbody.innerHTML = '';
    
    if (ips.length === 0) {
        const row = document.createElement('tr');
        row.innerHTML = '<td colspan="8" class="text-center text-muted">No IPs currently blocked</td>';
        tbody.appendChild(row);
        return;
    }
    
    ips.forEach(ip => {
        const row = document.createElement('tr');
        
        // Format remaining time
        const remainingTime = formatRemainingTime(ip.remaining_time);
        
        // Format recent activity
        const recentActivity = formatRecentActivity(ip.recent_activity);
        
        // Determine status badge class
        const statusClass = ip.status === 'active' ? 'bg-danger' : 'bg-secondary';
        const statusText = ip.status === 'active' ? 'Active' : 'Expired';
        
        // Determine remaining time display
        const remainingTimeDisplay = ip.status === 'active' ? remainingTime : 'Expired';
        const remainingTimeClass = ip.status === 'active' ? 'bg-warning' : 'bg-secondary';
        
        row.innerHTML = `
            <td><code>${ip.ip}</code></td>
            <td><span class="badge ${statusClass}">${statusText}</span></td>
            <td>${formatTime(ip.unblock_time)}</td>
            <td><span class="badge ${remainingTimeClass}">${remainingTimeDisplay}</span></td>
            <td>${ip.total_requests}</td>
            <td><span class="badge bg-danger">${ip.blocked_requests}</span></td>
            <td>${recentActivity}</td>
            <td>
                ${ip.status === 'active' ? 
                    `<button class="btn btn-sm btn-success" onclick="unblockIp('${ip.ip}')">
                        <i class="fas fa-unlock"></i> Unblock
                    </button>` : 
                    `<button class="btn btn-sm btn-warning" onclick="removeExpiredIp('${ip.ip}')">
                        <i class="fas fa-trash"></i> Remove
                    </button>`
                }
            </td>
        `;
        tbody.appendChild(row);
    });
}

// Format remaining time
function formatRemainingTime(seconds) {
    if (seconds <= 0) return 'Expired';
    
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    
    if (hours > 0) {
        return `${hours}h ${minutes}m`;
    } else {
        return `${minutes}m`;
    }
}

// Format recent activity
function formatRecentActivity(activity) {
    if (!activity || activity.length === 0) return 'No recent activity';
    
    const blockedCount = activity.filter(a => a.blocked).length;
    const totalCount = activity.length;
    
    return `${blockedCount}/${totalCount} blocked`;
}

// Block IP
function blockIp() {
    const ip = document.getElementById('block-ip-address').value;
    const duration = parseInt(document.getElementById('block-duration').value);
    const reason = document.getElementById('block-reason').value || 'Manually blocked';
    
    if (!ip) {
        showNotification('Please enter an IP address', 'error');
        return;
    }
    
    fetch('/api/block-ip', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ 
            ip: ip, 
            duration: duration,
            reason: reason
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification(data.message, 'success');
            document.getElementById('block-ip-address').value = '';
            document.getElementById('block-reason').value = '';
            loadBlockedIPs();
            
            // Close modal
            const modal = bootstrap.Modal.getInstance(document.getElementById('blockIpModal'));
            modal.hide();
        } else {
            showNotification(data.error, 'error');
        }
    })
    .catch(error => {
        console.error('Error blocking IP:', error);
        showNotification('Error blocking IP', 'error');
    });
}

// Unblock IP
function unblockIp(ip) {
    if (confirm(`Are you sure you want to unblock IP ${ip}?`)) {
        fetch(`/api/unblock-ip/${ip}`, {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showNotification(data.message, 'success');
                loadBlockedIPs();
            } else {
                showNotification(data.error, 'error');
            }
        })
        .catch(error => {
            console.error('Error unblocking IP:', error);
            showNotification('Error unblocking IP', 'error');
        });
    }
}

// Remove expired IP
function removeExpiredIp(ip) {
    if (confirm(`Are you sure you want to remove the expired IP ${ip}?`)) {
        fetch(`/api/remove-expired-ip/${ip}`, {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showNotification(data.message, 'success');
                loadBlockedIPs();
            } else {
                showNotification(data.error, 'error');
            }
        })
        .catch(error => {
            console.error('Error removing expired IP:', error);
            showNotification('Error removing expired IP', 'error');
        });
    }
}

// Load ML models
function loadMLModels() {
    fetch('/api/ml-models')
        .then(response => response.json())
        .then(data => {
            populateMLModels(data);
        })
        .catch(error => {
            console.error('Error loading ML models:', error);
        });
}

// Populate ML models dropdown
function populateMLModels(data) {
    const select = document.getElementById('ml-model-version');
    select.innerHTML = '';
    
    data.available_models.forEach(model => {
        const option = document.createElement('option');
        option.value = model;
        option.textContent = model;
        if (model === data.current_model) {
            option.selected = true;
        }
        select.appendChild(option);
    });
    
    // Add change listener
    select.addEventListener('change', function() {
        setMLModel(this.value);
    });
}

// Set ML model
function setMLModel(version) {
    fetch(`/api/set-model/${version}`, {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification(data.message, 'success');
        } else {
            showNotification(data.error, 'error');
        }
    })
    .catch(error => {
        console.error('Error setting ML model:', error);
        showNotification('Error setting ML model', 'error');
    });
}

// Load analytics
function loadAnalytics() {
    fetch('/api/analytics')
        .then(response => response.json())
        .then(data => {
            updateAnalyticsChart(data.daily_stats);
            updateAnalyticsSummary(data);
        })
        .catch(error => {
            console.error('Error loading analytics:', error);
        });
}

// Update analytics chart
function updateAnalyticsChart(dailyStats) {
    const ctx = document.getElementById('analyticsChart');
    
    if (analyticsChart) {
        analyticsChart.destroy();
    }
    
    const dates = Object.keys(dailyStats).sort();
    const allowedData = dates.map(date => dailyStats[date].allowed || 0);
    const blockedData = dates.map(date => dailyStats[date].blocked || 0);
    
    analyticsChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: dates,
            datasets: [
                {
                    label: 'Allowed Requests',
                    data: allowedData,
                    borderColor: '#1cc88a',
                    backgroundColor: 'rgba(28, 200, 138, 0.1)',
                    tension: 0.4
                },
                {
                    label: 'Blocked Requests',
                    data: blockedData,
                    borderColor: '#e74a3b',
                    backgroundColor: 'rgba(231, 74, 59, 0.1)',
                    tension: 0.4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true
                }
            },
            plugins: {
                legend: {
                    position: 'top'
                }
            }
        }
    });
}

// Update analytics summary
function updateAnalyticsSummary(data) {
    const container = document.getElementById('analytics-summary');
    
    const summaryItems = [
        { label: 'Total Requests', value: data.total_requests },
        { label: 'Total Blocked', value: data.total_blocked },
        { label: 'Block Rate', value: ((data.total_blocked / data.total_requests) * 100).toFixed(1) + '%' }
    ];
    
    container.innerHTML = '';
    summaryItems.forEach(item => {
        const div = document.createElement('div');
        div.className = 'analytics-summary-item';
        div.innerHTML = `
            <span class="analytics-label">${item.label}</span>
            <span class="analytics-value">${item.value}</span>
        `;
        container.appendChild(div);
    });
}

// View request details
function viewRequestDetails(requestId) {
    fetch(`/api/request-details/${requestId}`)
        .then(response => response.json())
        .then(data => {
            showRequestDetailsModal(data);
        })
        .catch(error => {
            console.error('Error loading request details:', error);
            showNotification('Error loading request details', 'error');
        });
}

// Show request details modal
function showRequestDetailsModal(requestData) {
    // Create modal content
    const modalContent = `
        <div class="modal-header">
            <h5 class="modal-title">Request Details</h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
        </div>
        <div class="modal-body">
            <div class="row">
                <div class="col-md-6">
                    <h6>Basic Information</h6>
                    <p><strong>IP Address:</strong> <code>${requestData.remote_addr}</code></p>
                    <p><strong>Method:</strong> <span class="badge bg-secondary">${requestData.method}</span></p>
                    <p><strong>Path:</strong> <code>${requestData.path}</code></p>
                    <p><strong>Timestamp:</strong> ${formatTime(requestData.timestamp)}</p>
                    <p><strong>Status:</strong> <span class="status-badge ${requestData.blocked ? 'blocked' : 'allowed'}">${requestData.blocked ? 'Blocked' : 'Allowed'}</span></p>
                </div>
                <div class="col-md-6">
                    <h6>Details</h6>
                    <p><strong>User Agent:</strong> ${requestData.user_agent || 'N/A'}</p>
                    <p><strong>Query String:</strong> <code>${requestData.query || 'N/A'}</code></p>
                    <p><strong>Reason:</strong> ${requestData.reason || 'N/A'}</p>
                    <p><strong>ML Prediction:</strong> ${requestData.ml_prediction || 'N/A'}</p>
                </div>
            </div>
            ${requestData.body ? `
            <div class="row mt-3">
                <div class="col-12">
                    <h6>Request Body</h6>
                    <pre class="bg-light p-2 rounded"><code>${requestData.body}</code></pre>
                </div>
            </div>
            ` : ''}
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
        </div>
    `;
    
    // Create and show modal
    const modal = document.createElement('div');
    modal.className = 'modal fade';
    modal.id = 'requestDetailsModal';
    modal.innerHTML = `
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                ${modalContent}
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    
    const bsModal = new bootstrap.Modal(modal);
    bsModal.show();
    
    // Remove modal from DOM after it's hidden
    modal.addEventListener('hidden.bs.modal', function() {
        document.body.removeChild(modal);
    });
}

// Show notification
function showNotification(message, type = 'info') {
    const toast = document.getElementById('notification-toast');
    const toastMessage = document.getElementById('toast-message');
    
    toastMessage.textContent = message;
    
    // Update toast classes based on type
    toast.className = `toast ${type === 'error' ? 'bg-danger text-white' : ''}`;
    
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();
}

// Format timestamp
function formatTime(timestamp) {
    if (!timestamp) return 'N/A';
    
    try {
        const date = new Date(timestamp);
        return date.toLocaleString();
    } catch (e) {
        return 'Invalid Date';
    }
}

// Export functions for global access
window.refreshStats = refreshStats;
window.refreshRequests = refreshRequests;
window.applyFilters = applyFilters;
window.saveSettings = saveSettings;
window.saveRules = saveRules;
window.refreshRules = refreshRules;
window.blockIp = blockIp;
window.unblockIp = unblockIp;
window.removeExpiredIp = removeExpiredIp;
window.changePage = changePage;
window.viewRequestDetails = viewRequestDetails; 