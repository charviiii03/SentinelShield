// =============================================================================
// dashboard.js - SentinelShield Dashboard JavaScript
// =============================================================================
// Handles:
//   - Auto-refresh of dashboard stats
//   - Reset logs functionality
//   - Toast notifications
// =============================================================================

/**
 * Show a toast notification at the bottom-right of the screen.
 * @param {string} message - Text to display
 * @param {string} type - 'success' | 'danger' | 'warning' | 'info'
 */
function showToast(message, type = 'info') {
    // Remove any existing toasts
    const existing = document.querySelector('.sentinel-toast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.className = `sentinel-toast alert alert-${type}`;
    toast.style.cssText = `
        position: fixed;
        bottom: 80px;
        right: 20px;
        z-index: 9999;
        min-width: 280px;
        padding: 12px 16px;
        border-radius: 8px;
        font-size: 13px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.4);
        animation: slideIn 0.3s ease;
    `;
    toast.innerHTML = `<i class="bi bi-info-circle me-2"></i>${message}`;
    document.body.appendChild(toast);

    // Auto-dismiss after 3 seconds
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.3s';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

/**
 * Reset all logs via the API endpoint.
 * Confirms with user before proceeding.
 */
function resetLogs() {
    if (!confirm('Reset all logs? This will clear all request history and alerts. This action cannot be undone.')) {
        return;
    }

    fetch('/api/reset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            showToast('All logs cleared successfully. Refreshing...', 'success');
            setTimeout(() => window.location.reload(), 1200);
        } else {
            showToast('Failed to clear logs.', 'danger');
        }
    })
    .catch(err => {
        showToast('Error: ' + err.message, 'danger');
    });
}

/**
 * Auto-refresh the dashboard stats every 15 seconds.
 * Updates the stat cards without a full page reload.
 */
function startAutoRefresh() {
    setInterval(() => {
        fetch('/api/stats')
            .then(res => res.json())
            .then(stats => {
                // Update stat cards if elements exist
                const totalEl = document.querySelector('[data-stat="total"]');
                const blockedEl = document.querySelector('[data-stat="blocked"]');
                const allowedEl = document.querySelector('[data-stat="allowed"]');
                const rateLimitedEl = document.querySelector('[data-stat="rate_limited"]');

                if (totalEl) totalEl.textContent = stats.total_requests;
                if (blockedEl) blockedEl.textContent = stats.blocked_requests;
                if (allowedEl) allowedEl.textContent = stats.allowed_requests;
                if (rateLimitedEl) rateLimitedEl.textContent = stats.rate_limited_requests;
            })
            .catch(() => {}); // Silently fail on refresh errors
    }, 15000); // 15 second refresh
}

// ── Initialize on DOM Ready ────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    // Start auto-refresh on dashboard page
    if (window.location.pathname === '/') {
        startAutoRefresh();
    }

    // Highlight rows in the alert feed on hover
    const alertItems = document.querySelectorAll('.alert-item');
    alertItems.forEach(item => {
        item.style.cursor = 'default';
    });

    // Add CSS animation for toast
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to   { transform: translateX(0); opacity: 1; }
        }
    `;
    document.head.appendChild(style);
});