/**
 * QUANTUM-SHIELD // MAIN APPLICATION SCRIPT
 * Handles CSRF-authenticated requests, clipboard actions, toast alerts, and UI utilities.
 */

document.addEventListener('DOMContentLoaded', () => {
    initMobileNav();
    initAlertDismissal();
    initFileInputSync();
});

// Retrieve CSRF token from meta tag
function getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
}

// Global Toast Notification Helper
function showToast(message, type = 'info') {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    // Choose icon
    let icon = 'ℹ️';
    if (type === 'success') icon = '✓';
    if (type === 'danger' || type === 'error') icon = '⚠️';
    
    toast.innerHTML = `<span>${icon}</span> <span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(10px)';
        toast.style.transition = '0.3s ease-out';
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}

// Copy to clipboard utility
function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    const text = element.value !== undefined ? element.value : element.innerText;
    if (!text) {
        showToast('Nothing to copy', 'danger');
        return;
    }

    navigator.clipboard.writeText(text).then(() => {
        showToast('Copied to clipboard!', 'success');
    }).catch(err => {
        // Fallback
        const textarea = document.createElement('textarea');
        textarea.value = text;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        showToast('Copied to clipboard!', 'success');
    });
}

// Mobile sidebar drawer toggle
function initMobileNav() {
    const toggle = document.querySelector('.mobile-toggle');
    const sidebar = document.querySelector('.sidebar');
    if (toggle && sidebar) {
        toggle.addEventListener('click', () => {
            sidebar.classList.toggle('open');
        });
    }
}

// Dismissible alerts
function initAlertDismissal() {
    document.querySelectorAll('.alert-close').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const alert = e.target.closest('.alert');
            if (alert) alert.remove();
        });
    });
}

// Auto-read text from file inputs into textareas for rapid verification
function initFileInputSync() {
    const syncPairs = [
        { fileId: 'file_message', targetId: 'message' },
        { fileId: 'file_public_key', targetId: 'public_key' },
        { fileId: 'file_signature', targetId: 'signature' }
    ];

    syncPairs.forEach(pair => {
        const fileInput = document.getElementById(pair.fileId);
        const target = document.getElementById(pair.targetId);
        if (fileInput && target) {
            fileInput.addEventListener('change', (e) => {
                const file = e.target.files[0];
                if (file) {
                    const reader = new FileReader();
                    reader.onload = (event) => {
                        target.value = event.target.result;
                        showToast(`Loaded ${file.name}`, 'info');
                    };
                    reader.readAsText(file);
                }
            });
        }
    });
}

// Fetch helper with CSRF header
async function secureFetch(url, options = {}) {
    options.headers = options.headers || {};
    options.headers['X-CSRFToken'] = getCsrfToken();
    options.headers['Accept'] = 'application/json';
    if (!options.headers['Content-Type'] && !(options.body instanceof FormData)) {
        options.headers['Content-Type'] = 'application/json';
    }
    return fetch(url, options);
}
