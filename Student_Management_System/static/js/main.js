// Main JavaScript for Student Portal
document.addEventListener('DOMContentLoaded', function() {
    // Auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.opacity = '0';
            setTimeout(() => alert.remove(), 300);
        }, 5000);
    });

    // Session timeout warning (4 minutes before timeout)
    let idleTime = 0;
    const idleLimit = 4; // minutes before warning
    
    setInterval(() => {
        idleTime++;
        if (idleTime >= idleLimit) {
            alert('Your session will expire soon due to inactivity. Please save your work.');
        }
    }, 60000);

    document.addEventListener('mousemove', () => idleTime = 0);
    document.addEventListener('keypress', () => idleTime = 0);
});
