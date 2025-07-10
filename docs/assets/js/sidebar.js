// Sidebar toggle functionality for mobile
document.addEventListener('DOMContentLoaded', function() {
    const sidebarToggle = document.querySelector('.sidebar-toggle');
    const sidebar = document.querySelector('.book-sidebar');
    const overlay = document.querySelector('.sidebar-overlay');
    
    if (sidebarToggle && sidebar && overlay) {
        sidebarToggle.addEventListener('click', function() {
            const isOpen = sidebar.classList.contains('sidebar-open');
            
            if (isOpen) {
                // Close sidebar
                sidebar.classList.remove('sidebar-open');
                overlay.classList.remove('overlay-visible');
                sidebarToggle.setAttribute('aria-expanded', 'false');
            } else {
                // Open sidebar
                sidebar.classList.add('sidebar-open');
                overlay.classList.add('overlay-visible');
                sidebarToggle.setAttribute('aria-expanded', 'true');
            }
        });
        
        // Close sidebar when clicking overlay
        overlay.addEventListener('click', function() {
            sidebar.classList.remove('sidebar-open');
            overlay.classList.remove('overlay-visible');
            sidebarToggle.setAttribute('aria-expanded', 'false');
        });
        
        // Close sidebar on escape key
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape' && sidebar.classList.contains('sidebar-open')) {
                sidebar.classList.remove('sidebar-open');
                overlay.classList.remove('overlay-visible');
                sidebarToggle.setAttribute('aria-expanded', 'false');
            }
        });
    }
});