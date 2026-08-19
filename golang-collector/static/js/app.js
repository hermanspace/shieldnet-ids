// app.js - Custom JavaScript minimal untuk ShieldNet IDS
// Sebagian besar interaktivitas ditangani oleh HTMX dan Chart.js

// Konfirmasi sebelum aksi yang berpotensi merusak
document.addEventListener('DOMContentLoaded', function () {
    // Highlight menu sidebar yang sedang aktif berdasarkan URL
    const currentPath = window.location.pathname;
    document.querySelectorAll('nav a').forEach(function (link) {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('bg-gray-700', 'text-white');
            link.classList.remove('text-gray-300');
        }
    });
});
