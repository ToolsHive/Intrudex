document.addEventListener('DOMContentLoaded', function() {
            const el = document.getElementById('last-updated');
            if (el) {
               const now = new Date();
               el.textContent = now.toLocaleString();
               el.classList.add('transition-colors', 'duration-500');
               el.addEventListener('mouseenter', () => el.style.color = '#ef4444');
               el.addEventListener('mouseleave', () => el.style.color = '');
            }
         });