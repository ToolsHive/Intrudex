function setBodyOverflowHidden(hidden) {
            document.body.style.overflow = hidden ? "hidden" : "";
        }
        function closeViewModal() {
            let modal = document.getElementById('view-modal');
            if (modal && modal.__x && modal.__x.$data) {
                modal.__x.$data.open = false;
                modal.__x.$data.content = '';
            } else {
                modal.style.display = 'none';
                let contentDiv = modal.querySelector('[x-html="content"]');
                if (contentDiv) contentDiv.innerHTML = '';
            }
            setBodyOverflowHidden(true);
        }

        // Initialize log row click handlers on page load
        document.addEventListener('DOMContentLoaded', function() {
            document.querySelectorAll('.log-row').forEach(row => {
                row.onclick = function() {
                    fetch(row.dataset.detailUrl)
                        .then(r => r.text())
                        .then(html => {
                            let modal = document.getElementById('view-modal');
                            if (modal && modal.__x && modal.__x.$data) {
                                modal.__x.$data.content = html;
                                modal.__x.$data.open = true;
                            } else {
                                modal.style.display = 'flex';
                                modal.querySelector('[x-html="content"]').innerHTML = html;
                            }
                            setBodyOverflowHidden(false);
                        });
                }
            });
        });

        document.body.addEventListener('htmx:afterSwap', function(evt) {
            if (evt.detail.target.id === "log-table") {
                document.querySelectorAll('.log-row').forEach(row => {
                    row.onclick = function() {
                        fetch(row.dataset.detailUrl)
                            .then(r => r.text())
                            .then(html => {
                                let modal = document.getElementById('view-modal');
                                if (modal && modal.__x && modal.__x.$data) {
                                    modal.__x.$data.content = html;
                                    modal.__x.$data.open = true;
                                } else {
                                    modal.style.display = 'flex';
                                    modal.querySelector('[x-html="content"]').innerHTML = html;
                                }
                                setBodyOverflowHidden(false);
                            });
                    }
                });
            }
        });
        // Allow closing modal by clicking outside
        document.addEventListener('click', function(e) {
            let modal = document.getElementById('view-modal');
            if (modal && modal.style.display !== 'none' && e.target === modal) {
                closeViewModal();
            }
        });
        // Allow closing modal with Escape key
        document.addEventListener('keydown', function(e) {
            if (e.key === "Escape") closeViewModal();
        });

        // Highlight the active log type tab on navigation (client-side for htmx navigation)
        document.addEventListener('htmx:pushedIntoHistory', function(evt) {
            highlightActiveLogType();
        });
        document.addEventListener('DOMContentLoaded', function() {
            highlightActiveLogType();
        });
        function highlightActiveLogType() {
            const path = window.location.pathname;
            const match = path.match(/\/view\/(sysmon|system|application|security)/);
            const activeType = match ? match[1] : "sysmon";
            document.querySelectorAll('#log-type-nav a[data-logtype]').forEach(a => {
                a.classList.remove(
                    "bg-blue-700", "text-white", "shadow-lg", "scale-105",
                    "bg-red-700", "bg-green-700", "bg-purple-700",
                    "text-blue-300", "text-red-300", "text-green-300", "text-purple-300"
                );
                // Remove all highlight classes
                if (a.dataset.logtype === activeType) {
                    if (activeType === "sysmon") {
                        a.classList.add("bg-blue-700", "text-white", "shadow-lg", "scale-105");
                    } else if (activeType === "system") {
                        a.classList.add("bg-red-700", "text-white", "shadow-lg", "scale-105");
                    } else if (activeType === "application") {
                        a.classList.add("bg-green-700", "text-white", "shadow-lg", "scale-105");
                    } else if (activeType === "security") {
                        a.classList.add("bg-purple-700", "text-white", "shadow-lg", "scale-105");
                    }
                } else {
                    if (a.dataset.logtype === "sysmon") {
                        a.classList.add("text-blue-300");
                    } else if (a.dataset.logtype === "system") {
                        a.classList.add("text-red-300");
                    } else if (a.dataset.logtype === "application") {
                        a.classList.add("text-green-300");
                    } else if (a.dataset.logtype === "security") {
                        a.classList.add("text-purple-300");
                    }
                }
            });
        }
        // On page load, ensure overflow is hidden
        setBodyOverflowHidden(true);