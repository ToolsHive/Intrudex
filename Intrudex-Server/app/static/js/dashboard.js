// Chart.js rendering
  function renderChart(counts) {
    const ctx = document.getElementById('eventsChart').getContext('2d');
    if (window._chart) window._chart.destroy();
    window._chart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: ['Sysmon', 'Application', 'Security', 'System'],
        datasets: [{
          label: 'Events',
          data: [
            counts.sysmon || 0,
            counts.application || 0,
            counts.security || 0,
            counts.system || 0
          ],
          backgroundColor: [
            '#60a5fa', '#4ade80', '#a78bfa', '#f87171'
          ],
          borderRadius: 8
        }]
      },
      options: {
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: '#222' }, ticks: { color: '#ccc' } },
          y: { grid: { color: '#222' }, ticks: { color: '#ccc' }, beginAtZero: true }
        }
      }
    });
  }

  // Fetch stats and update chart/cards
  async function fetchStatsAndChart() {
    const res = await fetch('/api/logs/counts');
    const counts = await res.json();
    document.getElementById('stat-sysmon').textContent = counts.sysmon || 0;
    document.getElementById('stat-application').textContent = counts.application || 0;
    document.getElementById('stat-security').textContent = counts.security || 0;
    document.getElementById('stat-system').textContent = counts.system || 0;
    renderChart(counts);
    document.getElementById('last-updated').textContent = new Date().toLocaleTimeString();
  }

  document.addEventListener('DOMContentLoaded', () => {
    fetchStatsAndChart();
    setInterval(fetchStatsAndChart, 5000); // Refresh stats/chart every 5s
  });

  // Modal logic
  function showModal(html) {
    document.getElementById('modal-body').innerHTML = html;
    document.getElementById('modal-bg').style.display = 'flex';
  }
  function closeModal() {
    document.getElementById('modal-bg').style.display = 'none';
    document.getElementById('modal-body').innerHTML = '';
  }
  document.getElementById('modal-bg').addEventListener('click', function(e) {
    if (e.target === this) closeModal();
  });

  // Integration Status (simulate, replace with real API if available)
  function updateIntegrationStatus() {
    // Simulate status: could fetch from /api/integration/status
    const status = { connected: true, desc: "All integrations operational" };
    document.getElementById('integration-status-dot').style.background = status.connected ? "#4ade80" : "#f87171";
    document.getElementById('integration-status-label').textContent = status.connected ? "Connected" : "Disconnected";
    document.getElementById('integration-status-desc').textContent = status.desc;
  }
  document.addEventListener('DOMContentLoaded', updateIntegrationStatus);

  // Enrichment Popover logic
  let popoverTimeout = null;
  document.addEventListener('mouseover', function(e) {
    const enrichable = e.target.closest('.enrichable');
    if (enrichable) {
      clearTimeout(popoverTimeout);
      const value = enrichable.getAttribute('data-enrich');
      const type = enrichable.getAttribute('data-enrich-type');
      const rect = enrichable.getBoundingClientRect();
      // Fetch enrichment info
      fetch(`/api/enrich?type=${encodeURIComponent(type)}&value=${encodeURIComponent(value)}`)
        .then(r => r.text())
        .then(html => {
          const popover = document.getElementById('popover-content');
          document.getElementById('popover-bg').style.display = 'block';
          popover.style.display = 'block';
          document.getElementById('popover-inner').innerHTML = html;
          // Position popover
          popover.style.top = (window.scrollY + rect.bottom + 8) + 'px';
          popover.style.left = (window.scrollX + rect.left) + 'px';
        });
    }
  });
  document.addEventListener('mouseout', function(e) {
    if (e.target.classList.contains('enrichable')) {
      popoverTimeout = setTimeout(() => {
        document.getElementById('popover-bg').style.display = 'none';
        document.getElementById('popover-content').style.display = 'none';
      }, 120);
    }
  });
  document.getElementById('popover-bg').addEventListener('mouseover', function() {
    clearTimeout(popoverTimeout);
  });
  document.getElementById('popover-bg').addEventListener('mouseout', function() {
    popoverTimeout = setTimeout(() => {
      document.getElementById('popover-bg').style.display = 'none';
      document.getElementById('popover-content').style.display = 'none';
    }, 120);
  });

  // Delegate click events for logs, users, alerts
  document.addEventListener('click', async function(e) {
    // Log row (ignore if clicking the "View" button)
    let tr = e.target.closest('tr[data-log-id]');
    if (tr && !e.target.closest('button')) {
      let logId = tr.getAttribute('data-log-id');
      let logType = tr.getAttribute('data-log-type');
      if (logType === "System") {
        await showSystemLogDetail(logId);
      } else if (logType === "Sysmon") {
        await showSysmonLogDetail(logId);
      } else if (logType === "Application") {
        await showApplicationLogDetail(logId);
      } else if (logType === "Security") {
        await showSecurityLogDetail(logId);
      }
      return;
    }
    // Top user
    let userLi = e.target.closest('li[data-user]');
    if (userLi) {
      let user = userLi.getAttribute('data-user');
      let res = await fetch(`/api/logs/user/${encodeURIComponent(user)}`);
      let html = await res.text();
      showModal(html);
      return;
    }
    // Alert
    let alertLi = e.target.closest('li[data-alert-id]');
    if (alertLi) {
      let alertId = alertLi.getAttribute('data-alert-id');
      let res = await fetch(`/api/logs/security/${alertId}`);
      let html = await res.text();
      showModal(html);

    }
  });

  // Add these functions for the "View" button in details
  async function showSystemLogDetail(logId) {
    let res = await fetch(`/api/logs/system/${logId}`);
    let html = await res.text();
    showModal(html);
  }
  async function showSysmonLogDetail(logId) {
    let res = await fetch(`/api/logs/sysmon/${logId}`);
    let html = await res.text();
    showModal(html);
  }
  async function showApplicationLogDetail(logId) {
    let res = await fetch(`/api/logs/application/${logId}`);
    let html = await res.text();
    showModal(html);
  }
  async function showSecurityLogDetail(logId) {
    let res = await fetch(`/api/logs/security/${logId}`);
    let html = await res.text();
    showModal(html);
  }
  async function showUserDetail(user) {
    let res = await fetch(`/api/logs/user/${encodeURIComponent(user)}`);
    let html = await res.text();
    showModal(html);
  }
