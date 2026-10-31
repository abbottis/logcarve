/* Overview charts, rendered from server-provided JSON embedded in
 * <script type="application/json"> elements (never executable code).
 * Chart.js and htmx are local vendor bundles; no network calls here.
 * Tick/grid/legend colors follow the active theme, and charts
 * re-render when the theme changes or htmx swaps the fragment. */
(function () {
  "use strict";
  var charts = [];

  function readData(id) {
    var el = document.getElementById(id);
    if (!el) return null;
    try {
      return JSON.parse(el.textContent);
    } catch (err) {
      return null;
    }
  }

  function palette() {
    var dark = document.documentElement.getAttribute("data-theme") === "dark";
    return {
      tick: dark ? "#e2e8f0" : "#475569",
      grid: dark ? "rgba(148, 163, 184, 0.2)" : "rgba(100, 116, 139, 0.2)",
      line: dark ? "#38bdf8" : "#0284c7",
    };
  }

  function baseOptions(displayLegend) {
    var colors = palette();
    return {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: displayLegend,
          labels: { color: colors.tick },
        },
      },
      scales: {
        x: { ticks: { color: colors.tick }, grid: { color: colors.grid } },
        y: {
          beginAtZero: true,
          ticks: { precision: 0, color: colors.tick },
          grid: { color: colors.grid },
        },
      },
    };
  }

  function renderAll() {
    if (!window.Chart) return;
    charts.forEach(function (chart) {
      try {
        chart.destroy();
      } catch (err) {
        /* A swapped-out canvas is already gone. */
      }
    });
    charts = [];
    var colors = palette();
    var timelineCanvas = document.getElementById("traffic-timeline");
    var timeline = readData("traffic-timeline-data");
    if (timelineCanvas && timeline) {
      var points = timeline.buckets || [];
      charts.push(new window.Chart(timelineCanvas, {
        type: "line",
        data: {
          labels: points.map(function (b) { return b.label; }),
          datasets: [
            {
              label: timeline.requestsLabel || "Requests",
              data: points.map(function (b) { return b.requests; }),
              borderColor: colors.line,
              backgroundColor: colors.line,
              fill: false,
              tension: 0.15,
              pointRadius: 0,
            },
          ],
        },
        options: baseOptions(true),
      }));
    }
    var statusCanvas = document.getElementById("status-distribution");
    var status = readData("status-distribution-data");
    if (statusCanvas && status) {
      var rows = status.rows || [];
      charts.push(new window.Chart(statusCanvas, {
        type: "bar",
        data: {
          labels: rows.map(function (r) { return String(r.status); }),
          datasets: [
            {
              label: status.requestsLabel || "Requests",
              data: rows.map(function (r) { return r.requests; }),
              backgroundColor: colors.line,
            },
          ],
        },
        options: baseOptions(false),
      }));
    }
  }

  // Re-render on viewport changes: a canvas sized for a wide layout
  // keeps its inline dimensions and would otherwise force overflow.
  var resizeTimer = null;
  window.addEventListener("resize", function () {
    if (resizeTimer) window.clearTimeout(resizeTimer);
    resizeTimer = window.setTimeout(renderAll, 150);
  });

  document.addEventListener("DOMContentLoaded", renderAll);
  document.addEventListener("logcarve:theme", renderAll);
  document.addEventListener("htmx:afterSwap", renderAll);
})();
