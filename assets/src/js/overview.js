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
      error: dark ? "#f87171" : "#dc2626",
      bytes: dark ? "#34d399" : "#059669",
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
            {
              label: timeline.errorsLabel || "Errors",
              data: points.map(function (b) { return b.errors || 0; }),
              borderColor: colors.error,
              backgroundColor: colors.error,
              fill: false,
              tension: 0.15,
              pointRadius: 0,
            },
            {
              label: timeline.bytesLabel || "Bytes",
              data: points.map(function (b) { return b.bytes_total || 0; }),
              borderColor: colors.bytes,
              backgroundColor: colors.bytes,
              fill: false,
              tension: 0.15,
              pointRadius: 0,
              yAxisID: "y1",
            },
          ],
        },
        options: (function () {
          var opts = baseOptions(true);
          opts.scales.y1 = {
            beginAtZero: true,
            position: "right",
            ticks: { precision: 0, color: colors.tick },
            grid: { drawOnChartArea: false },
          };
          return opts;
        })(),
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
    var breakdownCanvas = document.getElementById("traffic-breakdown");
    var breakdown = readData("traffic-breakdown-data");
    if (breakdownCanvas && breakdown) {
      var buckets = breakdown.buckets || [];
      charts.push(new window.Chart(breakdownCanvas, {
        type: "doughnut",
        data: {
          labels: buckets.map(function (b) { return b.traffic; }),
          datasets: [
            {
              label: breakdown.requestsLabel || "Requests",
              data: buckets.map(function (b) { return b.requests; }),
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: true, labels: { color: colors.tick } } },
        },
      }));
    }
    var groupsCanvas = document.getElementById("bot-provider-groups");
    var groupsData = readData("bot-provider-groups-data");
    if (groupsCanvas && groupsData) {
      var providers = groupsData.rows || [];
      charts.push(new window.Chart(groupsCanvas, {
        type: "bar",
        data: {
          labels: providers.map(function (r) { return String(r.name); }),
          datasets: [
            {
              label: groupsData.requestsLabel || "Requests",
              data: providers.map(function (r) { return r.requests; }),
              backgroundColor: colors.line,
            },
          ],
        },
        options: baseOptions(false),
      }));
    }
    var browserCanvas = document.getElementById("browser-families");
    var browserData = readData("browser-families-data");
    if (browserCanvas && browserData) {
      var families = browserData.rows || [];
      var labelKey = browserData.labelKey || "family";
      charts.push(new window.Chart(browserCanvas, {
        type: "bar",
        data: {
          labels: families.map(function (r) { return String(r[labelKey]); }),
          datasets: [
            {
              label: browserData.requestsLabel || "Requests",
              data: families.map(function (r) { return r.requests; }),
              backgroundColor: colors.line,
            },
          ],
        },
        options: baseOptions(false),
      }));
    }
    // Parity report charts (performance, SEO, referrers, countries):
    // server-provided JSON only, same theme handling; every chart has
    // a table alternative.
    renderBar("overview-countries-chart", "overview-countries-chart-data", "country", null);
    renderBar("perf-slow-chart", "perf-slow-chart-data", "path", null);
    renderBar("perf-cache-chart", "perf-cache-chart-data", "value", null);
    renderBar("perf-mime-chart", "perf-mime-chart-data", "mime", null);
    renderBar("perf-http-chart", "perf-http-chart-data", "value", null);
    renderBar("perf-tls-chart", "perf-tls-chart-data", "value", null);
    renderBar("perf-hosts-chart", "perf-hosts-chart-data", "value", null);
    renderBar("seo-groups-chart", "seo-groups-chart-data", "path", null);
    renderBar("ref-targets-chart", "ref-targets-chart-data", "target_path", null);
    renderBar("journeys-chart", "journeys-chart-data", "entry_path", null);
    renderBar("journey-entries-chart", "journey-entries-chart-data", "entry_path", null);
    renderBar("security-findings-chart", "security-findings-chart-data", "label", null);
    // Current-vs-baseline comparison: grouped bars (current, baseline)
    // per metric with the same theme treatment; the semantic table in
    // the page carries the exact values and ratio honesty notes.
    renderComparison("compare-metrics-chart", "compare-metrics-chart-data");
  }

  function renderComparison(canvasId, dataId) {
    var canvas = document.getElementById(canvasId);
    var data = readData(dataId);
    if (!canvas || !data || !window.Chart) return;
    var rows = data.rows || [];
    var colors = palette();
    charts.push(new window.Chart(canvas, {
      type: "bar",
      data: {
        labels: rows.map(function (r) { return shortLabel(r.label || r.name, 42); }),
        datasets: [
          {
            label: data.requestsLabel || "Current",
            data: rows.map(function (r) {
              return typeof r.current === "number" && isFinite(r.current) ? r.current : 0;
            }),
            backgroundColor: colors.line,
          },
          {
            label: data.baselineLabel || "Baseline",
            data: rows.map(function (r) {
              return typeof r.previous === "number" && isFinite(r.previous) ? r.previous : 0;
            }),
            backgroundColor: colors.error,
          },
        ],
      },
      options: (function () {
        var opts = barOptions();
        opts.plugins.legend.display = true;
        return opts;
      })(),
    }));
  }

  function shortLabel(value, maxLen) {
    var text = String(value == null ? "" : value);
    if (text.length > maxLen) return text.slice(0, maxLen - 1) + "…";
    return text;
  }

  function renderBar(canvasId, dataId, labelKey, valueKey) {
    var canvas = document.getElementById(canvasId);
    var data = readData(dataId);
    if (!canvas || !data) return;
    var rows = data.rows || [];
    var key = valueKey || data.valueKey || "requests";
    var colors = palette();
    charts.push(new window.Chart(canvas, {
      type: "bar",
      data: {
        labels: rows.map(function (r) {
          if (labelKey === "mime") {
            return shortLabel(r.mime_type + " (" + r.resource_kind + ")", 42);
          }
          return shortLabel(r[labelKey], 42);
        }),
        datasets: [
          {
            label: data.requestsLabel || "Requests",
            data: rows.map(function (r) {
              var v = key === "requests" ? r.requests : r[key];
              return typeof v === "number" && isFinite(v) ? v : 0;
            }),
            backgroundColor: colors.line,
          },
        ],
      },
      options: barOptions(),
    }));
  }

  function barOptions() {
    var colors = palette();
    return {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false, labels: { color: colors.tick } },
      },
      scales: {
        x: {
          ticks: {
            color: colors.tick,
            maxRotation: 45,
            minRotation: 0,
            autoSkip: true,
            maxTicksLimit: 8,
          },
          grid: { color: colors.grid },
        },
        y: {
          beginAtZero: true,
          ticks: { precision: 0, color: colors.tick },
          grid: { color: colors.grid },
        },
      },
    };
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
