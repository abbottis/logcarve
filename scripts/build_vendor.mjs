// Copy pinned local dependencies into app/web/static for serving.
// Fails loudly on any missing file so the build never silently ships
// a partial vendor bundle. Records provenance in vendor/PROVENANCE.md.
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const nm = (p) => join(root, "node_modules", p);
const out = (p) => join(root, "app", "web", "static", p);
const versions = {};
for (const name of [
  "htmx.org",
  "chart.js",
  "@fontsource-variable/inter",
  "@fontsource-variable/jetbrains-mono",
  "lucide-static",
]) {
  versions[name] = JSON.parse(
    (await import("node:fs")).readFileSync(nm(`${name}/package.json`), "utf8"),
  ).version;
}

mkdirSync(out("vendor/js"), { recursive: true });
mkdirSync(out("fonts"), { recursive: true });
mkdirSync(out("icons"), { recursive: true });

copyFileSync(nm("htmx.org/dist/htmx.min.js"), out("vendor/js/htmx.min.js"));
copyFileSync(nm("chart.js/dist/chart.umd.min.js"), out("vendor/js/chart.umd.min.js"));

copyFileSync(
  nm("@fontsource-variable/inter/files/inter-latin-wght-normal.woff2"),
  out("fonts/inter-latin-wght-normal.woff2"),
);
copyFileSync(nm("@fontsource-variable/inter/LICENSE"), out("fonts/INTER-OFL.txt"));
copyFileSync(
  nm("@fontsource-variable/jetbrains-mono/files/jetbrains-mono-latin-wght-normal.woff2"),
  out("fonts/jetbrains-mono-latin-wght-normal.woff2"),
);
copyFileSync(
  nm("@fontsource-variable/jetbrains-mono/LICENSE"),
  out("fonts/JETBRAINS-MONO-OFL.txt"),
);

const icons = [
  "layout-dashboard",
  "shield-alert",
  "bot",
  "circle-alert",
  "sparkles",
  "settings",
  "database",
  "log-in",
  "log-out",
  "chart-line",
  "clock",
  "globe",
  "info",
  "triangle-alert",
  "menu",
  "sun",
  "moon",
  "check",
];
for (const icon of icons) {
  copyFileSync(nm(`lucide-static/icons/${icon}.svg`), out(`icons/${icon}.svg`));
  // Template copy: inlined via Jinja so currentColor follows the theme.
  // The upstream license banner stays recorded in LUCIDE-ISC.txt and
  // PROVENANCE.md instead of the inlined copy. Only the root <svg>
  // tag is touched (inner shapes keep their geometry); it gains the
  // sizing class plus aria-hidden for its decorative use sites.
  let svg = readFileSync(nm(`lucide-static/icons/${icon}.svg`), "utf8").replace(
    /^<!--[\s\S]*?-->\s*/,
    "",
  );
  svg = svg.replace(/<svg([^>]*)>/, (tag) => {
    if (/\sclass="[^"]*"/.test(tag)) {
      tag = tag.replace(/\sclass="([^"]*)"/, ' class="lc-icon $1"');
    } else {
      tag = tag.replace("<svg", '<svg class="lc-icon"');
    }
    return tag
      .replace(/\swidth="[^"]*"/, "")
      .replace(/\sheight="[^"]*"/, "")
      .replace("<svg", '<svg aria-hidden="true"');
  });
  if (!svg.startsWith("<svg") || svg.includes("{{") || svg.includes("{%")) {
    throw new Error(`refusing to inline unexpected icon markup: ${icon}`);
  }
  mkdirSync(join(root, "app", "web", "templates", "icons"), { recursive: true });
  writeFileSync(join(root, "app", "web", "templates", "icons", `${icon}.svg`), svg);
}
copyFileSync(nm("lucide-static/LICENSE"), out("icons/LUCIDE-ISC.txt"));

writeFileSync(
  out("vendor/PROVENANCE.md"),
  `# Vendored browser assets (generated, do not edit by hand)\n\nBuilt by \`npm run build:vendor\` from pinned npm packages in \`package.json\`/\`package-lock.json\`:\n\n- htmx.org ${versions["htmx.org"]} (Zero-Clause BSD): \`vendor/js/htmx.min.js\`\n- chart.js ${versions["chart.js"]} (MIT): \`vendor/js/chart.umd.min.js\`\n- Inter Variable ${versions["@fontsource-variable/inter"]} (SIL OFL 1.1, see \`fonts/INTER-OFL.txt\`): \`fonts/inter-latin-wght-normal.woff2\`\n- JetBrains Mono Variable ${versions["@fontsource-variable/jetbrains-mono"]} (SIL OFL 1.1, see \`fonts/JETBRAINS-MONO-OFL.txt\`): \`fonts/jetbrains-mono-latin-wght-normal.woff2\`\n- Lucide icons ${versions["lucide-static"]} (ISC, see \`icons/LUCIDE-ISC.txt\`): \`icons/*.svg\` (${icons.length}-icon subset)\n\nNo CDN or remote fetch is used at runtime; every browser asset is served from this server.\n`,
);
console.log(`vendored htmx ${versions["htmx.org"]}, chart.js ${versions["chart.js"]}, lucide ${versions["lucide-static"]}`);
