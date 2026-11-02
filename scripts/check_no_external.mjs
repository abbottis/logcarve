// Fail if any served HTML/JS/CSS references a remote URL.
// Run: node ./scripts/check_no_external.mjs
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const roots = ["app/web/static", "app/web/templates"];
// Third-party bundles under vendor/ carry upstream URL strings in comments
// but issue no runtime requests; their provenance is recorded separately.
const SKIP = new Set(["vendor", "fonts", "icons"]);
// Only real fetch vectors count: license-banner comments (e.g. the
// Tailwind MIT banner naming its homepage) are not network requests.
// The CC BY 4.0 credit the DB-IP Country Lite license requires (T5a /
// PAR-09) is a plain text anchor to exactly https://db-ip.com: the
// browser issues no request unless the user deliberately follows it,
// so that one href is allowlisted while every other remote reference
// (all src/fetch/import/url forms, any other href) still fails.
const REMOTE = /(@import\s+["']https?:|url\(\s*["']?https?:|src=["']https?:|fetch\(\s*["']https?:|from\s+["']https?:)/i;
const CREDIT_HREF = /href=["']https?:\/\/[^"']*["']/i;
const CREDIT_ALLOWLIST = new Set(["https://db-ip.com"]);
let failures = 0;

function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) {
      if (dir.endsWith("static") && SKIP.has(entry)) continue;
      walk(path);
      continue;
    }
    if (!/\.(html|js|css|svg|json)$/.test(entry)) continue;
    const text = readFileSync(path, "utf8");
    const lines = text.split("\n");
    lines.forEach((line, i) => {
      if (REMOTE.test(line)) {
        console.error(`${path}:${i + 1}: possible external reference: ${line.trim().slice(0, 120)}`);
        failures += 1;
        return;
      }
      const hrefs = line.match(CREDIT_HREF) || [];
      for (const href of hrefs) {
        const url = href.slice(6, -1);
        if (!CREDIT_ALLOWLIST.has(url)) {
          console.error(`${path}:${i + 1}: possible external reference: ${line.trim().slice(0, 120)}`);
          failures += 1;
          break;
        }
      }
    });
  }
}

for (const dir of roots) {
  try {
    walk(dir);
  } catch (err) {
    console.error(`cannot scan ${dir}: ${err.message}`);
    failures += 1;
  }
}
if (failures > 0) {
  console.error(`${failures} external-reference finding(s)`);
  process.exit(1);
}
console.log("no external references in served assets/templates");
