// Fail if any served HTML/JS/CSS references a remote URL.
// Run: node ./scripts/check_no_external.mjs
// Guard tests: node --test ./scripts/check_no_external.test.mjs
import { readFileSync, readdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, resolve } from "node:path";

const roots = ["app/web/static", "app/web/templates"];
// Third-party bundles under vendor/ carry upstream URL strings in comments
// but issue no runtime requests; their provenance is recorded separately.
const SKIP = new Set(["vendor", "fonts", "icons"]);
// Only real fetch vectors count: license-banner comments (e.g. the
// Tailwind MIT banner naming its homepage) are not network requests.
// The CC BY 4.0 credit the DB-IP Country Lite license requires (T5a /
// PAR-09) is exactly one plain anchor tag pointing at
// https://db-ip.com: the browser issues no request unless the user
// deliberately follows it, so that one shape is allowlisted while
// every other remote reference still fails — including the credit
// URL reused as a stylesheet, image, script, preload or any other
// non-anchor tag, any second href on the same line, all
// src/fetch/import/url() forms and any other href.
const REMOTE = /(@import\s+["']https?:|url\(\s*["']?https?:|src=["']https?:|fetch\(\s*["']https?:|from\s+["']https?:)/i;
const HREF = /href=["'](https?:\/\/[^"']*)["']/gi;
const CREDIT_ALLOWLIST = new Set(["https://db-ip.com"]);

/** Offending remote references on one line (empty when the line is clean). */
export function scanLine(line) {
  const findings = [];
  if (REMOTE.test(line)) {
    findings.push(line.trim().slice(0, 120));
    return findings;
  }
  for (const match of line.matchAll(HREF)) {
    const url = match[1];
    if (!CREDIT_ALLOWLIST.has(url) || !isPlainAnchor(line, match.index)) {
      findings.push(line.trim().slice(0, 120));
      return findings;
    }
  }
  return findings;
}

/** True only when the href at index sits in a plain <a ...> open tag. */
function isPlainAnchor(line, hrefIndex) {
  const open = line.lastIndexOf("<", hrefIndex);
  if (open === -1) return false;
  // A closing tag or another element closed in between ends the anchor.
  if (line.lastIndexOf(">", hrefIndex) > open) return false;
  const tag = line.slice(open + 1, hrefIndex);
  return /^a[\s>]/.test(tag);
}

/** All offending lines in a text, as [lineNumber, excerpt] pairs. */
export function scanText(text) {
  const findings = [];
  text.split("\n").forEach((line, i) => {
    for (const excerpt of scanLine(line)) {
      findings.push([i + 1, excerpt]);
    }
  });
  return findings;
}

function walk(dir) {
  let failures = 0;
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) {
      if (dir.endsWith("static") && SKIP.has(entry)) continue;
      failures += walk(path);
      continue;
    }
    if (!/\.(html|js|css|svg|json)$/.test(entry)) continue;
    const text = readFileSync(path, "utf8");
    for (const [lineNumber, excerpt] of scanText(text)) {
      console.error(`${path}:${lineNumber}: possible external reference: ${excerpt}`);
      failures += 1;
    }
  }
  return failures;
}

function main() {
  let failures = 0;
  for (const dir of roots) {
    try {
      failures += walk(dir);
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
}

const invoked = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invoked) {
  main();
}
