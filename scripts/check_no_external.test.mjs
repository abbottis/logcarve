// Guard tests for scripts/check_no_external.mjs (T5a residual 4).
// Run: node --test ./scripts/check_no_external.test.mjs
// Synthetic temp fixtures only: no network, no external HTTP.
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { scanLine, scanText } from "./check_no_external.mjs";

const CREDIT = "https://db-ip.com";
const EVIL = "https://evil.example.invalid/app.css";

describe("credit anchor allowlist", () => {
  it("passes the exact plain credit anchor", () => {
    assert.deepEqual(scanLine(`<a class="link" href="${CREDIT}">IP Geolocation</a>`), []);
    assert.deepEqual(scanLine(`<p><a href="${CREDIT}">x</a></p>`), []);
  });

  it("fails the credit URL reused as a stylesheet", () => {
    assert.equal(scanLine(`<link rel="stylesheet" href="${CREDIT}">`).length, 1);
  });

  it("fails the credit URL on image, script and preload tags", () => {
    assert.equal(scanLine(`<img src="${CREDIT}">`).length, 1);
    assert.equal(scanLine(`<script src="${CREDIT}"></script>`).length, 1);
    assert.equal(scanLine(`<link rel="preload" as="image" href="${CREDIT}">`).length, 1);
  });

  it("scans every href on one line: credit plus evil stylesheet fails", () => {
    const line =
      `<a href="${CREDIT}">credit</a>` + `<link rel="stylesheet" href="${EVIL}">`;
    assert.equal(scanLine(line).length, 1);
  });

  it("fails evil hrefs even after a valid credit anchor on the same line", () => {
    const line = `<a href="${CREDIT}">credit</a><a href="${EVIL}">evil</a>`;
    assert.equal(scanLine(line).length, 1);
  });
});

describe("remote fetch vectors", () => {
  it("still fails CSS imports, url(), script fetch and remote src", () => {
    assert.equal(scanLine(`@import "https://evil.example.invalid/x.css";`).length, 1);
    assert.equal(scanLine(`  background: url(https://evil.example.invalid/x.png);`).length, 1);
    assert.equal(scanLine(`fetch("https://evil.example.invalid/x")`).length, 1);
    assert.equal(scanLine(`import x from "https://evil.example.invalid/x.mjs";`).length, 1);
    assert.equal(scanLine(`<script src="https://evil.example.invalid/x.js"></script>`).length, 1);
  });

  it("still fails any other remote href", () => {
    assert.equal(scanLine(`<a href="${EVIL}">evil</a>`).length, 1);
    assert.equal(scanLine(`<link rel="stylesheet" href="${EVIL}">`).length, 1);
  });

  it("passes local references and license-banner comments", () => {
    assert.deepEqual(scanLine(`<script src="/static/js/app.js" defer></script>`), []);
    assert.deepEqual(scanLine(`<a href="/requests?site=default">requests</a>`), []);
    assert.deepEqual(
      scanLine(`/*! tailwindcss v4.3.3 | MIT License | https://tailwindcss.com */`),
      [],
    );
  });
});

describe("temp fixture scan", () => {
  it("flags exactly the offending fixture lines without any network", (t) => {
    const dir = mkdtempSync(join(tmpdir(), "logcarve-noext-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const clean = join(dir, "clean.html");
    const dirty = join(dir, "dirty.html");
    writeFileSync(clean, `<a href="${CREDIT}">IP Geolocation by DB-IP</a>\n`, "utf8");
    writeFileSync(
      dirty,
      `<a href="${CREDIT}">credit</a>\n<link rel="stylesheet" href="${CREDIT}">\n`,
      "utf8",
    );
    assert.deepEqual(scanText(readFileSync(clean, "utf8")), []);
    const findings = scanText(readFileSync(dirty, "utf8"));
    assert.equal(findings.length, 1);
    assert.equal(findings[0][0], 2);
  });
});
