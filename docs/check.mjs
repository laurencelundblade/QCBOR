import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve, relative } from "node:path";

const root = resolve("site");
const revision = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
const repository = process.env.DOCS_REPOSITORY || "https://github.com/laurencelundblade/QCBOR";
function walk(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap(e =>
    e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)]);
}
const pages = walk(root).filter(f => f.endsWith(".html"));
const contents = new Map(pages.map(f => [f, readFileSync(f, "utf8")]));
let internalLinks = 0, sourceLinks = 0;
const errors = [];
function checkLink(href, file) {
  const url = new URL(href.replaceAll("&amp;", "&"), `https://docs.invalid/QCBOR/${relative(root, file)}`);
  if (url.origin === "https://docs.invalid") {
    internalLinks++;
    assert(url.pathname.startsWith("/QCBOR/"), `outside base: ${href}`);
    let target = join(root, decodeURIComponent(url.pathname.slice(7)));
    if (existsSync(target) && statSync(target).isDirectory()) target = join(target, "index.html");
    assert(existsSync(target), `missing file: ${href}`);
    if (url.hash && contents.has(target)) {
      const id = decodeURIComponent(url.hash.slice(1));
      const html = contents.get(target);
      assert(html.includes(`id="${id}"`) || html.includes(`name="${id}"`), `missing anchor: ${href}`);
    }
  } else if (url.href.startsWith(`${repository}/blob/`)) {
    sourceLinks++;
    assert(url.href.startsWith(`${repository}/blob/${revision}/`), `unpinned source: ${href}`);
    const source = decodeURIComponent(url.pathname.split(`/blob/${revision}/`)[1]);
    assert(!source.includes("..") && existsSync(source), `invalid source path: ${href}`);
    assert(/^#L[1-9][0-9]*$/.test(url.hash), `invalid source line: ${href}`);
    assert(Number(url.hash.slice(2)) <= readFileSync(source, "utf8").split("\n").length, `source line out of range: ${href}`);
  }
}
for (const [file, html] of contents) {
  if (/\/Users\/|\/home\/runner\//.test(html)) errors.push(`${relative(root, file)}: local path leaked`);
  if (relative(root, file).startsWith("api/") && /qcbor_private\.h|(?:QCBOR|QCBOREncode|QCBORDecode)_Private_/.test(html)) errors.push(`${relative(root, file)}: private API leaked`);
  for (const match of html.matchAll(/(?:href|src)="([^"]+)"/g)) {
    try { checkLink(match[1], file); } catch (e) { errors.push(`${relative(root, file)}: ${e.message}`); }
  }
}
const search = JSON.parse(readFileSync(join(root, "search-index.json"), "utf8"));
for (const entry of search) {
  try { checkLink(entry.url, join(root, "index.html")); } catch (e) { errors.push(`search ${entry.title}: ${e.message}`); }
}
assert(pages.length > 10 && sourceLinks > 0 && search.length > 100, "incomplete site");
if (errors.length) {
  console.error(errors.join("\n"));
  process.exit(1);
}
console.log(JSON.stringify({ revision, pages: pages.length, searchEntries: search.length, internalLinks, sourceLinks, errors: 0 }, null, 2));
