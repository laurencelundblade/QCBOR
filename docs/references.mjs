import { cpSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve, join, dirname, relative } from "node:path";

cpSync("doxygen/html", "site/doxygen", { recursive: true });
const root = resolve("site");
const checkout = resolve(".") + "/";
const html = new Map();
function walk(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap(e =>
    e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)]);
}
for (const file of walk(root).filter(f => f.endsWith(".html"))) {
  html.set(file, readFileSync(file, "utf8").replaceAll(checkout, ""));
}
function hasAnchor(file, anchor) {
  return html.has(file) && (!anchor || html.get(file).includes(`id="${anchor}"`) || html.get(file).includes(`name="${anchor}"`));
}
let repaired = 0;
for (const [file, body] of html) {
  if (relative(root, file).startsWith("doxygen/")) {
    // Doxygen 1.18 emits alphabet links without anchors for short indexes.
    let native = body;
    for (const [, letter] of body.matchAll(/href="#index_([a-z])"/g)) {
      if (!hasAnchor(file, `index_${letter}`)) {
        native = native.replace(new RegExp(`<li>(?=${letter})`, "i"), `<li id="index_${letter}">`);
      }
    }
    writeFileSync(file, native);
    continue;
  }
  const result = body.replace(/href="([^"\s]+)"/g, (original, href) => {
    if (/^[a-z]+:/i.test(href) || !href.includes("#")) return original;
    const [path, anchor] = href.split("#");
    const target = path ? resolve(dirname(file), path) : file;
    if (hasAnchor(target, anchor)) return original;
    let replacement;
    // Moxygen emits original Doxygen refids for file sections and enum values.
    // Native Doxygen filenames and anchors follow the compound_1anchor scheme.
    const split = anchor.indexOf("_1");
    const compound = split < 0 ? anchor : anchor.slice(0, split);
    const nativeAnchor = split < 0 ? "" : anchor.slice(split + 2);
    const native = join(root, "doxygen", `${compound}.html`);
    if (hasAnchor(native, nativeAnchor)) {
      replacement = relative(dirname(file), native) + (nativeAnchor ? `#${nativeAnchor}` : "");
    } else if (file.includes("-union-") && target === file.slice(0, file.indexOf("-union-")) + ".html" && hasAnchor(file, anchor)) {
      replacement = `#${anchor}`;
    }
    if (!replacement) return original; // The independent checker reports it.
    repaired++;
    return `href="${replacement}"`;
  });
  writeFileSync(file, result);
}
console.log(`Resolved ${repaired} generated cross-references.`);
