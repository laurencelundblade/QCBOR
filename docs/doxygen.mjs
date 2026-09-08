import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

execFileSync("doxygen", ["Doxyfile"], { cwd: "doxygen", stdio: "inherit" });
// Doxygen XML locations may contain absolute checkout paths. Keep the
// generated input portable and avoid exposing a developer's home directory.
const root = resolve(".").replaceAll("\\", "/") + "/";
for (const file of readdirSync("doxygen/xml").filter(name => name.endsWith(".xml"))) {
  const path = `doxygen/xml/${file}`;
  const xml = readFileSync(path, "utf8");
  writeFileSync(path, xml.replaceAll(root, "").replace(/\b(file|bodyfile)="(?:\.\.\/)+/g, '$1="'));
}
