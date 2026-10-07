import { defineConfig, doxygen, markdown } from "sourcey";
import { execFileSync } from "node:child_process";

const repository = process.env.DOCS_REPOSITORY || "https://github.com/laurencelundblade/QCBOR";
const revision = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();

export default defineConfig({
  name: process.env.DOCS_PREVIEW ? "QCBOR — Unofficial PR Preview" : "QCBOR Documentation",
  siteUrl: process.env.DOCS_SITE_URL || "https://laurencelundblade.github.io",
  baseUrl: "/QCBOR",
  prettyUrls: false,
  repo: repository,
  theme: {
    preset: "default",
    css: ["./docs/sourcey.css"],
    colors: {
      primary: "#315f7d",
      light: "#5685a3",
      dark: "#17384d"
    }
  },
  navbar: {
    links: [
      {
        type: "link",
        label: "QCBOR v2 alpha docs",
        href: "https://www.securitytheory.com/qcbor-docs/"
      },
      { type: "github", href: repository }
    ]
  },
  footer: {
    links: [
      { type: "link", label: "Source", href: `${repository}/tree/${revision}` },
      { type: "link", label: "Security", href: `${repository}/security/policy` }
    ]
  },
  navigation: {
    tabs: [
      {
        tab: "Overview",
        slug: "",
        source: markdown({
          groups: [{ group: "QCBOR", pages: ["index"] }]
        })
      },
      {
        tab: "Guides",
        slug: "guides",
        source: markdown({
          groups: [
            { group: "Project Guide", pages: ["README"] },
            { group: "Concepts", pages: ["doc/Tagging", "doc/TimeTag1FAQ"] }
          ]
        })
      },
      {
        tab: "API Reference",
        slug: "api",
        source: doxygen({
          xml: "./doxygen/xml",
          groups: true,
          index: "none",
          sourceUrl: `${repository}/blob/${revision}/{path}#L{line}`
        })
      }
    ]
  }
});
