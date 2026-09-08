# Building the documentation

Install Node.js 22 or newer, pnpm 11.8.0 and Doxygen (tested locally with
1.18.0; CI uses Ubuntu's packaged version). From the repository root:

```sh
pnpm install --frozen-lockfile
pnpm run docs
```

This generates Doxygen XML from the existing public headers, normalizes
checkout paths in that generated XML, and renders it alongside the existing
Markdown guides using Sourcey 3.6.5. It does not use an LLM to write API prose.
The native Doxygen HTML is also published under `doxygen/`. Sourcey 3.6.5
does not preserve every Doxygen section/enum anchor. A post-build step routes
those references to the exact native Doxygen section, and fixes anonymous
union member links to their generated member page. Unresolved links fail the
build instead of silently dropping the reference.
The final check validates files, fragments, search destinations, pinned source
paths and line ranges, and known private symbol exclusions.

Serve the generated site locally at `/QCBOR/` (for example, symlink `site`
as `QCBOR` inside a temporary server directory and serve that directory).
For a fork preview, set `DOCS_REPOSITORY` to the fork's HTTPS GitHub URL,
`DOCS_SITE_URL` to the preview origin, and `DOCS_PREVIEW=1` before building.
The visible title then identifies the site as an unofficial PR preview.

GitHub Actions builds documentation on relevant pull requests and on pushes
to master. The contributor branch also builds an artifact on fork pushes.
Only the upstream repository's master can deploy. Enable Settings → Pages →
GitHub Actions to allow deployment; pull requests never deploy the site.

The documentation tooling is separate from the C build. Generated HTML/XML
and node_modules are ignored. Existing Doxygen undocumented-member warnings
remain visible: related public functions sometimes share documentation, so
globally hiding undocumented members could remove legitimate interfaces.
The reference retains those interfaces and does not invent missing prose.
Search entries are headings and API entries, not a count of distinct APIs.
Source links currently appear on generated type/member pages; the footer
links to the build revision for group pages as well.

The project may prefer publishing Doxygen HTML directly to avoid maintaining
Node/Sourcey dependencies. Sourcey adds unified guide/API navigation and
search; the existing Doxygen HTML output remains available for comparison.
