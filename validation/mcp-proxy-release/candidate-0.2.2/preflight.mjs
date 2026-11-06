#!/usr/bin/env node
/**
 * Fresh-clone guard for @strixgov/mcp-proxy's test suite.
 *
 * Sibling of packages/strixgov-mcp-adapter/scripts/preflight.mjs. The two are
 * deliberately duplicated rather than shared: these packages publish
 * independently, and importing a guard across the workspace would either add a
 * dependency edge that does not exist at runtime or require shipping the guard
 * in the tarball. The REQUIRED list below is this package's own, not a copy.
 *
 * This package resolves its Strix dependencies through pnpm workspace links
 * (`workspace:^` entries resolved in pnpm-lock.yaml as `link:../<pkg>`). In a
 * checkout that has not been installed, those links do not exist, and
 * `node --test` fails with a wall of ERR_MODULE_NOT_FOUND traces that name the
 * missing specifiers but never say what to do about it. Read cold, that looks
 * like a broken package rather than an uninstalled tree.
 *
 * This guard prints the one command that fixes it and exits non-zero instead.
 * It is silent on success, so CI — which runs `pnpm install --frozen-lockfile`
 * first — never sees extra output.
 *
 * Why dynamic import() and not require.resolve():
 * tool-gateway's package.json "exports" map declares only an "import"
 * condition and does not export "./package.json", so BOTH
 * require.resolve("@strixgov/tool-gateway") and
 * require.resolve("@strixgov/tool-gateway/package.json") throw even when the
 * package is correctly installed. import() is also the exact operation src/
 * and the tests perform, which makes a pass here a faithful predicate for
 * "the suite can load" rather than an approximation of it.
 */

/**
 * Every specifier the suite needs in order to run.
 *
 * - @strixgov/tool-gateway and @strixgov/mcp-adapter are imported by
 *   src/proxy.mjs at module scope.
 * - @modelcontextprotocol/sdk is a registry dependency, not a workspace link,
 *   but it fails the same way in an uninstalled tree and deserves the same
 *   message. The subpath is checked rather than the bare name because the SDK
 *   ships an "exports" map with no root export.
 * - @strixgov/capabilities-mcp-common is dynamically imported by
 *   resolveCapabilities() in src/config.mjs and exercised by
 *   test/config.test.mjs, so its absence is a real test failure.
 *
 * Deliberately NOT listed: @strixgov/mcp-proxy itself. The only import of it
 * lives inside a generated temp project in test/installed-tarball.test.mjs,
 * which resolves it from that project's own install, not from this workspace.
 */
const REQUIRED = [
  "@strixgov/tool-gateway",
  "@strixgov/mcp-adapter",
  "@modelcontextprotocol/sdk/client/index.js",
  "@strixgov/capabilities-mcp-common/notion",
];

/**
 * @param {string} specifier
 * @returns {Promise<boolean>} true if the specifier loads.
 */
async function resolves(specifier) {
  try {
    await import(specifier);
    return true;
  } catch (err) {
    if (err?.code === "ERR_MODULE_NOT_FOUND") return false;
    // The package is present but threw while loading (a syntax error inside
    // it, a broken transitive import). That is a real failure, but it is not
    // the one this guard exists to explain — let the test run surface it
    // verbatim rather than mislabelling it as "not installed".
    return true;
  }
}

/** @type {string[]} */
const missing = [];
for (const specifier of REQUIRED) {
  if (!(await resolves(specifier))) missing.push(specifier);
}

if (missing.length > 0) {
  // Deduplicate to package names: reporting several subpaths of one missing
  // package is noise for what is a single missing install.
  const packages = [
    ...new Set(missing.map((s) => s.split("/").slice(0, 2).join("/"))),
  ];

  process.stderr.write(
    [
      "",
      "  @strixgov/mcp-proxy: dependencies are not installed.",
      "",
      "  Cannot resolve:",
      ...packages.map((p) => `    - ${p}`),
      "",
      "  This package resolves its Strix dependencies through the pnpm",
      "  workspace (and the rest from the registry), so the repository has",
      "  to be installed once before its tests can run:",
      "",
      "      pnpm install                                 # from the repo root",
      "      pnpm --dir packages/strixgov-mcp-proxy test",
      "",
      "  Nothing is wrong with the published package: installing it from npm",
      "  pulls these in automatically as regular dependencies. This only",
      "  affects running the suite from a source checkout.",
      "",
    ].join("\n") + "\n",
  );
  process.exit(1);
}
