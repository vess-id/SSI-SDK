import { defineConfig } from 'vitest/config'
// const tsconfigPaths = require('vite-tsconfig-paths');

export default defineConfig({
  // plugins: [tsconfigPaths()],
  test: {
    // oid4vci-issuer-rest-api is excluded: depends on un-migrated @sphereon/oid4vci-issuer-server
    // and is unused. Keep in sync with the exclusion in pnpm-workspace.yaml.
    workspace: ['packages/*', '!packages/oid4vci-issuer-rest-api'],
    server: {
      deps: {
        fallbackCJS: true,
        inline: true,
      },
    },
    /* for example, use global to avoid globals imports (describe, test, expect): */
    globals: false,
    testTimeout: 30000,
  },
})
