import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { defineConfig } from 'tsdown'

const pkg = JSON.parse(readFileSync(join(process.cwd(), 'package.json'), 'utf8'))

export default defineConfig([
  // Host half only: Node ESM bundle for the plugin entry and invariant companion.
  // No client half — this plugin serves HTTP routes and mounts no browser UI.
  {
    name: pkg.name,
    entry: {
      index: 'src/index.ts',
      invariant: 'src/invariant.ts',
    },
    outDir: 'lib',
    format: ['esm'],
    platform: 'node',
    target: 'es2024',
    fixedExtension: false,
    dts: false,
    clean: false,
    deps: {
      neverBundle: [/^@deepseek-ai\//, /^cordis(\/|$)/],
    },
  },
])
