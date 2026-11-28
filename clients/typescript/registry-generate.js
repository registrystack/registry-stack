#!/usr/bin/env node
import { existsSync } from 'node:fs'

const generator = new URL('./dist/generate-project.js', import.meta.url)
if (existsSync(generator)) {
  await import(generator.href)
} else {
  console.error('Run npm run build first to use registry-generate from this checkout.')
  process.exitCode = 1
}
