#!/usr/bin/env node
const shep = require('./shep32.js')

;(async () => {
  const res = await shep.runCli(process.argv.slice(2), { exe: require('path').basename(process.argv[1] || 'shepCLI.js') })
  if (res.stdout) process.stdout.write(res.stdout)
  if (res.stderr) process.stderr.write(res.stderr)
  process.exit(res.exitCode || 0)
})().catch(err => {
  process.stderr.write('error: ' + err.message + '\n')
  process.exit(1)
})
