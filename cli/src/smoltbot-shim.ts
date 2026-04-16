#!/usr/bin/env node
// smoltbot is deprecated — this shim prints a warning then hands off to mnemom
process.stderr.write(
  '\n⚠️  The smoltbot command is deprecated. Use mnemom instead.\n' +
  '   Install: npm install -g @mnemom/mnemom\n\n'
);
// Dynamic import runs index.ts which calls program.parse(process.argv) automatically
await import('./index.js');
