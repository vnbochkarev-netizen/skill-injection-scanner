#!/usr/bin/env node
"use strict";
/**
 * skill-injection-scanner — npm CLI wrapper.
 * Runs the Python tool (stdlib only, Python 3.8+ required).
 *
 * Usage:
 *   skill-injection-scanner --skills ~/.openclaw/skills
 *   skill-injection-scanner --skills /path/to/skills --format json
 *   skill-injection-scanner --self-test
 */
const { spawnSync } = require("child_process");
const path = require("path");

const script = path.join(__dirname, "..", "scanner.py");
const r = spawnSync("python3", [script, ...process.argv.slice(2)], {
  stdio: "inherit",
});
process.exit(r.status === null ? 1 : r.status);
