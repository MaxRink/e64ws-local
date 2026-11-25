#!/usr/bin/env node
/* Run the committed Decaid plugin's pure GBS endpoint against shared fixtures. */

const fs = require("fs");

function loadPlugin(path) {
  const source = fs.readFileSync(path, "utf8");
  const module = { exports: {} };
  const factory = new Function("module", "exports", source + "\nmodule.exports = { createPlugin };\n");
  factory(module, module.exports);
  return module.exports.createPlugin;
}

function normalize(value) {
  const result = {};
  for (const key of ["algorithm", "phase", "candidateDdDum", "returnedDdDum", "committed", "locked", "sequence", "index"]) {
    if (Object.prototype.hasOwnProperty.call(value, key)) result[key] = value[key];
  }
  if (!Object.prototype.hasOwnProperty.call(result, "locked")) result.locked = false;
  return result;
}

async function main() {
  const fixturePath = process.argv[2];
  const pluginPath = process.argv[3];
  if (!fixturePath || !pluginPath) throw new Error("usage: gbs_parity_node.js FIXTURES PLUGIN");
  const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
  const createPlugin = loadPlugin(pluginPath);
  const results = [];
  for (const testCase of fixture.cases) {
    const plugin = createPlugin({
      log() {},
      emit() {},
      async grinder() { throw new Error("transport not allowed in GBS parity runner"); }
    });
    const outputs = [];
    for (const call of testCase.calls) {
      const response = await plugin.handleHttpRequest({
        endpoint: "gbsAdjust",
        method: "POST",
        body: Object.assign({ algorithm: testCase.algorithm }, call)
      });
      if (response.status !== 200) throw new Error(`${testCase.name}: HTTP ${response.status}: ${response.body}`);
      outputs.push(normalize(JSON.parse(response.body)));
    }
    results.push({ name: testCase.name, outputs });
  }
  process.stdout.write(JSON.stringify({ firmware_build: fixture.firmware_build, cases: results }));
}

main().catch((error) => {
  console.error(error.stack || String(error));
  process.exitCode = 1;
});
