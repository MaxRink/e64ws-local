#!/usr/bin/env node
/* Execute GBS vectors against the shipped Decaid plugin's pure gbsAdjust path.
 *
 * Input: one JSON object on stdin:
 *   { plugin: "<path>", vectors: [{ id, algorithm, calls, cases, preState, postState }] }
 * Output: { results: { "<id>": [normalized output, ..., { "__postState__": {...} }] } }
 *
 * The plugin is loaded with a fake host. log/emit are no-ops and grinder()
 * throws, so the plugin's normal transport path cannot be used. This is a test
 * harness, not a sandbox: the plugin source is trusted repository code. The
 * plugin's own status endpoint exposes state.gbs, which is used for post-state
 * checks.
 */

const fs = require("fs");

const POST_STATE = "__postState__";

const ALGORITHM_KEYS = [
  "algorithm",
  "phase",
  "central",
  "correction",
  "candidateDdDum",
  "returnedDdDum",
  "committed",
  "locked",
  "sequence",
  "index"
];

function loadPlugin(path) {
  const source = fs.readFileSync(path, "utf8");
  const module = { exports: {} };
  const factory = new Function(
    "module",
    "exports",
    source + "\nmodule.exports = { createPlugin };\n"
  );
  factory(module, module.exports);
  return module.exports.createPlugin;
}

function normalize(value, keys) {
  const result = {};
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(value, key)) result[key] = value[key];
  }
  return result;
}

function normalizeAlgorithm(value) {
  const result = normalize(value, ALGORITHM_KEYS);
  if (!Object.prototype.hasOwnProperty.call(result, "locked")) result.locked = false;
  return result;
}

function snapshotState(algorithm, gbs) {
  if (algorithm === "GbS1") {
    return {
      records: gbs.v1.records.map(function (record) {
        return [record.value, record.age];
      }),
      state: gbs.v1.state,
      outputTenths: gbs.v1.outputTenths
    };
  }
  if (algorithm === "GbS2") {
    return {
      points: gbs.v2.points.map(function (point) {
        return [point.x, point.y];
      }),
      lastResultDum: gbs.v2.lastResultDum
    };
  }
  if (algorithm === "GbS3" || algorithm === "GbS4") {
    const source = algorithm === "GbS3" ? gbs.v3 : gbs.v4;
    const snapshot = {
      history: source.history.map(function (point) {
        return [point.x, point.y];
      }),
      farFactor: source.farFactor,
      midFactor: source.midFactor,
      nearFactor: source.nearFactor,
      filterRetention: source.filterRetention,
      holdCyclesSetting: source.holdCyclesSetting,
      holdCyclesRemaining: source.holdCyclesRemaining,
      lastTargetDum: source.lastTargetDum,
      lastAdjustmentDum: source.lastAdjustmentDum,
      filteredDdTimesBrew: source.filteredDdTimesBrew
    };
    if (algorithm === "GbS3") {
      snapshot.nearThreshold = source.nearThreshold;
      snapshot.keepMediumInterval = source.keepMediumInterval;
    }
    return snapshot;
  }
  if (algorithm === "DdEff") {
    return {
      initialDdDum: gbs.ddEff.initialDdDum,
      index: gbs.ddEff.index
    };
  }
  throw new Error("no post-state snapshot for " + String(algorithm));
}

async function readState(plugin) {
  const response = await plugin.handleHttpRequest({ endpoint: "status", method: "GET" });
  return JSON.parse(response.body).gbs;
}

function callBody(vector, call, first) {
  const mapping = {
    actualMs: "actualBrewTimeMs",
    targetMs: "targetBrewTimeMs",
    estimatedDdDum: "estimatedDdDum",
    setpointDdDum: "setpointDdDum",
    toleranceMs: "toleranceMs",
    calls: "calls",
    reset: "reset"
  };
  const body = { algorithm: vector.algorithm };
  for (const key of Object.keys(mapping)) {
    if (Object.prototype.hasOwnProperty.call(call, key)) body[mapping[key]] = call[key];
  }
  if (first && vector.algorithm === "GbS2") {
    const restored = vector.preState && vector.preState.v2;
    if (restored && Array.isArray(restored.points)) {
      body.points = restored.points.map(function (point) {
        return { x: point[0], y: point[1] };
      });
    }
  }
  return body;
}

async function runAlgorithm(plugin, vector) {
  const outputs = [];
  for (let index = 0; index < vector.calls.length; index++) {
    const response = await plugin.handleHttpRequest({
      endpoint: "gbsAdjust",
      method: "POST",
      body: callBody(vector, vector.calls[index], index === 0)
    });
    if (response.status !== 200) {
      outputs.push({ error: "HTTP " + response.status + ": " + String(response.body) });
      continue;
    }
    outputs.push(normalizeAlgorithm(JSON.parse(response.body)));
  }
  if (vector.postState) {
    outputs.push({ [POST_STATE]: snapshotState(vector.algorithm, await readState(plugin)) });
  }
  return outputs;
}

async function main() {
  const request = JSON.parse(fs.readFileSync(0, "utf8"));
  let createPlugin;
  try {
    createPlugin = loadPlugin(request.plugin);
  } catch (error) {
    process.stdout.write(JSON.stringify({ fatal: String((error && error.stack) || error) }));
    return;
  }
  const results = {};
  for (const vector of request.vectors) {
    try {
      const plugin = createPlugin({
        log() {},
        emit() {},
        async grinder() {
          throw new Error("transport is not allowed in the GBS vector runner");
        }
      });
      results[vector.id] = await runAlgorithm(plugin, vector);
    } catch (error) {
      results[vector.id] = [{ error: String((error && error.message) || error) }];
    }
  }
  process.stdout.write(JSON.stringify({ results: results }));
}

main().catch(function (error) {
  process.stdout.write(JSON.stringify({ fatal: String((error && error.stack) || error) }));
  process.exitCode = 1;
});
