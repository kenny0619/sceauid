#!/usr/bin/env node

const command = process.argv[2] ?? "help";

if (command === "help") {
  console.log("SceauID CLI");
  console.log("");
  console.log("Commands will be added as identity flows are implemented.");
  process.exit(0);
}

console.error(`Unknown command: ${command}`);
process.exit(1);
