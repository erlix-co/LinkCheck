import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";

const env = {
  ...process.env,
  VITE_API_BASE_URL: "https://erlix.net/api",
};

const hasFrontendReact = existsSync("../frontend/node_modules/react/package.json");

if (!hasFrontendReact) {
  const installResult = spawnSync("npm", ["install", "--no-audit", "--no-fund"], {
    cwd: "../frontend",
    env,
    stdio: "inherit",
    shell: true,
  });

  if (installResult.status !== 0) {
    process.exit(installResult.status ?? 1);
  }
}

const buildResult = spawnSync("npx", ["vite", "build"], {
  cwd: "../frontend",
  env,
  stdio: "inherit",
  shell: true,
});

if (buildResult.status !== 0) {
  process.exit(buildResult.status ?? 1);
}
