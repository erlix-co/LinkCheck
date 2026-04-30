import { spawnSync } from "node:child_process";

const env = {
  ...process.env,
  VITE_API_BASE_URL: "https://erlix.net/api",
};

const result = spawnSync("npm", ["run", "build"], {
  cwd: "../frontend",
  env,
  stdio: "inherit",
  shell: true,
});

if (result.status !== 0) {
  process.exit(result.status ?? 1);
}
