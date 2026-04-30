#!/usr/bin/env bash
set -euo pipefail
exec >> /var/log/linkcheck-deploy.log 2>&1

LOCK_FILE="/tmp/linkcheck-deploy.lock"
exec 9>"${LOCK_FILE}"
if ! flock -n 9; then
  echo "[deploy] another deploy is already running"
  exit 0
fi

echo "[deploy] starting at $(date -u +%FT%TZ)"
trap 'echo "[deploy] failed at $(date -u +%FT%TZ)"' ERR

cd /root/erlix/linkcheck

git fetch origin main
git checkout -f main
git reset --hard origin/main
git clean -fd

cd /root/erlix/linkcheck/backend
systemctl restart linkcheck-backend

cd /root/erlix/linkcheck/frontend
npm ci --no-audit --no-fund
npm run build

rm -rf /var/www/linkcheck/*
cp -r dist/* /var/www/linkcheck/
cp /root/erlix/linkcheck/deploy/seo/robots.txt /var/www/html/robots.txt
cp /root/erlix/linkcheck/deploy/seo/sitemap.xml /var/www/html/sitemap.xml

systemctl reload nginx

echo "[deploy] completed at $(date -u +%FT%TZ)"
