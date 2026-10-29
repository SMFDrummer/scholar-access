#!/usr/bin/env bash
# scholar-access one-click installer (macOS / Linux)
set -euo pipefail

cd "$(dirname "$0")"

if [ ! -f "scholar_access/cli.py" ]; then
  echo "✗ 找不到 scholar_access/cli.py，请在仓库目录里运行" >&2
  exit 1
fi

find_python() {
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
      version=$("$candidate" -c 'import sys; print("%d.%d" % sys.version_info[:2])')
      case "$version" in
        3.9|3.1[0-9]) echo "$candidate"; return 0 ;;
      esac
    fi
  done
  return 1
}

PY=$(find_python) || {
  echo "✗ 需要 Python 3.9+：macOS 请先安装（brew install python3 或官网 pkg），Linux 用包管理器" >&2
  exit 1
}

echo "· 使用 $(command -v "$PY") ($("$PY" -V 2>&1))"
export PYTHONPATH="$(pwd):${PYTHONPATH:-}"
exec "$PY" -m scholar_access install "$@"
