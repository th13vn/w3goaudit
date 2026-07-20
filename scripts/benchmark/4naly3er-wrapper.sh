#!/bin/sh
set -eu

FOURNALY3ER_REF="8a9d1ebb7d362bc94f036fa9123d0977c6cb7436"

if [ "${1:-}" = "--version" ]; then
    printf '4naly3er %s\n' "${FOURNALY3ER_REF}"
    exit 0
fi

if [ "$#" -ne 2 ]; then
    echo "usage: 4naly3er <target> <out.md>" >&2
    exit 2
fi

target="$(realpath "$1")"
output="$2"
case "${output}" in
    /*) ;;
    *) output="$(pwd)/${output}" ;;
esac

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT INT TERM

if [ -d "${target}" ]; then
    base_path="${target}"
    set -- "${base_path}"
else
    base_path="$(dirname "${target}")"
    scope_file="${workdir}/scope.txt"
    basename "${target}" > "${scope_file}"
    set -- "${base_path}" "${scope_file}"
fi

mkdir -p "$(dirname "${output}")"
cd "${workdir}"
/opt/4naly3er/node_modules/.bin/ts-node /opt/4naly3er/src/index.ts "$@"
test -f report.md
cp report.md "${output}"
