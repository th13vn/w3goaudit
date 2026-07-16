#!/bin/sh
set -eu

if [ "$#" -gt 0 ]; then
    exec "$@"
fi

suite="${SUITE:-competitive}"
tools="${TOOLS:-w3goaudit,slither,semgrep,4naly3er}"
run_name="${RUN_NAME:-latest}"

case "${suite}" in
    competitive|slither|decurity|4naly3er) ;;
    *)
        echo "unsupported benchmark suite: ${suite}" >&2
        exit 2
        ;;
esac

case "${tools}" in
    ""|,*|*,|*,,*)
        echo "TOOLS must be a non-empty comma-separated tool list" >&2
        exit 2
        ;;
esac

old_ifs="${IFS}"
IFS=,
set -- ${tools}
IFS="${old_ifs}"
for tool in "$@"; do
    case "${tool}" in
        w3goaudit|slither|semgrep|4naly3er|aderyn) ;;
        *)
            echo "unsupported benchmark tool: ${tool}" >&2
            exit 2
            ;;
    esac
done

case "${run_name}" in
    ""|.|..|.*|*[!A-Za-z0-9._-]*)
        echo "RUN_NAME must contain only letters, digits, dot, underscore, or dash" >&2
        exit 2
        ;;
esac

mkdir -p "${HOME}" "${XDG_CACHE_HOME}"
output="/workspace/benchmarks/results/${run_name}"

python3 benchmarks/run_benchmark.py \
    --suite "${suite}" \
    --tools "${tools}" \
    --w3goaudit-bin /usr/local/bin/w3goaudit \
    --naly3er-cmd /usr/local/bin/4naly3er \
    --out "${output}"

case ",${tools}," in
    *,w3goaudit,*)
        python3 benchmarks/assert_thresholds.py "${output}/benchmark.json"
        ;;
esac
