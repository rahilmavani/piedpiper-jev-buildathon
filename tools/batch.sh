#!/usr/bin/env bash
# Run tasks in parallel. Usage: batch.sh <label> <parallelism> <agent:TASK>...
set -u
LABEL="$1"; PAR="$2"; shift 2
DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$DIR/../runs/$LABEL"; mkdir -p "$OUT"
printf '%s\n' "$@" | xargs -n1 -P "$PAR" "$DIR/run-one.sh" "$OUT"
