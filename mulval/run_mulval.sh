#!/bin/bash
# run_mulval.sh — Run MulVAL analysis on input facts
# Input: /tmp/input.P (Prolog facts)
# Output: /tmp/VERTICES.CSV, /tmp/ARCS.CSV

INPUT="${1:-/tmp/input.P}"
OUTPUT_DIR="${2:-/tmp}"

if [ ! -f "$INPUT" ]; then
    echo "Error: Input file $INPUT not found"
    exit 1
fi

echo "[MulVAL] Processing $INPUT..."

# If MulVAL is installed, run it
if command -v graph_gen.sh &> /dev/null; then
    cd "$OUTPUT_DIR"
    graph_gen.sh "$INPUT" -l -p
    echo "[MulVAL] Analysis complete"
else
    echo "[MulVAL] MulVAL not installed — use Python fallback emulator"
    exit 1
fi
