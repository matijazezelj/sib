#!/bin/bash
# SIB Analyze - AI-powered security alert analysis
# Usage: sib-analyze [options]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANALYSIS_DIR="${SCRIPT_DIR}/../analysis"

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not installed."
    exit 1
fi

# Check for dependencies
if ! python3 -c "import requests, yaml" 2>/dev/null; then
    echo "Installing dependencies..."
    pip3 install -q -r "${ANALYSIS_DIR}/requirements.txt"
fi

# Run the analyzer
cd "${ANALYSIS_DIR}"
python3 analyzer.py "$@"
