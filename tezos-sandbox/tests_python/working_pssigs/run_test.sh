#!/bin/bash

PYTHON_SCRIPT=$1
TARGET_DIR=$(dirname "${PYTHON_SCRIPT}") 
echo "[+] Running ... $PYTHON_SCRIPT"
echo "[+] Contracts ... $TARGET_DIR"

PYTHONPATH=$(pwd) python3 $PYTHON_SCRIPT $TARGET_DIR
