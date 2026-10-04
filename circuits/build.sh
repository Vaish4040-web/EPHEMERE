#!/bin/bash
# EPHEMERE ZK spike: compile circuit + DEV-ONLY trusted setup (Groth16).
# Usage: ./build.sh      (needs ./circom binary and `npm install` done)
set -e
cd "$(dirname "$0")"
mkdir -p build keys
S="npx snarkjs"

echo "[1/7] compile circuit"
./circom age_proof.circom --r1cs --wasm --sym -o build
$S r1cs info build/age_proof.r1cs

# 4,544 constraints -> 2^13 = 8192 is enough. Slowest step is phase2 prepare
# (minutes in JS). Skip it on re-runs if keys/pot13_final.ptau already exists.
if [ ! -f keys/pot13_final.ptau ]; then
  echo "[2/7] powers of tau (dev only)"
  $S powersoftau new bn128 13 keys/pot13_0.ptau
  echo "[3/7] contribute"
  $S powersoftau contribute keys/pot13_0.ptau keys/pot13_1.ptau --name="dev" -e="$(head -c 32 /dev/urandom | base64)"
  echo "[4/7] prepare phase2 (slow)"
  $S powersoftau prepare phase2 keys/pot13_1.ptau keys/pot13_final.ptau
fi

echo "[5/7] groth16 setup"
$S groth16 setup build/age_proof.r1cs keys/pot13_final.ptau keys/age_0.zkey
echo "[6/7] zkey contribute"
$S zkey contribute keys/age_0.zkey keys/age_final.zkey --name="dev" -e="$(head -c 32 /dev/urandom | base64)"
echo "[7/7] export verification key"
$S zkey export verificationkey keys/age_final.zkey keys/verification_key.json
echo "DONE. Now run: node test_age_proof.mjs"
