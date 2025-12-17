#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DATASET_DIR="$DIR/dataset"
DECOMPILERS=("ghidra" "hexrays")
#PROJECTS=("minizip" "avahi" "qt" "libdwarf" "c-blosc" "unbound" "qpdf" "file" "wavpack" "libsrtp" "fribidi" "libconfig" "jansson" "strongswan" "pjsip" "croaring")
PROJECTS=("file")
export LIBCLANG_PATH="/usr/lib/llvm-18/lib/libclang-18.so.1"

test -f "$LIBCLANG_PATH" || { echo "Please set LIBCLANG_PATH correctly."; exit 1; }

test -f "$DIR/libfunction.so" || { echo "Please build libfunction.so first."; exit 1; }

test -d "$DIR/oss-fuzz/build" && { echo "Build directory already exists. Please remove it before running this script."; exit 1; }

test -d "$DATASET_DIR" && { echo "Dataset directory already exists. Please remove it before running this script."; exit 1; }

test -d "$DIR/tmp_results" && { echo "Temporary results directory already exists. Please remove it before running this script."; exit 1; }

set -xeuo pipefail

# create a comma-separated project list from the PROJECTS array
PROJECTS_CSV="$(IFS=, ; echo "${PROJECTS[*]}")"
echo "Using projects: $PROJECTS_CSV"
python extract_functions.py --config "$DIR/config.yaml" --project "$PROJECTS_CSV"

python compile_ossfuzz.py --config "$DIR/config.yaml" --output "$DATASET_DIR"

# generate --with-<decompiler> flags from the DECOMPILERS array
DECOMPILER_FLAGS=()
for d in "${DECOMPILERS[@]}"; do
	DECOMPILER_FLAGS+=("--with-$d")
done
echo "Using decompilers: ${DECOMPILERS[*]}"

python "$DIR/decompiler-service/manage.py" "${DECOMPILER_FLAGS[@]}" build

python "$DIR/decompiler-service/manage.py" "${DECOMPILER_FLAGS[@]}" start &
echo "Started decompiler service"
sleep 5  # wait for the decompiler service to start

# gracefully stop the decompiler service on exit
stop_decompiler_service() {
	python "$DIR/decompiler-service/manage.py" "${DECOMPILER_FLAGS[@]}" stop || true
}
trap 'stop_decompiler_service' EXIT INT TERM

rm my_task_queue.json || true

python "$DIR/decompiler-service/scripts/test_decompile_async.py"

test -f my_task_queue.json || { echo "Decompilation task queue not found!"; exit 1; }

# create a comma-separated decompiler list from the DECOMPILERS array
DECOMPILERS_CSV="$(IFS=, ; echo "${DECOMPILERS[*]}")"
echo "Using decompilers: $DECOMPILERS_CSV"
python decompile.py --base-dataset-path "$DATASET_DIR" --output "$DATASET_DIR/decompiled_ds" --decompilers "$DECOMPILERS_CSV"

echo "Merging base dataset ($DATASET_DIR) with decompiled dataset ($DATASET_DIR/decompiled_ds)"
python merge.py --base-dataset-path "$DATASET_DIR" --decompiled-datasets "$DATASET_DIR/decompiled_ds" --output "$DATASET_DIR/decompiled_ds_all"

# Generate base libfunction.so files required for CER evaluation
python evaluate_rsr.py --config "$DIR/config.yaml" --decompiled-dataset "$DATASET_DIR/decompiled_ds_all" --decompilers func

# Evaluate RSR for the configured traditional decompilers
python evaluate_rsr.py --config "$DIR/config.yaml" --decompiled-dataset "$DATASET_DIR/decompiled_ds_all" --decompilers "$DECOMPILERS_CSV"

# Run CER evaluation (coverage) on the merged dataset
python evaluate_cer.py --dataset "$DATASET_DIR/decompiled_ds_all"

