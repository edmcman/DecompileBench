#!/usr/bin/env python3

import argparse
import json
import pathlib
import subprocess
import sys
import tempfile
import time

import datasets
import yaml
from datasets import load_from_disk

from evaluate_cer import ReexecutableRateEvaluator
from evaluate_rsr import TEMPLATE, make_function_static

STDERR_TAIL_CHARS = 1000


def parse_args():
    parser = argparse.ArgumentParser(
        description="Check a single candidate function with CER-style coverage equivalence."
    )
    parser.add_argument("--config", type=str, default="./config.yaml")
    parser.add_argument("--dataset", type=str, required=True)
    parser.add_argument("--project", type=str, required=True)
    parser.add_argument("--function", type=str, required=True)
    parser.add_argument("--candidate-file", type=str, required=True)
    parser.add_argument("--output-json", type=str, default=None)
    return parser.parse_args()


def decode_stderr(stderr_obj) -> str:
    if stderr_obj is None:
        return ""
    if isinstance(stderr_obj, bytes):
        return stderr_obj.decode("utf-8", errors="replace")
    return str(stderr_obj)


def fail_with_errors(errors: list[str], exit_code: int = 2):
    print("Prerequisite check failed:", file=sys.stderr)
    for item in errors:
        print(f"- {item}", file=sys.stderr)
    sys.exit(exit_code)


def load_first_matching_row(ds: datasets.Dataset, project: str, function: str) -> dict:
    required_columns = ["project", "file", "include", "opt", "path"]
    missing = [c for c in required_columns if c not in ds.column_names]
    if missing:
        raise ValueError(
            f"Dataset missing required columns: {missing}. "
            "Expected merged dataset with project/file/include/opt/path."
        )

    for row in ds:
        if row.get("project") == project and row.get("file") == function:
            return row
    raise ValueError(f"No row found in dataset for project={project}, function={function}")


def build_candidate_source(include_code: str, candidate_code: str, function: str) -> str:
    source = "#include <defs.h>\n" + include_code + "\n" + candidate_code
    source = make_function_static(source, function)
    return source + "\n" + TEMPLATE.format(function=function)


def gather_prereq_errors(oss_fuzz_path: pathlib.Path, project: str, function: str) -> list[str]:
    errors = []
    baseline_lib = oss_fuzz_path / "build" / "challenges" / project / function / "libfunction.so"
    out_dir = oss_fuzz_path / "build" / "out" / project
    corpus_dir = oss_fuzz_path / "build" / "corpus" / project
    stats_dir = oss_fuzz_path / "build" / "stats" / project

    if not baseline_lib.exists():
        errors.append(
            f"Missing baseline lib: {baseline_lib}\n"
            "Run:\n"
            "  python evaluate_rsr.py --config ./config.yaml --decompiled-dataset <merged_dataset_path> --decompilers func"
        )
    if not out_dir.exists():
        errors.append(
            f"Missing built fuzzers directory: {out_dir}\n"
            "Run:\n"
            f"  python extract_functions.py --config ./config.yaml --project {project}"
        )
    if not corpus_dir.exists():
        errors.append(
            f"Missing corpus directory: {corpus_dir}\n"
            "Run:\n"
            f"  python extract_functions.py --config ./config.yaml --project {project}"
        )
    if not stats_dir.exists():
        errors.append(
            f"Missing coverage stats directory: {stats_dir}\n"
            "Run:\n"
            f"  python extract_functions.py --config ./config.yaml --project {project}"
        )
    return errors


def run_allow_fail(evaluator: ReexecutableRateEvaluator, cmd: list[str], **kwargs):
    try:
        result = evaluator.exec_in_container(cmd, **kwargs)
        return result.returncode, result.stdout, result.stderr
    except subprocess.CalledProcessError as exc:
        return exc.returncode, exc.stdout, exc.stderr


def compile_candidate_per_opt(
    evaluator: ReexecutableRateEvaluator,
    source_root_host: pathlib.Path,
    source_root_docker: pathlib.Path,
    function: str,
    opts: list[str],
    source_text: str,
) -> dict[str, dict]:
    compile_results: dict[str, dict] = {}

    for opt in opts:
        source_dir = source_root_host / opt
        source_dir.mkdir(parents=True, exist_ok=True)
        c_host = source_dir / f"{function}.c"
        c_host.write_text(source_text)

        run_allow_fail(evaluator, ["mkdir", "-p", f"/challenges/{function}/{opt}/candidate"], cwd="/")
        run_allow_fail(evaluator, ["chmod", "777", f"/challenges/{function}/{opt}/candidate"], cwd="/")

        c_docker = source_root_docker / opt / f"{function}.c"
        lib_docker = pathlib.Path("/challenges") / function / opt / "candidate" / "libfunction.so"

        returncode, _stdout, stderr = run_allow_fail(
            evaluator,
            [
                "clang",
                f"-{opt}",
                "-I/fix/func",
                c_docker.as_posix(),
                "-shared",
                "-fPIC",
                "-o",
                lib_docker.as_posix(),
                "-fprofile-instr-generate",
                "-fcoverage-mapping",
                "-pthread",
                "-Wl,--no-as-needed",
                "-Wl,-ldl",
                "-Wl,-lm",
                "-Wno-unused-command-line-argument",
            ],
            cwd="/",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        lib_exists = run_allow_fail(
            evaluator,
            ["test", "-f", lib_docker.as_posix()],
            cwd="/",
        )[0] == 0

        stderr_text = decode_stderr(stderr)
        compile_results[opt] = {
            "success": returncode == 0 and lib_exists,
            "stderr_tail": stderr_text[-STDERR_TAIL_CHARS:] if stderr_text else None,
        }
    return compile_results


def evaluate_coverage(
    evaluator: ReexecutableRateEvaluator,
    function: str,
    opts: list[str],
    fuzzers: list[str],
    compile_results: dict[str, dict],
) -> dict[str, dict]:
    coverage = {opt: {} for opt in opts}

    if not any(compile_results[opt]["success"] for opt in opts):
        for opt in opts:
            for fuzzer in fuzzers:
                coverage[opt][fuzzer] = {"pass": False, "reason": "candidate compile failed"}
        return coverage

    for fuzzer in fuzzers:
        _, _, diff_result = evaluator.link_and_test_for_function(fuzzer, function)
        for opt in opts:
            if not compile_results[opt]["success"]:
                coverage[opt][fuzzer] = {"pass": False, "reason": "candidate compile failed"}
                continue
            if not diff_result:
                coverage[opt][fuzzer] = {"pass": False, "reason": "CER runtime failed before comparison"}
                continue

            key = f"candidate-{opt}"
            if key not in diff_result:
                coverage[opt][fuzzer] = {"pass": False, "reason": "CER runtime failed before comparison"}
            elif diff_result[key]:
                coverage[opt][fuzzer] = {"pass": True, "reason": "coverage matched baseline on deterministic lines"}
            else:
                coverage[opt][fuzzer] = {"pass": False, "reason": "deterministic coverage mismatch"}
    return coverage


def print_summary(
    opts: list[str],
    fuzzers: list[str],
    compile_results: dict[str, dict],
    coverage_results: dict[str, dict],
    per_opt_pass: dict[str, bool],
    overall_pass: bool,
):
    print("=== Candidate Correctness Report ===")
    print("Compile status per optimization:")
    for opt in opts:
        verdict = "PASS" if compile_results[opt]["success"] else "FAIL"
        print(f"  {opt}: {verdict}")
        if not compile_results[opt]["success"] and compile_results[opt].get("stderr_tail"):
            print(f"    stderr_tail: {compile_results[opt]['stderr_tail']}")

    print("Coverage status per optimization:")
    for opt in opts:
        passed = sum(1 for item in coverage_results[opt].values() if item["pass"])
        print(f"  {opt}: {passed}/{len(fuzzers)} fuzzers passed; opt verdict={'PASS' if per_opt_pass[opt] else 'FAIL'}")
        for fuzzer in fuzzers:
            item = coverage_results[opt].get(fuzzer, {"pass": False, "reason": "missing result"})
            print(f"    {fuzzer}: {'PASS' if item['pass'] else 'FAIL'} ({item['reason']})")

    print(f"Overall verdict: {'PASS' if overall_pass else 'FAIL'}")


def main():
    args = parse_args()
    repo_path = pathlib.Path(__file__).resolve().parent
    candidate_path = pathlib.Path(args.candidate_file)
    if not candidate_path.exists():
        print(f"Candidate file does not exist: {candidate_path}", file=sys.stderr)
        sys.exit(2)

    with open(args.config, "r") as f:
        config = yaml.safe_load(f)
    oss_fuzz_path = pathlib.Path(config["oss_fuzz_path"]).resolve()
    opts = list(config["opts"])

    ds = load_from_disk(args.dataset)
    row = load_first_matching_row(ds, args.project, args.function)
    candidate_source = build_candidate_source(row.get("include", ""), candidate_path.read_text(), args.function)

    prereq_errors = gather_prereq_errors(oss_fuzz_path, args.project, args.function)
    if prereq_errors:
        fail_with_errors(prereq_errors)

    evaluator = ReexecutableRateEvaluator(config, args.project)
    evaluator.decompilers = ["candidate"]
    fuzzers = sorted([name for name, fn_map in evaluator.functions.items() if args.function in fn_map])
    if not fuzzers:
        print(
            f"No covered fuzzers found for function {args.function} in project {args.project}.",
            file=sys.stderr,
        )
        print(f"Check coverage stats under {oss_fuzz_path / 'build' / 'stats' / args.project}", file=sys.stderr)
        sys.exit(2)

    corpus_errors = []
    for fuzzer in fuzzers:
        corpus = oss_fuzz_path / "build" / "corpus" / args.project / fuzzer
        if not corpus.exists():
            corpus_errors.append(
                f"Missing corpus for fuzzer {fuzzer}: {corpus}\n"
                "Run:\n"
                f"  python extract_functions.py --config ./config.yaml --project {args.project}"
            )
    if corpus_errors:
        fail_with_errors(corpus_errors)

    compile_start = time.perf_counter()
    tmp_root = repo_path / "tmp"
    tmp_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="candidate_sources_", dir=tmp_root) as tmp_dir:
        source_root_host = pathlib.Path(tmp_dir)
        source_root_docker = pathlib.Path("/oss-fuzz") / source_root_host.relative_to(repo_path)
        with evaluator.start_container(keep=False):
            compile_results = compile_candidate_per_opt(
                evaluator=evaluator,
                source_root_host=source_root_host,
                source_root_docker=source_root_docker,
                function=args.function,
                opts=opts,
                source_text=candidate_source,
            )
            coverage_start = time.perf_counter()
            coverage_results = evaluate_coverage(
                evaluator=evaluator,
                function=args.function,
                opts=opts,
                fuzzers=fuzzers,
                compile_results=compile_results,
            )
            coverage_end = time.perf_counter()
            run_allow_fail(evaluator, ["bash", "-c", "rm -f /out/*_patched"])

    per_opt_pass = {
        opt: compile_results[opt]["success"] and all(coverage_results[opt][fuzzer]["pass"] for fuzzer in fuzzers)
        for opt in opts
    }
    overall_pass = all(per_opt_pass.values())

    print_summary(
        opts=opts,
        fuzzers=fuzzers,
        compile_results=compile_results,
        coverage_results=coverage_results,
        per_opt_pass=per_opt_pass,
        overall_pass=overall_pass,
    )

    report = {
        "project": args.project,
        "function": args.function,
        "candidate_file": str(candidate_path.resolve()),
        "opts": opts,
        "fuzzers": fuzzers,
        "compile": compile_results,
        "coverage": coverage_results,
        "summary": {"per_opt_pass": per_opt_pass, "overall_pass": overall_pass},
        "timing": {
            "compile_seconds": max(0.0, coverage_start - compile_start),
            "coverage_seconds": max(0.0, coverage_end - coverage_start),
        },
    }

    if args.output_json:
        output_path = pathlib.Path(args.output_json)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"Saved JSON report to {output_path}")

    sys.exit(0 if overall_pass else 1)


if __name__ == "__main__":
    main()
