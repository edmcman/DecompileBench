# CER Sensitivity Check

Given a CSV of CER sensitivity cases (columns: model, project, function, opt, cer, io_status, cases_passed, cases_total, all_io_tests_passed, cer_sensitivity_pattern, ground_truth_snippet, prediction_snippet), run `check_candidate_correctness.py` for each row and accumulate results.

## Steps

1. Ask the user for:
   - Path to the input CSV
   - Which projects to include (or all)
   - Output CSV filename (default: `cer_check_results.csv`)

2. Write a script (or reuse `run_cer_checks.py` if it exists) that:
   - Reads the input CSV
   - Filters to the specified projects
   - For each row, writes `prediction_snippet` to `./tmp.c`
   - Runs: `python check_candidate_correctness.py --config config.yaml --dataset dataset/decompiled_ds_all --project {project} --function {function} --candidate-file ./tmp.c --output-json ./report.json`
   - Parses `report.json` for: `overall_pass`, `per_opt_pass`, and `compile_{opt}` for each opt level
   - Appends those fields to the row and writes to the output CSV incrementally (flush after each row)
   - Prints progress as `[i/n] model / project / function / opt -> PASS/FAIL`

3. After running, analyze the results:
   - Report total rows processed, pass count, fail count
   - Break down failures by type:
     - **Compile failures**: all compile_{opt} columns are False
     - **Compiles but CER fails**: at least one compile_{opt} is True, overall_pass is False
     - Within compile-but-fail: note if the failure is likely due to a different allocator/wrapper (e.g. using `malloc` instead of a project-specific wrapper like `avahi_malloc`) by checking if the candidate and ground truth have the same structure but differ in the called allocator
   - Highlight any failures that compile successfully AND are not explained by allocator substitution — these are the most interesting cases

## Notes

- `run_cer_checks.py` already implements the core loop; reuse it rather than rewriting
- The script should work from the DecompileBench project root
- Prerequisites: baseline `libfunction.so` files must exist (evaluate_rsr.py --decompilers func), fuzzers and corpus must be built
- If the dataset doesn't have a row for a given project/function, `check_candidate_correctness.py` will error — report these as skipped
