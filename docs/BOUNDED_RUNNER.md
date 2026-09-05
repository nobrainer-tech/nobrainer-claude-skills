# Bound one command

The optional helper at `skills/nobrainer-sessions/scripts/run_bounded.py` runs
one explicit command under a wall-time limit and a combined stdout/stderr
capture limit. It uses Python 3.11+ and POSIX process groups, with no extra
package, daemon or hook installation. It ships inside the Sessions skill so
copy installations retain the helper. Windows is explicitly unsupported.

From a reviewed checkout, run this harmless example. Choose a fresh receipt
path; the runner refuses existing files, directories and symlinks.

```bash
python3 skills/nobrainer-sessions/scripts/run_bounded.py \
  --wall-seconds 5 --max-output-bytes 4096 \
  --receipt ./example-receipt.json -- \
  python3 -c 'print("checked command")'
```

Inspect the receipt and exit status. `completed` means the command exited zero
within the limits; it does not mean its output is correct or the task accepted.
The receipt records configured limits, observed and retained output bytes,
elapsed time, process exit/signal and cleanup attempts. It omits argv by default.
Use `--record-argv` only for non-sensitive arguments. Output and working-directory
paths may still be sensitive; keep receipts in the appropriate project location.

## A timeout is not success

Use another fresh receipt path:

```bash
python3 skills/nobrainer-sessions/scripts/run_bounded.py \
  --wall-seconds 0.2 --max-output-bytes 4096 \
  --receipt ./timeout-receipt.json -- \
  python3 -c 'import time; time.sleep(30)'
```

The runner should return 124 and record `timed_out`. Output overflow returns
125 and `output_limit`; other command failures remain failures. Inspect the
receipt to disambiguate a child that itself returns 124 or 125. Setup/runner
errors return nonzero and may have no receipt; absence is never success.

## Exact boundary

- Limits apply only to this invocation, not other host tools or model turns.
- The runner owns a new POSIX process group. It can terminate members of that
  group; a process deliberately creating a new session can escape that group.
- It is not a sandbox: the child retains the caller's filesystem, network and
  environment authority. Run only already-authorized commands.
- Token count, model context, provider cost and total RAM are not measured or
  capped. Receipts mark model tokens and cost UNKNOWN.
- Stdin is closed. Interactive login, browser sessions and persistent services
  should use the appropriate host tool rather than this command guard.
- Capture is bounded; total execution includes a short termination/drain grace
  period. Output forwarding to a blocked downstream consumer is not a promise
  about the consumer's responsiveness.
- No automatic retries, model switches, installation or task acceptance follow
  from a receipt. Inspect the failure and decide the next authorized action.

Remove the helper's invocation to roll back; no global setting was changed.
The tests execute real child processes and are separate from model evaluations.
