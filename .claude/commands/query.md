---
description: Run a saved SIEM query against Splunk, analyze the results for suspicious activity, and generate an Obsidian-compatible investigation note mapped to ATT&CK
argument-hint: <query-file> [timerange] [severity] [assignee] [case_id] [output_dir]
allowed-tools: Bash, Read, Write, Glob
---

## Inputs

- `$1` — path to a text file containing the SPL query to run. Required.
- `$2` — Splunk time modifier for `earliest_time` (e.g. `-24h`, `-7d@d`, `-1h@h`). Optional, defaults to `-24h` if not provided.
- `$3` — `severity`: expected severity level for this investigation. Optional. If provided, must be one of `info`, `low`, `medium`, `high`, `critical` (case-insensitive) — if it's anything else, stop and tell the user rather than guessing which one they meant. If not provided, omit `severity` from the note's frontmatter entirely rather than defaulting to a guessed value.
- `$4` — `assignee`: analyst name to record against the investigation. Optional; omit from frontmatter if not provided.
- `$5` — `case_id`: an existing case/ticket identifier to link this investigation to. Optional; omit from frontmatter if not provided.
- `$6` — `output_dir`: directory to save the note into. Optional, defaults to `investigations/` if not provided.

Environment variables `SPLUNK_HOST` and `SPLUNK_TOKEN` must already be set. If either is missing, stop and tell the user which one is missing instead of guessing a value.

## Input Validation

Run these checks before submitting anything to Splunk. Checks 2 and 3 are hard stops — checks 1 and 4 have their own pass/fail behavior noted below.

1. **SPL syntax.** After reading and prefixing the query (Step 1 below), validate it against Splunk's parser instead of guessing whether it's well-formed:

   ```bash
   curl -sk "https://${SPLUNK_HOST}:8089/services/search/parser?output_mode=json" \
     -H "Authorization: Bearer ${SPLUNK_TOKEN}" \
     --data-urlencode "q=<the query from step 1>"
   ```

   If the response's `messages` contains an `ERROR`/`FATAL` entry, stop and surface it to the user rather than submitting a broken search job.

2. **Timerange format.** `$2` (if provided) must match a Splunk relative time modifier: `-<integer><unit>` where `<unit>` is `m`, `h`, or `d`, optionally followed by a snap-to (e.g. `@d`, `@h`) — valid examples: `-24h`, `-7d@d`, `-30m`. If it doesn't match, stop and tell the user rather than passing it through to `earliest_time` as-is.

3. **Severity.** `$3` (if provided) must be one of `info`, `low`, `medium`, `high`, `critical` (case-insensitive). If it's anything else, stop and tell the user rather than guessing which one they meant.

4. **Case ID format.** `$5` (if provided) is checked against a loose ticket-ID shape: a letter prefix, a separator, then digits (e.g. `CASE-1234`, `INC0012345`). This repo doesn't mandate a specific ticketing system, so this is a **warning, not a hard stop** — if it doesn't match, tell the user it looks unusual and proceed with the run anyway.

## Steps

1. **Read the query.** Read the file at `$1` with the Read tool. Treat its full contents (trimmed) as the SPL search string. If the query does not already start with `search`, `|`, or a generated streaming command, prefix it with `search ` before submitting — Splunk's search/jobs endpoint requires a leading `search` for raw searches but not for piped generating commands like `|tstats` or `|datamodel`. Then run the Input Validation checks above before continuing.

2. **Create the search job.** Using the Bash tool, submit the query to Splunk's REST API:

   ```bash
   curl -sk "https://${SPLUNK_HOST}:8089/services/search/jobs" \
     -H "Authorization: Bearer ${SPLUNK_TOKEN}" \
     --data-urlencode "search=<the query from step 1>" \
     --data-urlencode "earliest_time=<timerange, default -24h>" \
     --data-urlencode "latest_time=now" \
     -d "output_mode=json"
   ```

   Capture the returned `sid`. If Splunk uses a raw auth token rather than a bearer JWT in this environment and the request is rejected, retry with `-H "Authorization: Splunk ${SPLUNK_TOKEN}"` instead.

3. **Poll for completion.** Poll the job status endpoint until `dispatchState` is `DONE` (or `FAILED`):

   ```bash
   curl -sk "https://${SPLUNK_HOST}:8089/services/search/jobs/<sid>?output_mode=json" \
     -H "Authorization: Bearer ${SPLUNK_TOKEN}"
   ```

   Poll every couple of seconds with a reasonable cap (e.g. give up and report failure after ~60s). If `dispatchState` is `FAILED`, surface Splunk's `messages` to the user and stop.

4. **Fetch results.** Once done, retrieve results as JSON:

   ```bash
   curl -sk "https://${SPLUNK_HOST}:8089/services/search/jobs/<sid>/results?output_mode=json&count=0" \
     -H "Authorization: Bearer ${SPLUNK_TOKEN}"
   ```

   Note the total result count.

5. **Clean up the job.** Issue a `DELETE` to `https://${SPLUNK_HOST}:8089/services/search/jobs/<sid>` so the job doesn't linger on the search head. Don't fail the whole command if cleanup fails — just note it.

6. **Analyze the results.** Look through the returned events for suspicious patterns: anomalous process lineage, encoded/obfuscated command lines, known LOLBins, credential access artifacts, unusual auth patterns, rare/first-seen values, beaconing-like timing, etc. Base this on what's actually present in the data — don't invent findings if the result set is empty or benign.

7. **Map to ATT&CK.** For each distinct suspicious pattern found, identify the most specific matching ATT&CK technique or sub-technique ID (e.g. `T1003.001`, `T1059.001`). Only map techniques that are actually supported by the observed data.

8. **Write the investigation note.** Create the output directory (`$6`, defaulting to `investigations/`) if it doesn't exist. Save a new markdown file there named `<output_dir>/<YYYY-MM-DD>_<slug-of-query-filename>.md` (slugify the query file's basename). The note must contain:

   - YAML frontmatter with `date` (today, ISO format), `tags` (include `siem`, `investigation`, plus one tag per ATT&CK technique like `T1003.001`), and `techniques` (list of the mapped technique IDs). Additionally include `severity` (lowercased `$3`), `assignee` (`$4`), and `case_id` (`$5`) as frontmatter fields **only for the ones actually supplied** — don't add a field with a placeholder or guessed value for an argument that wasn't given.
   - An `[[T1003.001]]`-style Obsidian backlink for every mapped technique, inline in the summary text where it's discussed.
   - A **Summary** section describing what was found in plain language.
   - A **Query** section with the raw SPL query (as run) and the time range used.
   - A **Results** section stating the total result count and highlighting the specific events that drove each finding.
   - An **Analyst Notes** section left empty (just a heading) for the human analyst to fill in. If `case_id` was supplied, add a line above the heading noting the linked case (e.g. `Linked case: CASE-1234`).

9. Report back to the user with the path to the note you created and a one-line summary of what was found (or that nothing suspicious was found).
