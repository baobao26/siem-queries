---
description: Run a saved SIEM query against Splunk, analyze the results for suspicious activity, and generate an Obsidian-compatible investigation note mapped to ATT&CK
argument-hint: <query-file> [timerange]
allowed-tools: Bash, Read, Write, Glob
---

## Inputs

- `$1` — path to a text file containing the SPL query to run. Required.
- `$2` — Splunk time modifier for `earliest_time` (e.g. `-24h`, `-7d@d`, `-1h@h`). Optional, defaults to `-24h` if not provided.

Environment variables `SPLUNK_HOST` and `SPLUNK_TOKEN` must already be set. If either is missing, stop and tell the user which one is missing instead of guessing a value.

## Steps

1. **Read the query.** Read the file at `$1` with the Read tool. Treat its full contents (trimmed) as the SPL search string. If the query does not already start with `search`, `|`, or a generated streaming command, prefix it with `search ` before submitting — Splunk's search/jobs endpoint requires a leading `search` for raw searches but not for piped generating commands like `|tstats` or `|datamodel`.

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

8. **Write the investigation note.** Create the `investigations/` directory if it doesn't exist. Save a new markdown file there named `investigations/<YYYY-MM-DD>_<slug-of-query-filename>.md` (slugify the query file's basename). The note must contain:

   - YAML frontmatter with `date` (today, ISO format), `tags` (include `siem`, `investigation`, plus one tag per ATT&CK technique like `T1003.001`), and `techniques` (list of the mapped technique IDs).
   - An `[[T1003.001]]`-style Obsidian backlink for every mapped technique, inline in the summary text where it's discussed.
   - A **Summary** section describing what was found in plain language.
   - A **Query** section with the raw SPL query (as run) and the time range used.
   - A **Results** section stating the total result count and highlighting the specific events that drove each finding.
   - An **Analyst Notes** section left empty (just a heading) for the human analyst to fill in.

9. Report back to the user with the path to the note you created and a one-line summary of what was found (or that nothing suspicious was found).
