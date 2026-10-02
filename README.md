# Continuous Recon Scanner

## Layout

```text
scanner-repo-name/
├── data/
│   ├── all-domains.txt
│   ├── .scan-state.json          # created/updated by GitHub Actions
│   └── <domain>/
│       ├── valid-subdomains.txt
│       └── <subdomain>/
│           ├── all-uniq-routs.txt
│           ├── all-uniq-params.txt
│           ├── no-validation-listener.txt
│           ├── p-xss-listener.txt
│           ├── validation-listener.txt
│           └── js_redirect_vulnerable.txt
├── tools/
│   ├── subdomain_enum.py
│   ├── bootstrap_url.py
│   ├── route_params_recon.py
│   ├── xss_reflect_checker.py
│   ├── unique_listener_scanner.py
│   └── js_redirect_tester.py
├── requirements.txt
└── .github/workflows/sync.yml
```

## How the workflow works

1. Reads apex domains from `data/all-domains.txt`.
2. Runs `subdomain_enum.py <domain>` and stores `valid-subdomains.txt`.
3. Processes valid subdomains one at a time.
4. Performs a same-host HTTP(S) GET with at most 4 redirects and requires final `200` + `text/html`.
5. Queries Wayback CDX and builds `q-urls.txt` from the bootstrap URL plus archive query URLs.
6. Runs route/parameter recon.
7. Runs reflection checking.
8. Runs the unique listener scanner.
9. Runs the client-side redirect tester.
10. Commits the completed checkpoint/results to the repository.
11. Each GitHub Actions run has a 5h45m limit. The scheduled run starts every 6 hours, so an interrupted stage is resumed on the next run.

Intermediate files are kept in `data/.work/` only while a stage is running and are removed after completion. They are not part of the final per-subdomain result set.

## Discord webhook

The Python scripts use:

```python
WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "")
```

The workflow passes the GitHub Actions secret `DISCORD_WEBHOOK_URL` into the job. Add that secret in the repository settings.

## Important GitHub Actions behavior

This is continuous scheduled scanning rather than a literally permanent process. GitHub-hosted runners are ephemeral and each job has a maximum runtime. The checkpoint/commit design is what makes the scan continue across jobs.

GitHub may also delay scheduled workflows. For unattended scanning, keep the repository active and monitor the Actions page.

## One-command GitHub upload

After extracting this ZIP into a directory, with GitHub CLI (`gh`) authenticated:

```bash
unzip -q scanner-repo-name.zip && cd scanner-repo-name && gh repo create scanner-repo-name --private --source=. --remote=origin --push
```

Then edit `data/all-domains.txt`, commit and push:

```bash
printf '%s\n' example.com another-target.com > data/all-domains.txt && git add data/all-domains.txt && git commit -m 'add scan targets' && git push
```
