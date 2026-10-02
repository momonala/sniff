# sniff

Capture an app's traffic through mitmproxy, then extract only the API calls
you care about (dropping analytics/SDK/OS noise) into a clean JSON file for
reverse-engineering the API contract.

Lifted from the `traffic/` tool in the UrbanSportsClub project, minus the
USC-specific auth and replay logic.

## Layout

```
hosts.txt          # host allowlist used by extract (edit per target)
scripts/sniff.sh   # mitmdump -> data/raw/<name>.flow
scripts/extract.sh # .flow -> data/processed/flows.json
src/sniff/
  filters.py       # hosts.txt loader + matching
  extract.py       # flow reader, JSON dump, summary table
data/              # gitignored: captures hold auth tokens / PII
```

## Usage

1. **Proxy the device.** Run `./scripts/sniff.sh` once; it prints this
   machine's IP. On the phone set Wi-Fi HTTP proxy to that IP, port 8080,
   then open http://mitm.it to install and trust the mitmproxy CA
   (iOS: Settings → General → About → Certificate Trust Settings).
2. **Record.**
   ```
   ./scripts/sniff.sh              # -> data/raw/capture.flow
   ./scripts/sniff.sh login        # -> data/raw/login.flow
   ```
   Drive the app, then Ctrl-C. Extra args pass through to `mitmdump`.
   Keep captures small and per-action; it is much easier to find the
   one relevant request afterwards.
3. **See what hosts the app talks to.**
   ```
   ./scripts/extract.sh --list-hosts
   ./scripts/extract.sh data/raw/login.flow --list-hosts
   ```
4. **Filter.** Put the first-party API hosts in `hosts.txt` (or pass
   `--host api.example.com`, repeatable; `.example.com` matches subdomains),
   then:
   ```
   ./scripts/extract.sh                          # capture.flow -> flows.json
   ./scripts/extract.sh data/raw/login.flow -o data/processed/login.json
   ```
   Each entry has `url, method, request_headers, request_body,
   response_status, response_headers, response_body`. A summary table of
   method/host/path counts is printed.

With no `hosts.txt` entries and no `--host`, every flow is kept.

## Notes

- Apps that pin certificates will fail to connect through the proxy; there
  is no workaround here.
- Never commit anything under `data/`; it contains live session tokens.
