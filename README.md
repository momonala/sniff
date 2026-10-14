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
  proto.py         # schema-less protobuf decoder (bodies -> field-number trees)
  tlslog.py        # mitmproxy addon: logs failed TLS handshakes (cert-pinning evidence)
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
   Failed TLS handshakes are logged to `data/raw/<name>.tls-failures.txt`
   with their hostname; pinned apps and Apple system hosts show up there
   instead of in the capture. Quiet the Apple noise with
   `--ignore-hosts '(apple\.com|icloud\.com)$'`.
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
   response_status, response_headers, response_body`. Bodies that parse as
   protobuf come out as `{"protobuf": {<field number>: [values...], ...}}`
   trees (every field is a list, one entry per occurrence), with no `.proto`
   needed; everything else is text. A summary table of
   method/host/path counts is printed.

With no `hosts.txt` entries and no `--host`, every flow is kept.

## Notes

- Apps that pin certificates will fail to connect through the proxy; there
  is no workaround here. Tell pinning apart from a broken cert install by
  loading a browser page first: if the browser also lands in the
  tls-failures log, the phone does not trust the mitmproxy CA.
- If every HTTPS host fails after reinstalling the CA profile, the trust
  toggle was reset: Settings → General → About → Certificate Trust Settings.
- Never commit anything under `data/`; it contains live session tokens.
