# sniff

Capture an app's traffic through mitmproxy, then extract only the API calls
you care about (dropping analytics/SDK/OS noise) into a clean JSON file for
reverse-engineering the API contract.

Lifted from the `traffic/` tool in the UrbanSportsClub project, minus the
USC-specific auth and replay logic.

## Layout

```
hosts.txt          # host allowlist used by extract (edit per target)
scripts/sniff.sh   # mitmdump (WireGuard tunnel, or --proxy) -> data/raw/<name>.flow
scripts/extract.sh # .flow -> data/processed/flows.json
src/sniff/
  filters.py       # hosts.txt loader + matching
  extract.py       # flow reader, JSON dump, summary table
  proto.py         # schema-less protobuf decoder (bodies -> field-number trees)
  tlslog.py        # mitmproxy addon: logs failed TLS handshakes (cert-pinning evidence)
  grpclog.py       # mitmproxy addon: streams gRPC through, logs each message to JSONL
  wgqr.py          # prints the WireGuard client config as a terminal QR code
data/              # gitignored: captures hold auth tokens / PII
```

## Usage

1. **One-time phone setup.**
   - Install the WireGuard app from the App Store.
   - Run `./scripts/sniff.sh --qr`. It prints a QR code. In WireGuard:
     Add a tunnel → Create from QR code. The keys live in
     `~/.mitmproxy/wireguard.conf` and are reused on every run, so the
     tunnel stays valid.
   - With the tunnel on and the capture running, open http://mitm.it on
     the phone, install the mitmproxy CA profile, then trust it
     (Settings → General → About → Certificate Trust Settings).
2. **Record.**
   ```
   ./scripts/sniff.sh              # -> data/raw/capture.flow
   ./scripts/sniff.sh login        # -> data/raw/login.flow
   ```
   Switch the tunnel on, drive the app, switch the tunnel off, then
   Ctrl-C. Extra args pass through to `mitmdump`.

   The tunnel sends *all* of the phone's traffic here, which also catches
   apps that ignore the HTTP proxy setting (Firebase Firestore's gRPC
   client does). Other apps' traffic lands in the capture too; `hosts.txt`
   filters it out at extract time.

   `--proxy` switches to the classic HTTP proxy on port 8080 instead (set
   it as the phone's Wi-Fi HTTP proxy, tunnel off).

   Terminal output is request lines and warnings only (`termlog_verbosity=warn`),
   so TLS-failure warnings still show. For the connect, disconnect and DNS lines
   add `--set termlog_verbosity=info`. To keep other hosts out of the capture,
   add `--allow-hosts '^api\.ostrom\.de'` (a regex): other hosts pass through
   undecrypted and stop appearing in `tls-failures.txt`. Matching by hostname
   under the WireGuard tunnel is untested; if the host vanishes from the
   capture, drop the flag.

   Each run writes, next to the `.flow`:
   - `<name>.tls-failures.txt`: hosts whose TLS handshake failed. Pinned
     apps and Apple system hosts show up here instead of in the capture.
     Quiet the Apple noise with
     `--ignore-hosts '(apple\.com|icloud\.com)(:\d+)?$'` (mitmproxy
     matches against `host:port`, so the port suffix is needed).
   - `<name>.grpc.jsonl`: gRPC calls (`content-type: application/grpc`)
     are streamed instead of buffered so long-lived streams keep working,
     which means their bodies are not in the `.flow` file. Each message is
     decoded and logged here instead: `start` (headers),
     `request`/`response` (one line per message) and `end` (`grpc-status`).

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

- Only switch the tunnel on while a capture is running. It routes all
  phone traffic to this machine, so with mitmproxy stopped the phone has
  no internet. Don't enable WireGuard's On-Demand auto-connect.
- The tunnel's endpoint is this machine's LAN IP at setup time. If the IP
  changes (new network, new DHCP lease), the tunnel connects to nothing:
  re-run with `--qr` and re-scan, or edit the Endpoint in the WireGuard
  app. A DHCP reservation for this machine avoids it.
- Apps that pin certificates fail the handshake; there is no workaround
  here. Firestore on iOS behaves like this (it ships its own root CAs), so
  its traffic shows up only in the tls-failures log. Tell pinning apart
  from a broken CA install by loading a browser page first: if the
  browser also lands in the tls-failures log, the phone does not trust
  the mitmproxy CA.
- If every HTTPS host fails after reinstalling the CA profile, the trust
  toggle was reset: Settings → General → About → Certificate Trust Settings.
- Never commit anything under `data/`; it contains live session tokens.
