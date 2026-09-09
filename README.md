# pwnagotchi_plugins

Custom Pwnagotchi plugins. Drop the `.py` file(s) directly into your
`custom_plugins` directory (plugin discovery is a flat, non-recursive
`glob("*.py")`, so don't nest them in subfolders) and merge the matching
`.toml` snippet into `config.toml`.

## hashtopolis_uploader

Automatically uploads captured WPA/WPA2 handshakes and PMKIDs to a
self-hosted [Hashtopolis](https://github.com/hashtopolis/server) server for
cracking, whenever the Pwnagotchi has internet connectivity.

### What it does

On every `on_internet_available` event (throttled by `min_interval_seconds`,
default 5 minutes), the plugin:

1. Scans `handshake_dir` for `.pcapng`/`.pcap` files not already recorded as
   uploaded or invalid, skipping anything matching `main.whitelist`.
2. **Sanitizes** each candidate (see below) and skips anything that isn't a
   genuine capture with real key material.
3. Converts valid captures to hashcat's `22000` format locally via
   `hcxpcapngtool` (reusing an existing `.22000` file next to the capture if
   one is already present and up to date - some Pwnagotchi setups generate
   this themselves).
4. Creates one Hashlist per handshake directly on the Hashtopolis server via
   its APIv2, embedding the hash lines in the creation request itself (no
   separate file upload step).
5. Records the outcome (`uploaded` / `invalid` / `failed`) in a small JSON
   state file inside `handshake_dir`, so the same handshake is never
   re-uploaded on a later run.
6. Shows brief status on the Pwnagotchi's display (`Hashtopolis (2/5)`, via
   `display.on_uploading()` / `on_normal()`, the same mechanism the built-in
   `wpa-sec` and `ohcapi` plugins use) and logs progress/results to
   `pwnagotchi.log`.

This mirrors the structure of this fork's own `ohcapi.py` and `pwncrack.py`
plugins (directory-scan-on-internet-available, `hcxpcapngtool` conversion,
`StatusFile`-based dedup) rather than inventing a new pattern.

### Prerequisites

- A running, reachable Hashtopolis server (APIv2).
- A Hashtopolis **API Token** (Settings -> API Tokens in the web UI) scoped
  with at least `permHashlistCreate`. This is a long-lived JWT string, not
  your account password - use it as-is for `api_key`.
- The token's user must be a member of the `access_group_id` you configure
  (group `1` is the default "everyone" group on a fresh install).
- `hcxpcapngtool` installed and on `PATH` (it already is on stock Pwnagotchi
  images, since the OS itself uses it for its own handshake tooling).
- Outbound network reachability from the Pwnagotchi to `hashtopolis_url`.

### Config reference

See [`hashtopolis_uploader.toml`](hashtopolis_uploader.toml) for a full
annotated example. Summary:

| Option | Default | Meaning |
|---|---|---|
| `enabled` | - | Standard Pwnagotchi plugin toggle. |
| `hashtopolis_url` | - | **Required.** Base URL of your server, no trailing slash. |
| `api_key` | - | **Required.** Hashtopolis API Token (Bearer JWT), scope `permHashlistCreate`. |
| `access_group_id` | `1` | Hashtopolis access group the new hashlists belong to. |
| `handshake_dir` | `bettercap.handshakes` from the same config | Where to look for captures. |
| `hashlist_name_format` | `"{hostname}-{essid}-{timestamp}"` | Template for each hashlist's name. Placeholders: `{hostname} {essid} {bssid} {timestamp} {filename}`. |
| `delete_after_upload` | `false` | Delete the local `.pcapng`/`.22000` pair only after a *confirmed* successful upload. |
| `min_free_space_mb` | `50` | Skip the whole cycle if free space on `handshake_dir`'s filesystem is below this. |
| `retry_count` | `3` | HTTP upload retries with exponential backoff before giving up for this run. |
| `timeout_seconds` | `30` | Timeout for both `hcxpcapngtool` and each HTTP request. |
| `verify_ssl` | `true` | Verify the server's TLS cert. Set `false` only for a trusted self-signed cert. |
| `min_interval_seconds` | `300` | Minimum gap between upload cycles, since `on_internet_available` can fire repeatedly. |
| `force_reupload` | `false` | Wipes the upload-state file on every config reload while `true`. Use to force a full re-scan, then set back to `false`. |

**Manual resend of a single handshake:** open the JSON state file at
`<handshake_dir>/.hashtopolis_uploads` and delete that file's entry from
whichever of the `uploaded`/`invalid`/`failed` sections it's in, then wait
for the next internet-available cycle (or force one via `force_reupload`).

### What "sanitization" checks, and why

Uploading is bandwidth and server storage you're spending, so a handshake is
only sent if it passes all of these:

1. **File sanity** - non-empty, and the first 4 bytes match a known
   pcap/pcapng magic number. Catches zero-byte or truncated files before
   wasting a subprocess call on them.
2. **Not whitelisted** - handshakes matching `main.whitelist` (your own
   networks) are never uploaded to a third-party server, same as the
   built-in `wpa-sec`/`ohcapi` plugins.
3. **Real key material** - the file is run through `hcxpcapngtool` and the
   resulting `.22000` output must be non-empty. A `.pcapng` that only
   captured beacons, probes, or a partial/incomplete EAPOL exchange produces
   no output here and is marked `invalid` rather than uploaded - this is
   the actual "is this crackable" check, not just a file-format check.

Anything that fails is recorded in the `invalid` section of the state file
with a reason, so you can check *why* a given handshake was skipped without
guessing - grep `pwnagotchi.log` for `HASHTOPOLIS:` or read the state file
directly.

A separate `failed` bucket tracks handshakes that validated fine but whose
*upload* failed (network error, server rejected the request, etc.) after
exhausting `retry_count` attempts *within that cycle*. `retry_count` only
bounds that immediate retry burst - a handshake in `failed` is not given up
on, it's retried again (another up-to-`retry_count` burst) on every
subsequent cycle indefinitely, until it succeeds or you intervene (whitelist
it, or fix whatever the logged error says is wrong server-side). Losing a
real handshake to a transient server error would be worse than the wasted
bandwidth of retrying every `min_interval_seconds`.

### Design decision: `.pcapng` vs `.22000`, and why

Hashtopolis does not convert pcap/pcapng server-side. The APIv2 hashlist
create endpoint (`POST /api/v2/ui/hashlists`) takes a `hashTypeId` and hash
*text* (via `sourceType: "paste"` + base64-encoded `sourceData`), not a
capture file. So the client is expected to run `hcxpcapngtool` (or
equivalent) itself and submit pre-converted hash lines - confirmed directly
against:

- `hashtopolis/server`'s own hash-type seed data
  (`src/inc/startup/hashtypes.json`): `hashTypeId 22000` is literally named
  `"WPA-PBKDF2-PMKID+EAPOL"`, `isSalted: 0` - the modern, combined
  EAPOL+PMKID hashcat mode. There is no separate `hashTypeId` for
  `.hccapx`/`.pcapng` as a submittable format; `.hccapx` is legacy and not
  what current hashcat/hcxtools target.
- `hashtopolis/server`'s `ci/apiv2/testfiles/hashlist/*.json` fixtures and
  `HashlistAPI.php`'s `createObject()`: a hashlist is created by embedding
  hash text directly (`sourceType: "paste"`, `sourceData`: base64 of the hash
  lines), not by pointing at an uploaded capture file.
- This fork's own `ohcapi.py` and `pwncrack.py` plugins, which already do
  exactly this - `hcxpcapngtool -o file.22000 file.pcapng`, then upload the
  resulting text - for their respective third-party services.

Given that, and that each handshake's `.22000` text is tiny (well under any
reasonable request-size limit), this plugin uses the "paste" hashlist
creation path directly rather than a separate `File` upload (which exists in
the API for other workflows, e.g. wordlists) or the `sourceType: "url"` mode
(which would require the Pwnagotchi to host the file for the server to pull,
adding complexity for no benefit here since the device is already the one
initiating the connection).

### Known limitations / things not fully verified

- **API version assumption.** All of the above was verified against the
  `master` branch of `hashtopolis/server` as of this writing (JSON:API-style
  APIv2, JWT Bearer auth, `POST /api/v2/ui/hashlists`). If you're running an
  older Hashtopolis release, field names, the auth scheme, or the endpoint
  path may differ - the community wiki lags the code in places, so treat a
  failed request's logged response body as the most reliable diagnostic.
- **`python-hashtopolis` (the official client library) was not used.** It's
  not published to PyPI, and its own `pyproject.toml` depends on `tuspy` and
  `confidence` - extra weight and packaging friction that isn't clearly
  worth it on a Pi Zero-class device for the single "create a hashlist"
  call this plugin needs. This plugin makes that one HTTP call directly with
  `requests` (already a dependency of the built-in `wpa-sec`/`ohcapi`/
  `pwncrack` plugins) instead. If you'd rather depend on the official
  library, `pip install` it from
  `https://github.com/hashtopolis/python-hashtopolis` first.
- **Brain/dedup features are left off** (`useBrain: false`). Hashtopolis
  Brain (cross-task duplicate-hash skipping) wasn't evaluated here; nothing
  stops you from enabling it server-side for the resulting hashlists
  manually.
- **No superhashlist/task automation.** This plugin only creates hashlists;
  it doesn't create or assign a cracking Task, Supertask, or agent for you.
  That's a deliberate scope cut - task/agent setup is a per-server policy
  decision (wordlists, rules, priority) that doesn't belong hardcoded into a
  Pwnagotchi plugin.
- **`hcxpcapngtool`'s exit code is intentionally ignored.** Its exit-code
  behavior has been inconsistent across versions/builds; this plugin instead
  checks the resulting `.22000` file directly (present, non-empty), matching
  how `ohcapi.py` already handles this in this same fork.
- **Size/rate limits beyond the API's own validation weren't found in the
  server's PHP source** (no explicit max length on `sourceData`) - practical
  limits are whatever your web server/PHP `post_max_size` allow, which is a
  deployment concern rather than something this plugin can detect in
  advance. Handshake-sized payloads (a few hundred bytes to a few KB) are far
  below any default you're likely to encounter.
