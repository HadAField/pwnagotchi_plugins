# pwnagotchi_plugins

Custom Pwnagotchi plugins. Drop the `.py` file(s) directly into your
`custom_plugins` directory (plugin discovery is a flat, non-recursive
`glob("*.py")`, so don't nest them in subfolders) and merge the matching
`.toml` snippet into `config.toml`.

## already_pwned

Fixes a real gap in pwnagotchi's own "don't re-target an AP I already have a
handshake for" logic: that check (`Agent._has_handshake()` /
`_should_interact()`) is driven entirely by an in-memory dict,
`agent._handshakes`, that starts **empty** on every process start. It's
populated only by live captures during the current run, plus an optional
recovery file that's written by exactly one call path
(`Agent._restart()`) - a plain `systemctl restart`, a crash, `sudo reboot`,
and even some of pwnagotchi's own internal recovery paths (confirmed in this
fork's `fix_services.py`, which calls the bare `pwnagotchi.restart()`
function directly) all skip that save entirely. In practice this means a
routine restart can make the unit walk back up to an AP it already has a
complete capture for and attack it again.

This plugin closes that gap without touching any core pwnagotchi file - and
**without inserting into `agent._handshakes` directly**, which is where an
earlier version of this plugin got it wrong. That dict does double duty in
core: it's both the dedup memory `_has_handshake()` reads, *and* the source
of the left-hand "handshakes since reboot" counter on the display
(`len(agent._handshakes)` in `Agent._update_handshakes()`). Seeding disk
history into it directly made that counter show something closer to the
lifetime total instead of a real since-reboot count.

Instead, on `on_ready` - once, right before the main loop starts - it scans
`handshake_dir` for existing `<name>_<bssid>.pcapng` files into its own,
separate set, then patches `agent._has_handshake()` (an instance-level
shadow, not a core file edit) to check that set in addition to whatever's
genuinely in `agent._handshakes`. Dedup correctly recognizes disk history;
`agent._handshakes` itself is never touched, so the since-reboot counter
only ever reflects handshakes actually captured in the current session, same
as before this plugin existed. Because the disk scan re-derives from the
handshakes directory (ground truth) on every single startup rather than
trusting whichever restart path fired, it protects against *all* restart
types uniformly, not just the ones that happen to save recovery data.

Idempotent - the patch guards against being applied twice, and re-scanning
the directory is harmless. Filenames that don't match the
`<name>_<bssid>.pcapng` pattern (missing a trailing 12-hex-char BSSID) are
skipped, not guessed at. Only `.pcapng` is scanned; `.pcap` is deprecated and
no longer written by bettercap/pwnagotchi.

### Handshake validation and cleanup

A pure filename match has a real failure mode: bettercap/pwnagotchi
sometimes writes an empty (0-byte) or otherwise invalid `.pcapng` - a
beacon/probe-only capture, or a partial EAPOL exchange with no actual key
material. Before this existed, a file like that sitting in `handshake_dir`
got its BSSID seeded as "already captured" on every boot forever,
permanently blocking that AP from ever being attacked again even though
there was never a usable handshake for it - the exact restart-survives-
nothing case this plugin exists to close, just working against itself.

With `validate_handshakes = true` (the default), each filename match must
also pass the same real-key-material check
[`hashtopolis_uploader.py`](hashtopolis_uploader.py) uses: non-empty file,
correct pcapng magic bytes, then a genuine `hcxpcapngtool` pass confirming
non-empty `.22000` output. That `.22000` is scratch and deleted immediately
either way - the confirmed-valid result is recorded instead in this
plugin's own tiny state file, `<handshake_dir>/.already_pwned_validated`
(path -> mtime), so a file already confirmed valid on an earlier boot
doesn't cost another `hcxpcapngtool` call unless it changes. This
deliberately doesn't reuse `hashtopolis_uploader.py`'s `.22000` as a shared
cache, since that plugin may delete its own `.22000` after a successful
upload (`delete_22000_after_upload`) - the two plugins' disk-hygiene
choices are intentionally decoupled.

A file that fails validation is, with `delete_invalid_handshakes = true`
(the default), deleted outright - not just skipped - so the AP goes back to
being a normal, attackable target instead of silently blocked forever.
Anything `hcxpcapngtool` can't confirm one way or the other (a timeout, the
binary erroring) counts as *not valid, but also not deleted*: this plugin
only ever removes a capture a completed run actually confirmed empty, never
one it merely failed to check. If `hcxpcapngtool` isn't on `PATH` at all,
validation is skipped for that boot (with a warning) and the plugin falls
back to filename-only seeding rather than silently seeding nothing.

Set `validate_handshakes = false` to disable all of this and go back to
pure filename-based seeding (pre-2.0.0 behavior).

**Known limitations:**

- `on_ready` fires from a plugin worker thread slightly after the main
  agent thread starts polling live bettercap events (see `Agent.start()`),
  so there's a small startup window where a live capture could
  theoretically land before the disk-seeded state is in place. Narrow and
  non-destructive if it happens - worst case is one AP briefly untracked
  for a few hundred milliseconds at boot, not a wrong result.
- With `validate_handshakes = true`, that window isn't fixed-size anymore:
  a boot with many not-yet-cached files (e.g. the first boot after
  upgrading to 2.0.0, or a device that's captured a lot with
  `hashtopolis_uploader` disabled) spends real time running
  `hcxpcapngtool` once per uncached file before `on_ready` finishes.
  Subsequent boots are fast again once the state cache is populated, since
  only new or changed files get re-checked.

### Config reference

| Option | Default | Meaning |
|---|---|---|
| `enabled` | - | Standard Pwnagotchi plugin toggle. |
| `handshake_dir` | `bettercap.handshakes` from the same config | Where to look for existing captures to seed from. |
| `validate_handshakes` | `true` | Require the same real-key-material check `hashtopolis_uploader.py` uses (magic bytes + `hcxpcapngtool`) before trusting a file. `false` restores old filename-only seeding. |
| `validation_timeout_seconds` | `15` | Per-file timeout for the `hcxpcapngtool` validation pass. |
| `delete_invalid_handshakes` | `true` | Delete a `.pcapng` that fails validation so its AP stays eligible for recapture. Only takes effect when `validate_handshakes = true`. |

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
  your account password - use it as-is for `api_key`. Add `permHashlistDelete`
  too if you plan to use `cleanup_existing_essid_duplicates` (see below).
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
| `delete_22000_after_upload` | `false` | Delete the locally-generated `.22000` conversion file after a *confirmed* successful upload. Safe to enable - dedup state (path + ESSID) is persisted to `.hashtopolis_uploads` at upload time and never depends on the `.22000` file continuing to exist. There is deliberately no `delete_pcapng_after_upload` option: the `.pcapng` itself is never deleted by this plugin, since [already_pwned](#already_pwned)'s disk-seeded dedup depends on that file surviving restarts. |
| `min_free_space_mb` | `50` | Skip the whole cycle if free space on `handshake_dir`'s filesystem is below this. |
| `retry_count` | `3` | HTTP upload retries with exponential backoff before giving up for this run. |
| `timeout_seconds` | `30` | Timeout for both `hcxpcapngtool` and each HTTP request. |
| `verify_ssl` | `true` | Verify the server's TLS cert. Set `false` only for a trusted self-signed cert. |
| `min_interval_seconds` | `300` | Minimum gap between upload cycles, since `on_internet_available` can fire repeatedly. |
| `force_reupload` | `false` | Wipes the upload-state file on every config reload while `true`. Use to force a full re-scan, then set back to `false`. |
| `dedupe_essid` | `true` | Skip uploading a handshake whose SSID already has an uploaded hashlist; keeps the oldest capture as canonical. See "SSID deduplication" below. |
| `cleanup_existing_essid_duplicates` | `false` | One-time, opt-in: DELETEs already-uploaded duplicate-SSID hashlists from the server, keeping the oldest capture. Real, immediate server-side change - see below. |

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

### SSID deduplication

A single physical network commonly ends up as more than one `.pcapng` file:
the Pwnagotchi walks past the same AP again on a later session, or a dual-band
router broadcasts the same SSID from two different BSSIDs (2.4GHz/5GHz) that
share one PSK. Without dedup, each of those becomes its own hashlist on
Hashtopolis - same password, wasted cracking effort, more clutter.

With `dedupe_essid = true` (the default), the *first* handshake seen for a
given SSID becomes canonical and gets uploaded normally; every later capture
of that same SSID is skipped and recorded in the state file's
`duplicate_essid` section (with the path of the canonical capture and its
hashlist ID) instead of creating a second hashlist. "First" means **oldest by
actual capture time** (the `.pcapng`'s mtime), not upload order - within a
single cycle, pending handshakes are processed oldest-first so this holds
even when several duplicates of the same SSID are discovered at once.
Deliberately simple: since only handshakes that already passed the "real key
material" validation above ever reach `uploaded`, every candidate for the
canonical slot is already known-valid, so there's no need to rank captures
against each other by quality - oldest-first is enough. `essid == "unknown"`
(ESSID couldn't be parsed from the hash line) is never deduped, since two
"unknown" captures can't be confirmed to be the same network.

This uses SSID text as the dedup key, not SSID+BSSID - deliberately, so the
dual-band-AP case above collapses correctly. The tradeoff: a generic default
SSID (e.g. two unrelated "NETGEAR44" routers at different locations, or an
enterprise deployment broadcasting one SSID from many independent APs with
different passwords) would incorrectly collapse to one hashlist too. If your
environment has that pattern, set `dedupe_essid = false`.

**Cleaning up hashlists uploaded before this feature existed:** set
`cleanup_existing_essid_duplicates = true` and let a cycle run. This groups
everything already in the state file's `uploaded` section by SSID, keeps the
oldest capture per SSID, and issues a `DELETE` against the Hashtopolis server
for every other hashlist in that group - moving them into `duplicate_essid`
locally to match. This is a real, immediate, mostly-irreversible change to
data already on your server (it needs `permHashlistDelete` on the API token,
in addition to `permHashlistCreate`), so it defaults to `false` and only ever
touches hashlists this plugin's own state file has a `hashlist_id` for. A
failed `DELETE` (e.g. the token lacks the delete scope) leaves that entry in
`uploaded` untouched and retries on the next cycle rather than losing track
of it.

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
