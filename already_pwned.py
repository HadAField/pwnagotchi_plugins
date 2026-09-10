import logging
import os
import re
import shutil
import subprocess

from pwnagotchi import plugins
from pwnagotchi.utils import StatusFile

TAG = "ALREADY_PWNED"

# Matches the "<sanitized-hostname>_<bssid-hex>" stem bettercap/pwnagotchi
# writes handshake files as, e.g. "ITCVideo_92c8c1a395b9.pcapng".
_BSSID_RE = re.compile(r"^(.*)_([0-9a-fA-F]{12})$")

# pcapng Section Header Block magic - the same 4 bytes regardless of the
# file's internal byte order (it's deliberately palindromic; the real
# endianness marker comes right after it). Classic .pcap isn't checked for
# here since bettercap/pwnagotchi only ever write .pcapng captures now.
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


class already_pwned(plugins.Plugin):
    __author__ = "hadfield.seth@gmail.com"
    __version__ = "2.0.0"
    __license__ = "GPL3"
    __description__ = (
        "Makes the agent recognize APs it already has a full, valid capture for on "
        "disk, even after a restart that doesn't preserve its in-memory session "
        "state, and deletes invalid/empty captures so those APs stay eligible for "
        "recapture. Does this by patching _has_handshake() to also check a "
        "disk-seeded set, NOT by inserting into agent._handshakes directly - that "
        "dict is also what drives the 'handshakes since reboot' counter on the "
        "display (len(agent._handshakes) in _update_handshakes()), so seeding into "
        "it directly makes that counter show the lifetime total instead."
    )

    def __init__(self):
        self.options = dict()
        self._seeded_bssids = set()
        self.state = None

    def on_ready(self, agent):
        try:
            self._load_seeded_bssids(agent)
            self._patch_has_handshake(agent)
        except Exception:
            # Startup-path plugin code must never take the main loop down with it.
            logging.exception(f"{TAG}: unhandled exception while seeding, skipping.")

    def _load_seeded_bssids(self, agent):
        handshake_dir = self.options.get("handshake_dir") or agent.config()["bettercap"]["handshakes"]
        validate = bool(self.options.get("validate_handshakes", True))
        delete_invalid = bool(self.options.get("delete_invalid_handshakes", True))
        timeout = int(self.options.get("validation_timeout_seconds", 15))

        if validate and not shutil.which("hcxpcapngtool"):
            logging.warning(
                f"{TAG}: validate_handshakes is enabled but hcxpcapngtool isn't on "
                "PATH - falling back to filename-only seeding for this boot."
            )
            validate = False

        cache = {}
        if validate:
            state_path = os.path.join(handshake_dir, ".already_pwned_validated")
            try:
                self.state = StatusFile(state_path, data_format="json")
            except ValueError:
                # Corrupt/truncated state file (e.g. power loss mid-write) - start
                # clean rather than crashing plugin load forever.
                logging.warning(f"{TAG}: state file {state_path} is corrupt, resetting it.")
                os.remove(state_path)
                self.state = StatusFile(state_path, data_format="json")
            cache = self.state.data_field_or("validated", default={})

        try:
            files = [f for f in os.listdir(handshake_dir) if f.endswith(".pcapng")]
        except OSError as e:
            logging.error(f"{TAG}: cannot list {handshake_dir}: {e}")
            return

        unparsed = 0
        deleted = 0
        from_cache = 0
        freshly_validated = 0
        new_cache = {}

        for filename in files:
            stem = filename.rsplit(".", 1)[0]
            match = _BSSID_RE.match(stem)
            if not match:
                unparsed += 1
                continue

            path = os.path.join(handshake_dir, filename)
            bssid_hex = match.group(2).lower()
            bssid = ":".join(bssid_hex[i:i + 2] for i in range(0, 12, 2))

            if not validate:
                self._seeded_bssids.add(bssid)
                continue

            try:
                mtime = os.path.getmtime(path)
            except OSError:
                continue  # vanished mid-scan, skip it this boot

            if cache.get(path) == mtime:
                # Already confirmed valid on a previous boot and hasn't changed
                # since - trust it without spending another hcxpcapngtool call.
                self._seeded_bssids.add(bssid)
                new_cache[path] = mtime
                from_cache += 1
                continue

            if self._is_valid_capture(path, timeout):
                self._seeded_bssids.add(bssid)
                new_cache[path] = mtime
                freshly_validated += 1
            elif delete_invalid:
                self._delete_invalid(path)
                deleted += 1
            # else: validate_handshakes caught it as invalid but
            # delete_invalid_handshakes is off - leave it in place, don't seed
            # it (so the AP stays attackable), don't cache it (re-checked next
            # boot too, in case it gets cleaned up by something else meanwhile).

        if validate:
            self.state.update(data={"validated": new_cache})

        logging.info(
            f"{TAG}: loaded {len(self._seeded_bssids)} already-captured BSSID(s) from "
            f"{handshake_dir} ({unparsed} unparsed filename(s)"
            + (
                f", {from_cache} from cache, {freshly_validated} freshly validated, "
                f"{deleted} invalid/empty capture(s) deleted"
                if validate else ""
            )
            + ")."
        )

    def _is_valid_capture(self, pcap_path, timeout):
        """
        Same real-key-material check hashtopolis_uploader.py uses: magic-byte
        sanity, then a genuine hcxpcapngtool pass confirming the capture
        actually contains crackable EAPOL/PMKID material, not just "looks like
        a pcapng file". The .22000 this produces is scratch - deleted
        immediately either way, since the confirmed-valid result is recorded in
        this plugin's own state cache instead. (hashtopolis_uploader may delete
        its own .22000 after a successful upload, so a shared on-disk artifact
        can't be relied on as a cache here.)

        Anything we can't confirm (hcxpcapngtool errors or times out) counts as
        NOT valid, never as valid - this plugin only ever deletes a capture a
        completed hcxpcapngtool run actually confirmed empty, never one it
        merely failed to check.
        """
        try:
            if os.path.getsize(pcap_path) == 0:
                return False
            with open(pcap_path, "rb") as f:
                magic = f.read(4)
        except OSError as e:
            logging.debug(f"{TAG}: cannot read {pcap_path}: {e}")
            return False

        if magic != _PCAPNG_MAGIC:
            return False

        hash_path = pcap_path.rsplit(".", 1)[0] + ".22000"
        try:
            subprocess.run(
                ["hcxpcapngtool", "-o", hash_path, pcap_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
                check=False,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            logging.debug(f"{TAG}: hcxpcapngtool failed on {pcap_path}: {e}")
            self._remove_quiet(hash_path)
            return False

        valid = os.path.exists(hash_path) and os.path.getsize(hash_path) > 0
        self._remove_quiet(hash_path)
        return valid

    def _delete_invalid(self, pcap_path):
        if self._remove_quiet(pcap_path):
            logging.info(
                f"{TAG}: deleted invalid/empty capture {pcap_path} - that AP is "
                "eligible for recapture."
            )
        # In case a stray .22000 from an earlier run is still sitting next to it.
        self._remove_quiet(pcap_path.rsplit(".", 1)[0] + ".22000")

    def _remove_quiet(self, path):
        try:
            if os.path.exists(path):
                os.remove(path)
                return True
            return False
        except OSError as e:
            logging.warning(f"{TAG}: could not remove {path}: {e}")
            return False

    def _patch_has_handshake(self, agent):
        if getattr(agent, "_already_pwned_patched", False):
            return  # e.g. a second on_ready somehow firing - don't double-wrap

        if not hasattr(agent, "_has_handshake"):
            logging.error(
                f"{TAG}: agent has no _has_handshake - pwnagotchi's internals may have "
                "changed since this plugin was written, refusing to guess."
            )
            return

        original_has_handshake = agent._has_handshake  # bound method, 'self' already captured
        seeded = self._seeded_bssids

        def patched_has_handshake(bssid):
            return bssid.lower() in seeded or original_has_handshake(bssid)

        # Assigning a plain function as an instance attribute shadows the class
        # method for this agent only, without touching agent._handshakes (and
        # therefore without touching the since-reboot counter that reads it).
        agent._has_handshake = patched_has_handshake
        agent._already_pwned_patched = True

        logging.info(
            f"{TAG}: patched _has_handshake() to also recognize {len(seeded)} "
            "disk-seeded BSSID(s)."
        )
