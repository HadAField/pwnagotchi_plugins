import logging
import os
import re

from pwnagotchi import plugins

TAG = "ALREADY_PWNED"

# Matches the "<sanitized-hostname>_<bssid-hex>" stem bettercap/pwnagotchi
# writes handshake files as, e.g. "ITCVideo_92c8c1a395b9.pcapng".
_BSSID_RE = re.compile(r"^(.*)_([0-9a-fA-F]{12})$")


class already_pwned(plugins.Plugin):
    __author__ = "hadfield.seth@gmail.com"
    __version__ = "1.1.0"
    __license__ = "GPL3"
    __description__ = (
        "Makes the agent recognize APs it already has a full capture for on disk, "
        "even after a restart that doesn't preserve its in-memory session state. "
        "Does this by patching _has_handshake() to also check a disk-seeded set, "
        "NOT by inserting into agent._handshakes directly - that dict is also what "
        "drives the 'handshakes since reboot' counter on the display "
        "(len(agent._handshakes) in _update_handshakes()), so seeding into it "
        "directly makes that counter show the lifetime total instead."
    )

    def __init__(self):
        self.options = dict()
        self._seeded_bssids = set()

    def on_ready(self, agent):
        try:
            self._load_seeded_bssids(agent)
            self._patch_has_handshake(agent)
        except Exception:
            # Startup-path plugin code must never take the main loop down with it.
            logging.exception(f"{TAG}: unhandled exception while seeding, skipping.")

    def _load_seeded_bssids(self, agent):
        handshake_dir = self.options.get("handshake_dir") or agent.config()["bettercap"]["handshakes"]

        try:
            files = [f for f in os.listdir(handshake_dir) if f.endswith(".pcapng") or f.endswith(".pcap")]
        except OSError as e:
            logging.error(f"{TAG}: cannot list {handshake_dir}: {e}")
            return

        unparsed = 0
        for filename in files:
            stem = filename.rsplit(".", 1)[0]
            match = _BSSID_RE.match(stem)
            if not match:
                unparsed += 1
                continue

            bssid_hex = match.group(2).lower()
            bssid = ":".join(bssid_hex[i:i + 2] for i in range(0, 12, 2))
            self._seeded_bssids.add(bssid)

        logging.info(
            f"{TAG}: loaded {len(self._seeded_bssids)} already-captured BSSID(s) from "
            f"{handshake_dir} ({unparsed} filename(s) didn't match the "
            "<name>_<bssid>.pcapng pattern and were skipped)."
        )

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
