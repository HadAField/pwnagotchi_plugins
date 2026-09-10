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
    __version__ = "1.0.0"
    __license__ = "GPL3"
    __description__ = (
        "Seeds the agent's in-memory 'already captured' AP list from handshakes "
        "already on disk at startup. pwnagotchi's own _has_handshake() check only "
        "knows about APs captured during the current process's uptime (plus a "
        "recovery file that most restart paths - including a plain "
        "'systemctl restart' - never write), so without this a restart can make "
        "it re-target an AP it already has a full capture for."
    )

    def __init__(self):
        self.options = dict()

    def on_ready(self, agent):
        try:
            self._seed(agent)
        except Exception:
            # Startup-path plugin code must never take the main loop down with it.
            logging.exception(f"{TAG}: unhandled exception while seeding, skipping.")

    def _seed(self, agent):
        if not hasattr(agent, "_handshakes") or not hasattr(agent, "_has_handshake"):
            logging.error(
                f"{TAG}: agent has no _handshakes/_has_handshake - pwnagotchi's internals "
                "may have changed since this plugin was written, refusing to guess."
            )
            return

        handshake_dir = self.options.get("handshake_dir") or agent.config()["bettercap"]["handshakes"]

        try:
            files = [f for f in os.listdir(handshake_dir) if f.endswith(".pcapng") or f.endswith(".pcap")]
        except OSError as e:
            logging.error(f"{TAG}: cannot list {handshake_dir}: {e}")
            return

        seeded = 0
        already_known = 0
        unparsed = 0

        for filename in files:
            stem = filename.rsplit(".", 1)[0]
            match = _BSSID_RE.match(stem)
            if not match:
                unparsed += 1
                continue

            bssid_hex = match.group(2).lower()
            bssid = ":".join(bssid_hex[i:i + 2] for i in range(0, 12, 2))

            # _has_handshake() does a case-sensitive substring check against its
            # stored keys after lowercasing the query, so the seeded key must
            # already be lowercase to reliably match regardless of what case
            # bettercap happens to use elsewhere.
            if agent._has_handshake(bssid):
                already_known += 1
                continue

            key = f"seeded -> {bssid}"
            agent._handshakes[key] = {"seeded": True, "source": filename, "bssid": bssid}
            seeded += 1

        logging.info(
            f"{TAG}: seeded {seeded} already-captured AP(s) from {handshake_dir} "
            f"({already_known} already known this session, {unparsed} filename(s) "
            "didn't match the <name>_<bssid>.pcapng pattern and were skipped)."
        )
