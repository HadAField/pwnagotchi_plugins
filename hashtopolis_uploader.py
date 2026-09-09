import base64
import logging
import os
import shutil
import subprocess
import threading
import time

import requests

from pwnagotchi import plugins
from pwnagotchi.utils import StatusFile, remove_whitelisted

TAG = "HASHTOPOLIS"

# hashcat mode 22000 = "WPA-PBKDF2-PMKID+EAPOL", the combined format hcxpcapngtool
# emits for both EAPOL 4-way handshakes and PMKID captures. Confirmed against
# Hashtopolis' own hash-type seed data (src/inc/startup/hashtypes.json) on the
# server side: hashTypeId 22000 == "WPA-PBKDF2-PMKID+EAPOL", isSalted: 0.
HASHTOPOLIS_HASH_TYPE_ID = 22000

# pcapng: 0x0A0D0D0A (any byte order, it's a byte-swap-detectable magic).
# classic pcap (older bettercap/tools can still emit this): 0xA1B2C3D4 / 0xD4C3B2A1
# and the nanosecond variants 0xA1B23C4D / 0x4D3CB2A1.
_PCAP_MAGIC_BYTES = (
    b"\x0a\x0d\x0d\x0a",
    b"\xa1\xb2\xc3\xd4",
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x4d\x3c\xb2\xa1",
)


class hashtopolis_uploader(plugins.Plugin):
    __author__ = "hadfield.seth@gmail.com"
    __version__ = "1.0.0"
    __license__ = "GPL3"
    __description__ = "Uploads captured WPA/WPA2 handshakes and PMKIDs to a self-hosted Hashtopolis server for cracking."

    def __init__(self):
        self.options = dict()
        self.ready = False
        self.lock = threading.Lock()
        self.last_run = 0
        self.state = None
        self.handshake_dir = None
        self.whitelist = []

    def on_loaded(self):
        logging.info(f"{TAG}: plugin loaded.")

    def on_config_changed(self, config):
        """
        Resolve effective settings from config.toml every time the config is
        (re)loaded, mirroring pwncrack.py's approach in this fork rather than
        doing one-shot setup in on_loaded.
        """
        required = ["hashtopolis_url", "api_key"]
        missing = [f for f in required if not self.options.get(f)]
        if missing:
            logging.error(f"{TAG}: missing required option(s): {missing}. Plugin disabled.")
            self.ready = False
            return

        self.hashtopolis_url = self.options["hashtopolis_url"].rstrip("/")
        self.api_key = self.options["api_key"]
        self.access_group_id = int(self.options.get("access_group_id", 1))
        self.hashlist_name_format = self.options.get(
            "hashlist_name_format", "{hostname}-{essid}-{timestamp}"
        )
        # Split deliberately: deleting the .pcapng changes the handshake count the
        # Pwnagotchi UI/session-stats derive from the handshakes directory, while
        # deleting the .22000 (a conversion artifact this plugin generates) does not.
        self.delete_pcapng_after_upload = bool(self.options.get("delete_pcapng_after_upload", False))
        self.delete_22000_after_upload = bool(self.options.get("delete_22000_after_upload", False))
        self.min_free_space_mb = int(self.options.get("min_free_space_mb", 50))
        self.retry_count = max(1, int(self.options.get("retry_count", 3)))
        self.timeout_seconds = int(self.options.get("timeout_seconds", 30))
        self.verify_ssl = bool(self.options.get("verify_ssl", True))
        self.min_interval_seconds = int(self.options.get("min_interval_seconds", 300))
        self.force_reupload = bool(self.options.get("force_reupload", False))

        self.handshake_dir = self.options.get("handshake_dir") or config["bettercap"]["handshakes"]
        self.whitelist = config["main"].get("whitelist", [])

        state_path = os.path.join(self.handshake_dir, ".hashtopolis_uploads")
        try:
            self.state = StatusFile(state_path, data_format="json")
        except ValueError:
            # Corrupt/truncated state file (e.g. from a power loss mid-write) - start clean
            # rather than crashing plugin load forever.
            logging.warning(f"{TAG}: state file {state_path} is corrupt, resetting it.")
            os.remove(state_path)
            self.state = StatusFile(state_path, data_format="json")

        if self.force_reupload:
            logging.warning(
                f"{TAG}: force_reupload is enabled - clearing upload state, "
                "every handshake will be re-validated and re-uploaded. "
                "Set force_reupload back to false in config.toml once this run completes."
            )
            self._save_state({"uploaded": {}, "invalid": {}, "failed": {}})

        if not self.verify_ssl:
            logging.warning(f"{TAG}: verify_ssl is disabled, TLS certificate errors will be ignored.")

        self.ready = True
        logging.info(
            f"{TAG}: ready. server={self.hashtopolis_url} access_group_id={self.access_group_id} "
            f"handshake_dir={self.handshake_dir}"
        )

    def on_internet_available(self, agent):
        if not self.ready or self.lock.locked():
            return

        now = time.time()
        if now - self.last_run < self.min_interval_seconds:
            return

        with self.lock:
            self.last_run = time.time()
            try:
                self._run_upload_cycle(agent)
            except Exception:
                # A bad handshake or a flaky upload must never take down the main loop.
                logging.exception(f"{TAG}: unhandled exception during upload cycle.")

    # -- state helpers --------------------------------------------------

    def _load_state(self):
        return {
            "uploaded": self.state.data_field_or("uploaded", default={}),
            "invalid": self.state.data_field_or("invalid", default={}),
            "failed": self.state.data_field_or("failed", default={}),
        }

    def _save_state(self, data):
        self.state.update(data=data)

    # -- main cycle -------------------------------------------------------

    def _run_upload_cycle(self, agent):
        try:
            free_mb = shutil.disk_usage(self.handshake_dir).free / (1024 * 1024)
        except OSError as e:
            logging.error(f"{TAG}: cannot stat handshake_dir {self.handshake_dir}: {e}")
            return

        if free_mb < self.min_free_space_mb:
            logging.warning(
                f"{TAG}: only {free_mb:.1f}MB free in {self.handshake_dir} "
                f"(min_free_space_mb={self.min_free_space_mb}), skipping this cycle."
            )
            return

        state = self._load_state()

        pcap_files = [
            f for f in os.listdir(self.handshake_dir)
            if f.endswith(".pcapng") or f.endswith(".pcap")
        ]
        pcap_paths = [os.path.join(self.handshake_dir, f) for f in pcap_files]
        pcap_paths = remove_whitelisted(pcap_paths, self.whitelist)

        pending = [
            p for p in pcap_paths
            if p not in state["uploaded"] and p not in state["invalid"]
        ]

        if not pending:
            logging.debug(f"{TAG}: no new handshakes to process.")
            return

        logging.info(f"{TAG}: found {len(pending)} new handshake(s) to validate and upload.")
        display = agent.view()
        uploaded_count = 0

        for idx, pcap_path in enumerate(pending):
            display.on_uploading(f"Hashtopolis ({idx + 1}/{len(pending)})")

            # A handshake that previously failed the upload (network/server error, not
            # validation) stays in `pending` every cycle and is retried indefinitely -
            # `retry_count` only bounds the immediate HTTP retry burst inside one
            # attempt, never how many cycles we keep trying. Losing a real handshake
            # to a transient server error is worse than a wasted retry every few minutes.
            try:
                self._process_one(pcap_path, state)
                if pcap_path in state["uploaded"]:
                    uploaded_count += 1
            except Exception:
                logging.exception(f"{TAG}: unexpected error processing {pcap_path}, skipping.")

            self._save_state(state)

        display.on_normal()
        if uploaded_count:
            logging.info(f"{TAG}: uploaded {uploaded_count}/{len(pending)} new handshake(s).")

    def _process_one(self, pcap_path, state):
        """
        Validate, convert, and upload a single capture. Mutates `state` in place;
        the caller is responsible for persisting it.
        """
        if not self._sanitize_capture(pcap_path):
            state["invalid"][pcap_path] = "not a valid/non-empty pcap(ng) capture"
            return

        hash_lines, hash_path = self._extract_22000(pcap_path)
        if not hash_lines:
            logging.info(f"{TAG}: {pcap_path} contains no crackable EAPOL/PMKID material, skipping.")
            state["invalid"][pcap_path] = "no crackable key material (hcxpcapngtool produced nothing)"
            if hash_path and os.path.exists(hash_path):
                os.remove(hash_path)
            return

        essid, bssid = self._extract_essid_bssid(hash_lines[0])
        hashlist_name = self._format_hashlist_name(essid, bssid, pcap_path)

        logging.info(f"{TAG}: uploading {pcap_path} as hashlist '{hashlist_name}' ({len(hash_lines)} line(s)).")
        ok, detail = self._upload_hashlist(hashlist_name, hash_lines)

        if ok:
            logging.info(f"{TAG}: {pcap_path} uploaded successfully -> hashlist id {detail}.")
            state["uploaded"][pcap_path] = {
                "hashlist_id": detail,
                "essid": essid,
                "bssid": bssid,
                "uploaded_at": int(time.time()),
            }
            state["failed"].pop(pcap_path, None)
            self._delete_local_copies(
                pcap_path if self.delete_pcapng_after_upload else None,
                hash_path if self.delete_22000_after_upload else None,
            )
        else:
            attempts = state["failed"].get(pcap_path, {"attempts": 0})["attempts"] + 1
            logging.error(f"{TAG}: upload of {pcap_path} failed (attempt {attempts}): {detail}")
            state["failed"][pcap_path] = {"attempts": attempts, "last_error": str(detail)}

    # -- sanitization -------------------------------------------------------

    def _sanitize_capture(self, pcap_path):
        try:
            if os.path.getsize(pcap_path) == 0:
                logging.debug(f"{TAG}: {pcap_path} is empty.")
                return False
            with open(pcap_path, "rb") as f:
                magic = f.read(4)
        except OSError as e:
            logging.debug(f"{TAG}: cannot read {pcap_path}: {e}")
            return False

        if magic not in _PCAP_MAGIC_BYTES:
            logging.debug(f"{TAG}: {pcap_path} does not look like a pcap/pcapng capture (bad magic).")
            return False
        return True

    def _extract_22000(self, pcap_path):
        """
        Convert to hashcat 22000 format via hcxpcapngtool, reusing an existing
        .22000 file if it's already present and newer than the pcapng (some
        Pwnagotchi setups run hcxpcapngtool themselves and drop it alongside
        the capture). Returns (list_of_hash_lines, path_to_22000_file).
        """
        hash_path = pcap_path.rsplit(".", 1)[0] + ".22000"

        reuse = (
            os.path.exists(hash_path)
            and os.path.getsize(hash_path) > 0
            and os.path.getmtime(hash_path) >= os.path.getmtime(pcap_path)
        )

        if not reuse:
            try:
                subprocess.run(
                    ["hcxpcapngtool", "-o", hash_path, pcap_path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    timeout=self.timeout_seconds,
                    check=False,
                )
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
                logging.error(f"{TAG}: hcxpcapngtool failed on {pcap_path}: {e}")
                return [], hash_path

        if not os.path.exists(hash_path) or os.path.getsize(hash_path) == 0:
            if os.path.exists(hash_path):
                os.remove(hash_path)
            return [], hash_path

        with open(hash_path, "r", errors="replace") as f:
            lines = [line.strip() for line in f if line.strip()]

        return lines, hash_path

    def _extract_essid_bssid(self, hash_line):
        """
        hashcat 22000 line layout: WPA*TYPE*PMKID/MIC*MACAP*MACSTA*ESSID*...
        """
        parts = hash_line.split("*")
        essid, bssid = "unknown", "000000000000"

        if len(parts) > 5:
            try:
                essid = bytes.fromhex(parts[5]).decode("utf-8", errors="replace") or "unknown"
            except ValueError:
                pass
        if len(parts) > 3 and len(parts[3]) == 12:
            bssid = parts[3]

        # Keep the generated hashlist name filesystem/URL-safe.
        safe_essid = "".join(c if c.isalnum() else "_" for c in essid) or "unknown"
        return safe_essid, bssid

    def _format_hashlist_name(self, essid, bssid, pcap_path):
        ctx = {
            "hostname": os.uname().nodename if hasattr(os, "uname") else "pwnagotchi",
            "essid": essid,
            "bssid": bssid,
            "timestamp": time.strftime("%Y%m%d-%H%M%S"),
            "filename": os.path.basename(pcap_path),
        }
        try:
            return self.hashlist_name_format.format(**ctx)
        except (KeyError, IndexError):
            logging.warning(f"{TAG}: hashlist_name_format has an unknown placeholder, using a fallback name.")
            return f"{ctx['hostname']}-{ctx['essid']}-{ctx['timestamp']}"

    # -- upload -------------------------------------------------------------

    def _upload_hashlist(self, name, hash_lines):
        """
        Creates a Hashlist via the Hashtopolis APIv2 with sourceType=paste, so the
        hash text is embedded directly in the create request - no separate File
        upload/TUS step is needed for handshake-sized payloads.
        """
        source_data = base64.b64encode("\n".join(hash_lines).encode("utf-8")).decode("ascii")

        payload = {
            "data": {
                "type": "Hashlist",
                "attributes": {
                    "name": name,
                    "hashTypeId": HASHTOPOLIS_HASH_TYPE_ID,
                    "format": 0,
                    "separator": ":",
                    "isSalted": False,
                    "isHexSalt": False,
                    "accessGroupId": self.access_group_id,
                    "useBrain": False,
                    "brainFeatures": 0,
                    "notes": "Uploaded by pwnagotchi hashtopolis_uploader plugin.",
                    "sourceType": "paste",
                    "sourceData": source_data,
                    "hashCount": 0,
                    "isArchived": False,
                    "isSecret": False,
                },
            }
        }

        url = f"{self.hashtopolis_url}/api/v2/ui/hashlists"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        last_error = "unknown error"
        for attempt in range(1, self.retry_count + 1):
            try:
                response = requests.post(
                    url,
                    headers=headers,
                    json=payload,
                    timeout=self.timeout_seconds,
                    verify=self.verify_ssl,
                )
            except requests.exceptions.RequestException as e:
                last_error = str(e)
                logging.warning(f"{TAG}: attempt {attempt}/{self.retry_count} network error: {e}")
            else:
                if response.status_code == 201:
                    try:
                        return True, response.json()["data"]["id"]
                    except (ValueError, KeyError):
                        return True, None
                last_error = f"HTTP {response.status_code}: {response.text[:500]}"
                logging.warning(f"{TAG}: attempt {attempt}/{self.retry_count} rejected - {last_error}")

            if attempt < self.retry_count:
                time.sleep(min(2 ** attempt, 30))

        return False, last_error

    def _delete_local_copies(self, pcap_path, hash_path):
        for path in (pcap_path, hash_path):
            try:
                if path and os.path.exists(path):
                    os.remove(path)
            except OSError as e:
                logging.warning(f"{TAG}: could not delete {path} after upload: {e}")
