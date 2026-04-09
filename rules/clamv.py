#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import gzip
import io
import json
import tarfile
import tempfile
from pathlib import Path
from typing import List

import requests
from aboutcode.pipeline import BasePipeline


def extract_cvd(cvd_path, output_dir):
    """
    Extract a CVD file. CVD format: 512-byte header + gzipped tar archive and returns Path to output directory
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    with open(cvd_path, "rb") as f:
        f.seek(512)  # Skip header
        compressed_data = f.read()

    decompressed_data = gzip.decompress(compressed_data)
    tar_buffer = io.BytesIO(decompressed_data)

    with tarfile.open(fileobj=tar_buffer, mode="r:") as tar:
        tar.extractall(path=output_path)

    for file in output_path.rglob("*"):
        if file.is_file():
            file.chmod(0o644)  # rw-r--r--
    return output_path


def parse_ndb_file(ndb_path: Path) -> List[dict]:
    """Parse a .ndb file (extended signatures). Return list of dicts."""
    signatures = []
    with ndb_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(":")
            if len(parts) >= 4:
                signatures.append(
                    {
                        "name": parts[0],
                        "target_type": parts[1],
                        "offset": parts[2],
                        "hex_signature": parts[3],
                        "line_num": line_num,
                    }
                )
    return signatures


def parse_hdb_file(hdb_path: Path) -> List[dict]:
    """Parse a .hdb file (MD5 hash signatures). Return list of dicts."""
    signatures = []
    with hdb_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(":")
            if len(parts) >= 3:
                signatures.append(
                    {
                        "hash": parts[0],
                        "file_size": parts[1],
                        "name": parts[2],
                        "line_num": line_num,
                    }
                )
    return signatures


class ClamVRulesPipeline(BasePipeline):
    """
    Pipeline that downloads ClamAV database (main.cvd), extracts signatures,
    parses .ndb and .hdb files and save the in one json result
    """

    license_url = "https://github.com/Cisco-Talos/clamav/blob/c73755d3fc130b0c60ccf4e8f8d28c62fc58c95b/README.md#licensing"
    license_expression = "GNU GENERAL PUBLIC LICENSE"
    rule_type = "clamv"

    @classmethod
    def steps(cls):
        return (
            cls.download_database,
            cls.extract_database,
            cls.collect_and_store,
        )

    def download_database(self):
        """Download ClamAV database using the supported API with proper headers."""

        self.log("Downloading ClamAV database…")
        self.db_dir = Path(tempfile.mkdtemp()) / "clamav_db"
        self.db_dir.mkdir(parents=True, exist_ok=True)

        database_url = "https://database.clamav.net/main.cvd?api-version=1"
        headers = {
            "User-Agent": "ClamAV-Client/1.0",
            "Accept": "*/*",
        }

        filename = self.db_dir / "main.cvd"
        self.log(f"Downloading {database_url} → {filename}")

        resp = requests.get(database_url, headers=headers, stream=True, timeout=30)
        resp.raise_for_status()

        with filename.open("wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)

        self.log("ClamAV DB file downloaded successfully.")

    def extract_database(self):
        """Extract the downloaded CVD into a directory"""
        out_dir = self.db_dir / "extracted"
        self.extract_cvd_dir = extract_cvd(self.db_dir / "main.cvd", out_dir)
        self.log(f"Extracted CVD to {self.extract_cvd_dir}")

    def collect_and_store(self):
        """Parse .ndb and .hdb files and store rules in a JSON file as separate lists."""

        hdb_rules_raw = parse_hdb_file(self.extract_cvd_dir / "main.hdb")
        ndb_rules_raw = parse_ndb_file(self.extract_cvd_dir / "main.ndb")

        processed_hdb = []
        for rule_entry in hdb_rules_raw:
            name = rule_entry.get("name", "").strip()
            if not name:
                continue

            signature_data = {
                "name": name,
                "signature": rule_entry.get("hash"),
                "file_size": rule_entry.get("file_size"),
                "line_num": rule_entry.get("line_num"),
            }
            signature_data = {k: v for k, v in signature_data.items() if v is not None}
            processed_hdb.append(signature_data)

        processed_ndb = []
        for rule_entry in ndb_rules_raw:
            name = rule_entry.get("name", "").strip()
            if not name:
                continue

            signature_data = {
                "name": name,
                "hex_signature": rule_entry.get("hex_signature"),
                "target_type": rule_entry.get("target_type"),
                "offset": rule_entry.get("offset"),
                "line_num": rule_entry.get("line_num"),
            }
            signature_data = {k: v for k, v in signature_data.items() if v is not None}
            processed_ndb.append(signature_data)

        final_output = {"hdb_rules": processed_hdb, "ndb_rules": processed_ndb}
        target_path = Path("data") / self.rule_type
        target_path.mkdir(parents=True, exist_ok=True)

        output_file = target_path / "clamav_db.json"
        with output_file.open("w", encoding="utf-8") as f:
            json.dump(final_output, f, indent=4)

        self.log(
            f"Successfully saved {len(processed_hdb)} HDB rules and {len(processed_ndb)} NDB rules to {output_file}"
        )
