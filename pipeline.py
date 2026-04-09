import hashlib
import json
import re
from pathlib import Path

from aboutcode.pipeline import BasePipeline
from fetchcode.vcs import fetch_via_vcs


class BaseRulePipeline(BasePipeline):
    repo_url = None
    rule_type = None
    rglob_patterns = []

    @classmethod
    def steps(cls):
        return (
            cls.clone_repo,
            cls.collect_and_store_rules,
        )

    def clone_repo(self):
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(f"git+{self.repo_url}")

    def collect_and_store_rules(self):
        base_directory = Path(self.vcs_response.dest_dir)
        repo_hash = hashlib.sha256(str(self.repo_url).encode('utf-8')).hexdigest()
        output_dir = Path("data") / self.rule_type / repo_hash

        file_paths = set()
        for pattern in self.rglob_patterns:
            file_paths.update(p for p in base_directory.glob(pattern) if p.is_file())

        for file_path in file_paths:
            raw_text = file_path.read_text(encoding="utf-8", errors="ignore")
            rules_data = self.to_json(raw_text)

            relative_path = file_path.relative_to(base_directory)
            target_path = (output_dir / relative_path).with_suffix('.json')
            target_path.parent.mkdir(parents=True, exist_ok=True)

            source_url = f"{self.repo_url}/blob/master/{relative_path}"
            processed_data = {
                "source_url": source_url,
                "rules": rules_data
            }

            with open(target_path, 'w', encoding='utf-8') as f:
                json.dump(processed_data, f, indent=4, ensure_ascii=False)

    def extract_metadata(self, raw_text):
       raise NotImplementedError

    def get_related_vulnerabilities(self, raw_text):
        """
        Find all CVE in a rule text
        ex:
        >>> self.get_related_vulnerabilities("rule LOG_SUSP_EXPL_POC_VMWare_Workspace_ONE_CVE_2022_22954_Apr22_")
        ['CVE-2022-22954']

        >>> self.get_related_vulnerabilities("Detects payload as seen in PoC code to exploit Workspace ONE Access freemarker server-side template injection CVE-2022-22954")
        ['CVE-2022-22954']

        >>> sorted(self.get_related_vulnerabilities("Detects suspicious file writes ... such as CVE-2025-49704, CVE-2025-49706 or CVE-2025-53770. "))
        ['CVE-2025-49704', 'CVE-2025-49706', 'CVE-2025-53770']

        >>> self.get_related_vulnerabilities("No valid CVE- in this text")
        set()
        """
        cve_regex = re.compile(r"CVE[-_]\d{4}[-_]\d{4,19}", re.IGNORECASE)
        matches = cve_regex.findall(raw_text)
        return list(set([cve.upper().replace("_", "-") for cve in matches]))

    def to_json(self, text):
        raise NotImplementedError