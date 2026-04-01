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
        output_dir = Path("data") / self.rule_type
        output_dir.mkdir(parents=True, exist_ok=True)

        for pattern in self.rglob_patterns:
            for p in base_directory.glob(pattern):
                if p.is_file():
                    try:
                        relative_path = p.relative_to(base_directory)
                        target_path = output_dir / relative_path
                        target_path.parent.mkdir(parents=True, exist_ok=True)

                        content = p.read_text(encoding="utf-8")
                        target_path.write_text(content, encoding="utf-8")

                    except Exception as e:
                        print(f"Failed to process {p}: {e}")
