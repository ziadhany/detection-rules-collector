#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from rules.pipeline import BaseRulePipeline


class SuricataRulesPipeline(BaseRulePipeline):
    rule_type = "suricata"
    rglob_patterns = ["**/*.rules"]


class SudohyakSuricataPipeline(SuricataRulesPipeline):
    repo_url = "https://github.com/sudohyak/suricata-rules"
    license_url = "https://github.com/sudohyak/suricata-rules/blob/main/LICENSE"


class OISFSuricataPipeline(SuricataRulesPipeline):
    repo_url = "https://github.com/OISF/suricata"
    rglob_patterns = ["rules/**/*.rules"]
    license_url = "https://github.com/OISF/suricata?tab=GPL-2.0-2-ov-file"
