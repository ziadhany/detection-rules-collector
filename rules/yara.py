#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from pipeline import BaseRulePipeline
import plyara
from plyara.utils import rebuild_yara_rule
from plyara.exceptions import ParseTypeError

class YaraRulesPipeline(BaseRulePipeline):
    rule_type = "yara"
    rglob_patterns = [
        "**/*.yara",
        "**/*.yar",
    ]

    def extract_metadata(self, parsed_rule):
        metadata = {
            "rule_name": parsed_rule.get("rule_name"),
            "tags": parsed_rule.get("tags", [])
        }
        for entry in parsed_rule.get("metadata", []):
            metadata.update(entry)
        return metadata

    def to_json(self, raw_text):
        parser = plyara.Plyara()
        try:
            parsed_rules = parser.parse_string(raw_text)
        except ParseTypeError as e:
            self.log(f"Skipping malformed YARA rule due to parser error: {e}")
            return []

        results = []
        for rule in parsed_rules:
            rule_metadata = self.extract_metadata(rule)
            rule_text = rebuild_yara_rule(rule)
            results.append({
                "rule_metadata": rule_metadata,
                "rule_text": rule_text,
                "vulnerabilities": self.get_related_vulnerabilities(raw_text)
            })
        return results


class ProtectionsArtifactsYara(YaraRulesPipeline):
    repo_url = "https://github.com/elastic/protections-artifacts"
    license_url = (
        "https://github.com/elastic/protections-artifacts/blob/main/LICENSE.txt"
    )
    rglob_patterns = ["yara/rules/**/*.yar"]


class YaraRulesYara(YaraRulesPipeline):
    repo_url = "https://github.com/Yara-Rules/rules"
    license_url = "https://github.com/Yara-Rules/rules/blob/master/LICENSE"
    rglob_patterns = [
        "antidebug_antivm/**/*.yar",
        "capabilities/**/*.yar",
        "crypto/**/*.yar",
        "cve_rules/**/*.yar",
        "deprecated/**/*.yar",
        "email/**/*.yar",
        "exploit_kits/**/*.yar",
        "maldocs/**/*.yar",
        "malware/**/*.yar",
        "mobile_malware/**/*.yar",
        "packers/**/*.yar",
        "utils/**/*.yar",
        "webshells/**/*.yar",
    ]


class XumeiquerForensicsYara(YaraRulesPipeline):
    repo_url = "https://github.com/Xumeiquer/yara-forensics"
    license_url = "https://github.com/Xumeiquer/yara-forensics/blob/master/LICENSE"


class ReversinglabsYaraRules(YaraRulesPipeline):
    repo_url = "https://github.com/reversinglabs/reversinglabs-yara-rules"
    license_url = (
        "https://github.com/reversinglabs/reversinglabs-yara-rules/blob/develop/LICENSE"
    )


class AdvancedThreatResearchYara(YaraRulesPipeline):
    repo_url = "https://github.com/advanced-threat-research/Yara-Rules"
    license_url = (
        "https://github.com/advanced-threat-research/Yara-Rules/blob/master/LICENSE"
    )


class BartblazeYaraRules(YaraRulesPipeline):
    repo_url = "https://github.com/bartblaze/Yara-rules"
    license_url = "https://github.com/bartblaze/Yara-rules/blob/master/LICENSE"


class GodaddyYaraRules(YaraRulesPipeline):
    repo_url = "https://github.com/godaddy/yara-rules"  # archived
    license_url = "https://github.com/godaddy/yara-rules/blob/master/LICENSE.md"


class SupportIntelligenceIcewaterYara(YaraRulesPipeline):
    repo_url = "https://github.com/SupportIntelligence/Icewater"
    license_url = "https://github.com/SupportIntelligence/Icewater/blob/master/LICENSE"


class Jeff0FalltradesSignaturesYara(YaraRulesPipeline):
    repo_url = "https://github.com/jeFF0Falltrades/YARA-Signatures"
    license_url = (
        "https://github.com/jeFF0Falltrades/YARA-Signatures/blob/master/LICENSE.md"
    )


class TjnelRepoYara(YaraRulesPipeline):
    repo_url = "https://github.com/tjnel/yara_repo"
    license_url = "https://github.com/tjnel/yara_repo/blob/master/LICENSE"


class JpcertccJpcertYara(YaraRulesPipeline):
    repo_url = "https://github.com/JPCERTCC/jpcert-yara"
    license_url = "https://github.com/JPCERTCC/jpcert-yara/blob/main/LICENSE"


class MikesxrsOpenSourceYaraRules(YaraRulesPipeline):
    repo_url = "https://github.com/mikesxrs/Open-Source-YARA-rules"
    license_url = None


class FboldewinYaraRules(YaraRulesPipeline):
    repo_url = "https://github.com/fboldewin/YARA-rules"
    license_url = None


class H3x2bYaraRules(YaraRulesPipeline):
    repo_url = "https://github.com/h3x2b/yara-rules"
    license_url = None


class RoadwyDefenderYara(YaraRulesPipeline):
    repo_url = "https://github.com/roadwy/DefenderYara"
    license_url = None


class MthchtThreatHuntingKeywordsYara(YaraRulesPipeline):
    repo_url = "https://github.com/mthcht/ThreatHunting-Keywords-yara-rules"
    license_url = (
        "https://github.com/mthcht/ThreatHunting-Keywords-yara-rules/blob/main/LICENSE"
    )


class Neo23x0SignatureBaseYara(YaraRulesPipeline):
    repo_url = "https://github.com/Neo23x0/signature-base"
    license_url = None


class MalpediaSignatorRulesYara(YaraRulesPipeline):
    repo_url = "https://github.com/malpedia/signator-rules"
    license_url = "https://creativecommons.org/licenses/by-sa/4.0/"


class BaderjYara(YaraRulesPipeline):
    repo_url = "https://github.com/baderj/yara"
    license_url = "https://github.com/baderj/yara/blob/main/LICENSE"


class DeadbitsYaraRules(YaraRulesPipeline):
    repo_url = "https://github.com/deadbits/yara-rules"
    license_url = "https://github.com/deadbits/yara-rules/blob/master/UNLICENSE"


class PmelsonYaraRules(YaraRulesPipeline):
    repo_url = "https://github.com/pmelson/yara_rules"
    license_url = None


class SbousseadenYaraHunts(YaraRulesPipeline):
    repo_url = "https://github.com/sbousseaden/YaraHunts"
    license_url = None


class EmbeeResearchYaraRules(YaraRulesPipeline):
    repo_url = "https://github.com/embee-research/Yara-detection-rules"
    license_url = "https://github.com/embee-research/Yara-detection-rules/tree/main?tab=readme-ov-file#detection-rule-license-drl-11"


class RussianPanda95YaraRules(YaraRulesPipeline):
    repo_url = "https://github.com/RussianPanda95/Yara-Rules"
    license_url = None


class AilProjectAilYaraRules(YaraRulesPipeline):
    repo_url = "https://github.com/ail-project/ail-yara-rules"
    license_url = "https://github.com/ail-project/ail-yara-rules?tab=AGPL-3.0-1-ov-file"


class MalgamyYaraRules(YaraRulesPipeline):
    repo_url = "https://github.com/MalGamy/YARA_Rules"
    license_url = "https://github.com/MalGamy/YARA_Rules/blob/main/LICENSE.md"


class ElceefYaraRulz(YaraRulesPipeline):
    repo_url = "https://github.com/elceef/yara-rulz"
    license_url = "https://github.com/elceef/yara-rulz/tree/main?tab=MIT-1-ov-file"


class TenableYaraRules(YaraRulesPipeline):
    repo_url = "https://github.com/tenable/yara-rules"
    license_url = (
        "https://github.com/tenable/yara-rules/tree/master?tab=BSD-3-Clause-1-ov-file"
    )

class Dr4k0niaYaraRules(YaraRulesPipeline):
    repo_url = "https://github.com/dr4k0nia/yara-rules"
    license_url = "https://github.com/dr4k0nia/yara-rules/blob/main/LICENSE.md"


class Umair9747YaraRules(YaraRulesPipeline):
    repo_url = "https://github.com/umair9747/yara-rules"
    license_url = "https://github.com/umair9747/yara-rules?tab=GPL-3.0-1-ov-file"
