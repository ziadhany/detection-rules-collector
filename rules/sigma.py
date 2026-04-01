#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from pipeline import BaseRulePipeline

class CollectSigmaRulesPipeline(BaseRulePipeline):
    rule_type = "sigma"
    rglob_patterns = ["**/*.yml"]


class SigmaHQImproverPipeline(CollectSigmaRulesPipeline):
    repo_url = "https://github.com/SigmaHQ/sigma"
    license_url = "https://github.com/SigmaHQ/Detection-Rule-License"
    rglob_patterns = [
        "rules/**/*.yml",
        "rules-emerging-threats/**/*.yml",
        "rules-placeholder/**/*.yml",
        "rules-threat-hunting/**/*.yml",
        "rules-compliance/**/*.yml",
    ]


class SigmaSamuraiMDRImproverPipeline(CollectSigmaRulesPipeline):
    repo_url = "https://github.com/SamuraiMDR/sigma-rules"
    license_urls = "https://github.com/SamuraiMDR/sigma-rules/blob/main/LICENSE"


class SigmaMbabinskiImproverPipeline(CollectSigmaRulesPipeline):
    repo_url = "https://github.com/mbabinski/Sigma-Rules"
    license_urls = "https://github.com/mbabinski/Sigma-Rules/blob/main/LICENSE"


class P4T12ICKSigmaImproverPipeline(CollectSigmaRulesPipeline):
    repo_url = "https://github.com/P4T12ICK/Sigma-Rule-Repository"
    license_urls = (
        "https://github.com/P4T12ICK/Sigma-Rule-Repository/blob/master/LICENSE.md"
    )
