/*
 * Example placeholder rule. This is intentionally non-detecting.
 * Add reviewed rules from sources you trust; do not treat this file as a threat feed.
 */
rule ThreatGuard_Example_Placeholder
{
    meta:
        description = "Non-detecting placeholder for local YARA integration"
    strings:
        $placeholder = "THREATGUARD_RULE_PLACEHOLDER"
    condition:
        false
}
