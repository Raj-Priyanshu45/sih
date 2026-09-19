package com.college.sih.enums;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Overall verdict for a capture, derived from the numeric score AND the worst
 * failed rule, so one fatal flaw cannot hide behind otherwise good settings
 * (same idea as the grade caps used by SSL Labs).
 *
 * Severity names follow the CVSS qualitative scale (Low/Medium/High/Critical).
 * The score-to-grade cut-offs are project policy.
 */
public enum Grade {
    GOOD, FAIR, WEAK, POOR;

    /** @param worstFailure worst severity among failed rules, or null when nothing failed */
    public static Grade of(int score, Severity worstFailure) {
        Grade byScore = score >= 90 ? GOOD
                : score >= 75 ? FAIR
                : score >= 50 ? WEAK
                : POOR;

        if (worstFailure == Severity.CRITICAL) {
            return POOR;                                   // e.g. NULL cipher, DH group 1
        }
        if (worstFailure == Severity.HIGH && byScore.compareTo(WEAK) < 0) {
            return WEAK;                                   // e.g. IKEv1, 3DES: never better than WEAK
        }
        return byScore;
    }

    /** Human-readable policy, exposed by GET /api/v1/rulebook. */
    public static Map<String, String> policy() {
        Map<String, String> p = new LinkedHashMap<>();
        p.put("GOOD", "score >= 90");
        p.put("FAIR", "score 75-89");
        p.put("WEAK", "score 50-74, or any HIGH failure");
        p.put("POOR", "score < 50, or any CRITICAL failure");
        return p;
    }
}