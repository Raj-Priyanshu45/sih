package com.college.sih.enums;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * How much of the rule book could actually be evaluated on this capture.
 * A score is only as trustworthy as the share of checks behind it.
 * LOW lines up with the rule book's "provisional" threshold (0.5).
 */
public enum Confidence {
    HIGH, MEDIUM, LOW;

    /** @param coverage fraction of rules evaluated, 0.0 - 1.0 */
    public static Confidence of(double coverage) {
        if (coverage >= 0.8) {
            return HIGH;
        }
        if (coverage >= 0.5) {
            return MEDIUM;
        }
        return LOW;
    }

    public static Map<String, String> policy() {
        Map<String, String> p = new LinkedHashMap<>();
        p.put("HIGH", "at least 80% of rules evaluated");
        p.put("MEDIUM", "50-79% of rules evaluated");
        p.put("LOW", "under 50% of rules evaluated (score is provisional)");
        return p;
    }
}