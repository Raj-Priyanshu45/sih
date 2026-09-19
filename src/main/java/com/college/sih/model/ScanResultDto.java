package com.college.sih.model;

import java.util.List;

public record ScanResultDto(
        int score,
        String riskLevel,          // "NONE" when engine returns null
        boolean provisional,
        int rulesEvaluated,
        int rulesTotal,
        List<RuleFinding> findings,
        String rulebookVersion
) {
    public static ScanResultDto from(SecurityAnalysisReport r) {
        return new ScanResultDto(r.score(),
                r.riskLevel() == null ? "NONE" : r.riskLevel().name(),
                r.provisional(), r.rulesEvaluated(), r.rulesTotal(),
                r.findings(), r.rulebookVersion());
    }
}