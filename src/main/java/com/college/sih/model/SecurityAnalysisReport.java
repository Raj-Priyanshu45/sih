package com.college.sih.model;

import com.college.sih.enums.Severity;

import java.util.List;

/**
 * Final report for one capture: score (100 minus points per failed rule's
 * worst severity, floored at 0), the overall risk level, how much of the rule
 * book could actually be evaluated, and every rule's finding.
 */
public record SecurityAnalysisReport(
        String rulebookVersion,
        int score,
        boolean provisional,   // true when evaluated-rule coverage is below thresholds.provisionalScoreBelowCoverage
        Severity riskLevel,    // null means no rule failed (risk level NONE)
        int rulesEvaluated,
        int rulesTotal,
        List<RuleFinding> findings
) {}
