package com.college.sih.model;

import com.college.sih.enums.EvaluationStatus;
import com.college.sih.enums.Severity;

import java.util.List;

/**
 * The rolled-up result of one rule against a capture. {@code evidence} has one
 * line per target that was actually checked (evaluated or not) so the UI/report
 * can show why the status came out the way it did.
 */
public record RuleFinding(
        String ruleId,
        String title,
        String target,
        EvaluationStatus status,
        Severity severity,          // set only when status == FAIL
        String reference,
        String recommendation,
        String passNote,            // may be null
        List<String> evidence,
        int evaluatedTargets,
        int totalTargets
) {}
