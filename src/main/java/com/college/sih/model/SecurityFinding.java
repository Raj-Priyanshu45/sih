package com.college.sih.model;

import com.college.sih.enums.EvaluationStatus;
import com.college.sih.enums.Severity;

public record SecurityFinding(
        String ruleId,
        EvaluationStatus status,
        Severity severity,
        String title,
        String observed,
        String description,
        String recommendation,
        String reference
) {
}