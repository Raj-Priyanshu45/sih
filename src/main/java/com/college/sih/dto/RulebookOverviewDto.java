package com.college.sih.dto;

import com.college.sih.model.RuleMeta;
import com.college.sih.model.Thresholds;

import java.util.List;
import java.util.Map;

/** GET /api/v1/rulebook: everything needed to explain how a score was produced. */
public record RulebookOverviewDto(
        String rulebookVersion,
        Thresholds thresholds,
        Map<String, Integer> severityPoints,
        Map<String, String> gradePolicy,
        Map<String, String> confidencePolicy,
        List<RuleMeta> rules
) {}