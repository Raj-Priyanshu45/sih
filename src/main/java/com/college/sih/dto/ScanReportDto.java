package com.college.sih.dto;

import com.college.sih.enums.Confidence;
import com.college.sih.enums.Grade;
import com.college.sih.enums.Severity;
import com.college.sih.model.RuleFinding;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;
import java.util.Map;

/**
 * What POST /api/v1/pcap/analyze returns. Built by ScanReportAssembler from the
 * analyzer output plus the engine's report. Never contains the server-side
 * temp path of the uploaded capture.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ScanReportDto(
        String rulebookVersion,
        int score,
        Grade grade,
        Severity riskLevel,                  // NONE when no rule failed
        Confidence confidence,
        boolean provisional,
        CoverageSummary coverage,
        PcapAnalysisResponse.Vpn vpn,        // null if the analyzer saw no VPN traffic
        Summary summary,
        List<RuleFinding> findings,
        List<Recommendation> recommendations,          // from FAILED rules only, worst first
        List<NotEvaluatedReason> notEvaluatedReasons,  // why rules could not run
        List<String> analyzerNotes,
        PcapAnalysisResponse raw                       // only with ?include=raw
) {

    public record CoverageSummary(int rulesEvaluated, int rulesTotal, double percent) {}

    public record Summary(int passed, int failed, int notEvaluated, Map<String, Integer> bySeverity) {}

    /** One deduplicated fix; ruleIds lists every failed rule it addresses. */
    public record Recommendation(String severity, List<String> ruleIds, String recommendation) {}

    public record NotEvaluatedReason(String ruleId, String title, List<String> reasons) {}
}