package com.college.sih.service;

import com.college.sih.dto.PcapAnalysisResponse;
import com.college.sih.dto.ScanReportDto;
import com.college.sih.dto.ScanReportDto.CoverageSummary;
import com.college.sih.dto.ScanReportDto.NotEvaluatedReason;
import com.college.sih.dto.ScanReportDto.Recommendation;
import com.college.sih.dto.ScanReportDto.Summary;
import com.college.sih.enums.Confidence;
import com.college.sih.enums.EvaluationStatus;
import com.college.sih.enums.Grade;
import com.college.sih.enums.Severity;
import com.college.sih.model.RuleFinding;
import com.college.sih.model.SecurityAnalysisReport;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Turns the engine's report + analyzer output into the API response:
 * adds grade, confidence, summary counts, deduplicated recommendations and
 * the reasons rules could not be evaluated. Pure derivation, no new analysis.
 */
@Component
@RequiredArgsConstructor
public class ScanReportAssembler {

    private static final List<Severity> SEVERITY_ORDER =
            List.of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW);

    private final RuleBookLoader ruleBook;

    public ScanReportDto assemble(PcapAnalysisResponse resp, SecurityAnalysisReport report, boolean includeRaw) {
        List<RuleFinding> findings = report.findings();

        double fraction = report.rulesTotal() == 0 ? 0 : (double) report.rulesEvaluated() / report.rulesTotal();
        double percent = Math.round(fraction * 1000.0) / 10.0;
        Severity risk = report.riskLevel() == null ? Severity.NONE : report.riskLevel();

        return new ScanReportDto(
                report.rulebookVersion(),
                report.score(),
                Grade.of(report.score(), report.riskLevel()),
                risk,
                Confidence.of(fraction),
                report.provisional(),
                new CoverageSummary(report.rulesEvaluated(), report.rulesTotal(), percent),
                resp.vpn(),
                summarize(findings),
                findings,
                recommendations(findings),
                notEvaluatedReasons(findings),
                resp.notes() == null ? List.of() : resp.notes(),
                includeRaw ? withoutServerPath(resp) : null);
    }

    private Summary summarize(List<RuleFinding> findings) {
        int passed = 0, failed = 0, notEvaluated = 0;
        Map<String, Integer> bySeverity = new LinkedHashMap<>();
        SEVERITY_ORDER.forEach(s -> bySeverity.put(s.name(), 0));

        for (RuleFinding f : findings) {
            switch (f.status()) {
                case PASS -> passed++;
                case NOT_EVALUATED -> notEvaluated++;
                case FAIL -> {
                    failed++;
                    if (f.severity() != null && bySeverity.containsKey(f.severity().name())) {
                        bySeverity.merge(f.severity().name(), 1, Integer::sum);
                    }
                }
            }
        }
        return new Summary(passed, failed, notEvaluated, bySeverity);
    }

    /** Failed rules only, worst first, same advice from several rules merged into one entry. */
    private List<Recommendation> recommendations(List<RuleFinding> findings) {
        Map<String, List<RuleFinding>> byAdvice = findings.stream()
                .filter(f -> f.status() == EvaluationStatus.FAIL)
                .sorted(Comparator.comparingInt((RuleFinding f) -> points(f.severity())).reversed())
                .collect(Collectors.groupingBy(RuleFinding::recommendation, LinkedHashMap::new, Collectors.toList()));

        return byAdvice.entrySet().stream()
                .map(e -> new Recommendation(
                        severityName(e.getValue().get(0).severity()),   // list is sorted, first = worst
                        e.getValue().stream().map(RuleFinding::ruleId).toList(),
                        e.getKey()))
                .toList();
    }

    private List<NotEvaluatedReason> notEvaluatedReasons(List<RuleFinding> findings) {
        return findings.stream()
                .filter(f -> f.status() == EvaluationStatus.NOT_EVALUATED)
                .map(f -> new NotEvaluatedReason(
                        f.ruleId(),
                        f.title(),
                        f.evidence().isEmpty()
                                ? List.of(ruleBook.rule(f.ruleId()).notEvaluatedWhen())
                                : f.evidence()))
                .toList();
    }

    private int points(Severity s) {
        return s == null ? 0 : ruleBook.severityPoints(s);
    }

    private static String severityName(Severity s) {
        return s == null ? null : s.name();
    }

    /** The analyzer's temp path is server-internal: never return it. */
    private static PcapAnalysisResponse withoutServerPath(PcapAnalysisResponse r) {
        return new PcapAnalysisResponse(r.schemaVersion(), r.status(), r.error(), null,
                r.vpn(), r.ikeSas(), r.childSaNegotiations(), r.pfs(), r.espTraffic(),
                r.lifetime(), r.coverage(), r.notes());
    }
}