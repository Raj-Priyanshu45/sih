package com.college.sih.model;

import com.college.sih.enums.Severity;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Human-readable metadata for one rule, as written in rulebook.json. The engine
 * pulls title/reference/recommendation/severity from here so that text lives in
 * exactly one place; the actual pass/fail logic still has to be Java (failWhen /
 * notEvaluatedWhen are prose, not executable), but they're kept here too so a
 * findings API can show the full rule definition alongside a result.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RuleMeta(
        String id,
        String title,
        String target,
        List<String> reads,
        String failWhen,
        String notEvaluatedWhen,
        String severity,       // "FROM_TABLE" or a fixed Severity name (e.g. "HIGH")
        String reference,
        String recommendation,
        String passNote        // optional
) {
    /** Only valid when severity is a fixed name, not "FROM_TABLE". */
    public Severity fixedSeverity() {
        return Severity.valueOf(severity);
    }
}
