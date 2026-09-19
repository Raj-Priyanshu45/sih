package com.college.sih.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;
import java.util.Map;

/** Root of rulebook.json. Unknown top-level keys (sources, classes, preferred, ...) are ignored on purpose. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RuleBookData(
        String rulebookVersion,
        Thresholds thresholds,
        Map<String, Integer> severityPoints,
        AlgorithmsData algorithms,
        List<RuleMeta> rules
) {}
