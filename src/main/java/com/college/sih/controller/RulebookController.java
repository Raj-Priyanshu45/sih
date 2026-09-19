package com.college.sih.controller;

import com.college.sih.dto.RulebookOverviewDto;
import com.college.sih.enums.Confidence;
import com.college.sih.enums.Grade;
import com.college.sih.model.AlgoEntry;
import com.college.sih.model.AlgorithmsData;
import com.college.sih.model.RuleBookData;
import com.college.sih.service.RuleBookLoader;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

/** Makes the scoring transparent: the rules, thresholds and algorithm tables behind every score. */
@Tag(name = "Rule book")
@RestController
@RequestMapping("/api/v1/rulebook")
@RequiredArgsConstructor
public class RulebookController {

    private final RuleBookLoader loader;

    @Operation(summary = "Rule book version, thresholds, severity points, grade policy and all rules")
    @GetMapping
    public RulebookOverviewDto overview() {
        RuleBookData rb = loader.getRuleBook();
        return new RulebookOverviewDto(
                rb.rulebookVersion(),
                rb.thresholds(),
                rb.severityPoints(),
                Grade.policy(),
                Confidence.policy(),
                rb.rules());
    }

    @Operation(summary = "Algorithm classification table",
            description = "type is one of: encryption, integrity, prf, dhGroup")
    @GetMapping("/algorithms/{type}")
    public List<AlgoEntry> algorithms(@PathVariable String type) {
        AlgorithmsData a = loader.getRuleBook().algorithms();
        return switch (type.toLowerCase()) {
            case "encryption" -> a.encryption();
            case "integrity" -> a.integrity();
            case "prf" -> a.prf();
            case "dhgroup" -> a.dhGroup();
            default -> throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                    "Unknown algorithm table '" + type + "'. Use encryption, integrity, prf or dhGroup.");
        };
    }
}