package com.college.sih.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record Thresholds(
        int minSymmetricKeyBits,
        long maxChildRekeySeconds,
        double provisionalScoreBelowCoverage
) {}
