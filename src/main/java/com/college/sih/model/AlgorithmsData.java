package com.college.sih.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record AlgorithmsData(
        List<AlgoEntry> encryption,
        List<AlgoEntry> integrity,
        List<AlgoEntry> prf,
        List<AlgoEntry> dhGroup
) {}
