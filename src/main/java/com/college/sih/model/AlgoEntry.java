package com.college.sih.model;

import com.college.sih.enums.AlgoClass;
import com.college.sih.enums.Severity;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * One row of rulebook.json's encryption/integrity/prf/dhGroup tables.
 * "class" is a reserved word in Java, so the field is named {@code clazz} and
 * mapped back to the JSON key explicitly.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AlgoEntry(
        Integer id,
        String name,
        @JsonProperty("class") AlgoClass clazz,
        Severity severity,          // null exactly when clazz == ACCEPTABLE
        String basis,
        String note,                // optional
        Boolean aead,                // only meaningful in the encryption table
        Boolean variableKeyLength    // only meaningful in the encryption table
) {}