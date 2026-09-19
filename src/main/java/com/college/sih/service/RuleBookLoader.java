package com.college.sih.service;

import com.college.sih.enums.Severity;
import com.college.sih.model.AlgoEntry;
import com.college.sih.model.RuleBookData;
import com.college.sih.model.RuleMeta;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;


@Slf4j
@Component
public class RuleBookLoader {

    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    @Getter
    private RuleBookData ruleBook;

    private Map<String, RuleMeta> rulesById;
    private Map<Integer, AlgoEntry> encryptionById;
    private Map<Integer, AlgoEntry> integrityById;
    private Map<Integer, AlgoEntry> prfById;
    private Map<Integer, AlgoEntry> dhGroupById;

    @PostConstruct
    void load() {
        try (InputStream in = new ClassPathResource("rulebook.json").getInputStream()) {
            ruleBook = MAPPER.readValue(in, RuleBookData.class);
        } catch (IOException e) {
            throw new IllegalStateException("Could not load rulebook.json from the classpath", e);
        }

        rulesById = new LinkedHashMap<>();
        for (RuleMeta r : ruleBook.rules()) {
            rulesById.put(r.id(), r);
        }

        encryptionById = index(ruleBook.algorithms().encryption());
        integrityById = index(ruleBook.algorithms().integrity());
        prfById = index(ruleBook.algorithms().prf());
        dhGroupById = index(ruleBook.algorithms().dhGroup());

        log.info("Loaded rulebook {} ({} rules; {} encryption / {} integrity / {} prf / {} DH entries)",
                ruleBook.rulebookVersion(), rulesById.size(),
                encryptionById.size(), integrityById.size(), prfById.size(), dhGroupById.size());
    }

    private static Map<Integer, AlgoEntry> index(List<AlgoEntry> entries) {
        Map<Integer, AlgoEntry> map = new HashMap<>();
        for (AlgoEntry e : entries) {
            map.put(e.id(), e);
        }
        return map;
    }

    public RuleMeta rule(String id) {
        RuleMeta m = rulesById.get(id);
        if (m == null) {
            throw new IllegalStateException("Rule " + id + " is not defined in rulebook.json");
        }
        return m;
    }

    public Optional<AlgoEntry> encryption(Integer id) {
        return Optional.ofNullable(id == null ? null : encryptionById.get(id));
    }

    public Optional<AlgoEntry> integrity(Integer id) {
        return Optional.ofNullable(id == null ? null : integrityById.get(id));
    }

    public Optional<AlgoEntry> prf(Integer id) {
        return Optional.ofNullable(id == null ? null : prfById.get(id));
    }

    public Optional<AlgoEntry> dhGroup(Integer id) {
        return Optional.ofNullable(id == null ? null : dhGroupById.get(id));
    }

    /**
     * Table lookup by IANA transform-type label. Accepts both the classic labels
     * (ENCR/INTEG/PRF/D-H) and the newer KE/SN aliases (RFC 9370/9827). Returns
     * empty for ESN/SN and any type this rule book doesn't classify.
     */
    public Optional<AlgoEntry> byTransformType(String type, Integer id) {
        if (type == null || id == null) {
            return Optional.empty();
        }
        return switch (type) {
            case "ENCR" -> encryption(id);
            case "INTEG" -> integrity(id);
            case "PRF" -> prf(id);
            case "D-H", "KE" -> dhGroup(id);
            default -> Optional.empty();
        };
    }

    public int severityPoints(Severity s) {
        Integer pts = ruleBook.severityPoints().get(s.name());
        return pts == null ? 0 : pts;
    }
}