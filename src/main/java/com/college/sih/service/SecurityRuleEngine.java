package com.college.sih.service;


import com.college.sih.dto.PcapAnalysisResponse;
import com.college.sih.dto.PcapAnalysisResponse.Algorithm;
import com.college.sih.dto.PcapAnalysisResponse.ChildSaNegotiation;
import com.college.sih.dto.PcapAnalysisResponse.IkeSa;
import com.college.sih.dto.PcapAnalysisResponse.Lifetime;
import com.college.sih.dto.PcapAnalysisResponse.Pfs;
import com.college.sih.dto.PcapAnalysisResponse.Proposal;
import com.college.sih.dto.PcapAnalysisResponse.RekeyInterval;
import com.college.sih.dto.PcapAnalysisResponse.Selected;
import com.college.sih.dto.PcapAnalysisResponse.Transform;
import com.college.sih.enums.AlgoClass;
import com.college.sih.enums.EvaluationStatus;
import com.college.sih.enums.Severity;
import com.college.sih.model.AlgoEntry;
import com.college.sih.model.RuleFinding;
import com.college.sih.model.RuleMeta;
import com.college.sih.model.SecurityAnalysisReport;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;


@Service
@RequiredArgsConstructor
public class SecurityRuleEngine {

    private final RuleBookLoader ruleBook;

    private static final List<AlgoClass> WEAK = List.of(AlgoClass.FORBIDDEN, AlgoClass.DISCOURAGED, AlgoClass.LEGACY);

    public SecurityAnalysisReport evaluate(PcapAnalysisResponse resp) {
        List<IkeSa> ikeSas = orEmpty(resp.ikeSas());
        List<ChildSaNegotiation> childSas = orEmpty(resp.childSaNegotiations());

        List<RuleFinding> findings = new ArrayList<>();
        findings.add(evalVersion(ikeSas));
        findings.add(evalIkeEncryption(ikeSas));
        findings.add(evalIkeIntegrity(ikeSas));
        findings.add(evalIkePrf(ikeSas));
        findings.add(evalIkeDh(ikeSas));
        findings.add(evalIkeOffer(ikeSas));
        findings.add(evalChildEncryption(childSas));
        findings.add(evalChildIntegrity(childSas));
        findings.add(evalChildPfs(resp.pfs()));
        findings.add(evalChildDh(childSas));
        findings.add(evalLifetime(resp.lifetime()));

        return buildReport(findings);
    }

    // ---------------------------------------------------------------- VER-001

    private RuleFinding evalVersion(List<IkeSa> ikeSas) {
        RuleMeta meta = ruleBook.rule("VER-001");
        List<TargetOutcome> outcomes = new ArrayList<>();
        for (IkeSa sa : ikeSas) {
            String label = spiLabel(sa);
            String version = sa.ikeVersion();
            if (version == null) {
                outcomes.add(TargetOutcome.notEvaluated(label + ": IKE version not visible"));
                continue;
            }
            String major = version.split("\\.")[0];
            if ("1".equals(major)) {
                outcomes.add(TargetOutcome.fail(meta.fixedSeverity(), label + ": IKEv1 (" + version + ")"));
            } else {
                outcomes.add(TargetOutcome.pass(label + ": IKEv" + version));
            }
        }
        return rollUp(meta, outcomes);
    }

    // ------------------------------------------------------------ IKE-ENC-001

    private RuleFinding evalIkeEncryption(List<IkeSa> ikeSas) {
        RuleMeta meta = ruleBook.rule("IKE-ENC-001");
        int minBits = ruleBook.getRuleBook().thresholds().minSymmetricKeyBits();
        List<TargetOutcome> outcomes = new ArrayList<>();

        for (IkeSa sa : ikeSas) {
            String label = spiLabel(sa);
            Selected selected = selectedOf(sa);
            if (selected == null || selected.encryption() == null) {
                outcomes.add(TargetOutcome.notEvaluated(label + ": IKE_SA_INIT not visible"));
                continue;
            }
            Algorithm enc = selected.encryption();
            var entryOpt = ruleBook.encryption(enc.id());
            if (entryOpt.isEmpty()) {
                outcomes.add(TargetOutcome.notEvaluated(label + ": encryption ID " + enc.id() + " not in table"));
                continue;
            }
            AlgoEntry entry = entryOpt.get();
            if (WEAK.contains(entry.clazz())) {
                outcomes.add(TargetOutcome.fail(entry.severity(),
                        label + ": " + entry.name() + " is " + entry.clazz() + " (" + entry.basis() + ")"));
                continue;
            }
            if (Boolean.TRUE.equals(entry.variableKeyLength())) {
                if (enc.keyLength() == null) {
                    outcomes.add(TargetOutcome.notEvaluated(label + ": " + entry.name() + " selected, key length not visible"));
                    continue;
                }
                if (enc.keyLength() < minBits) {
                    // The algorithm table classifies the cipher, not the chosen key size,
                    // so there's no table severity for "acceptable cipher, weak key length".
                    // MEDIUM is this engine's own call - tune here if your policy differs.
                    outcomes.add(TargetOutcome.fail(Severity.MEDIUM,
                            label + ": " + entry.name() + " with a " + enc.keyLength() + "-bit key (< " + minBits + ")"));
                    continue;
                }
            }
            outcomes.add(TargetOutcome.pass(label + ": " + entry.name()
                    + (enc.keyLength() != null ? " (" + enc.keyLength() + "-bit)" : "")));
        }
        return rollUp(meta, outcomes);
    }

    // ------------------------------------------------------------ IKE-INT-001

    private RuleFinding evalIkeIntegrity(List<IkeSa> ikeSas) {
        RuleMeta meta = ruleBook.rule("IKE-INT-001");
        List<TargetOutcome> outcomes = new ArrayList<>();

        for (IkeSa sa : ikeSas) {
            String label = spiLabel(sa);
            Selected selected = selectedOf(sa);
            if (selected == null || selected.encryption() == null) {
                outcomes.add(TargetOutcome.notEvaluated(label + ": IKE_SA_INIT not visible"));
                continue;
            }
            outcomes.add(integrityOutcome(label, selected));
        }
        return rollUp(meta, outcomes);
    }

    /** Shared by IKE-INT-001 and CHILD-INT-001: non-AEAD ciphers need a classified integrity transform. */
    private TargetOutcome integrityOutcome(String label, Selected selected) {
        Algorithm enc = selected.encryption();
        var encEntryOpt = ruleBook.encryption(enc.id());
        if (encEntryOpt.isEmpty()) {
            return TargetOutcome.notEvaluated(label + ": encryption ID " + enc.id() + " not in table, AEAD status unknown");
        }
        AlgoEntry encEntry = encEntryOpt.get();
        boolean aead = Boolean.TRUE.equals(encEntry.aead());
        Algorithm integ = selected.integrity();

        if (aead) {
            return TargetOutcome.pass(label + ": AEAD cipher (" + encEntry.name() + "), no separate integrity needed");
        }
        if (integ == null) {
            // Fixed CRITICAL: a non-AEAD cipher with no integrity transform means no
            // authentication at all, independent of anything in the integrity table.
            return TargetOutcome.fail(Severity.CRITICAL, label + ": non-AEAD cipher with no integrity transform (NONE)");
        }
        var integEntryOpt = ruleBook.integrity(integ.id());
        if (integEntryOpt.isEmpty()) {
            return TargetOutcome.notEvaluated(label + ": integrity ID " + integ.id() + " not in table");
        }
        AlgoEntry integEntry = integEntryOpt.get();
        if (integEntry.clazz() == AlgoClass.FORBIDDEN || integEntry.clazz() == AlgoClass.LEGACY) {
            return TargetOutcome.fail(integEntry.severity(), label + ": " + integEntry.name() + " is " + integEntry.clazz());
        }
        return TargetOutcome.pass(label + ": " + integEntry.name());
    }

    // ------------------------------------------------------------ IKE-PRF-001

    private RuleFinding evalIkePrf(List<IkeSa> ikeSas) {
        RuleMeta meta = ruleBook.rule("IKE-PRF-001");
        List<TargetOutcome> outcomes = new ArrayList<>();

        for (IkeSa sa : ikeSas) {
            String label = spiLabel(sa);
            Selected selected = selectedOf(sa);
            if (selected == null || selected.prf() == null) {
                outcomes.add(TargetOutcome.notEvaluated(label + ": IKE_SA_INIT or PRF not visible"));
                continue;
            }
            Algorithm prf = selected.prf();
            var entryOpt = ruleBook.prf(prf.id());
            if (entryOpt.isEmpty()) {
                outcomes.add(TargetOutcome.notEvaluated(label + ": PRF ID " + prf.id() + " not in table"));
                continue;
            }
            AlgoEntry entry = entryOpt.get();
            if (entry.clazz() == AlgoClass.FORBIDDEN || entry.clazz() == AlgoClass.LEGACY) {
                outcomes.add(TargetOutcome.fail(entry.severity(), label + ": " + entry.name() + " is " + entry.clazz()));
            } else {
                outcomes.add(TargetOutcome.pass(label + ": " + entry.name()));
            }
        }
        return rollUp(meta, outcomes);
    }

    // ------------------------------------------------------------- IKE-DH-001

    private RuleFinding evalIkeDh(List<IkeSa> ikeSas) {
        RuleMeta meta = ruleBook.rule("IKE-DH-001");
        List<TargetOutcome> outcomes = new ArrayList<>();

        for (IkeSa sa : ikeSas) {
            String label = spiLabel(sa);
            Selected selected = selectedOf(sa);
            if (selected == null || selected.dhGroup() == null) {
                outcomes.add(TargetOutcome.notEvaluated(label + ": IKE_SA_INIT or DH group not visible"));
                continue;
            }
            outcomes.add(dhOutcome(label, selected.dhGroup()));
        }
        return rollUp(meta, outcomes);
    }

    /** Shared by IKE-DH-001 and CHILD-DH-001. */
    private TargetOutcome dhOutcome(String label, Algorithm dh) {
        var entryOpt = ruleBook.dhGroup(dh.id());
        if (entryOpt.isEmpty()) {
            return TargetOutcome.notEvaluated(label + ": DH group ID " + dh.id() + " not in table");
        }
        AlgoEntry entry = entryOpt.get();
        if (WEAK.contains(entry.clazz())) {
            return TargetOutcome.fail(entry.severity(), label + ": " + entry.name() + " is " + entry.clazz());
        }
        return TargetOutcome.pass(label + ": " + entry.name());
    }

    // --------------------------------------------------------- IKE-OFFER-001

    private RuleFinding evalIkeOffer(List<IkeSa> ikeSas) {
        RuleMeta meta = ruleBook.rule("IKE-OFFER-001");
        List<TargetOutcome> outcomes = new ArrayList<>();

        for (IkeSa sa : ikeSas) {
            String label = spiLabel(sa);
            List<Proposal> offered = sa.ikeSaInit() == null ? null : sa.ikeSaInit().offered();
            if (offered == null || offered.isEmpty()) {
                outcomes.add(TargetOutcome.notEvaluated(label + ": initiator's offer not visible"));
                continue;
            }
            List<String> weak = new ArrayList<>();
            for (Proposal p : offered) {
                for (Transform t : p.transforms()) {
                    ruleBook.byTransformType(t.type(), t.id()).ifPresent(entry -> {
                        if (entry.clazz() == AlgoClass.FORBIDDEN || entry.clazz() == AlgoClass.DISCOURAGED) {
                            weak.add(t.type() + " " + t.name() + " (id " + t.id() + ", " + entry.clazz() + ")");
                        }
                    });
                }
            }
            if (weak.isEmpty()) {
                outcomes.add(TargetOutcome.pass(label + ": no FORBIDDEN/DISCOURAGED transforms offered"));
            } else {
                outcomes.add(TargetOutcome.fail(meta.fixedSeverity(), label + ": offered " + String.join(", ", weak)));
            }
        }
        return rollUp(meta, outcomes);
    }

    // ------------------------------------------------------------ CHILD-*-001

    /** Only ESP responses carry a "selected" the child-SA rules can grade. */
    private List<ChildSaNegotiation> espResponses(List<ChildSaNegotiation> childSas) {
        List<ChildSaNegotiation> out = new ArrayList<>();
        for (ChildSaNegotiation c : childSas) {
            if (c.selected() != null && "ESP".equals(c.selected().protocol())) {
                out.add(c);
            }
        }
        return out;
    }

    private RuleFinding evalChildEncryption(List<ChildSaNegotiation> childSas) {
        RuleMeta meta = ruleBook.rule("CHILD-ENC-001");
        List<TargetOutcome> outcomes = new ArrayList<>();
        for (ChildSaNegotiation c : espResponses(childSas)) {
            String label = childLabel(c);
            Algorithm enc = c.selected().encryption();
            if (enc == null) {
                outcomes.add(TargetOutcome.notEvaluated(label + ": no selected encryption"));
                continue;
            }
            var entryOpt = ruleBook.encryption(enc.id());
            if (entryOpt.isEmpty()) {
                outcomes.add(TargetOutcome.notEvaluated(label + ": encryption ID " + enc.id() + " not in table"));
                continue;
            }
            AlgoEntry entry = entryOpt.get();
            if (WEAK.contains(entry.clazz())) {
                outcomes.add(TargetOutcome.fail(entry.severity(), label + ": " + entry.name() + " is " + entry.clazz()));
            } else {
                outcomes.add(TargetOutcome.pass(label + ": " + entry.name()));
            }
        }
        return rollUp(meta, outcomes);
    }

    private RuleFinding evalChildIntegrity(List<ChildSaNegotiation> childSas) {
        RuleMeta meta = ruleBook.rule("CHILD-INT-001");
        List<TargetOutcome> outcomes = new ArrayList<>();
        for (ChildSaNegotiation c : espResponses(childSas)) {
            String label = childLabel(c);
            if (c.selected().encryption() == null) {
                outcomes.add(TargetOutcome.notEvaluated(label + ": no selected encryption"));
                continue;
            }
            outcomes.add(integrityOutcome(label, c.selected()));
        }
        return rollUp(meta, outcomes);
    }

    private RuleFinding evalChildPfs(Pfs pfs) {
        RuleMeta meta = ruleBook.rule("CHILD-PFS-001");
        List<TargetOutcome> outcomes = new ArrayList<>();
        if (pfs == null || !Boolean.TRUE.equals(pfs.determinable())) {
            outcomes.add(TargetOutcome.notEvaluated("PFS: no decrypted CREATE_CHILD_SA seen"));
        } else if (Boolean.FALSE.equals(pfs.enabled())) {
            outcomes.add(TargetOutcome.fail(meta.fixedSeverity(), "PFS: not enabled on child SA rekeys"));
        } else {
            outcomes.add(TargetOutcome.pass("PFS: enabled on child SA rekeys"));
        }
        return rollUp(meta, outcomes);
    }

    private RuleFinding evalChildDh(List<ChildSaNegotiation> childSas) {
        RuleMeta meta = ruleBook.rule("CHILD-DH-001");
        List<TargetOutcome> outcomes = new ArrayList<>();
        for (ChildSaNegotiation c : childSas) {
            boolean isCreateChildResponse = "CREATE_CHILD_SA".equals(c.exchange()) && Boolean.TRUE.equals(c.response());
            if (!isCreateChildResponse || c.selected() == null || c.selected().dhGroup() == null) {
                continue; // not a target for this rule at all -> doesn't affect coverage
            }
            outcomes.add(dhOutcome(childLabel(c), c.selected().dhGroup()));
        }
        return rollUp(meta, outcomes);
    }

    // -------------------------------------------------------------- LIFE-001

    private RuleFinding evalLifetime(Lifetime lifetime) {
        RuleMeta meta = ruleBook.rule("LIFE-001");
        long maxSeconds = ruleBook.getRuleBook().thresholds().maxChildRekeySeconds();
        List<TargetOutcome> outcomes = new ArrayList<>();
        List<RekeyInterval> intervals = lifetime == null ? List.of() : orEmpty(lifetime.observedRekeyIntervals());

        for (RekeyInterval ri : intervals) {
            String label = ri.source() + " -> " + ri.destination() + " (" + ri.oldSpi() + " -> " + ri.newSpi() + ")";
            if (ri.intervalSeconds() == null) {
                outcomes.add(TargetOutcome.notEvaluated(label + ": no interval recorded"));
                continue;
            }
            double seconds = ri.intervalSeconds();
            boolean lowerBoundOnly = Boolean.TRUE.equals(ri.lowerBoundOnly());
            if (seconds > maxSeconds) {
                // A definite FAIL even if this is only a lower bound: the real interval
                // is at least this long, and it's already over the threshold.
                outcomes.add(TargetOutcome.fail(meta.fixedSeverity(),
                        label + ": rekeyed after " + seconds + "s (> " + maxSeconds + "s)"
                                + (lowerBoundOnly ? ", lower bound only" : "")));
            } else if (lowerBoundOnly) {
                outcomes.add(TargetOutcome.notEvaluated(
                        label + ": >=" + seconds + "s (lower bound only; real value may exceed the threshold)"));
            } else {
                outcomes.add(TargetOutcome.pass(label + ": rekeyed after " + seconds + "s"));
            }
        }
        return rollUp(meta, outcomes);
    }

    // ------------------------------------------------------------- roll-up

    /**
     * FAIL if any target failed; else PASS if any target passed; else
     * NOT_EVALUATED. Severity is the worst among the failed targets, by points.
     */
    private RuleFinding rollUp(RuleMeta meta, List<TargetOutcome> outcomes) {
        long evaluated = outcomes.stream().filter(o -> o.status() != EvaluationStatus.NOT_EVALUATED).count();
        boolean anyFail = outcomes.stream().anyMatch(o -> o.status() == EvaluationStatus.FAIL);
        boolean anyPass = outcomes.stream().anyMatch(o -> o.status() == EvaluationStatus.PASS);

        EvaluationStatus overall = anyFail ? EvaluationStatus.FAIL
                : anyPass ? EvaluationStatus.PASS
                : EvaluationStatus.NOT_EVALUATED;

        Severity worst = null;
        if (anyFail) {
            worst = outcomes.stream()
                    .filter(o -> o.status() == EvaluationStatus.FAIL)
                    .map(TargetOutcome::severity)
                    .filter(Objects::nonNull)
                    .max(Comparator.comparingInt(ruleBook::severityPoints))
                    .orElse(null);
        }

        List<String> evidence = outcomes.stream().map(TargetOutcome::evidence).toList();

        return new RuleFinding(meta.id(), meta.title(), meta.target(), overall, worst,
                meta.reference(), meta.recommendation(), meta.passNote(),
                evidence, (int) evaluated, outcomes.size());
    }

    private SecurityAnalysisReport buildReport(List<RuleFinding> findings) {
        int score = 100;
        Severity riskLevel = null;
        int evaluatedRules = 0;

        for (RuleFinding f : findings) {
            if (f.status() != EvaluationStatus.NOT_EVALUATED) {
                evaluatedRules++;
            }
            if (f.status() == EvaluationStatus.FAIL && f.severity() != null) {
                score -= ruleBook.severityPoints(f.severity());
                if (riskLevel == null || ruleBook.severityPoints(f.severity()) > ruleBook.severityPoints(riskLevel)) {
                    riskLevel = f.severity();
                }
            }
        }
        score = Math.max(score, 0);

        double coverage = findings.isEmpty() ? 0 : (double) evaluatedRules / findings.size();
        boolean provisional = coverage < ruleBook.getRuleBook().thresholds().provisionalScoreBelowCoverage();

        return new SecurityAnalysisReport(ruleBook.getRuleBook().rulebookVersion(), score, provisional,
                riskLevel, evaluatedRules, findings.size(), findings);
    }

    // ------------------------------------------------------------- helpers

    private static Selected selectedOf(IkeSa sa) {
        return sa.ikeSaInit() == null ? null : sa.ikeSaInit().selected();
    }

    private static String spiLabel(IkeSa sa) {
        return "IKE SA " + sa.initiatorSpi() + (sa.responderSpi() != null ? "/" + sa.responderSpi() : "");
    }

    private static String childLabel(ChildSaNegotiation c) {
        return "Child SA (frame " + c.frame() + ", " + c.exchange() + ")";
    }

    private static <T> List<T> orEmpty(List<T> list) {
        return list == null ? List.of() : list;
    }

    /** One rule evaluated against one target: an IKE SA, a child SA negotiation, a rekey interval... */
    private record TargetOutcome(EvaluationStatus status, Severity severity, String evidence) {
        static TargetOutcome pass(String evidence) {
            return new TargetOutcome(EvaluationStatus.PASS, null, evidence);
        }

        static TargetOutcome fail(Severity severity, String evidence) {
            return new TargetOutcome(EvaluationStatus.FAIL, severity, evidence);
        }

        static TargetOutcome notEvaluated(String evidence) {
            return new TargetOutcome(EvaluationStatus.NOT_EVALUATED, null, evidence);
        }
    }
}