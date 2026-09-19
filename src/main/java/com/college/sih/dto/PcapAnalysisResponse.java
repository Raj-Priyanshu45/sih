package com.college.sih.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Maps the JSON printed by analyze_pcap.py (schema_version 1.x).
 *
 * Read it with a snake_case mapper (see PcapService). Every field is a
 * wrapper type on purpose: a missing value must stay null, not become 0 or
 * false.
 *
 * NULL MEANS "NOT VISIBLE IN THIS CAPTURE", NOT "SAFE". The rule engine
 * should report those checks as NOT_EVALUATED.
 *
 * When the analyzer fails it prints only {"status": "error", "error": "..."},
 * so on failure every field except status and error is null.
 */
public record PcapAnalysisResponse(
        String schemaVersion,
        String status,
        String error,                                    // only set when status is "error"
        String pcapFile,                                 // server-side temp path: do not expose to clients
        Vpn vpn,
        List<IkeSa> ikeSas,                              // may be empty
        List<ChildSaNegotiation> childSaNegotiations,    // empty without IKE keys
        Pfs pfs,
        EspTraffic espTraffic,
        Lifetime lifetime,
        Coverage coverage,
        List<String> notes
) {

    public record Vpn(
            String protocol,        // always "IPsec"
            String ikeVersion,      // null if no IKE packets, e.g. "2.0"
            String source,          // null if no IKE and no ESP packets
            String destination,
            Boolean espDetected
    ) {}

    /** One IKE SA. A capture can contain several (rekey / reauth). */
    public record IkeSa(
            String initiatorSpi,
            String responderSpi,    // null if the responder never appears
            String ikeVersion,
            String initiator,
            String responder,
            Integer firstFrame,
            IkeSaInit ikeSaInit     // null for IKEv1 SAs
    ) {}

    /** If the handshake is not in the capture, selected is null and offered is empty. */
    public record IkeSaInit(
            Integer requestFrame,
            Integer responseFrame,
            List<Proposal> offered, // what the initiator proposed
            Algorithm keDhGroup,    // DH group of the initiator's KE payload
            Selected selected       // what the responder chose
    ) {}

    public record Proposal(
            Integer number,
            String protocol,        // "IKE", "ESP" or "AH"
            List<Transform> transforms
    ) {}

    /** type is ENCR, INTEG, PRF, D-H or ESN. Match rules on id, not name. */
    public record Transform(
            String type,
            String name,
            Integer id,             // IANA transform ID
            Integer keyLength       // only ENCR transforms with a key-length attribute
    ) {}

    /** The algorithms the responder actually selected. */
    public record Selected(
            String protocol,
            Algorithm encryption,
            Algorithm integrity,    // null with AEAD ciphers such as AES-GCM
            Algorithm prf,          // null in ESP proposals
            Algorithm dhGroup,      // null in ESP proposals without PFS
            Algorithm esn           // null in IKE proposals
    ) {}

    /** name + IANA id; keyLength is only ever set on encryption. */
    public record Algorithm(
            String name,
            Integer id,
            Integer keyLength
    ) {}

    /** Only present when the IKE messages could be decrypted. */
    public record ChildSaNegotiation(
            Integer frame,
            String ikeInitiatorSpi,
            String exchange,        // "IKE_AUTH" or "CREATE_CHILD_SA"
            @JsonProperty("is_response") Boolean response,
            List<Proposal> proposals,
            Selected selected,      // null for requests
            Boolean pfs             // only for CREATE_CHILD_SA, else null
    ) {}

    /** enabled is null unless determinable is true. */
    public record Pfs(
            Boolean determinable,
            Boolean enabled,
            List<PfsEvidence> evidence
    ) {}

    public record PfsEvidence(
            Integer frame,
            Boolean pfs
    ) {}

    public record EspTraffic(
            Integer totalPackets,
            List<EspTunnel> tunnels // may be empty
    ) {}

    /** One direction of one child SA, identified by SPI. */
    public record EspTunnel(
            String source,
            String destination,
            String spi,
            Integer packetCount,
            Long totalBytes,
            Integer firstSequence,
            Integer lastSequence,
            Integer firstFrame,
            Integer lastFrame,
            Boolean startedInCapture,   // false = already running when capture began
            Double durationSeconds
    ) {}

    public record Lifetime(
            List<RekeyInterval> observedRekeyIntervals  // may be empty
    ) {}

    /** Approximate. If lowerBoundOnly is true, the real interval is longer. */
    public record RekeyInterval(
            String source,
            String destination,
            String oldSpi,
            String newSpi,
            Double intervalSeconds,
            Boolean lowerBoundOnly
    ) {}

    /** Which rule-engine checks could actually be evaluated. */
    public record Coverage(
            Boolean ikeSaNegotiationVisible,
            Boolean childSaNegotiationVisible,
            Boolean pfsDeterminable,
            Boolean configuredLifetimesVisible
    ) {}
}