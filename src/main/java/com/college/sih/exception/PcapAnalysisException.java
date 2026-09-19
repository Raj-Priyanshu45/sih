package com.college.sih.exception;

/**
 * Any failure while running or reading the PCAP analyzer.
 * Handle it in a @RestControllerAdvice: log the full message, but return
 * only a generic message to the client.
 */
public class PcapAnalysisException extends RuntimeException {

    public PcapAnalysisException(String message) {
        super(message);
    }

    public PcapAnalysisException(String message, Throwable cause) {
        super(message, cause);
    }
}