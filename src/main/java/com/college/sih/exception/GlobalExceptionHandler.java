package com.college.sih.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

/** Full details go to the log; clients only ever get a generic message. */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(PcapAnalysisException.class)
    public ProblemDetail onAnalysisFailure(PcapAnalysisException e) {
        log.error("PCAP analysis failed", e);
        ProblemDetail pd = ProblemDetail.forStatusAndDetail(
                HttpStatus.UNPROCESSABLE_ENTITY, "The capture could not be analyzed.");
        pd.setTitle("PCAP analysis failed");
        return pd;
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ProblemDetail onTooLarge(MaxUploadSizeExceededException e) {
        ProblemDetail pd = ProblemDetail.forStatusAndDetail(
                HttpStatus.PAYLOAD_TOO_LARGE, "The uploaded capture is too large.");
        pd.setTitle("Upload too large");
        return pd;
    }
}