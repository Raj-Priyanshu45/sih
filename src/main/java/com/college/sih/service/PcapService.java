package com.college.sih.service;

import com.college.sih.dto.PcapAnalysisResponse;
import com.college.sih.exception.PcapAnalysisException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
public class PcapService {

    // The analyzer prints snake_case JSON. A dedicated mapper keeps that
    // setting away from the JSON your own REST API returns.
    private static final JsonMapper ANALYZER_MAPPER = JsonMapper.builder()
            .propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
            .build();

    @Value("${pcap.upload-dir}")
    private String uploadDir;

    @Value("${pcap.analyzer-script}")
    private String analyzerScript;

    @Value("${pcap.analyzer-timeout-seconds:60}")
    private long timeoutSeconds;

    public PcapAnalysisResponse runPythonPcap(MultipartFile file) {

        if (file == null || file.isEmpty()) {
            throw new PcapAnalysisException("Uploaded file is empty");
        }

        Path saved = null;
        try {
            saved = Files.createTempFile(Path.of(uploadDir), "capture-", ".pcap");
            file.transferTo(saved);
            return analyze(saved);
        } catch (IOException e) {
            throw new PcapAnalysisException("Could not store the uploaded file", e);
        } finally {
            // Captures can contain sensitive traffic: never keep them
            deleteQuietly(saved);
        }
    }

    private PcapAnalysisResponse analyze(Path pcap) {

        Process process;
        try {
            process = new ProcessBuilder("python3", analyzerScript, pcap.toString())
                    .start();
        } catch (IOException e) {
            throw new PcapAnalysisException("Could not start the analyzer", e);
        }

        // stdout is the JSON, stderr is diagnostics. Keep them separate
        // (merging would corrupt the JSON if Python prints a warning) and
        // drain both at once so a full pipe can never block the process.
        CompletableFuture<String> stdout = readAsync(process.getInputStream());
        CompletableFuture<String> stderr = readAsync(process.getErrorStream());

        try {
            if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                throw new PcapAnalysisException(
                        "Analyzer timed out after " + timeoutSeconds + " seconds");
            }
        } catch (InterruptedException e) {
            process.destroyForcibly();
            Thread.currentThread().interrupt();
            throw new PcapAnalysisException("Analysis was interrupted", e);
        }

        String output = stdout.join().trim();
        String errors = stderr.join().trim();

        if (!errors.isEmpty()) {
            log.warn("Analyzer stderr: {}", errors);
        }

        if (output.isEmpty()) {
            throw new PcapAnalysisException(
                    "Analyzer produced no output (exit code " + process.exitValue() + ")");
        }

        PcapAnalysisResponse result;
        try {
            result = ANALYZER_MAPPER.readValue(output, PcapAnalysisResponse.class);
        } catch (JacksonException e) {
            throw new PcapAnalysisException("Analyzer returned invalid JSON", e);
        }

        // The analyzer reports failures as {"status": "error", "error": "..."}
        if (!"ok".equals(result.status())) {
            throw new PcapAnalysisException("Analyzer error: " + result.error());
        }

        // Fail loudly if the analyzer schema changes incompatibly
        if (result.schemaVersion() == null || !result.schemaVersion().startsWith("1.")) {
            throw new PcapAnalysisException(
                    "Unsupported analyzer schema version: " + result.schemaVersion());
        }

        return result;
    }

    private static CompletableFuture<String> readAsync(InputStream in) {
        return CompletableFuture.supplyAsync(() -> {
            try (in) {
                return new String(in.readAllBytes(), StandardCharsets.UTF_8);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        });
    }

    private void deleteQuietly(Path path) {
        if (path == null) {
            return;
        }
        try {
            Files.deleteIfExists(path);
        } catch (IOException e) {
            log.warn("Could not delete temporary upload {}", path, e);
        }
    }
}