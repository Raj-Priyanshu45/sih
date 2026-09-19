package com.college.sih.controller;

import com.college.sih.dto.Pcap;
import com.college.sih.dto.PcapAnalysisResponse;
import com.college.sih.dto.ScanReportDto;
import com.college.sih.model.ScanResultDto;
import com.college.sih.model.SecurityAnalysisReport;
import com.college.sih.service.PcapService;
import com.college.sih.service.ScanReportAssembler;
import com.college.sih.service.SecurityRuleEngine;
import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class PcapController {

    private final PcapService pcapService;
    private final SecurityRuleEngine engine;
    private final SecurityRuleEngine ruleEngine;
    private final ScanReportAssembler assembler;


    @PostMapping(value = "/pcap" ,
            consumes = MediaType.MULTIPART_FORM_DATA_VALUE
    )
    public ResponseEntity<?> getPcapFile(
            @RequestPart MultipartFile file
            ) throws IOException, InterruptedException {

        return ResponseEntity.status(200).body(pcapService.runPythonPcap(file));
    }

    @PostMapping(value = "/pcapv2", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ScanResultDto analyze(@RequestPart MultipartFile file) {
        return ScanResultDto.from(engine.evaluate(pcapService.runPythonPcap(file)));
    }

    @Operation(summary = "Analyze an IPsec/IKE capture",
            description = "Runs the analyzer, evaluates every rule and returns score, grade, confidence, "
                    + "findings and recommendations. Use include=raw to also get the analyzer output.")
    @PostMapping(value = "/analyze", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ScanReportDto analyze(
            @RequestPart("file") MultipartFile file,
            @RequestParam(name = "include", required = false) String include) {

        PcapAnalysisResponse analysis = pcapService.runPythonPcap(file);
        SecurityAnalysisReport report = ruleEngine.evaluate(analysis);
        return assembler.assemble(analysis, report, "raw".equalsIgnoreCase(include));
    }
}
