package com.college.sih.controller;

import com.college.sih.dto.Pcap;
import com.college.sih.service.PcapService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class PcapController {

    private final PcapService pcapService;

    @PostMapping(value = "/pcap" ,
            consumes = MediaType.MULTIPART_FORM_DATA_VALUE
    )
    public ResponseEntity<?> getPcapFile(
            @RequestPart MultipartFile file
            ) throws IOException, InterruptedException {

        return ResponseEntity.status(200).body(pcapService.runPythonPcap(file));
    }
}
