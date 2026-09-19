package com.college.sih.dto;

import org.springframework.web.multipart.MultipartFile;

public record Pcap(
        MultipartFile file
) {
}
