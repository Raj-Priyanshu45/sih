package com.college.sih.dto;

public record Vpn (
        String protocol ,
        String ike_version,
        String source,
        String destination,
        boolean esp_detected
){
}
