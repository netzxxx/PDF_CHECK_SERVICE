package com.nietkali.restapi;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WelcomeCOntroller {

    // Этот метод сработает, когда кто-то зайдет просто на http://localhost:8080
    @GetMapping("/")
    public String welcome() {
        return "<h1>Alatau City Bank: PDF Security Scanner</h1>" +
                "<p>Service is working!</p>" +
                "<p>Pls, send POST-request with PDF-file to endpoint: <b>/api/pdf-check</b></p>";
    }
}