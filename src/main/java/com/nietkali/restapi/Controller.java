package com.nietkali.restapi;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

import java.io.IOException;

@RestController // обработка rest api запроса и возврат json
@RequestMapping("/api")
@Tag(name="PDF Security", description = "API for checking PDF files for threats")
public class Controller {
    @Autowired // запуск зависимостей и вкл сервиса
    private PdfAnalyzerservice pdfAnalyzerservice;
    @PostMapping(value = "/pdf-check", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Checking the PDF file", description = "Downloading file, analyzing and looking for injections")
    public ResponseEntity<?> checkPdf(@RequestParam("file")MultipartFile file){
        //проверка содержмое файла
        if (file.isEmpty()){
            return ResponseEntity.badRequest().body("File isn't uploadm try again");
        }
        //проверка расширение файла
        String fileName = file.getOriginalFilename();
        if (fileName == null || !fileName.toLowerCase().endsWith(".pdf")){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Sorry, you have to upload file with .pdf extension");
        }
        //передача файла для анализа
        PdfCheckResponce responce = pdfAnalyzerservice.analyze(file);
        return  ResponseEntity.ok(responce);
    }
    @PostMapping(value = "/pdf-sanitize", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<byte[]> sanitizePdf(@RequestParam("file") MultipartFile file) throws IOException{
        if (file.isEmpty()) return ResponseEntity.badRequest().build();
        byte[] cleanFile = pdfAnalyzerservice.sanitizePdf(file.getBytes());
        return  ResponseEntity.ok().header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"clean_" + file.getOriginalFilename()+ "\"").contentType(MediaType.APPLICATION_PDF).body(cleanFile);
    }
}
