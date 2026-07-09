package com.nietkali.restapi;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.nio.file.Path;
import java.nio.file.Paths;

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
            return ResponseEntity.badRequest().body("File isn't upload try again");
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
    @GetMapping("/download/{fileName}")
    @Operation(summary = "Download sanitized file", description = "Download a cleaned PDF file by its name.")
    public ResponseEntity <Resource> downloadCleanFile(@PathVariable String fileName){
        try {
            Path filePath = Paths.get("/storage/clean").resolve(fileName).normalize();
            Resource resource = new UrlResource(filePath.toUri());
            if (resource.exists()) {
                return  ResponseEntity.ok().header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + resource.getFilename() + "\"").body(resource);
            } else  {
                return ResponseEntity.internalServerError().build();
            }
        } catch (Exception e){
            return ResponseEntity.internalServerError().build();
        }
    }
}
