package com.nietkali.restapi;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController // обработка rest api запроса и возврат json
@RequestMapping("/api")
public class Controller {
    @Autowired // запуск зависимостей и вкл сервиса
    private PdfAnalyzerservice pdfAnalyzerservice;
    @PostMapping("/pdf-check")
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
}
