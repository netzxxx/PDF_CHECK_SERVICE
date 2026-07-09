package com.nietkali.restapi;

import com.google.zxing.BinaryBitmap;
import com.google.zxing.LuminanceSource;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.Result;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentInformation;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.graphics.PDXObject;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.text.PDFTextStripper;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class PdfAnalyzerservice {
    //лист опасных обьектов
    private static final List<String> danger_objects = Arrays.asList("/JS", "/JavaScript", "/OpenAction", "/AA", "/A", "/S", "/Embedded Files", "/EmbeddedFiles", "/FileAttachment", "/Collection", "/FS", "/F", "/Launch", "/Win", "/Mac", "/Unix", "/RichMedia", "/RichMediaContent", "/RichMediaConfiguration", "/RichMediaAnnotation");
    //лист sqli, xss payloads
    private static final List<String> injection = Arrays.asList("' or '1'='1", "union select", "drop table", "<script>", "<svg onload", "admin' --", "xp_cmdshell", "../../../");
    //директория с опасными файлами
    private static final String suspicious_dir = "/storage/suspicious";
    private static final String clean_dir = "/storage/clean";
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(PdfAnalyzerservice.class);
    public PdfCheckResponce analyze(MultipartFile file) {
        String fileName = file.getOriginalFilename();
        List<String> detected = new ArrayList<>();
        try {
            //чтение файла и перевод в текст
            byte[] fileBytes = file.getBytes();
            String fileContent = new String(fileBytes, "ISO-8859-1");
            //поиск уязвимостей
            for (String obj : danger_objects) {
                String regex = Pattern.quote(obj) + "(?=[\\s\\/<>\\[\\]\\(\\)])"; //делает из строки безопасный шаблон(для ложных срабатываний)
                Matcher matcher = Pattern.compile(regex).matcher(fileContent);
                //добавление с список обнаруженных
                if (matcher.find()){
                    String match = obj + "[pdf structural tag]";
                    if (!detected.contains(match)) {
                        detected.add(match);
                    }
                }
            }
            //анализ и сбор данных
            try (PDDocument document = Loader.loadPDF(fileBytes)){
                //поиск метаданных
                PDDocumentInformation info = document.getDocumentInformation();
                String data = String.join(" ", info.getTitle(), info.getAuthor(), info.getSubject(), info.getKeywords(), info.getCustomMetadataValue("Description"));
                //извлечение всего текст из файла
                PDFTextStripper s = new PDFTextStripper();
                String parse = s.getText(document);
                //поиска картинок(кьюар)
                StringBuilder qr = new StringBuilder();
                for (PDPage page : document.getPages()){
                    PDResources resources = page.getResources();
                    for (COSName x : resources.getXObjectNames()){
                        PDXObject xObject = resources.getXObject(x);
                        if (xObject instanceof PDImageXObject){
                            PDImageXObject image = (PDImageXObject) xObject;
                            //анализ картинки для расшифроки
                            try {
                                BufferedImage bImage = image.getImage();
                                LuminanceSource source = new BufferedImageLuminanceSource(bImage);
                                BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));
                                Result result = new MultiFormatReader().decode(bitmap);
                                String qrc = result.getText();
                                qr.append(" ").append(qrc);
                                detected.add("QR was read. The message of qr: " + qrc + ".");
                            } catch (Exception ignored){}
                        }
                    }
                }
                //объединение данных, скрытого текста и кьюара
                String combinedc = data + " " + parse + qr.toString();
                String combinedl = combinedc.toLowerCase();
                //поиск инъекций, поиск индекса инъекции для того чтобы посмотреть что скрыто в нем и вывод
                for (String payload : injection) {
                    int index = combinedl.indexOf(payload.toLowerCase());
                    if (index!=-1){
                        int start = Math.max(0, index-30);
                        int end = Math.min(combinedc.length(), index + payload.length() + 50);
                        String content = combinedc.substring(start, end).replace("\n", " ").replace("\r", " ").trim();
                        detected.add("Injection: " + payload + " [Content: ..." + content + "...]");
                    }
                }
            } catch (Exception e){
                detected.add("Invalid PDF structure");
            }
            if (detected.isEmpty()) {
                log.info("File [{}] checked. Status: safe", fileName);
                return new PdfCheckResponce(fileName, true, "No unsafe objects detected", detected, null);
            } else {
                log.warn("File [{}] Checked. Status: suspicious. Threats found: {}", fileName, detected.size());
                saveSuspiciousFile(fileBytes, fileName, suspicious_dir);
                byte[] cleanBytes = sanitizePdf(fileBytes);
                String cleanFileNames = "clean_" + System.currentTimeMillis() + "_" + fileName;
                saveSuspiciousFile(cleanBytes, cleanFileNames, clean_dir);
                String downloadUrl = "http://localhost:8080/api/download/" + cleanFileNames;
                return new PdfCheckResponce(fileName, false, "Potentially unsafe objects have been detected", detected, downloadUrl);
            }
        } catch (IOException e) {
            detected.add("File_Read_Error");
            return new PdfCheckResponce(fileName, false, "Error in reading the file", detected, null);
        }
    }
    public byte[] sanitizePdf(byte[] inputBytes) throws IOException{
        try (PDDocument document = Loader.loadPDF(inputBytes)){
            document.getDocumentCatalog().setOpenAction(null);
            document.getDocumentCatalog().getCOSObject().removeItem(COSName.AA);
            document.getDocumentCatalog().getCOSObject().removeItem(COSName.JS);
            document.setDocumentInformation(new PDDocumentInformation());
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            document.save(baos);
            return baos.toByteArray();
        }
    }
    //метод для сохранения зараженных файлов
    private void saveSuspiciousFile(byte[] fileBytes, String fileName, String dir){
        try {
            Path dirPath = Paths.get(dir);
            if (!Files.exists(dirPath)){
                Files.createDirectories(dirPath);
            }
            Path filePath = dirPath.resolve(fileName);
            Files.write(filePath, fileBytes);
        } catch (IOException e ){
            System.out.println("Error when suspicious file was saving: " + e.getMessage());
        }
    }
}
