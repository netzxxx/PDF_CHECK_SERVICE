package com.nietkali.restapi;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;
public class PdfCheckResponce {
    private String fileName;
    @com.fasterxml.jackson.annotation.JsonProperty("isSafe")
    private boolean isSafe;
    private String result;
    private List<String> detectedObjects;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String downloadUrl;
    //конструктор
    public PdfCheckResponce(String fileName, boolean isSafe, String result, List<String> detectedObjects, String downloadUrl){
        this.fileName=fileName;
        this.isSafe=isSafe;
        this.result=result;
        this.detectedObjects=detectedObjects;
        this.downloadUrl=downloadUrl;
    }
    //чтение значений переменных и сбор в json
    public String getFileName() {return fileName;}
    @com.fasterxml.jackson.annotation.JsonIgnore //игнорирование дупликатов в ответе
    public boolean isSafe() {return isSafe;}
    public String getResult() {return result;}
    public List<String> getDetectedObjects() {return detectedObjects;}
    public String getDownloadUrl() {return downloadUrl;}
}
