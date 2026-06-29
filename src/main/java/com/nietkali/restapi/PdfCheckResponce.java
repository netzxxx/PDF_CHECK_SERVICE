package com.nietkali.restapi;
import java.util.List;
public class PdfCheckResponce {
    private String fileName;
    @com.fasterxml.jackson.annotation.JsonProperty("isSafe")
    private boolean isSafe;
    private String result;
    private List<String> detectedObjects;
    //конструктор
    public PdfCheckResponce(String fileName, boolean isSafe, String result, List<String> detectedObjects){
        this.fileName=fileName;
        this.isSafe=isSafe;
        this.result=result;
        this.detectedObjects=detectedObjects;
    }
    //чтение значений переменных и сбор в json
    public String getFileName() {return fileName;}
    @com.fasterxml.jackson.annotation.JsonIgnore //игнорирование дупликатов в ответе
    public boolean isSafe() {return isSafe;}
    public String getResult() {return result;}
    public List<String> getDetectedObjects() {return detectedObjects;}
}
