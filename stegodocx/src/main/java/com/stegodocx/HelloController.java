package com.stegodocx;

import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.scene.control.TextField;

import java.io.*;
import java.util.zip.*;
import java.nio.ByteBuffer;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class HelloController {

    @FXML
    private TextField docxTextField;
    @FXML
    private TextField jpegTextField;

    @FXML
    private TextField keyTextField;

    @FXML
    private TextField docxTextResult;

    @FXML
    private TextField jpegResultTextField;

    private Stage docxStage;

    private Stage jpgStage;

    private static final int docxBase64LenBuffer = 128;
    private static final int signatureFF = 0xFF;
    private static final int signatureD9 = 0xD9;

    private static final String AES_ALGORITHM = "AES";
    private static final String AES_CIPHER_MODE = "AES/CBC/PKCS5Padding";
    private String secretKey = "1234512345123456"; // 16, 24, or 32 bytes

    private static final String INIT_VECTOR = "0123456789abcdef"; // 16 bytes

    private void setSecretKey(String str) {
        this.secretKey = str;
    }
    private byte[] getSecretKey() throws UnsupportedEncodingException {
        return this.secretKey.getBytes("UTF-8");
    }

    @FXML
    protected void selOpenDocxFile() {
        FileChooser fileChooser = new FileChooser();

        fileChooser.getExtensionFilters().addAll((new FileChooser.ExtensionFilter("문서파일 : Docx 파일", "*.docx")));
        File file = fileChooser.showOpenDialog(docxStage);

        if (file != null) {
            docxTextField.setText(file.getPath());
        } else {
            docxTextField.setText("Select Button Click~");
        }

    }


    @FXML
    protected void selOpenJpgFile() {
        FileChooser fileChooser = new FileChooser();

        fileChooser.getExtensionFilters().addAll((new FileChooser.ExtensionFilter("JPEG파일 : jpg 파일", "*.jpg")));
        File file = fileChooser.showOpenDialog(jpgStage);

        if (file != null) {
            jpegTextField.setText(file.getPath());
        } else {
            jpegTextField.setText("Select Button Click~");
        }
    }



    // JPEG 데이터의 FF D9 시그니처 바로 전에 데이터를 삽입하는 메서드
    private static byte[] insertData(byte[] jpegData, byte[] dataToInsert) {
        // FF D9 시그니처의 위치를 찾음
        int signatureIndex = findSignatureIndex(jpegData);

        int dataToInsertLen = dataToInsert.length;

        // FF D9 시그니처 전까지의 데이터와 삽입할 데이터를 병합하여 새로운 byte 배열 생성
        byte[] modifiedData = new byte[jpegData.length + dataToInsertLen];
        System.out.println("dataToInsert.length");
        System.out.println(dataToInsert.length);

        System.arraycopy(jpegData, 0, modifiedData, 0, signatureIndex);

        System.arraycopy(dataToInsert, 0, modifiedData, signatureIndex, dataToInsert.length);

        System.arraycopy(jpegData, signatureIndex, modifiedData, signatureIndex + dataToInsert.length, jpegData.length - signatureIndex);

        return modifiedData;
    }


    // JPEG 데이터의 FF D9 시그니처 바로 전에 데이터를 삽입하는 메서드
    private static byte[] insertDataAddLen(byte[] jpegData, byte[] docxData) {
        // FF D9 시그니처의 위치를 찾음
        int signatureIndex = findSignatureIndex(jpegData);

        int docxDataLen = docxData.length; System.out.println("docxDataLen.length");System.out.println(docxData.length);
        byte[] lenByte = intToBytesUsingByteBuffer(docxDataLen);System.out.println("dataToInsertLen byte  value: " + lenByte);

        //원본 docx 데이터에 1024바이트(원본docx데이타길이)를 더해준다.
        byte[] docxMergedData = new byte[docxDataLen + docxBase64LenBuffer];
        System.arraycopy(docxData, 0, docxMergedData, 0, docxDataLen);
        System.arraycopy(lenByte, 0, docxMergedData, docxDataLen, lenByte.length);
        int docxMergedDataLen = docxMergedData.length;

        //System.arraycopy(src, srcPos, dest, destPos, length)
        // FF D9 시그니처 전까지의 데이터와 삽입할 데이터를 병합하여 새로운 byte 배열 생성
        byte[] modifiedData = new byte[jpegData.length + docxMergedData.length];

        System.arraycopy(jpegData, 0, modifiedData, 0, signatureIndex);

        System.arraycopy(docxMergedData, 0, modifiedData, signatureIndex, docxMergedDataLen);

        System.arraycopy(jpegData, signatureIndex, modifiedData, signatureIndex + docxMergedDataLen, jpegData.length - signatureIndex);

        return modifiedData;
    }

    public static byte[] intToBytesUsingByteBuffer(int value) {
        ByteBuffer buffer = ByteBuffer.allocate(docxBase64LenBuffer); // 1024바이트 할당
        buffer.putInt(value);

        return buffer.array();
    }

    // JPEG 데이터에서 FF D9 시그니처의 위치를 찾는 메서드
    private static int findSignatureIndex(byte[] jpegData) {
        for (int i = 0; i < jpegData.length - 1; i++) {
            if ((jpegData[i] & signatureFF) == signatureFF && (jpegData[i + 1] & signatureFF) == signatureD9) {
                return i;
            }
        }
        return -1; // 시그니처를 찾지 못한 경우
    }
    public static String getFileNameWithoutExtension(String fileName) {
        int dotIndex = fileName.lastIndexOf('.');
        if (dotIndex != -1 && dotIndex > 0) {
            return fileName.substring(0, dotIndex);
        }
        return fileName;
    }

    //파일의 확장자를 리턴
    public static String getFileExtension(String fileName) {
        int dotIndex = fileName.lastIndexOf('.');
        if (dotIndex != -1 && dotIndex < fileName.length() - 1) {
            return fileName.substring(dotIndex + 1);
        }
        return "";
    }

    //결과파일 export 파일명
    private static String getResultFile(String jpegTxt) {
        String jpgFileResult = getFileNameWithoutExtension(jpegTxt) +"_result." + getFileExtension(jpegTxt);
        return jpgFileResult;
    }

    // 문자열을 AES로 암호화하는 메서드
    public String encryptAES(byte[] data) {
        try {
            byte[] keyBytes = this.getSecretKey();

            byte[] ivBytes = INIT_VECTOR.getBytes("UTF-8");
            System.out.println("====");
            System.out.println(keyBytes.length);
            System.out.println("====");

            SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, AES_ALGORITHM);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

            Cipher cipher = Cipher.getInstance(AES_CIPHER_MODE);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

            //1. 암호화
            byte[] encryptedBytes = cipher.doFinal(data);

            //2. base64 encode 처리
            return Base64.getEncoder().encodeToString(encryptedBytes);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    // 문자열을 AES로 복호화하는 메서드
    public byte[] decryptAES(byte[] data) {
        try {
            byte[] keyBytes = this.getSecretKey();
            byte[] ivBytes = INIT_VECTOR.getBytes("UTF-8");
            System.out.println("====");
            System.out.println(keyBytes.length);
            System.out.println("====");

            SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, AES_ALGORITHM);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

            Cipher cipher = Cipher.getInstance(AES_CIPHER_MODE);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

            //2. 암호화 할때 base64 encode 처리했으니 다시 decode 처리해아함.
            byte[] base64DecodeData = Base64.getDecoder().decode(data);

            //1. base64디코드 처리된 값을 복호화 처리
            byte[] decryptedBytes = cipher.doFinal(base64DecodeData);

            return  decryptedBytes;

        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    // FFD9 이전 docxBase64Len 할당된 길이만큼 리턴
    private static byte[] getReadDocxBase64Len (FileInputStream fis) throws IOException {
        int bytesRead;
        int byteRead;
        int count = 0;
        byte[] buffer = new byte[docxBase64LenBuffer];

        while ((byteRead = fis.read()) != -1) {
            if (byteRead == signatureFF && count > 0) {
                int nextByte = fis.read();
                if (nextByte == signatureD9) {
                    break;
                }
            }

            buffer[count % docxBase64LenBuffer] = (byte) byteRead;
            count++;
        }
        System.out.println("Read " + count + " bytes before FF D9 signature:");
        for (int i = 0; i < count % docxBase64LenBuffer; i++) {
            System.out.print(buffer[i] + " ");
        }
        return buffer;
    }
    //특정 주소부터 읽기
    public static byte[] readBytesFromOffset(String filePath, int startOffset, int length) {
        byte[] data = new byte[length];

        try (FileInputStream fis = new FileInputStream(filePath)) {
            fis.skip(startOffset); // 지정된 offset 주소로 이동

            int bytesRead = fis.read(data, 0, length);
            if (bytesRead != length) {
                throw new IOException("Failed to read " + length + " bytes from offset " + startOffset);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return data;
    }


    // 스트림을 String으로
    public static StringBuilder convertStreamToString(InputStream inputStream) throws IOException {
        StringBuilder stringBuilder = new StringBuilder();
        int character;

        while ((character = inputStream.read()) != -1) {
            stringBuilder.append((char) character);
        }

        return stringBuilder;
    }

    public static byte[] filetoByteArray(String path) {
        byte[] data;
        try {
            InputStream input = new FileInputStream(path);
            int byteReads;
            ByteArrayOutputStream output = new ByteArrayOutputStream(1024);
            while ((byteReads = input.read()) != -1) {
                output.write(byteReads);
            }
            data = output.toByteArray();
            output.close();
            input.close();
            return data;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    /**
     * Method to get byte array data from given InputStream
     *
     * @param is InputStream to read
     * @return Stream data as byte array
     */
    public static byte[] streamToBytes(InputStream is) throws IOException {
        final int BUF_SIZE = 512;
        int bytesRead;
        byte[] data;

        try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            data = new byte[BUF_SIZE];

            while ((bytesRead = is.read(data, 0, BUF_SIZE)) >= 0) {
                bos.write(data, 0, bytesRead);
            }

            return bos.toByteArray();
        }
    }

    //docx 를 zip 으로 압축한다.
    public byte[] compressDocxToZip(String docxFilePath) throws IOException {
        byte[] msg = this.filetoByteArray(docxFilePath);
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             GZIPOutputStream zos = new GZIPOutputStream(bos)) {
            zos.write(msg);
            zos.finish();
            zos.flush();
            return bos.toByteArray();
        }
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder stringBuilder = new StringBuilder();
        for (byte b : bytes) {
            stringBuilder.append(String.format("%02X", b));
        }
        return stringBuilder.toString();
    }

    public static String identifyImageFormat(byte[] headerBytes) {
        String headerHex = bytesToHex(headerBytes);

        if (headerHex.startsWith("89504E47")) {
            return "PNG";
        } else if (headerHex.startsWith("47494638")) {
            return "GIF";
        } else if (headerHex.startsWith("424D")) {
            return "BMP";
        } else if (headerHex.startsWith("FFD8FFE000104A464946")) {
            return "JPEG";
        } else if (headerHex.startsWith("FFD8FFE800104A464946")) {
            return "JPEG";
        } else if (headerHex.startsWith("FFD8FFE12FFE45786966")) {
            return "JPEG/EXIF I-Phone";
        } else if (headerHex.startsWith("49492A00")) {
            return "TIFF";
        } else if (headerHex.startsWith("4D4D002A")) {
            return "TIFF";
        } else {
            return "Unknown";
        }
    }

    //zip 으로 압축된 docx 를 다시 복구한다.
    public byte[] decompressZipToDocx(byte[] msg) throws IOException {
        //byte[] msg = this.filetoByteArray(zipFilePath);
        try (ByteArrayInputStream bis = new ByteArrayInputStream(msg);
             GZIPInputStream zis = new GZIPInputStream(bis)) {
            msg = this.streamToBytes(zis);
        }

        return msg;
    }

    @FXML
    protected void btnHidden() throws IOException {
        String docxTxt = docxTextField.getText();
        String jpegTxt = jpegTextField.getText();
        String encryptionKey = keyTextField.getText();
        //docxTxt = "C:\\Users\\websw\\OneDrive\\문서\\안티포렌식 과제 1-파일시그니처.docx";
        //jpegTxt = "C:\\Users\\websw\\OneDrive\\사진\\pian-grande.jpg";

        if ("".equals(docxTxt) || docxTxt.isEmpty()) {
            Alert alert = new Alert((Alert.AlertType.INFORMATION));
            alert.setTitle("ERROR");
            alert.setContentText("은닉할 Docx 문서를 선택해 주세요");
            alert.show();
        } else {
            if ("".equals(jpegTxt)|| jpegTxt == null || jpegTxt.isEmpty()) {
                Alert alert = new Alert((Alert.AlertType.INFORMATION));
                alert.setTitle("ERROR");
                alert.setContentText("JPEG 파일을 선택해야 합니다");
                alert.show();
            }
            System.out.println("encryptionKey {}"+ encryptionKey);

            if ("".equals(encryptionKey) || encryptionKey == null || encryptionKey.isEmpty()) {
                Alert alert = new Alert((Alert.AlertType.INFORMATION));
                alert.setTitle("ERROR");
                alert.setContentText("암호는 16자리를 입력해야 합니다");
                alert.show();
            }

            if (encryptionKey.length() != 16) {
                Alert alert = new Alert((Alert.AlertType.INFORMATION));
                alert.setTitle("ERROR");
                alert.setContentText("암호는 16자리를 입력해야 합니다");
                alert.show();
            } else {
                //암호 셋팅
                this.setSecretKey(encryptionKey);

                //docx 파일을 읽어들인다.
                //FileInputStream fis = new FileInputStream(docxTxt);
                //StringBuilder docxContent = readDocxWithStyle(fis);

                //1. docx 파일을 읽어서 zip 압축한다.
                byte[] docxContent = this.compressDocxToZip(docxTxt);

                // 2. 압축한 byte 를 AES로 암호화
                String docxBase64Bytes = encryptAES(docxContent);

                //String docxBase64 = Base64.getEncoder().encodeToString(docxContent.getBytes(StandardCharsets.UTF_8));
                // Base64 문자열을 byte 배열로 변환

                int docxLen = docxBase64Bytes.length();

                //헤더 byte 를 체크
                FileInputStream inputStream = new FileInputStream(jpegTxt);
                byte[] headerBytes = new byte[10];
                int bytesRead = inputStream.read(headerBytes);

                String header = identifyImageFormat(headerBytes);
                if (bytesRead >= 4 && !("JPEG".equals(header) || "JPEG".equals(header))) {
                    System.out.println("JPEG Header: " + bytesToHex(headerBytes));
                    Alert alert = new Alert((Alert.AlertType.INFORMATION));
                    alert.setTitle("ERROR");
                    alert.setContentText(header+ "입니다. JPEG파일의 형식이어야 합니다");
                    alert.show();

                } else {


                    // JPEG 파일을 읽기 위한 FileInputStream 생성
                    FileInputStream fileInputStream = new FileInputStream(jpegTxt);

                    // JPEG 파일의 데이터를 ByteArrayOutputStream에 복사
                    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                    byte[] buffer = new byte[1024];

                    while ((bytesRead = fileInputStream.read(buffer)) != -1) {
                        byteArrayOutputStream.write(buffer, 0, bytesRead);
                    }

                    // JPEG 파일 데이터를 byte 배열로 가져옴
                    byte[] jpegData = byteArrayOutputStream.toByteArray();
                    System.out.println("====jpegData====");
                    System.out.println(jpegData.toString());

                    // 변환한 Base64 데이터를 JPEG 데이터의 FF D9 시그니처 바로 전에, content << content length << FFD9 삽입
                    //byte[] modifiedJpegData = insertData(jpegData, docxBase64Bytes);
                    byte[] modifiedJpegData = insertDataAddLen(jpegData, docxBase64Bytes.getBytes());

                    System.out.println("====modifiedJpegData====");
                    System.out.println(modifiedJpegData.toString());

                    // 수정된 데이터로 JPEG 파일을 생성
                    String jpgFileResult = getResultFile(jpegTxt);
                    System.out.println("===jpgFileResult===");
                    System.out.println(jpgFileResult);
                    FileOutputStream fileOutputStream = new FileOutputStream(jpgFileResult);
                    fileOutputStream.write(modifiedJpegData);

                    // 스트림 닫기
                    fileInputStream.close();
                    fileOutputStream.close();

                    docxTextResult.setText("성공적으로 실행헀습니다.");
                    System.out.println("Base64 data inserted successfully.");
                    jpegResultTextField.setText(jpgFileResult);
                }
            }
        }

    }


    @FXML
    protected void btnFind() throws IOException {
        String jpegTxt = jpegResultTextField.getText();
        String docxTxt = docxTextField.getText();
        String encryptionKey = keyTextField.getText();
        //jpegTxt = "C:\\Users\\websw\\OneDrive\\사진\\pian-grande_result.jpg";
        //docxTxt = "C:\\Users\\websw\\OneDrive\\문서\\안티포렌식 과제 1-파일시그니처_recovery.docx";

        if ("".equals(jpegTxt)|| jpegTxt.isEmpty()) {
            Alert alert = new Alert((Alert.AlertType.INFORMATION));
            alert.setTitle("Information");
            alert.setContentText("JPEG 이미지 파일를 선택해 주세요");
            alert.show();
        } else {

            System.out.println("encryptionKey {}"+ encryptionKey);
            if ("".equals(encryptionKey)|| encryptionKey == null|| encryptionKey.isEmpty()) {
                Alert alert = new Alert((Alert.AlertType.INFORMATION));
                alert.setTitle("Information");
                alert.setContentText("암호는 16자리를 입력해야 합니다");
                alert.show();
            }

            if (encryptionKey.length() != 16) {
                Alert alert = new Alert((Alert.AlertType.INFORMATION));
                alert.setTitle("Information");
                alert.setContentText("암호는 16자리를 입력해야 합니다");
                alert.show();
            } else {
                //암호 셋팅
                this.setSecretKey(encryptionKey);

                // JPEG 파일을 읽기 위한 FileInputStream 생성
                //FileInputStream fileInputStream = new FileInputStream(jpegTxt);
                //byte[] jpegData = fileInputStream.readAllBytes();

                File file = new File(jpegTxt);
                byte[] jpegData = new byte[(int) file.length()];
                FileInputStream fis = new FileInputStream(file);
                fis.read(jpegData);
                fis.close();


                int ffd9Pos = findSignatureIndex(jpegData);
                System.out.println("===ffd9Pos===");
                System.out.println(ffd9Pos);

                int docxBase64LenStart = ffd9Pos - docxBase64LenBuffer;
                byte[] docxBas64LenByte = readBytesFromOffset(jpegTxt, docxBase64LenStart, docxBase64LenBuffer);

                //base64로 변환된 docx 파일 길이 읽기
                ByteBuffer buffer = ByteBuffer.wrap(docxBas64LenByte);
                int docxBas64Len = buffer.getInt();
                System.out.println("===docxBas64Len===");
                System.out.println(docxBas64Len);

                //docxBase64 스트림 읽기
                //read 시작위치 가져오기(파일 길이 만큼)
                int docxStartLen = docxBase64LenStart - docxBas64Len;
                byte[] docxByte = readBytesFromOffset(jpegTxt, docxStartLen, docxBas64Len);

                //2. AES로 복호화
                byte[] decryptedContent = decryptAES(docxByte);

                //1. zip 압축 해제하고 파일로 저장한다
                byte[] decomPressDocx = decompressZipToDocx(decryptedContent);

                // 수정된 데이터로 DOCX 파일을 생성
                String docxFileResult = getResultFile(docxTxt);
                System.out.println("===docxFileResult===");
                FileOutputStream fileOutputStream = new FileOutputStream(docxFileResult);
                fileOutputStream.write(decomPressDocx);
                // 스트림 닫기
                fileOutputStream.close();

                docxTextResult.setText(docxFileResult + ",  성공적으로 실행 했습니다.");
                System.out.println("docx writed successfully.");
            }
        }
    }

}