package cn.ruannh.wechat;

import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Formatter;

/**
 * @author xiongxx
 * @date 2023/8/22 09:12
 * @description
 */
public class Main {
    public static void main(String[] args) throws IOException {
        decryptDb("", "C:\\Users\\Username\\Documents\\WeChat Files\\wxid\\Msg\\Multi\\MSG0.db");
    }


    /**
     *
     * @param textKey 微信数据库秘钥
     * @param inDbPath 需要解密的数据库文件
     * @throws IOException
     */
    public static void decryptDb(String textKey, String inDbPath) throws IOException {
        Path filePath = FileSystems.getDefault().getPath(inDbPath);
        byte[] dbBuf = Files.readAllBytes(filePath);
        byte[] salt = new byte[16];
        System.arraycopy(dbBuf, 0, salt, 0, salt.length);
        byte[] mKey = hexStrToByteArray(textKey);
        PBEParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA1Digest());
        generator.init(mKey, salt, 64000);
        byte[] keyBytes = ((KeyParameter) generator.generateDerivedParameters(256)).getKey();
        int page = 1;
        int pTemp = 0;
        int pageLen = dbBuf.length;
        int offset = 16;
        byte[] result = new byte[4096];
        int loop = pageLen / 4096;

        System.out.println("数据库解密中...");

        while (page <= loop) {
            try {
                System.out.println(inDbPath + " 解密数据页:" + page + "/" + loop);

                Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
                SecretKeySpec decKey = new SecretKeySpec(keyBytes, "AES");
                byte[] ivByte = new byte[16];
                System.arraycopy(dbBuf, pTemp + 4048, ivByte, 0, ivByte.length);
                IvParameterSpec ivspec = new IvParameterSpec(ivByte);
                cipher.init(2, decKey, ivspec);
                byte[] dceBuffer = new byte[4048 - offset];
                System.arraycopy(dbBuf, pTemp + offset, dceBuffer, 0, dceBuffer.length);
                byte[] decSep = cipher.update(dceBuffer, 0, dceBuffer.length);
                String outPutFile = inDbPath + "_dec.db";
                if (page == 1) {
                    byte[] peHeader = "SQLite format 3".getBytes(StandardCharsets.UTF_8);
                    System.arraycopy(peHeader, 0, result, 0, peHeader.length);
                    System.arraycopy(new byte[1], 0, result, 16, 1);
                    if (Files.exists(Paths.get(outPutFile), new LinkOption[0])) {
                        Files.delete(Paths.get(outPutFile));
                    }
                }

                System.arraycopy(decSep, 0, result, offset, decSep.length);
                byte[] padding = new byte[48];
                System.arraycopy(dbBuf, pTemp + 4096 - 48, padding, 0, 48);
                FileOutputStream out = new FileOutputStream(outPutFile, true);
                System.arraycopy(padding, 0, result, result.length - 48, padding.length);
                out.write(result);
                out.close();
                offset = 0;
                pTemp += 4096;
                ++page;
            } catch (Exception e) {
                System.out.println("解密数据库失败," + e.getMessage());
            }
        }

    }

    public static byte[] hexStrToByteArray(String str) {
        if (str == null) {
            return null;
        } else if (str.length() == 0) {
            return new byte[0];
        } else {
            byte[] byteArray = new byte[str.length() / 2];

            for(int i = 0; i < byteArray.length; ++i) {
                String subStr = str.substring(i * 2, i * 2 + 2);
                byteArray[i] = (byte)Integer.parseInt(subStr, 16);
            }

            return byteArray;
        }
    }

}
