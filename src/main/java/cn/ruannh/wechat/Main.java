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
     * @param hexKey 微信数据库秘钥
     * @param inDbPath 需要解密的数据库文件
     * @throws IOException
     */
    public static void decryptDb(String hexKey, String inDbPath) throws IOException {
        Path filePath = FileSystems.getDefault().getPath(inDbPath);
        byte[] dbBuf = Files.readAllBytes(filePath);
        byte[] salt = new byte[16];
        System.arraycopy(dbBuf, 0, salt, 0, salt.length);
        byte[] macSalt = new byte[16];

        for(int i = 0; i < macSalt.length; ++i) {
            macSalt[i] = (byte)(salt[i] ^ 58);
        }
        byte[] mKey = hexStrToByteArray(hexKey);
        PBEParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA1Digest());
        generator.init(mKey, salt, 64000);
        byte[] keyBytes = ((KeyParameter)generator.generateDerivedParameters(256)).getKey();
        PBEParametersGenerator generatoorSha1 = new PKCS5S2ParametersGenerator(new SHA1Digest());
        generatoorSha1.init(keyBytes, macSalt, 2);
        byte[] ctxCode = ((KeyParameter)generatoorSha1.generateDerivedParameters(256)).getKey();
        int page = 1;
        int pTemp = 0;
        int pageLen = dbBuf.length;
        int offset = 16;
        byte[] result = new byte[4096];
        int loop = pageLen / 4096;
        int n = 1;
        int c = 1;
        byte[] hexNum;
        if (loop / 256 + 1 == 1) {
            hexNum = new byte[4];
        } else {
            hexNum = new byte[loop / 256 + 1];
        }

        int count;
        for(count = 0; count < hexNum.length; ++count) {
            hexNum[count] = 0;
        }

        System.out.println("数据库解密中...");

        while(page <= loop) {
            try {
                count = 4048 - offset + 16;
                byte[] buffer = new byte[count];
                System.out.println(inDbPath + " 解密数据页:" + page + "/" + loop);
                System.arraycopy(dbBuf, pTemp + offset, buffer, 0, count);
                SecretKeySpec signingKey = new SecretKeySpec(ctxCode, "HmacSHA1");
                Mac mac = Mac.getInstance("HmacSHA1");
                mac.init(signingKey);
                if (c == 256) {
                    hexNum[1] = (byte)n;
                    ++n;
                    c = 0;
                }

                hexNum[0] = (byte)c;
                mac.update(buffer, 0, count);
                mac.update(hexNum, 0, 4);
                String hashSum = byteArray2Hex(mac.doFinal());
                byte[] pageHash = new byte[20];
                System.arraycopy(dbBuf, pTemp + 4096 - 48 + 16, pageHash, 0, 20);
                //校验
//                if (!hashSum.equals(byteArray2Hex(pageHash))) {
//                    if (byteArray2Hex(pageHash).startsWith("0000")) {
//                        System.out.println("解密完成，数据页:" + page);
//                    } else {
//                        System.out.println(byteArray2Hex(pageHash));
//                        System.out.println("哈希值错误!");
//                    }
//
//                    return;
//                }

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
                ++c;
            } catch (Exception e) {
                System.out.println("解密数据库失败," + e.getMessage());
            }
        }

    }

    public static String byteArray2Hex(byte[] hash) {
        Formatter formatter = new Formatter();

        for(int i = 0; i < hash.length; ++i) {
            byte b = hash[i];
            formatter.format("%02x", b);
        }

        return formatter.toString();
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
