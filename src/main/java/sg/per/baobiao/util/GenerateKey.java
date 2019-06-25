package sg.per.baobiao.util;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class GenerateKey
{
    private GenerateKey()
    {
        throw new IllegalStateException("GenerateKey is a utility class.");
    }
    
    public static void generateAesKey(Path keyFile, int keyLength) throws IOException, GeneralSecurityException
    {
        SecureRandom random = SecureRandom.getInstanceStrong();
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keyLength, random);
        SecretKey key = keyGen.generateKey();
        String aesKey = Base64.getEncoder().encodeToString(key.getEncoded());
        try (BufferedWriter output = Files.newBufferedWriter(keyFile, StandardCharsets.UTF_8))
        {
            output.write(aesKey);
        }
    }
}
