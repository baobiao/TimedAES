package sg.per.baobiao.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.InvalidParameterException;
import java.util.Base64;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import sg.per.baobiao.junit.ext.TestLifecycleLoggerInterface;

@ExtendWith(sg.per.baobiao.junit.ext.TimingExtension.class)
public class GenerateKeyTest implements TestLifecycleLoggerInterface
{
    @TempDir
    public static Path TEMP_DIR;
    
    @ParameterizedTest
    @ValueSource(ints = { 128, 192, 256 })
    public void testGenerateAesKeyPositive(int keyLength) throws IOException, GeneralSecurityException
    {
        Path keyFileTestLoc = TEMP_DIR.resolve("tempKeyFile.txt");
        GenerateKey.generateAesKey(keyFileTestLoc, keyLength);
        try (BufferedReader reader = Files.newBufferedReader(keyFileTestLoc, StandardCharsets.UTF_8))
        {
            String keyString = reader.readLine();
            byte[] keyBytes = Base64.getDecoder().decode(keyString);
            Assertions.assertEquals((keyLength/8), keyBytes.length, "Generated key must be of correct length.");
        }
    }

    @ParameterizedTest
    @ValueSource(ints = { 0, 127, 191, 512 })
    public void testGenerateAesKeyNegative(int keyLength) throws IOException, GeneralSecurityException
    {
        Path keyFileTestLoc = TEMP_DIR.resolve("tempKeyFile.txt");
        Exception exception = Assertions.assertThrows(InvalidParameterException.class, () ->
            GenerateKey.generateAesKey(keyFileTestLoc, keyLength));
        Assertions.assertEquals("Wrong keysize: must be equal to 128, 192 or 256", exception.getMessage(), "Exception message must match.");
    }

    
}
