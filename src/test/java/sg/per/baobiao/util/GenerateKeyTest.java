package sg.per.baobiao.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.InvalidParameterException;
import java.util.Base64;
import java.util.stream.Stream;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import sg.per.baobiao.junit.ext.TestLifecycleLoggerInterface;

@ExtendWith(sg.per.baobiao.junit.ext.TimingExtension.class)
public class GenerateKeyTest implements TestLifecycleLoggerInterface
{
    @TempDir
    public static Path TEMP_DIR;
    
    @DisplayName("Generate AES Key Positive")
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

    
    @DisplayName("Generate AES Key Negative")
    @ParameterizedTest
    @MethodSource("getArgs_testGenerateAesKeyNegative")
    public void testGenerateAesKeyNegative(int keyLength, String keyFile) throws IOException, GeneralSecurityException
    {
        Path keyFileTestLoc = TEMP_DIR.resolve(keyFile);
        Exception exception = Assertions.assertThrows(InvalidParameterException.class, () ->
            GenerateKey.generateAesKey(keyFileTestLoc, keyLength));
        Assertions.assertEquals("Wrong keysize: must be equal to 128, 192 or 256", exception.getMessage(), "Exception message must match.");
    }

    private static Stream<Arguments> getArgs_testGenerateAesKeyNegative()
    {
        return Stream.of(
                Arguments.of(0,     "testKeyFile.txt"),
                Arguments.of(127,   "testKeyFile.txt"),
                Arguments.of(191,   "testKeyFile.txt"),
                Arguments.of(512,   "testKeyFile.txt")
                );
    }

    
    @DisplayName("Generate AES Key Negative - Wrong key file")
    @ParameterizedTest
    @EmptySource
    public void testGenerateAesKeyNegativeWrongKeyFile(String keyFile) throws IOException, GeneralSecurityException
    {
        Path keyFileTestLoc = TEMP_DIR.resolve(keyFile);
        Assertions.assertThrows(AccessDeniedException.class, () ->
            GenerateKey.generateAesKey(keyFileTestLoc, 128));
    }

    
    @Test
    public void testConstructorGenerateKey() throws Exception
    {
        Constructor<GenerateKey> cnt = GenerateKey.class.getDeclaredConstructor();
        cnt.setAccessible(true);
        Exception exception = Assertions.assertThrows(InvocationTargetException.class, () -> cnt.newInstance());
        Assertions.assertEquals("GenerateKey is a utility class.", exception.getCause().getMessage(), "Exception message must match.");
    }

}
