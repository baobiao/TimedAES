package sg.per.baobiao.util;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.time.LocalDateTime;
import java.util.Random;
import java.util.stream.Stream;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullSource;

import sg.per.baobiao.junit.ext.TestLifecycleLoggerInterface;

@ExtendWith(sg.per.baobiao.junit.ext.TimingExtension.class)
public class EncryptDecryptTest implements TestLifecycleLoggerInterface
{
    @TempDir
    public static Path TEMP_DIR;
    
    
    @DisplayName("Encrypt-Descrpt Test Positive")
    @ParameterizedTest
    @MethodSource("getArgs_testEncryptDecrypt")
    public void testEncryptDecrypt(int keyLength, Encryption.AllowByUOM uom, int val) throws IOException, GeneralSecurityException
    {
        Path keyFileTestLoc = TEMP_DIR.resolve("tempKeyFile.txt");
        GenerateKey.generateAesKey(keyFileTestLoc, keyLength);
        String testInput = "Test123";
        String encryptedString = Encryption.encryptWithAES(testInput, keyFileTestLoc, uom, val);
        try
        {
            String decryptedString = Decryption.decryptWithAES(encryptedString, keyFileTestLoc);
            Assertions.assertEquals(testInput, decryptedString, "Decrypted string must match original test input.");
        }
        catch(IllegalStateException e)
        {
            Assertions.assertEquals("Decryption date-time mismatch.", e.getMessage(), "Decryption date-time message must match.");
        }
    }
    private static Stream<Arguments> getArgs_testEncryptDecrypt()
    {
        LocalDateTime dateTime = LocalDateTime.now();
        // Integer, Enumeration, Random Integer.
        Random rand = new Random();
        return Stream.of(
                Arguments.of(128, Encryption.AllowByUOM.DAYOFMONTH, rand.nextInt(31)    ),
                Arguments.of(192, Encryption.AllowByUOM.DAYOFMONTH, rand.nextInt(31)    ),
                Arguments.of(256, Encryption.AllowByUOM.DAYOFMONTH, rand.nextInt(31)    ),
                Arguments.of(128, Encryption.AllowByUOM.DAYOFWEEK,  rand.nextInt(7)     ),
                Arguments.of(192, Encryption.AllowByUOM.DAYOFWEEK,  rand.nextInt(7)     ),
                Arguments.of(256, Encryption.AllowByUOM.DAYOFWEEK,  rand.nextInt(7)     ),
                Arguments.of(128, Encryption.AllowByUOM.MONTH,      rand.nextInt(12)    ),
                Arguments.of(192, Encryption.AllowByUOM.MONTH,      rand.nextInt(12)    ),
                Arguments.of(256, Encryption.AllowByUOM.MONTH,      rand.nextInt(12)    ),
                Arguments.of(128, Encryption.AllowByUOM.HOUR,       rand.nextInt(24)    ),
                Arguments.of(192, Encryption.AllowByUOM.HOUR,       rand.nextInt(24)    ),
                Arguments.of(256, Encryption.AllowByUOM.HOUR,       rand.nextInt(24)    ),
                Arguments.of(256, Encryption.AllowByUOM.DAYOFMONTH, dateTime.getDayOfMonth()-1),
                Arguments.of(256, Encryption.AllowByUOM.DAYOFWEEK,  dateTime.getDayOfWeek().getValue()-1),
                Arguments.of(256, Encryption.AllowByUOM.MONTH,      dateTime.getMonthValue()-1),
                Arguments.of(256, Encryption.AllowByUOM.HOUR,       dateTime.getHour()-1)
                );
    }

    
    @DisplayName("Encrypt-Descrpt Test Negative - Value out of bounds.")
    @ParameterizedTest
    @MethodSource("getArgs_testEncryptDecryptNegativeValOutOfBounds")
    public void testEncryptDecryptNegativeValOutOfBounds(Encryption.AllowByUOM uom, int val) throws IOException, GeneralSecurityException
    {
        Path keyFileTestLoc = TEMP_DIR.resolve("tempKeyFile.txt");
        GenerateKey.generateAesKey(keyFileTestLoc, 128);
        String testInput = "Test123";
        Exception exception = Assertions.assertThrows(IllegalArgumentException.class, () ->
            Encryption.encryptWithAES(testInput, keyFileTestLoc, uom, val));
        Assertions.assertEquals("Permissible values out-of-bounds.", exception.getMessage(), "Exception message must match.");
    }
    private static Stream<Arguments> getArgs_testEncryptDecryptNegativeValOutOfBounds()
    {
        return Stream.of(
                Arguments.of(Encryption.AllowByUOM.DAYOFMONTH, 100),
                Arguments.of(Encryption.AllowByUOM.DAYOFWEEK,  100),
                Arguments.of(Encryption.AllowByUOM.MONTH,      100),
                Arguments.of(Encryption.AllowByUOM.HOUR,       100),
                Arguments.of(Encryption.AllowByUOM.DAYOFMONTH, -1),
                Arguments.of(Encryption.AllowByUOM.DAYOFWEEK,  -1),
                Arguments.of(Encryption.AllowByUOM.MONTH,      -1),
                Arguments.of(Encryption.AllowByUOM.HOUR,       -1)
                );
    }

    
    @DisplayName("Encrypt-Descrpt Test Negative - Bad Input String.")
    @ParameterizedTest
    @NullSource
    public void testEncryptDecryptNegativeBadInputString(String testInput) throws IOException, GeneralSecurityException
    {
        Path keyFileTestLoc = TEMP_DIR.resolve("tempKeyFile.txt");
        GenerateKey.generateAesKey(keyFileTestLoc, 128);
        Assertions.assertThrows(NullPointerException.class, () ->
            Encryption.encryptWithAES(testInput, keyFileTestLoc, Encryption.AllowByUOM.DAYOFMONTH, 2));
    }

    @DisplayName("Encrypt-Descrpt Test Negative - Bad UOM.")
    @ParameterizedTest
    @NullSource
    public void testEncryptDecryptNegativeBadUOM(Encryption.AllowByUOM uom) throws IOException, GeneralSecurityException
    {
        Path keyFileTestLoc = TEMP_DIR.resolve("tempKeyFile.txt");
        String testInput = "Test123";
        GenerateKey.generateAesKey(keyFileTestLoc, 128);
        Assertions.assertThrows(NullPointerException.class, () ->
            Encryption.encryptWithAES(testInput, keyFileTestLoc, uom, 2));
    }
    
    
    @Test
    public void testConstructorEncryption() throws Exception
    {
        Constructor<Encryption> cnt = Encryption.class.getDeclaredConstructor();
        cnt.setAccessible(true);
        Exception exception = Assertions.assertThrows(InvocationTargetException.class, () -> cnt.newInstance());
        Assertions.assertEquals("Encryption is a utility class.", exception.getCause().getMessage(), "Exception message must match.");
    }

    
    @Test
    public void testConstructorDecryption() throws Exception
    {
        Constructor<Decryption> cnt = Decryption.class.getDeclaredConstructor();
        cnt.setAccessible(true);
        Exception exception = Assertions.assertThrows(InvocationTargetException.class, () -> cnt.newInstance());
        Assertions.assertEquals("Decryption is a utility class.", exception.getCause().getMessage(), "Exception message must match.");
    }
    
}
