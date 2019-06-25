package sg.per.baobiao.util;

import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.time.LocalDateTime;
import java.util.Random;
import java.util.stream.Stream;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
//import org.junit.jupiter.params.provider.ValueSource;

import sg.per.baobiao.junit.ext.TestLifecycleLoggerInterface;

@ExtendWith(sg.per.baobiao.junit.ext.TimingExtension.class)
public class EncryptDecryptTest implements TestLifecycleLoggerInterface
{
    @TempDir
    public static Path TEMP_DIR;
    
    @ParameterizedTest
    @MethodSource("getArgs_encryptDecryptTest")
    public void encryptDecryptTest(int keyLength, Encryption.AllowByUOM uom, int val) throws IOException, GeneralSecurityException
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
    
    private static Stream<Arguments> getArgs_encryptDecryptTest()
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
    
}
