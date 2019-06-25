package sg.per.baobiao.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Decryption
{
    private static final int    AESGCM_TAG_LENGTH       =   16; // By specification the authentication tag length is 128 (16x8) bits.
    private static final int    AESGCM_NONCE_LENGTH     =   12; // Initialization Vector of 12 bytes for Galois/Counter Mode (GCM).
                                                                // Must be 12 bytes.
                                                                // https://en.wikipedia.org/wiki/Galois/counter_mode

    private Decryption()
    {
        throw new IllegalStateException("Decryption is a utility class.");
    }
    
    /**
     * Throws IllegalStateException if the string cannot be decrypted at the current date time.
     * @param encryptedString               String to be decrypted.
     * @param secretKeyFile                 Path to AES secret key file.
     * @return                              Plain text string.
     * @throws GeneralSecurityException     Algorithm not found or other encryption issues.
     * @throws IOException                  Secret key file cannot be found.
     */
    public static String decryptWithAES(String encryptedString, Path secretKeyFile) throws IOException, GeneralSecurityException
    {
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedString); // Translate encrypted string in Base64 back into bytes.
        byte[] secretKeyBytes = null;
        try (BufferedReader reader = Files.newBufferedReader(secretKeyFile, StandardCharsets.UTF_8))
        {
            String keyString = reader.readLine();
            secretKeyBytes = Base64.getDecoder().decode(keyString);
        }
        byte[] initVector = Arrays.copyOfRange(encryptedBytes, 0, AESGCM_NONCE_LENGTH); // Fetch the Initialization Vector from encrypted bytes.
                                                                                        // First 12 bytes as per the GCM design.
        LocalDateTime dateTime = LocalDateTime.now();
        // First version of design where we put the Date-Time metadata in the least significant 2 bytes.
        int val = initVector[AESGCM_NONCE_LENGTH-1] & 0xff;
        boolean dateMismatch = false;
        switch(initVector[AESGCM_NONCE_LENGTH-2] & 0xff)
        {
        case 0: // MONTH
            if(val != (dateTime.getMonthValue()-1)) dateMismatch = true;
            break;
        case 1: // DAYOFMONTH
            if(val != (dateTime.getDayOfMonth()-1)) dateMismatch = true;
            break;
        case 2: // DAYOFWEEK
            if(val != (dateTime.getDayOfWeek().getValue()-1)) dateMismatch = true;
            break;
        case 3: // HOUR
            if(val != (dateTime.getHour()-1)) dateMismatch = true;
            break;
        default:
            // Do nothing.
        }
        if(dateMismatch)
        {
            throw new IllegalStateException("Decryption date-time mismatch.");
        }
        
        GCMParameterSpec gcmSpec = new GCMParameterSpec(AESGCM_TAG_LENGTH * Byte.SIZE, initVector); // We use 128 bits authentication tag size.
        SecretKeySpec secretKey = new SecretKeySpec(secretKeyBytes, "AES"); // Construct the Secret Key Spec from what is read in the key file. 
        Cipher decryptCipher = Cipher.getInstance("AES/GCM/NoPadding"); // Fetch cipher suite of AES.
        decryptCipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec); // Setup cipher.
        byte[] decryptedBytes = decryptCipher.doFinal(encryptedBytes, initVector.length, (encryptedBytes.length - initVector.length));

        return new String(decryptedBytes);
    }
    
}
