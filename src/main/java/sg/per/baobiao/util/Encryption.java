package sg.per.baobiao.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Encryption
{
    public enum AllowByUOM
    {
        MONTH,      // '0'
        DAYOFMONTH, // '1'
        DAYOFWEEK,  // '2'
        HOUR;       // '3'
    }

    private static final int    AESGCM_TAG_LENGTH       =   16; // By specification the authentication tag length is 128 (16x8) bits.
    private static final int    AESGCM_NONCE_LENGTH     =   12; // Initialization Vector of 12 bytes for Galois/Counter Mode (GCM).
                                                                // Must be 12 bytes.
                                                                // https://en.wikipedia.org/wiki/Galois/counter_mode

    private Encryption()
    {
        throw new IllegalStateException("Encryption is a utility class.");
    }
    
    /**
     * Encrypts the Plain Text string to allow decryption during specific Allow By UOM and Allow By Value.
     * @param plainText                     String to be encrypted.
     * @param secretKeyFile                 Path to AES secret key file.
     * @param allowByUOM                    Refer to AllowByUOM enumeration.
     * @param allowByValue                  Allowed values based on UOM.
     * @return                              Encrypted value.
     * @throws GeneralSecurityException     Algorithm not found or other encryption issues.
     * @throws IOException                  Secret key file cannot be found.
     */
    public static String encryptWithAES(String plainText, Path secretKeyFile, Encryption.AllowByUOM allowByUOM, int allowByValue) 
            throws GeneralSecurityException, IOException
    {
        byte[] plainTextBytes = plainText.getBytes(StandardCharsets.UTF_8);
        byte[] secretKeyBytes = null;
        try (BufferedReader reader = Files.newBufferedReader(secretKeyFile, StandardCharsets.UTF_8))
        {
            String keyString = reader.readLine();
            secretKeyBytes = Base64.getDecoder().decode(keyString);
        }
        byte[] initVector = new byte[AESGCM_NONCE_LENGTH]; // Always remember that IV of GCM is 12 bytes.
        (new SecureRandom()).nextBytes(initVector);
        
        // First version of design is to overwrite the least significant 2 bytes of initVector (nonce) with the extra data.
        switch(allowByUOM)
        {
            case MONTH:
                initVector[AESGCM_NONCE_LENGTH-2] = (byte)0;
                break;
            case DAYOFMONTH:
                initVector[AESGCM_NONCE_LENGTH-2] = (byte)1;
                break;
            case DAYOFWEEK:
                initVector[AESGCM_NONCE_LENGTH-2] = (byte)2;
                break;
            case HOUR:
                initVector[AESGCM_NONCE_LENGTH-2] = (byte)3;
                break;
            default:
                // Do nothing
        }
        initVector[AESGCM_NONCE_LENGTH-1] = (byte)allowByValue;
        
        GCMParameterSpec gcmSpec = new GCMParameterSpec(AESGCM_TAG_LENGTH * Byte.SIZE, initVector); // 128 bits authentication tag length.
        Cipher encryptCipher = Cipher.getInstance("AES/GCM/NoPadding"); // Fetch cipher suite of AES.
        SecretKeySpec secretKey = new SecretKeySpec(secretKeyBytes, "AES"); // Construct the Secret Key Spec from the contents of the environment specific key file.
        encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec); // Setup cipher.

        // Initialization Vector (12 bytes) is concatenate to the front of the encrypted String.
        byte[] encryptedBytes = Arrays.copyOf(initVector, initVector.length + encryptCipher.getOutputSize(plainTextBytes.length));

        encryptCipher.doFinal(plainTextBytes, 0, plainTextBytes.length, encryptedBytes, initVector.length);
        
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
    
}
