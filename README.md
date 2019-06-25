# Timed AES Encryption Library

Attempt to create an AES Encryption library that limits the decryption of secret to be during the Time specified in the encryption process.

**Version 1 Design**
> We propose to replace the least significant 2 bytes in the nonce with the `allowByUOM` and `allowByValue` respectively, keeping the first 10 bytes random.
> 
> `0xff 0xff 0xff 0xff 0xff 0xff 0xff 0xff 0xff 0xff [__allowByUOM__] [__allowByValue__]` 
> 
> The modified nonce is used to encrypt the plain text string. During decryption, the least significant 2 byes in the nonce is compared against the current local date time. Runtime exception is thrown if current date time does not match the values specified during encryption.
> 
> **Note - This design assumes assumes that the runtime system date time is not modified and in-sync with a Time Server on the network.**
> 

---

## 01 Encryption Method
```Java
Encryption.encryptWithAES(
    String plainText, 
    Path secretKeyFile, 
    Encryption.AllowByUOM allowByUOM, 
    int allowByValue)
```
- `plainText` - String to be encrypted.
- `secretKeyFile` - Path to AES secret key file.
- `allowByUOM` - Refer to AllowByUOM enumeration.
- `allowByValue` - Refer to AllowByUOM enumeration.

---

## 02 Decryption Method
```Java
Decryption.decryptWithAES(
    String encryptedString, 
    Path secretKeyFile)
```
- `encryptedString` - String to be decrypted.
- `secretKeyFile` - Path to AES secret key file.

---

## 03 Generate Secret Key Method
```Java
GenerateKey.generateAesKey(
    Path keyFile, 
    int keyLength)
```
- `keyFile` - Path to AES secret key file.
- `keyLength` - Length of AES secret key. By specifications must be 128, 192, or 256.

---

## 04 Encryption Enumeration
Encryption enumeration that limits the decryption to be permissible only during the following specified periods:
- `MONTH` (0 to 11 inclusive) - February is 1.
- `DAYOFMONTH` (0 to 30 inclusive) - First day of month is 0.
- `DAYOFWEEK` (0 to 6 inclusive) - Monday is 0.
- `HOUR` (0 to 23 inclusive) - Midnight is 0.

---
