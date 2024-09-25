# EX-4-ADVANCED-ENCRYPTION-STANDARD-DES-ALGORITHM

## Aim:
  To use Advanced Encryption Standard (AES) Algorithm for a practical application like URL Encryption.

## ALGORITHM: 
  1. AES is based on a design principle known as a substitution–permutation. 
  2. AES does not use a Feistel network like DES, it uses variant of Rijndael. 
  3. It has a fixed block size of 128 bits, and a key size of 128, 192, or 256 bits. 
  4. AES operates on a 4 × 4 column-major order array of bytes, termed the state

## PROGRAM: 
```
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
public class AES {
 private static SecretKeySpec secretKey;
 private static byte[] key;
 public static void setKey(String myKey) {
 MessageDigest sha = null;
 try {
 key = myKey.getBytes("UTF-8");
 sha = MessageDigest.getInstance("SHA-1");
 key = sha.digest(key);
 key = Arrays.copyOf(key, 16);
 secretKey = new SecretKeySpec(key, "AES");
 } catch (NoSuchAlgorithmException e) {
 e.printStackTrace();
 } catch (UnsupportedEncodingException e) {
 e.printStackTrace();
 }
 }
 public static String encrypt(String strToEncrypt, String secret) {
 try {
 setKey(secret);
 Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
 cipher.init(Cipher.ENCRYPT_MODE, secretKey);
 return 
Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
} catch (Exception e) {
 System.out.println("Error while encrypting: " + e.toString());
 }
 return null;
 }
 public static String decrypt(String strToDecrypt, String secret) {
 try {
 setKey(secret);
 Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
 cipher.init(Cipher.DECRYPT_MODE, secretKey);
 return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
 } catch (Exception e) {
 System.out.println("Error while decrypting: " + e.toString());
 }
 return null;
 }
 public static void main(String[] args) {
 final String secretKey = "saveetha university";
 String originalString = "www.saveethauniv.edu";
 String encryptedString = AES.encrypt(originalString, secretKey);
 String decryptedString = AES.decrypt(encryptedString, secretKey);
 System.out.println("URL Encryption Using AES Algorithm\n------------");
 System.out.println("Original URL : " + originalString);
 System.out.println("Encrypted URL : " + encryptedString);
 System.out.println("Decrypted URL : " + decryptedString);
 }
}
```
## OUTPUT:
![Screenshot 2024-09-25 154148](https://github.com/user-attachments/assets/54accedd-c6e9-4166-b270-bcfbf7970276)

## RESULT: 
  The Advanced Encryption Standard (AES) Algorithm for a practical application like URL Encryption is successfully runed.
