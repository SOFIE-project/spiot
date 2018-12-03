/*
 * This is part of the "Access Control Delegation for the Internet of Things" project
 * Author: ControlThingsOpenSource
 * More info: https://www.contronthings.gr https://github.com/ControlThingsOpenSource/Access-Control
 */

package gr.controlthings.core;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;

public class CTCore {
    private static final String             CTHINGS_MSK             = "jOhkR0z4HWQQmoqCMKdN2Jkn8QZeXwJALDBmYJH5gyc=";
    private static final int                CTHINGS_KEY_IV_LEN      = 32;
    private static final int                CTHINGS_AUTH_TOKEN_LEN  = 16;
    private static final Random             RANDOM                  = new Random(Double.doubleToLongBits(Math.random()));
    public  static final Map<String,String> ACL                     =  new HashMap<String,String>() 
    {{
        /* Acces control list of the form Resource name, ACP URI */
        put("mmlab.edu.gr","0xf8a1d7b266d9a06f0888839b87c4d63474d4727b");
        
    }};
    private static byte[] createKeyIV(String base64Token)
    {
        byte[] token = Base64.getDecoder().decode(base64Token);
        byte[] keyIV = new byte[CTHINGS_KEY_IV_LEN];
        Mac sha256_HMAC;
        try {
            sha256_HMAC = Mac.getInstance("HmacSHA256");        
            SecretKeySpec secret_key = new SecretKeySpec(Base64.getDecoder().decode(CTHINGS_MSK), "HmacSHA256");
            sha256_HMAC.init(secret_key);
            keyIV = sha256_HMAC.doFinal(token);
            System.out.println ("Generated Key: " + Base64.getEncoder().encodeToString(keyIV));
        }catch (NoSuchAlgorithmException | InvalidKeyException | IllegalStateException e) 
        {
            System.out.println("Exception in generating key: " + e.toString());
        } 
        return keyIV;
    }
    
    public static String createRandomToken64()
    {
        byte[] token = new byte[CTHINGS_AUTH_TOKEN_LEN];        
        RANDOM.nextBytes(token);
        return Base64.getEncoder().encodeToString(token);
    }
    
    public static byte[] encryptData(String base64Token, byte[] plaintext)
    {
        byte[] ciphertext = null;
        byte[] keyIV = createKeyIV(base64Token);
        byte[] key = Arrays.copyOfRange(keyIV, 0, 16);
        byte[] IV = Arrays.copyOfRange(keyIV, 16, 32);
        IvParameterSpec iv = new IvParameterSpec(IV);
        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
        try
        {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            ciphertext = cipher.doFinal(plaintext);
        }catch(InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e)
        {
            System.out.println("Exception " + e.toString());
        }
        return ciphertext;
    }
    
    public static String encryptData64(String base64Token, byte[] plaintext)
    {
        byte[] ciphertex = encryptData(base64Token,plaintext);
        return Base64.getEncoder().encodeToString(ciphertex);
        
    }
    
}
