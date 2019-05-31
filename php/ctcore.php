<?php
class CTCore
{
    private $CTHINGS_MSK             = "jOhkR0z4HWQQmoqCMKdN2Jkn8QZeXwJALDBmYJH5gyc=";
    private $CTHINGS_KEY_IV_LEN      = 32;
    private $CTHINGS_AUTH_TOKEN_LEN  = 16;
    
    /* The Access Control List */
    public $ACL = [
        "index" => "0xe226a34c9ddbd9f30add27db3a0438dc43153c5c"
        ];
    
    public function createKeyIV( $base64Token) 
    {
        $keyIV = hash_hmac('sha256',  base64_decode($base64Token) , base64_decode($this->CTHINGS_MSK),true);
        return $keyIV;
    }

    public function hmacToken( $base64Token) 
    {
        $keyIV = hash_hmac('sha256',  base64_decode($base64Token) , base64_decode($this->CTHINGS_MSK),true);
        $hmacToken = hash_hmac('sha256',  base64_decode($base64Token) ,$keyIV,true);
        return $hmacToken;
    }
    
    public function createRandomToken64()
    {
        $token = random_bytes($this->CTHINGS_AUTH_TOKEN_LEN);
        return base64_encode($token);
    }
    
    public function encryptData( $base64Token, $plaintext)
    {
        $cipher = "aes-128-gcm";
        $keyiv = $this->createKeyIV($base64Token); 
        $key = substr($keyiv, 0, 16);
        $iv  = substr($keyiv, 16, 16);
        $ciphertext = openssl_encrypt($plaintext, $cipher, $key, OPENSSL_RAW_DATA, $iv, $tag,"",16); 
        return $ciphertext.$tag;
    }
    
}
?>
