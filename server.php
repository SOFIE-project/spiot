<?php
require_once ('php/ctcore.php');

$ctcore = new CTCore();
if (isset($_GET['authtype']) && $_GET['authtype'] ==1)
{
    echo '{"token":"' .$ctcore->createRandomToken64().'","ACP":"0xadc6d997d6f3cff7ac482569574c0be131c49c3b", "ACPPubKeyBase64":"46E363VX0wsdDgYavCAZy/TiztlDCh0eofhKatyq8Rg="}';
}
else if (isset($_GET['authtype']) && $_GET['authtype'] ==2)
{
    $token = $ctcore->createRandomToken64();
    echo '{"token":"' .$token.'","ACP":"0xadc6d997d6f3cff7ac482569574c0be131c49c3b", "ACPPubKeyBase64":"46E363VX0wsdDgYavCAZy/TiztlDCh0eofhKatyq8Rg=","hmacToken":"'.base64_encode($ctcore->hmacToken($token)).'"}';
}
else if(isset($_GET['token']))
{
    $plaintext = "Hello world";
    echo base64_encode($ctcore->encryptData($plaintext,$_GET['token']));
    
}

?>
