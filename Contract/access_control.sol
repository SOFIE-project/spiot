pragma solidity ^0.4.24;

contract Access {

    struct policyRecord
    {
        address acp;
        bytes32 acpPK;
        string  URIPolicy;
        uint    price;
    }
    
    struct payment
    {
        address acp;
        uint    price;
        bytes32 hash;
    }
    
    mapping(string => policyRecord) private acl;
    mapping(string => payment) private pendingPayments;
    
    event authRequestEvent(
        string token,
        string URIresource,
        string URIPolicy,
        string hash,
        bytes32 publicKey
    );
    
    event authGranded(
         bytes32 publicKey,
         string token,
         string URIresource,
         string base64Esk
    );
    
    /* Create access control policy */
    function createACPolicy (string URIresource, string URIPolicy, address acp, bytes32 acpPK, uint price ) public {
        policyRecord storage record = acl[URIresource];
        record.acp       = acp;
        record.price     = price;
        record.acpPK     = acpPK;
        record.URIPolicy = URIPolicy;
    }
    
    /* Authorization Request no further check*/
    function authRequestStraw(string token, string URIresource, bytes32 publicKey ) public payable {
        require(msg.value == acl[URIresource].price);
        payment storage record = pendingPayments[token];
        policyRecord storage policy = acl[URIresource];
        record.acp       = policy.acp;
        record.price     = policy.price;
        emit authRequestEvent(token, URIresource, acl[URIresource].URIPolicy,'', publicKey);
    }
    
    /* Authorization Request, include the hash generated from the Thing*/
    function authRequestFirst(string token, string URIresource, string base64Hash, bytes32 publicKey  ) public payable {
        require(msg.value == acl[URIresource].price);
        payment storage record = pendingPayments[token];
        policyRecord storage policy = acl[URIresource];
        record.acp   = policy.acp;
        record.price = policy.price;
        emit authRequestEvent(token, URIresource, acl[URIresource].URIPolicy, base64Hash, publicKey);
    }
    
    /* Authorization Request, include the hash generated from the Thing, validation by the contract*/
    function authRequestSecond(string token, string URIresource, string base64challenge, bytes32 hash, bytes32 publicKey ) public payable {
        require(msg.value == acl[URIresource].price);
        payment storage record = pendingPayments[token];
        policyRecord storage policy = acl[URIresource];
        record.acp   = policy.acp;
        record.price = policy.price;
        record.hash  = hash;
        emit authRequestEvent(token, URIresource, acl[URIresource].URIPolicy,base64challenge, publicKey);
    }
    
     /* Authorization granted */
    function authorize1(bytes32 publicKey, string token, string URIresource, string base64Esk) public {
        payment storage record = pendingPayments[token];
        require (msg.sender == record.acp);
        msg.sender.transfer(record.price);
        delete pendingPayments[token];
        emit authGranded(publicKey, token, URIresource, base64Esk);
    }
    
    /* Authorization granted the Thing-publisher relationship verification*/
    function authorize2(bytes32 publicKey, string token, string URIresource, string base64Esk, string base64hashPreimage) public {
        payment storage record = pendingPayments[token];
        require (msg.sender == record.acp);
        bytes32 h = keccak256(abi.encodePacked(base64hashPreimage));
        require (h == record.hash);
        msg.sender.transfer(record.price);
        delete pendingPayments[token];
        emit authGranded(publicKey, token, URIresource, base64Esk);
    }

}
