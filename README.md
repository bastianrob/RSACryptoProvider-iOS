# RSACryptoProvider-iOS

## Get Started
Just copy RSACryptoProvider folder to your project, or.
Reference this project as embedded library

##How to Use

* Generate RSA Key Pair
```objective-c
[RSACryptoManager.instance generateKeyPair];
```

* Encrypt & Decrypt using generated key
```objective-c
NSData* data = [RSACryptoManager.instance encrypt:@“This is the plain string”];
NSLog(@“Encrypted data: %@”, [data base64EncodedStringWithOptions:kNilOptions]);
NSString* decrypted = [RSACryptoManager.instance decrypt:data];
NSLog(@"Decrypted string:%@", decrypted);

```

* Export public key to PEM string
```objective-c
NSString* pem = [RSACryptoManager.instance exportPublicKeyToPEM];
NSLog(@"Public Key:\n%@", pem);
```

* Add remote host public key
```objective-c
NSString* testKey = @"-----BEGIN PUBLIC KEY-----\n"
@"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUwPA4syH0K5x5EWwhGK/JLLSi\n"
@"jXMFmEPF5NbbgYvTDjCifPbg+/IypEgA514EQKxzuu3bvMko8XJWYY8AVk5tcGVR\n"
@"dZaauQqah1LI9hZkFi3kZzdzS6LeFTMh31OmOU1fGEwARzSNHmb9gvaEY8dZ971L\n"
@"Spc7T4S6V+2Q3+saiwIDAQAB\n"
@"-----END PUBLIC KEY-----";

//Only accept PEM format, tag is the key id in keychain
OSStatus status = [RSACryptoManager.instance addPublicKey:testKey tag:@"serverKey"];
assert(status == noErr);
```

* Encrypt using remote host public key
```objective-c
NSString* str = @"This is the plain string"
NSData* data = [RSACryptoManager.instance encrypt:str withPublicKey:@"serverKey"];
assert(data != nil);
NSLog(@"Encrypted String: %@", [data base64EncodedStringWithOptions:kNilOptions]);
```

* Get generated public key
```objective-c
SecKeyRef publicKey = [RSACryptoManager.instance getPublicKey];
```

* Sign using generated private key and verify
```objective-c
NSData* digitalSignature = [RSACryptoManager.instance sign:@"Sign this string!"];
assert(digitalSignature != nil);
    
NSString* base64signature = [digitalSignature base64EncodedStringWithOptions:kNilOptions];
NSLog(@"%@", base64signature);
    
SecKeyRef publicKey = [RSACryptoManager.instance getPublicKey];
assert(publicKey != nil);
    
bool verified = [RSACryptoManager.instance verify:@"Sign this string!" signature:digitalSignature publicKey:publicKey];
assert(verified);
```

* Verify signed data using remote host public key
```objective-c
//Suppose we have @“Hello, I’m Server!” as message from remote host
//And its digital signature in NSData format
SecKeyRef publicKey = [RSACryptoManager.instance getPublicKeyWithTag:@“serverKey”];
assert(publicKey != nil);
    
bool verified = [RSACryptoManager.instance verify:@“Hello, I’m Server!” signature:digitalSignature publicKey:publicKey];
assert(verified);
```
