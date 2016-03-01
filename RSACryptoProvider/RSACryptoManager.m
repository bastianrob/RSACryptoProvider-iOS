//
//  RSACryptoManager.m
//  RSACryptoProvider
//
//  Created by Robin Bastian on 2/12/16.
//  Copyright © 2016 Budu. All rights reserved.
//
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>

#import "RSACryptoManager.h"
#import "Base64.h"

@implementation RSACryptoManager

static const UInt8 publicKeyIdentifier[] = "com.budu.publickey\0";
static const UInt8 privateKeyIdentifier[] = "com.budu.privatekey\0";

+(instancetype)instance {
    static RSACryptoManager* instance = nil;
    @synchronized(self) {
        if (instance == nil)
            instance = [[self alloc]init];
    }
    return instance;
}

-(void) generateKeyPair {
    OSStatus status = noErr;
    NSMutableDictionary *privateKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary *publicKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary *keyPairAttr = [[NSMutableDictionary alloc] init];
    
    NSData * publicTag = [NSData dataWithBytes:publicKeyIdentifier
                                        length:strlen((const char *)publicKeyIdentifier)];
    NSData * privateTag = [NSData dataWithBytes:privateKeyIdentifier
                                         length:strlen((const char *)privateKeyIdentifier)];
    
    SecKeyRef publicKey = NULL;
    SecKeyRef privateKey = NULL;
    
    [keyPairAttr setObject:(__bridge id)kSecAttrKeyTypeRSA
                    forKey:(__bridge id)kSecAttrKeyType];
    [keyPairAttr setObject:[NSNumber numberWithInt:1024]
                    forKey:(__bridge id)kSecAttrKeySizeInBits];
    
    [privateKeyAttr setObject:[NSNumber numberWithBool:YES]
                       forKey:(__bridge id)kSecAttrIsPermanent];
    [privateKeyAttr setObject:privateTag
                       forKey:(__bridge id)kSecAttrApplicationTag];
    
    [publicKeyAttr setObject:[NSNumber numberWithBool:YES]
                      forKey:(__bridge id)kSecAttrIsPermanent];
    [publicKeyAttr setObject:publicTag
                      forKey:(__bridge id)kSecAttrApplicationTag];
    
    [keyPairAttr setObject:privateKeyAttr
                    forKey:(__bridge id)kSecPrivateKeyAttrs];
    [keyPairAttr setObject:publicKeyAttr
                    forKey:(__bridge id)kSecPublicKeyAttrs];
    
    status = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr,
                                &publicKey, &privateKey);
    
    
    if(publicKey) CFRelease(publicKey);
    if(privateKey) CFRelease(privateKey);
}

-(NSString *)getPublicKey {
    //Public key name in KeyChain
    NSData * publicTag = [NSData dataWithBytes:publicKeyIdentifier
                                        length:strlen((const char *)publicKeyIdentifier)];
    
    //Public key dictionary info for KeyChain Access
    NSMutableDictionary *queryPublicKey = [[NSMutableDictionary alloc] init];
    [queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPublicKey setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnData];
    
    NSData* publiKeyData;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)queryPublicKey, (void *)&publiKeyData);
    if (status != noErr) {
        return nil;
    }
    
    return [self PEMFormattedPublicKey:publiKeyData];
}

-(SecKeyRef)getPublicKeyWithTag:(NSString *)tagString {
    //Public key name in KeyChain
    NSData * tagData = [tagString dataUsingEncoding:NSUTF8StringEncoding];
    
    //Public key dictionary info for KeyChain Access
    NSDictionary *queryPublicKey =@{(__bridge id)kSecClass : (__bridge id)kSecClassKey,
                                    (__bridge id)kSecAttrKeyType : (__bridge id)kSecAttrKeyTypeRSA,
                                    (__bridge id)kSecAttrAccessible : (__bridge id)kSecAttrAccessibleWhenUnlocked,
                                    (__bridge id)kSecAttrApplicationTag : tagData,
                                    (__bridge id)kSecAttrKeyClass : (__bridge id)kSecAttrKeyClassPublic,
                                    (__bridge id)kSecReturnRef: [NSNumber numberWithBool:YES]};
    
    //Get the public key data
    SecKeyRef publicKey = NULL;
    OSStatus status = noErr;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)queryPublicKey, (CFTypeRef *)&publicKey);
    
    return publicKey;
}

-(NSData*)encrypt:(NSString*)data {
    //Public key name in KeyChain
    NSData * publicTag = [NSData dataWithBytes:publicKeyIdentifier
                                        length:strlen((const char *)publicKeyIdentifier)];
    
    //Public key dictionary info for KeyChain Access
    NSMutableDictionary *queryPublicKey = [[NSMutableDictionary alloc] init];
    [queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPublicKey setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    
    //Get the public key data
    SecKeyRef publicKey = NULL;
    OSStatus status = noErr;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)queryPublicKey, (CFTypeRef *)&publicKey);
    
    //  Allocate a buffer
    size_t cipherBufferSize = SecKeyGetBlockSize(publicKey);
    uint8_t* cipherBuffer = malloc(cipherBufferSize);
    const char* cStringValue = [data UTF8String];
    
    if (cipherBufferSize < sizeof(data)) {
        printf("Could not decrypt.  Packet too large.\n");
        return NULL;
    }
    
    // Encrypt using the public key
    status = SecKeyEncrypt(publicKey,
                           kSecPaddingPKCS1,
                           (const uint8_t*)cStringValue,
                           strlen(cStringValue),
                           cipherBuffer,
                           &cipherBufferSize
                           );
    
    //  Error handling
    //  Store or transmit the encrypted text
    if (publicKey) CFRelease(publicKey);
    
    NSData *encryptedData = [NSData dataWithBytes:cipherBuffer length:cipherBufferSize];
    
    free(cipherBuffer);
    return encryptedData;
}

-(NSString*)decrypt:(NSData*)data {
    //Private key name in the KeyChain
    NSData * privateTag = [NSData dataWithBytes:privateKeyIdentifier
                                         length:strlen((const char *)privateKeyIdentifier)];
    
    //Private key dictionary info for KeyChain Access
    NSMutableDictionary *queryPrivateKey = [[NSMutableDictionary alloc] init];
    [queryPrivateKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPrivateKey setObject:privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPrivateKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [queryPrivateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    
    //Get the private key data
    OSStatus status = noErr;
    SecKeyRef privateKey = NULL;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)queryPrivateKey, (CFTypeRef *)&privateKey);
    
    //  Allocate the buffer
    size_t plainBufferSize = SecKeyGetBlockSize(privateKey);
    uint8_t* plainBuffer = malloc(plainBufferSize);
    size_t cipherBufferSize = [data length];
    uint8_t *cipherBuffer = (uint8_t *)[data bytes];
    
    if (plainBufferSize < cipherBufferSize) {
        printf("Could not decrypt.  Packet too large.\n");
        return nil;
    }
    
    //TODO:Error handling
    //Decrypt using private key
    status = SecKeyDecrypt(privateKey,
                           kSecPaddingPKCS1,
                           cipherBuffer,
                           cipherBufferSize,
                           plainBuffer,
                           &plainBufferSize);
    
    //TODO:Error handling
    if(privateKey) CFRelease(privateKey);
    
    NSData* bufferData = [NSData dataWithBytes:plainBuffer length:plainBufferSize];
    NSString* decryptedString = [[NSString alloc]initWithData:bufferData
                                                     encoding:NSUTF8StringEncoding];
    
    return decryptedString;
}

-(NSData *)sign:(NSString*)data {
    //Private key name in the KeyChain
    NSData * privateTag = [NSData dataWithBytes:privateKeyIdentifier
                                         length:strlen((const char *)privateKeyIdentifier)];
    
    //Private key dictionary info for KeyChain Access
    NSMutableDictionary *queryPrivateKey = [[NSMutableDictionary alloc] init];
    [queryPrivateKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPrivateKey setObject:privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPrivateKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [queryPrivateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    
    //Get the private key data
    OSStatus status = noErr;
    SecKeyRef privateKey = NULL;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)queryPrivateKey, (CFTypeRef *)&privateKey);
    if (status != noErr || privateKey == nil) return nil;
    
    NSData* plainData = [data dataUsingEncoding:NSUTF8StringEncoding];
    
    size_t signedHashBytesSize = SecKeyGetBlockSize(privateKey);
    uint8_t* signedHashBytes = malloc(signedHashBytesSize);
    memset(signedHashBytes, 0x0, signedHashBytesSize);
    
    size_t hashBytesSize = CC_SHA256_DIGEST_LENGTH;
    uint8_t* hashBytes = malloc(hashBytesSize);
    
    if (!CC_SHA256([plainData bytes], (CC_LONG)[plainData length], hashBytes)) {
        return nil;
    }
    
    SecKeyRawSign(privateKey,
                  kSecPaddingPKCS1SHA256,
                  hashBytes,
                  hashBytesSize,
                  signedHashBytes,
                  &signedHashBytesSize);
    
    NSData* signedHash = [NSData dataWithBytes:signedHashBytes
                                        length:(NSUInteger)signedHashBytesSize];
    
    if (hashBytes)
        free(hashBytes);
    if (signedHashBytes)
        free(signedHashBytes);
    
    return signedHash;
}

-(bool)verify:(NSString *)data signature:(NSData *)signature publicKey:(SecKeyRef)publicKey {
    NSData* plainData = [data dataUsingEncoding:NSUTF8StringEncoding];
    
    size_t signedHashBytesSize = SecKeyGetBlockSize(publicKey);
    const void* signedHashBytes = [signature bytes];
    
    size_t hashBytesSize = CC_SHA256_DIGEST_LENGTH;
    uint8_t* hashBytes = malloc(hashBytesSize);
    if (!CC_SHA256([plainData bytes], (CC_LONG)[plainData length], hashBytes)) {
        return nil;
    }
    
    OSStatus status = SecKeyRawVerify(publicKey,
                                      kSecPaddingPKCS1SHA256,
                                      hashBytes,
                                      hashBytesSize,
                                      signedHashBytes,
                                      signedHashBytesSize);
    
    return status == errSecSuccess;
}

-(NSData*)stripPublicKeyHeader:(NSData *)publicKeyData {
    // Skip ASN.1 public key header
    if (publicKeyData == nil) return(nil);
    
    NSUInteger len = publicKeyData.length;
    if (!len) return(nil);
    
    unsigned char *c_key = (unsigned char *)[publicKeyData bytes];
    unsigned int  idx    = 0;
    
    if (c_key[idx++] != 0x30) return(nil);
    
    if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
    else idx++;
    
    // PKCS #1 rsaEncryption szOID_RSA_RSA
    static unsigned char seqiod[] =
    { 0x30,   0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00 };
    if (memcmp(&c_key[idx], seqiod, 15)) return(nil);
    
    idx += 15;
    
    if (c_key[idx++] != 0x03) return(nil);
    
    if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
    else idx++;
    
    if (c_key[idx++] != '\0') return(nil);
    
    // Now make a new NSData from this buffer
    return([NSData dataWithBytes:&c_key[idx] length:len - idx]);
}

-(OSStatus)addPublicKey:(NSString *)key tag:(NSString *)tagString {
    //strip key string from begin and end tag
    NSString* strippedKey = [NSString string];
    NSArray* keyArray = [key componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet];
    
    bool skip = false;
    
    for (NSString* line in keyArray) {
        if ([line isEqualToString:@"-----BEGIN PUBLIC KEY-----"]) {
            skip = true;
        }
        else if ([line isEqualToString:@"-----END PUBLIC KEY-----"]) {
            skip = false;
        }
        else if (skip) {
            strippedKey = [strippedKey stringByAppendingString:line];
        }
    }
    if (strippedKey.length == 0) return(false);
    
    //This will be base64 encoded, decode it.
    NSData* keyData = [strippedKey base64DecodedData];
    keyData = [self stripPublicKeyHeader:keyData];
    if (keyData == nil) return(false);
    
    
    
    NSData* tagData = [tagString dataUsingEncoding:NSUTF8StringEncoding];
    //NSData* keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    
    NSDictionary *saveDict = @{(__bridge id)kSecClass : (__bridge id)kSecClassKey,
                               (__bridge id)kSecAttrKeyType : (__bridge id)kSecAttrKeyTypeRSA,
                               (__bridge id)kSecAttrAccessible : (__bridge id)kSecAttrAccessibleWhenUnlocked,
                               (__bridge id)kSecAttrApplicationTag : tagData,
                               (__bridge id)kSecAttrKeyClass : (__bridge id)kSecAttrKeyClassPublic,
                               (__bridge id)kSecReturnPersistentRef: [NSNumber numberWithBool:YES],
                               (__bridge id)kSecValueData : keyData};
    
    CFTypeRef persistPeer = NULL;
    OSStatus sanityCheck = SecItemAdd((__bridge CFDictionaryRef) saveDict, &persistPeer);
    if (sanityCheck != errSecSuccess) {
        if (sanityCheck == errSecDuplicateItem) {
            // delete the duplicate and save again
            SecItemDelete((__bridge CFDictionaryRef) saveDict);
            sanityCheck = SecItemAdd((__bridge CFDictionaryRef) saveDict, &persistPeer);
        }
    }
    
    return sanityCheck;
}

-(NSData*)encrypt:(NSString *)data withPublicKey:(NSString *)tagString {
    OSStatus status = noErr;
    SecKeyRef publicKey = [self getPublicKeyWithTag:tagString];
    
    //  Allocate a buffer
    size_t cipherBufferSize = SecKeyGetBlockSize(publicKey);
    uint8_t* cipherBuffer = malloc(cipherBufferSize);
    const char* cStringValue = [data UTF8String];
    
    // Note: not sure what this code does???
     if (cipherBufferSize < sizeof(data)) {
     // Ordinarily, you would split the data up into blocks
     // equal to cipherBufferSize, with the last block being
     // shorter. For simplicity, this example assumes that
     // the data is short enough to fit.
     printf("Could not decrypt.  Packet too large.\n");
     return NULL;
     }
    
    // Encrypt using the public key
    status = SecKeyEncrypt(publicKey,
                           kSecPaddingPKCS1,
                           (const uint8_t*)cStringValue,
                           strlen(cStringValue),
                           cipherBuffer,
                           &cipherBufferSize
                           );
    
    //  Error handling
    //  Store or transmit the encrypted text
    if (publicKey) CFRelease(publicKey);
    
    NSData *encryptedData = [NSData dataWithBytes:cipherBuffer length:cipherBufferSize];
    
    free(cipherBuffer);
    return encryptedData;
}

-(size_t)encode:(unsigned char *)buffer length:(size_t)length {
    if (length < 128) {
        buffer[0] = length;
        return 1;
    }
    
    size_t i = (length / 256) + 1;
    buffer[0] = i + 0x80;
    for (size_t j = 0 ; j < i; ++j) {
        buffer[i - j] = length & 0xFF;
        length = length >> 8;
    }
    
    return i + 1;
}

-(NSString *)PEMFormattedPublicKey:(NSData *)publicKeyData {
    unsigned char builder[15];
    unsigned long bitstringEncLength;
    const unsigned char oidSequence [] = {
        0x30, 0x0d, 0x06,
        0x09, 0x2a, 0x86,
        0x48, 0x86, 0xf7,
        0x0d, 0x01, 0x01,
        0x01, 0x05, 0x00};
    
    
    if  ([publicKeyData length] + 1  < 128 ) {
        bitstringEncLength = 1 ;
    }
    else {
        bitstringEncLength = (([publicKeyData length ] + 1)/256) + 2;
    }
    
    builder[0] = 0x30;
    
    size_t i = sizeof(oidSequence) + 2 + bitstringEncLength + [publicKeyData length];
    size_t j = [self encode:&builder[1] length:i];
    
    NSMutableData *encodedKey = [[NSMutableData alloc] init];
    
    [encodedKey appendBytes:builder
                     length:j + 1];
    
    [encodedKey appendBytes:oidSequence
                     length:sizeof(oidSequence)];
    
    builder[0] = 0x03;
    j = [self encode:&builder[1] length:[publicKeyData length] + 1];
    
    builder[j+1] = 0x00;
    [encodedKey appendBytes:builder
                     length:j + 2];
    
    [encodedKey appendData:publicKeyData];
    
    NSString *returnString = [NSString stringWithFormat:@"%@\n%@\n%@",
                              @"-----BEGIN PUBLIC KEY-----",
                              [encodedKey base64EncodedStringWithWrapWidth:64],
                              @"-----END PUBLIC KEY-----"];
    
    return returnString;
}

@end