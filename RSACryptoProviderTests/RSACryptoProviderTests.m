//
//  RSACryptoProviderTests.m
//  RSACryptoProviderTests
//
//  Created by Robin Bastian on 2/12/16.
//  Copyright © 2016 Budu. All rights reserved.
//

#import <XCTest/XCTest.h>

#import "RSACryptoManager.h"

@interface RSACryptoProviderTests : XCTestCase

@end

@implementation RSACryptoProviderTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
    [RSACryptoManager.instance generateKeyPair];
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testEncryptAndDecrypt {
    NSData* data = [RSACryptoManager.instance encrypt:@"This is the plain string"];
    NSLog(@"Encrypted string:\n%@\n\n", [data base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength]);
    NSString* decrypted = [RSACryptoManager.instance decrypt:data];
    NSLog(@"Decrypted string:\n%@\n\n", decrypted);
    assert(data);
}

- (void)testExportPublicKeyToPEM {
    NSString* pem = [RSACryptoManager.instance exportPublicKeyToPEM];
    assert(pem != nil);
    NSLog(@"Public Key:\n%@", pem);
}

- (void)testAddPublicKey {
    NSString* testKey = @"-----BEGIN PUBLIC KEY-----\n"
    @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUwPA4syH0K5x5EWwhGK/JLLSi\n"
    @"jXMFmEPF5NbbgYvTDjCifPbg+/IypEgA514EQKxzuu3bvMko8XJWYY8AVk5tcGVR\n"
    @"dZaauQqah1LI9hZkFi3kZzdzS6LeFTMh31OmOU1fGEwARzSNHmb9gvaEY8dZ971L\n"
    @"Spc7T4S6V+2Q3+saiwIDAQAB\n"
    @"-----END PUBLIC KEY-----";
    
    OSStatus status = [RSACryptoManager.instance addPublicKey:testKey tag:@"serverKey"];
    assert(status == noErr);
}

- (void)testEncryptUsingRemoteHostPublicKey {
    NSData* data = [RSACryptoManager.instance encrypt:@"This is the plain string" withPublicKey:@"serverKey"];
    assert(data != nil);
    NSLog(@"Encrypted String:\n%@", [data base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength]);
}

- (void)testSignData {
    NSData* digitalSignature = [RSACryptoManager.instance sign:@"Sign this string!"];
    assert(digitalSignature != nil);
    
    NSString* base64signature = [digitalSignature base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    NSLog(@"%@", base64signature);
    
    SecKeyRef publicKey = [RSACryptoManager.instance getPublicKeyWithTag:@"com.budu.privatekey"];
    assert(publicKey != nil);
    
    bool verified = [RSACryptoManager.instance verify:@"Sign this string!" signature:digitalSignature publicKey:publicKey];
    assert(verified);
}

@end
