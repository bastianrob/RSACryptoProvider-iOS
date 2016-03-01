//
//  RSACryptoManager.h
//  RSACryptoProvider
//
//  Created by Robin Bastian on 2/12/16.
//  Copyright © 2016 Budu. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface RSACryptoManager : NSObject

/**
 Singleton instance for RSACryptoManager
 */
+(instancetype)instance;
+(instancetype)new __attribute__((unavailable("Please use the singleton instance.")));
-(instancetype)init __attribute__((unavailable("Please use the singleton instance.")));

/**
 Generate RSA Public and Private Key
 Keys will automatically stored in KeyChain
 
 This will be referred as client's key
 */
-(void)generateKeyPair;

/**
 Export client's public key to PEM string
 @return NSString: Public key in PEM format
 */
-(NSString*)exportPublicKeyToPEM;

/**
 Get client's public key stored in keychain
 @return SecKeyRef: RSA public key object
 */
-(SecKeyRef)getPublicKey;

/**
 Get a public key stored in KeyChain as tagString
 @param tagString: A public key name in the KeyChain
 @return SecKeyRef: An RSA public key object
 */
-(SecKeyRef)getPublicKeyWithTag:(NSString*)tagString;

/**
 Encrypt data using client's public key stored in KeyChain
 @param data: A plain string to be encrypted
 @return NSData: The encrypted data in bytes array
 */
-(NSData*)encrypt:(NSString*)data;

/**
 Decrypt data using client's private key stored in KeyChain
 @param data: An encrypted data in bytes array
 @return NSString: The decrypted data as plain text
 */
-(NSString*)decrypt:(NSData*)data;

/**
 Sign a plain text using clien't private key
 Computes hash for the given data and then sign the hash
 Uses SHA256 hash algorithm
 @param data: A plain string to be signed
 @return NSData: The signed hash
 */
-(NSData*)sign:(NSString*)data;

/**
 Verify data signature
 Uses SHA256 hash algorithm
 @param data: A plain string data
 @param signature: Signature attached to data
 @param publicKey: An RSA public key object
 @return bool: True if valid
 */
-(bool)verify:(NSString*)data signature:(NSData*)signature publicKey:(SecKeyRef)publicKey;

/**
 Add a public key from another host and save it to KeyChain
 @param key: A base64 encoded string that represent public key in PEM format
 @param tagString: A name to which the public key will be stored in KeyChain
 @warning Any duplicate to tagString in the KeyChain will be replaced
 @return OSStatus: OS status code containing result of adding key to KeyChain
 */
-(OSStatus)addPublicKey:(NSString*)key tag:(NSString *)tagString;

/**
 Encrypt data using a public key stored in the KeyChain tagged with tagString
 @param data: A plain string to be encrypted
 @param tagString: A public key name in KeyChain
 @return NSData: The encrypted data in bytes array
 */
-(NSData*)encrypt:(NSString*)data withPublicKey:(NSString*)tagString;

@end