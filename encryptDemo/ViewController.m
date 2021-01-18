//
//  ViewController.m
//  encryptDemo
//
//  Created by 小冬 on 2021/1/19.
//  Copyright © 2021 小冬. All rights reserved.
//

#import "ViewController.h"
#import "NSString+Hash.h"
#import "EncryptAESTool.h"
#import "EncryptRsaTool.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    self.view.backgroundColor = [UIColor lightGrayColor];
}


- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event{
    
        [self testHash];
    
        [self testAES];
    
    //1.加载公钥
//    [[EncryptRsaTool sharedRSACryptor] generateKeyPair:512];
    [[EncryptRsaTool sharedRSACryptor] loadPublicKey:[[NSBundle mainBundle] pathForResource:@"rsacert.der" ofType:nil]];
//    //2.加载私钥
    [[EncryptRsaTool sharedRSACryptor] loadPrivateKey: [[NSBundle mainBundle] pathForResource:@"p-123.p12" ofType:nil] password:@"123"];
    
    [self testRSA];
}

- (void)testHash{
    //密码
    NSString * pwd = @"123456";
    
    /*
     1: MD5 直接加密 e10adc3949ba59abbe56e057f20f883e
     不足：不够安全了。可以反查询！
     验证： md5 -s "123456"
     */
    NSString *encryString = pwd.md5String;
    NSLog(@"MD5: %@",encryString);
    
    /*
     2：MD5 加盐（动态盐）  b4f7127cca2309b8f1bf06308c2b0c3d
     弊端： 盐是固定的，写死在程序里面，一旦泄露就不安全了！
     验证： md5 -s "123456second"
     */
    NSString *encryString1 = [pwd stringByAppendingString:@"second"].md5String;
    NSLog(@"MD5加盐: %@",encryString1);
    
    
    /* 3：HMAC  ed958e95cc411a0f71b4234390438ae3
     使用一个密钥加密，并且做两次散列！
     在实际开发中，密钥（KEY）来自于服务器（动态的）！
     一个账号，对应一个KEY，而且还可以跟新！
     验证：echo -n "123456" | openssl dgst -md5 -hmac "hello"
     */
    NSString *encryString2 = [pwd hmacMD5StringWithKey:@"hello"];
    NSLog(@"HMAC加秘钥：%@",encryString2);
}

- (void)testAES{
    /** AES - ECB */
    NSString * key = @"abc";
    NSString *message = @"hello";
    /*  1：AES 加密 ecb
     d1QG4T2tivoi0Kiu3NEmZQ==
     echo -n hello | openssl enc -aes-128-ecb -K 616263 -nosalt | base64
     */
    NSString * encStr = [[EncryptAESTool sharedEncryptionTools] encryptString:message keyString:key iv:nil];
    NSLog(@"ECB加密：%@",encStr);
    
    /* 2：AES 解密 ecb
     echo -n d1QG4T2tivoi0Kiu3NEmZQ== | base64 -D | openssl enc -aes-128-ecb -K 616263 -nosalt -d
     */
    NSLog(@"ECB解密：%@",[[EncryptAESTool sharedEncryptionTools] decryptString:encStr keyString:key iv:nil]);
    
    
    /* 3：AES - CBC 加密  u3W/N816uzFpcg6pZ+kbdg==
     echo -n hello | openssl enc -aes-128-cbc -iv 0102030405060708 -K 616263 -nosalt | base64
     616263就是abc
     */
    uint8_t iv[8] = {1,2,3,4,5,6,7,8};
    NSData * ivData = [NSData dataWithBytes:iv length:sizeof(iv)];
    NSLog(@"CBC加密：%@",[[EncryptAESTool sharedEncryptionTools] encryptString:message keyString:key iv:ivData]);
    
    /* 4：解密 AES CBC 密码分组链接 iv向量
     echo -n u3W/N816uzFpcg6pZ+kbdg== | base64 -D | openssl enc -aes-128-cbc -iv 0102030405060708 -K 616263 -nosalt -d
     */
    NSLog(@"CBC解密：%@",[[EncryptAESTool sharedEncryptionTools] decryptString:@"u3W/N816uzFpcg6pZ+kbdg==" keyString:key iv:ivData]);
}

- (void)testRSA
{
    
    NSData * result = [[EncryptRsaTool sharedRSACryptor] encryptData:[@"hello" dataUsingEncoding:NSUTF8StringEncoding]];
    //base64编码
    NSString * base64 = [result base64EncodedStringWithOptions:0];
    NSLog(@"RSA公钥加密:%@\n",base64);
    
    // 解密
    NSData * dcStr = [[EncryptRsaTool sharedRSACryptor] decryptData:result];
    NSLog(@"私钥解密：%@",[[NSString alloc] initWithData:dcStr encoding:NSUTF8StringEncoding]);
}

@end
