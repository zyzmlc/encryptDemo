//
//  EncryptAESTool.h
//  NodeTest
//
//  Created by ICBC_App_11 on 2021/1/18.
//  Copyright © 2021 小冬. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface EncryptAESTool : NSObject
/**
 @constant   kCCAlgorithmAES     高级加密标准，128位(默认)
 @constant   kCCAlgorithmDES     数据加密标准
 */
@property (nonatomic, assign) uint32_t algorithm;

/* 单例 */

+ (instancetype)sharedEncryptionTools;

/**
 *  加密字符串并返回base64编码字符串
 *
 *  @param string    要加密的字符串
 *  @param keyString 加密密钥
 *  @param iv        初始化向量(8个字节)
 *  @return 返回加密后的base64编码字符串
 */
- (NSString *)encryptString:(NSString *)string keyString:(NSString *)keyString iv:(NSData *)iv;


/**
 *  解密字符串
 *
 *  @param string    加密并base64编码后的字符串
 *  @param keyString 解密密钥
 *  @param iv        初始化向量(8个字节)
 *  @return 返回解密后的字符串
 */
- (NSString *)decryptString:(NSString *)string keyString:(NSString *)keyString iv:(NSData *)iv;


@end

NS_ASSUME_NONNULL_END
