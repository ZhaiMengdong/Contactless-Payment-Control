/*
* File: sdf.h
* Copyright (c) SANGFOR 2017
*/

#ifndef _SDF_H_
#define _SDF_H_ 1


#include <stdint.h>


#ifdef __cplusplus
extern "C"{
#endif


/*自定义类型*/
typedef char          SGD_CHAR;
typedef int8_t        SGD_INT8;
typedef int16_t       SGD_INT16;
typedef int32_t       SGD_INT32;
typedef int64_t       SGD_INT64;
typedef unsigned char SGD_UCHAR;
typedef uint8_t       SGD_UINT8;
typedef uint16_t      SGD_UINT16;
typedef uint32_t      SGD_UINT32;
typedef uint64_t      SGD_UINT64;
typedef unsigned int  SGD_RV;
typedef void*         SGD_HANDLE;

/*设备信息结构体*/
typedef struct DeviceInfo_st {
	unsigned char IssuerName[40];
	unsigned char DeviceName[16];
	unsigned char DeviceSerial[64];
	unsigned char FirmwareVersion[10];
	unsigned int  StandardVersion;
	unsigned int  AsymAlgAbility[2];
	unsigned int  SymAlgAbility;
	unsigned int  HashAlgAbility;
	unsigned int  BufferSize;
} DEVICEINFO;


/*对称加解密算法模式*/
#define SGD_SM1_ECB 0x00000101
#define SGD_SM1_CBC 0x00000102
#define SGD_SM1_OFB 0x00000108

#define SGD_SM4_ECB 0x00002001
#define SGD_SM4_CBC 0x00002002
#define SGD_SM4_OFB 0x00002008

#define SGD_SM3    0x00000001
#define SGD_SHA256 0x00000004
	
//密钥类型:0x00:SM4对称密钥;0x01:SM1对称密钥; 0x02:SM2密钥对; 0x03:SM2公钥; 0x04:SM2私钥; 0x05:RSA密钥对; 0x06:RSA公钥; 0x07:RSA私钥
#define SGD_KEY_TYPE_SM4 			0x00
#define SGD_KEY_TYPE_SM1			0x01
#define SGD_KEY_TYPE_SM2_KEYPAIR	0x02
#define SGD_KEY_TYPE_SM2_PUBKEY		0x03
#define SGD_KEY_TYPE_SM2_PRIKEY		0x04
#define SGD_KEY_TYPE_RSA_KEYPAIR	0x05
#define SGD_KEY_TYPE_RSA_PUBKEY		0x06
#define SGD_KEY_TYPE_RSA_PRIKEY		0x07
	


/*返回值列表*/
#define SDR_OK               0x0 /*成功*/
#define SDR_BASE             0x01000000
#define SDF_DEVICES_MAX_COUNT_ERROR     0x0C000006  	//设备超出最大数
#define SDR_UNKNOWERR        (SDR_BASE + 0x00000001)    /*未知错误*/
#define SDR_NOTSUPPORT       (SDR_BASE + 0x00000002)    /*功能不支持*/
#define SDR_COMMFAIL         (SDR_BASE + 0x00000003)    /*ͨAPDU失败*/
#define SDR_HARDFAIL         (SDR_BASE + 0x00000004)    /*硬件错误*/
#define SDR_OPENDEVICE       (SDR_BASE + 0x00000005)    /*打开设备失败*/
#define SDR_OPENSESSION      (SDR_BASE + 0x00000006)    /*打开会话失败*/
#define SDR_KEYNOTEXIST      (SDR_BASE + 0x00000008)    /*设备不存在*/
#define SDR_ALGNOTSUPPORT    (SDR_BASE + 0x00000009)    /*算法不支持*/
#define SDR_ALGMODNOTSUPPORT (SDR_BASE + 0x0000000A)   	/*算法模式不支持*/
#define SDR_BUFFER_TOO_SMALL (SDR_BASE + 0x00000016)    /*缓存空间不够*/
#define SDR_INVALIDPARAMERR  (SDR_BASE + 0x00000017)  	/*参数错误*/
#define SDR_MALLOCFAILED	 (SDR_BASE + 0x00000018)	/*malloc失败*/


/*
功能:连接设备.返回设备句柄
参数:
	phDeviceHandle		输出,返回设备句柄;
返回值:
	返回0成功,其他值见错误码.
 */
SGD_RV HSF_ConnectDev(SGD_HANDLE *phDeviceHandle);
	
/*
功能:断开设备
参数:
	phDeviceHandle		输入,设备句柄.
返回值:
	返回0成功,其他值见错误码.
*/
SGD_RV HSF_DisConnectDev(SGD_HANDLE phDeviceHandle);

/*
功能:打开一个会话,返回会话句柄,连接设备后首先调用此接口获取会话句柄,其他接口大多需传入会话句柄参数.
参数:
	hDeviceHandle		输入,HSF_ConnectDev返回的设备句柄.
	phSessionHandle		输出,会话句柄.
返回值:
	返回0成功,其他值见错误码.	
*/
SGD_RV HSF_OpenSession(SGD_HANDLE hDeviceHandle, SGD_HANDLE *phSessionHandle);
	
/*
功能:关闭会话,销毁会话句柄
参数:
	hSessionHandle		输入,会话句柄.
返回值:
	返回0成功,其他值见错误码.	
*/
SGD_RV HSF_CloseSession(SGD_HANDLE hSessionHandle);
	
/*
功能:设置根密钥及序列号,根密钥只能为对称密钥,可设置其类型为SM1或者SM4.
参数:
	hSessionHandle		输入,会话句柄;
	rootKey				输入,根密钥,16字节的对称密钥;
	uiKeyType			输入,密钥类型,0x00:SM4类型；0x01:SM1类型;
	devSN				输入,设备序列号,最大支持32字节;
	len					输入,DevSN的长度.
返回值:
	返回0成功,其他值见错误码.
*/
SGD_RV HSF_ImportRootKeyAndDeviceSN(SGD_HANDLE hSessionHandle,SGD_UINT8 * rootKey, SGD_CHAR uiKeyType, SGD_UINT8 * devSN,SGD_UINT32 len);

	
/*
功能:读取设备信息
参数:
	hSessionHandle		输入,设备句柄;
	pstDeviceInfo		输出,设备信息,当前只支持序列号和固件版本;
返回值:
	返回0成功,其他值见错误码.
*/
SGD_RV HSF_GetDeviceInfo(SGD_HANDLE hSessionHandle, DEVICEINFO *pstDeviceInfo);
	
/*
功能:生成随机数
参数:
	hSessionHandle		输入,会话句柄;
	pOutRand			输出,随机数;
	ulRandLen			输入,要生成的随机数的长度;
返回值:
	返回0成功,其他值见错误码.
*/
SGD_RV HSF_GenerateRandom(SGD_HANDLE hSessionHandle, SGD_UCHAR* pOutRand, SGD_UINT32 ulRandLen);
	
/*
功能:设置私密信息,私密信息长度最大为1k.
参数:
	hSessionHandle		输入,会话句柄;
	pPrivateInfo		输入,要设置的私密信息,长度最大为1k;
	uiPrivateInfoLen	输入,pPrivateInfo的长度.
	uiOffset			输入,偏移量(0~1023),KEY内私密信息的空间总共为1k,此参数控制写入位置.
返回值:
	返回0成功,其他值见错误码.
*/
SGD_RV HSF_SetPrivateInfo(SGD_HANDLE hSessionHandle, SGD_UCHAR *pPrivateInfo, SGD_UINT32 uiPrivateInfoLen, SGD_UINT32 uiOffset);
	
/*
功能:获取私密信息,私密信息长度最大为1k.
参数:
	hSessionHandle		输入,会话句柄;
	pPrivateInfo		输出,返回私密信息;	
	uiPrivateInfoLen	输入,要获取私密信息的长度.
	uiOffset			输入,偏移量(0~1023),KEY内私密信息的空间总共为1k,此参数控制读取位置.
返回值:
	返回0成功,其他值见错误码.
*/
SGD_RV HSF_GetPrivateInfo(SGD_HANDLE hSessionHandle, SGD_UCHAR *pPrivateInfo, SGD_UINT32 uiPrivateInfoLen, SGD_UINT32 uiOffset);


/*
功能:读取二进制数据,KEY中存在一个可读写的二进制区域,大小为32640字节.
参数:
	hSessionHandle		输入,会话句柄;
	pOutData			输出,读出的二进制数据;
	OutDataLen			输入,要读取的长度;
	uiOffset			输入,偏移量,此参数控制读写位置;
返回值:
	返回0成功,其他值见错误码.
*/	
SGD_RV HSF_ReadBinary(SGD_HANDLE hSessionHandle, SGD_UCHAR *pOutData, SGD_UINT32 OutDataLen, SGD_UINT32 uiOffset);

/*
功能:写入二进制数据,KEY中存在一个可读写的二进制区域,大小为32640字节.
参数:
	hSessionHandle		输入,会话句柄;
	pInData				输出,要写入的二进制数据;
	OutDataLen			输入,要写入的长度;
	uiOffset			输入,偏移量,此参数控制读写位置;
返回值:
	返回0成功,其他值见错误码.
*/
SGD_RV HSF_WriteBinary(SGD_HANDLE hSessionHandle, SGD_UCHAR *pInData, SGD_UINT32 uiInDataLen, SGD_UINT32 uiOffset);

/*
功能:以密文加Mac的方式导入密钥,包括对称密钥,SM2密钥,RSA密钥
参数:
	hSessionHandle		输入,会话句柄;
	uiEncryptKeyID		输入,生成密文所使用的对称密钥的id,取值0~8;
	IVSelect			输入,对密钥明文加密时使用的初始向量IV进行选择,此参数传0x00使用16字节0x00为初始向量,传0x01,使用已获取的随机数作为初始向量.
	uiKeyType			输入,要导入的密钥的类型,取值0x00~0x07, 0x00:SM4对称密钥;0x01:SM1对称密钥; 0x02:SM2密钥对; 0x03:SM2公钥; 0x04:SM2私钥; 0x05:RSA密钥对; 0x06:RSA公钥; 0x07:RSA私钥
	uiKeyID				输入,给导入的密钥分配的id值,取值1~8;
	pKeyEncData			输入,导入密钥的密文数据, 密文组织方式:（1） 对密钥的明文数据进行填充，先填充1字节0x80，检查填充后的数据是否为16字节整数倍，如果是，完成填充，否则填充0x00至16字节整数倍;（2） 对填充后的数据，使用uiEncryptKeyID指定的密钥和密钥对应的算法进行ECB加密运算。
	pMAC				输入,对导入密钥的密文数据计算的Mac值.MAC计算方式如下:
							对密文数据，使用uiEncryptKeyID指定的密钥和密钥对应的算法进行CBC加密运算，其中IV取值由IVSelect决定，取最后一块密文的前8字节作为MAC值。IV值需要注意的是，当IV指定使用随机数时，如果仅获取了8字节随机数，后面8字节填充为0x00.
返回值:
	返回0成功,其他值见错误码.
*/
SGD_RV HSF_ImportKey(SGD_HANDLE hSessionHandle, SGD_CHAR uiEncryptKeyID, SGD_CHAR IVSelect, SGD_CHAR uiKeyType, SGD_CHAR uiKeyID, SGD_UCHAR *pKeyEncData, SGD_UINT32 uiKeyEncDataLen, SGD_UCHAR *pMAC);
	
/*
功能:删除密钥(对)
参数:
	uiKeyType		输入,要删除的密钥类型, 0x00:对称密钥; 0x02:SM2密钥对; 0x05:RSA密钥对.
	uiKeyID			输入,要删除的密钥ID,取值0x01~0x08;
	pMAC			输入,MAC值,执行该接口前需要获取8字节或者16字节随机数。MAC计算是使用根密钥，对获取的随机数（如果为8字节，后面填充8字节0x00至16字节）使用根密钥对应的算法进行ECB加密，取密文的前8字节作为MAC.
返回值:
	返回0成功,其他值见错误码.

*/
SGD_RV HSF_DestroyKey(SGD_HANDLE hSessionHandle, SGD_CHAR uiKeyType, SGD_CHAR uiKeyID, SGD_UCHAR *pMAC);	

	
/*
功能:获取密钥列表
参数:
	hSessionHandle		输入,会话句柄;
	pSM1KeyList			输出,SM1密钥列表,第一字节位存在的SM1密钥的个数n,后续n个字节存放SM1密钥对应的id;
	pSM4KeyList			输出,SM4密钥列表,第一字节位存在的SM4密钥的个数n,后续n个字节存放SM4密钥对应的id;
	pSM2KeyList			输出,SM2密钥列表,第一字节位存在的SM2密钥的个数n,后续n个字节存放SM2密钥对应的id
	pRSAKeyList			输出,RSA密钥列表,第一字节位存在的RSA密钥的个数n,后续n个字节存放RSA密钥对应的id;
返回值:
	返回0成功,其他值见错误码.
*/
SGD_RV HSF_GetKeyList(SGD_HANDLE hSessionHandle, SGD_UCHAR *pSM1KeyList, SGD_UCHAR *pSM4KeyList, SGD_UCHAR *pSM2KeyList, SGD_UCHAR *pRSAKeyList);

	
//读取密钥
/*
功能:读取密钥,可分别读取SM2公钥,SM2私钥,RSA公钥,RSA私钥, 不能读取对称密钥.
参数:
	hSessionHandle		输入,会话句柄;
	uiEncryptKeyID		输入,读取私钥时返回密文加Mac值,此参数用于指定生成密文和计算Mac所使用的对称密钥的id,取值0~8;
	IVSelect			输入,对密钥明文加密时使用的初始向量IV进行选择,此参数传0x00使用16字节0x00为初始向量;传0x01,使用已获取的随机数作为初始向量,需要先执行获取随机数操作.
	uiKeyType			输入,要读取的密钥的类型,0x03:SM2公钥；0x04:SM2私钥；0x06:RSA公钥；0x07:RSA私钥;
	uiKeyID				输入,要读取密钥的id值,取值1~8;
	pKeyData			输出,返回的密钥数据,uiKeyType=0x03:64字节SM2公钥明文;uiKeyType=0x04:SM2私钥密文; uiKeyType=0x06:RSA公钥（E||N）明文; uiKeyType=0x07:RSA私钥密文.
							密文组织方式:（1） 对密钥的明文数据进行填充，先填充1字节0x80，检查填充后的数据是否为16字节整数倍，如果是，完成填充，否则填充0x00至16字节整数倍;（2） 对填充后的数据，使用 uiEncryptKeyID 指定的密钥和密钥对应的算法进行ECB加密运算
	KeyDataLen			输入/输出,输入时表示pKeyData缓存区的长度,输出时表示返回数据的实际长度.
	pMAC				输出,8字节MAC值(读取私钥时有效).
返回值:
	返回0成功,其他值见错误码.
*/
SGD_RV HSF_ReadKey(SGD_HANDLE hSessionHandle, SGD_UCHAR uiEncryptKeyID, SGD_CHAR IVSelect, SGD_UCHAR uiKeyType,SGD_UCHAR uiKeyID, SGD_UCHAR *pKeyData, SGD_UINT32 *KeyDataLen, SGD_UCHAR *pMAC);

/*
功能:生成SM2密钥对, 并指定其id.
参数:
	hSessionHandle		输入,会话句柄;
	uiKeyID				输入,此参数用于指定生成密钥对的id,取值1~8;
返回值:
	返回0成功,其他值见错误码.
*/	
SGD_RV HSF_GenSM2KeyPair(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyID);
	
/*
功能:生成RSA密钥对, 并指定其id.
参数:
	hSessionHandle		输入,会话句柄;
	uiKeyID				输入,此参数用于指定生成密钥对的id,取值1~8;
	BitsLenth			输入,此参数用于指定生成的RSA密钥模长, 1:1024, 2:2048; 
返回值:
	返回0成功,其他值见错误码.
*/	
SGD_RV HSF_GenRSAKeyPair(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyID, SGD_UINT32 uiBitsLenth);
	
/*
功能:RSA签名
参数:
	hSessionHandle		输入,会话句柄;
	uiKeyID				输入,此参数用于指定用于签名的RSA密钥的id,取值0x01~0x08;
	pbData				输入,要签名的数据,根据参数HashFlag判断是否在内部对其进行sha256 Hash计算.
	ulDataLen			输入,要签名的原数据的长度.
	pbSignature			输出,签名结果.
	pulSignLen			输入/输出,输入表示签名结果缓冲区大小,输出表示签名结果实际长度.
	HashFlag			输入,值为0时,直接对pbData签名,值为1或其他值时对pbData做sha256 Hash后签名.
返回值:
	返回0成功,其他值见错误码.
*/
SGD_RV HSF_RSASignData(SGD_HANDLE hSessionHandle,SGD_UCHAR uiKeyID, SGD_UCHAR *pbData, SGD_UINT32 ulDataLen, SGD_UCHAR *pbSignature, SGD_UINT32 *pulSignLen, SGD_UINT32 HashFlag);

	
/*
功能:RSA验签
参数:
	hSessionHandle		输入,会话句柄;
	uiKeyID				输入,此参数用于指定用于验签的RSA密钥的id,取值0x01~0x08;
	pbData				输入,要验签的数据,根据参数HashFlag判断是否在内部对其进行sha256 Hash计算.
	ulDataLen			输入,要验签的原数据的长度.
	pbSignature			输入,签名结果.
	pulSignLen			输入,签名结果长度,必须为公钥的模长.
	HashFlag			输入,值为0时,直接对pbData验签,值为1或其他值时对pbData做sha256 Hash后验签.
返回值:
	返回0成功,其他值见错误码.
*/
SGD_RV HSF_RSAVerifyData(SGD_HANDLE hSessionHandle,SGD_UCHAR uiKeyID, SGD_UCHAR *pbData, SGD_UINT32 ulDataLen, SGD_UCHAR *pbSignature, SGD_UINT32 pulSignLen, SGD_UINT32 HashFlag);

/*
功能:SM2签名
参数:
	hSessionHandle		输入,会话句柄;
	uiKeyID				输入,此参数用于指定用于签名的SM2密钥的id,取值0x01~0x08;
	pbData				输入,要签名的数据,根据参数HashFlag判断是否在内部对其进行sm3 Hash计算.
	ulDataLen			输入,要签名的原数据的长度.
	pbSignature			输出,64字节签名结果.
	HashFlag			输入,值为0时,直接对pbData签名,值为1或其他值时对pbData做SM3 Hash后签名.
返回值:
	返回0成功,其他值见错误码.
*/
SGD_RV HSF_SM2SignData(SGD_HANDLE hSessionHandle,SGD_UCHAR uiKeyID, SGD_UCHAR *pbData, SGD_UINT32 ulDataLen, SGD_UCHAR *pbSignature, SGD_UINT32 HashFlag);

/*
功能:SM2验签
参数:
	hSessionHandle		输入,会话句柄;
	uiKeyID				输入,此参数用于指定用于验签的SM2密钥的id,取值0x01~0x08;
	pbData				输入,要验签的数据,根据参数HashFlag判断是否在内部对其进行sm3 Hash计算.
	ulDataLen			输入,要验签的原数据的长度.
	pbSignature			输入,64字节签名结果.
	HashFlag			输入,值为0,直接对pbData验签.值为1或其他值时对pbData做SM3 Hash后验签.
返回值:
	返回0成功,其他值见错误码.
*/
SGD_RV HSF_SM2VerifyData(SGD_HANDLE hSessionHandle,SGD_UCHAR uiKeyID, SGD_UCHAR *pbData, SGD_UINT32 ulDataLen, SGD_UCHAR *pbSignature, SGD_UINT32 HashFlag);
	
	
/*
功能:RSA加密(公钥运算)
参数:
	hSessionHandle		输入,会话句柄;
	uiKeyID				输入,此参数用于指定用于加密的RSA密钥的id,取值0x01~0x08;
	pbInputData			输入,指向待加密的原始数据缓冲区.
	ulInputDataLen		输入,待运算原始数据的长度，必须为公钥模长.
	pbOutputData			输出,指向加密结果缓冲区.
	ulOutputDataLen		输入/输出,输入时表示 pbOutputData 缓冲区的长度，输出时表示加密结果的实际长度
返回值:
	返回0成功,其他值见错误码.
*/
SGD_RV HSF_RSAEncrypt(SGD_HANDLE hSessionHandle,SGD_UCHAR uiKeyID,SGD_UCHAR *pbInputData, SGD_UINT32 ulInputDataLen, SGD_UCHAR *pbOutputData, SGD_UINT32 *ulOutputDataLen);
	
/*
功能:RSA解密(私钥运算)
参数:
	hSessionHandle		输入,会话句柄;
	uiKeyID				输入,此参数用于指定用于解密的RSA密钥的id,取值0x01~0x08;
	pbInputData			输入,指向待解密的数据缓冲区.
	ulInputDataLen		输入,待解密数据的长度，必须为公钥模长.
	pbOutputData		输出,指向解密结果缓冲区.
	ulOutputDataLen		输入/输出,输入时表示 pbOutputData 缓冲区的长度，输出时表示解密结果的实际长度
返回值:
	返回0成功,其他值见错误码.
*/
SGD_RV HSF_RSADecrypt(SGD_HANDLE hSessionHandle,SGD_UCHAR uiKeyID,SGD_UCHAR *pbInputData, SGD_UINT32 ulInputDataLen, SGD_UCHAR *pbOutputData, SGD_UINT32 *ulOutputDataLen);
	
/*
功能:SM2加密(公钥运算)
参数:
	hSessionHandle		输入,会话句柄;
	uiKeyID				输入,此参数用于指定用于加密的SM2密钥的id,取值0x01~0x08;
	pbInputData			输入,指向待加密的原始数据缓冲区.
	ulInputDataLen		输入,待加密原始数据的长度，待加密数据长度不能大于1K.
	pbOutputData		输出,指向加密结果缓冲区.
	ulOutputDataLen		输入/输出,输入时表示 pbOutputData 缓冲区的长度，输出时表示加密结果的实际长度
返回值:
	返回0成功,其他值见错误码.
*/
SGD_RV HSF_SM2Encrypt(SGD_HANDLE hSessionHandle,SGD_UCHAR uiKeyID,SGD_UCHAR *pbInputData, SGD_UINT32 ulInputDataLen, SGD_UCHAR *pbOutputData, SGD_UINT32 *ulOutputDataLen);
	
/*
功能:SM2解密(私钥运算)
参数:
	hSessionHandle		输入,会话句柄;
	uiKeyID				输入,此参数用于指定用于解密的SM2密钥的id,取值0x01~0x08;
	pbInputData			输入,指向待解密的数据缓冲区.
	ulInputDataLen		输入,待解密数据的长度，待解密数据长度不能大于1K+96字节.
	pbOutputData		输出,指向解密结果缓冲区.
	ulOutputDataLen		输入/输出,输入时表示 pbOutputData 缓冲区的长度，输出时表示解密结果的实际长度
返回值:
	返回0成功,其他值见错误码.
*/
SGD_RV HSF_SM2Decrypt(SGD_HANDLE hSessionHandle,SGD_UCHAR uiKeyID,SGD_UCHAR *pbInputData, SGD_UINT32 ulInputDataLen, SGD_UCHAR *pbOutputData, SGD_UINT32 *ulOutputDataLen);


/*
功能:加密初始化(SM1/SM4加密),用来设置算法类型/算法模式/使用的密钥,使用的密钥由参数ucKeyID或者pucKey指定,  此接口在调用HSF_Encryp前调用,调用一次之后可连续调用HSF_Encrypt.
参数:
	hSessionHandle		输入,会话句柄;
	ucKeyID				输入,加密使用的密钥ID,取值0x00~0x08,其中0x00代表使用根密钥,当参数pucKey不为空时此参数无效,加密时使用参数pucKey传入的数据作为密钥.
	pucKey				输入,加密使用的16字节密钥,当此参数为空时,使用参数ucKeyID指定的KEY内保存的密钥.
	ucAlgId				输入,算法模式, 	SGD_SM1_ECB 
										SGD_SM1_CBC 
										SGD_SM1_OFB 
										SGD_SM4_ECB 
										SGD_SM4_CBC 
										SGD_SM4_OFB 
返回值:
	返回0成功,其他值见错误码.
*/
SGD_RV HSF_EncryptInit(SGD_HANDLE hSessionHandle,SGD_UCHAR ucKeyID, SGD_UCHAR *pucKey, SGD_UCHAR *pucIV, SGD_UINT32 ucAlgId);
	
/*
功能:解密初始化(SM1/SM4解密),此接口在调用HSF_Decrypt前调用,调用一次之后可连续调用HSF_Decrypt
参数:
	hSessionHandle		输入,会话句柄;
	ucKeyID				输入,解密使用的密钥ID,取值0x00~0x08,其中0x00代表使用根密钥,当参数pucKey不为空时此参数无效,解密时使用参数pucKey传入的数据作为密钥.
	pucKey				输入,解密使用的16字节密钥,当此参数为空时,使用参数ucKeyID指定的KEY内保存的密钥.
	ucAlgId				输入,算法模式, 	SGD_SM1_ECB 
										SGD_SM1_CBC 
										SGD_SM1_OFB 
										SGD_SM4_ECB 
										SGD_SM4_CBC 
										SGD_SM4_OFB 
返回值:
	返回0成功,其他值见错误码.
*/
SGD_RV HSF_DecryptInit(SGD_HANDLE hSessionHandle,SGD_UCHAR ucKeyID, SGD_UCHAR *pucKey, SGD_UCHAR *pucIV, SGD_UINT32 ucAlgId);
	
/*
功能:加密
参数:
	hSessionHandle		输入,会话句柄;
	pucIV				输入,16字节初始向量,当模式为CBC或OFB时使用.
	pucData				输入,指向待加密原文数据缓存区.
	uiDataLength		输入,待加密原文数据长度.
	pucEncData			输出,指向加密结果缓存区.
	puiEncDataLength	输入/输出,输入时表示加密结果缓存区长度,输出时表示加密结果实际长度.
返回值:
	返回0成功,其他值见错误码.

*/
SGD_RV HSF_Encrypt(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, SGD_UCHAR *pucEncData, SGD_UINT32 *puiEncDataLength);	
	
/*
功能:解密
参数:
	hSessionHandle		输入,会话句柄;
	pucIV				输入,16字节初始向量,当模式为CBC或OFB时使用.
	pucEncData			输入,指向待解密密文数据缓存区.
	uiEncDataLength		输入,待解密密文数据长度,必须为16字节整数倍.
	pucData				输出,指向解密结果缓存区.
	puiDataLength		输入/输出,输入时表示解密结果缓存区长度,输出时表示解密结果实际长度.
返回值:
	返回0成功,其他值见错误码.
*/
SGD_RV HSF_Decrypt(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucEncData, SGD_UINT32 uiEncDataLength, SGD_UCHAR *pucData, SGD_UINT32 *puiDataLength);	
	
	
/*
功能:密码杂凑(Hash)初始化, 用于设置算法类型(SM3/SHA256)和签名者公钥和用户ID(用于SM2签名时,先获取Z值,拼接到原文前面再做Hash),若不需要获取Z值,可将pucPublicKey传空值.
参数:
	hSessionHandle		输入,会话句柄;
	ulAlgID				输入,算法标识,0x00000001:SM3; 0x00000004:SHA256.
	pucPublicKey		输入,签名者公钥。当ulAlgID为SGD_SM3时有效.
	pucID				输入,签名者的ID值，当ulAlgID为SGD_SM3时有效.
	uiIDLength			输入,签名者ID的长度，当ulAlgID为SGD_SM3时有效。
返回值:
	返回0成功,其他值见错误码.
*/
SGD_RV HSF_DigestInit(SGD_HANDLE hSessionHandle, SGD_UINT32 ulAlgID, SGD_UCHAR *pucPublicKey, SGD_UCHAR *pucID, SGD_UINT32 uiIDLength);

/*
功能:密码杂凑(Hash)
参数:
	hSessionHandle		输入,会话句柄;
	pbData				输入,指向消息数据的缓冲区.
	ulDataLen			输入,消息数据的长度。
	pbHashData			输出,指向密码杂凑结果数据缓冲区.
	pulHashLen			输入/输出,输入时表示结果数据缓冲区长度，输出时表示结果数据实际长度。
返回值:
	返回0成功,其他值见错误码.
*/
SGD_RV HSF_Digest (SGD_HANDLE hSessionHandle, SGD_UCHAR *pbData, SGD_UINT32 ulDataLen, SGD_UCHAR *pbHashData, SGD_UINT32 *pulHashLen);
	

#ifdef __cplusplus
}
#endif

#endif /*#ifndef _SDF_H_*/
