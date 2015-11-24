# AndroidBaseEncryptionByNDK\r
an project which can use to encrypt password and username \r
简单的android ndk 本地双向加密实现（使用ascaii码偏移）\r
a simple example encryption for android written by c++\r

changeLogs：
1.调整工程目录结构，将加解密模块剥离\r
2.准备增加几种加解密方式（下一个要完善的是基于矩阵加密的实现）\r
3.完善函数调用安全机制\r
4.初次使用请先使用  getPackageManager().getPackageInfo("com.sunshinehu.encryption",64).signatures[0].toCharsString() 在c 文件中配置签名值