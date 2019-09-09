## 无感支付控件

### 操作系统环境

* centos 7.6
* core 3.10

### 依赖

* gcc 4.8.5
* openssl-libs.i686
* openssl
* glibc.i686 glibc-devel.i686
* libstdc++.i686

### 结构

支付控件基于paho.mqtt的实例进行开发，保留了原有的依赖文件及Makefile

无感支付控件的实现全部都在`paho.mqtt.c-master/src/samples/MQTTClient_publish.c`中

加解密通过调用Ukey实现，所需动态链接库为`libhs_guomi.so`，头文件`HSAPI.h`

### 使用方法

1. 从GitHub中下载本项目
2. 解压到合适的目录（以`/root`为例）
3. 切换目录至`/root/paho.mqtt.c-master`
4. 执行`make clean`
5. 执行`make`
6. 执行`make install`（这一步可能不会成功，但不会对控件的使用产生影响）
7. 执行`./root/paho.mqtt.c-master/build/output/samples/MQTTClient_publish`即可运行支付控件

### 关于加解密

加解密通过调用Ukey实现，加密方法为`HSF_Encrypt`，解密方法为`HSF_Decrypt`。