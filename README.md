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

无感支付控件的实现全部都在`Contactless-Payment-Control/src/samples/MQTTClient_publish.c`中

加解密通过调用Ukey实现，所需动态链接库为`libhs_guomi.so`，头文件`HSAPI.h`

### 使用方法

1. 从GitHub中下载本项目
2. 解压到合适的目录（以`/root`为例）
3. 切换目录至`/root/Contactless-Payment-Control`
4. 将`/root/Contactless-Payment-Control/src`目录下的`libhs_guomi.so`拷贝至`/usr/lib/`
5. 执行`make clean`
6. 执行`make`
7. 执行`make install`（这一步可能不会成功，但不会对控件的使用产生影响）
8. 执行`./root/Contactless-Payment-Control/build/output/samples/MQTTClient_publish`即可运行支付控件

### 关于加解密

加解密通过调用Ukey实现，加密方法为`HSF_Encrypt`，解密方法为`HSF_Decrypt`。

### 模拟充电桩

`/root/Contactless-Payment-Control/`中的`socket_a_client.c`为模拟车辆身份认证、`socket_p_client.c`为模拟无感支付、`socket_server.c`为模拟充电桩接收返回结果，编译方法为

```bash
gcc -o socket_a_client socket_a_client.c
gcc -o socket_p_client socket_p_client.c
gcc -o socket_server socket_server.c -lpthread
```

直接执行编译后的`socket_a_client`、`socket_p_client`、`socket_server`即可使用响应的功能