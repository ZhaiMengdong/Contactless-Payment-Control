/*
 * @Description: 支付控件
 * @Version: 
 * @Autor: ZMD
 * @Date: 2019-08-30 10:12:25
 * @LastEditTime: 2019-09-03 10:48:26
 */
/*******************************************************************************
 * Copyright (c) 2012, 2017 IBM Corp.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution. 
 *
 * The Eclipse Public License is available at 
 *   http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at 
 *   http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    Ian Craggs - initial contribution
 *******************************************************************************/

#include <stdlib.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>       //pthread_t , pthread_attr_t and so on.
#include <stdio.h>
#include <netinet/in.h>      //structure sockaddr_in
#include <arpa/inet.h>       //Func : htonl; htons; ntohl; ntohs
#include <assert.h>          //Func :assert
#include <string.h>          //Func :memset
#include <unistd.h>          //Func :close,write,read
#include "MQTTClient.h"
#include "cJSON.h"
#include "cJSON.c"
#include "HSAPI.h"

#define ADDRESS     "tcp://106.75.214.136:1883" //mqtt broker的地址
#define CLIENTID    "ExampleClientPub"  //向无感支付平台提交信息时的mqtt client id
#define AUTHENTICATION_RESULT_CLIENTID "authentication_result"  //接收无感支付平台返回信息的mqtt client id
#define AUTHENTICATION_TOPIC    "authentication"    //进行充电车辆是否开通无感支付认证判断的mqtt client发送报文的主题
#define PAYMENT_TOPIC   "payment"
#define SUBSCRIBE_TOPIC_1   "authentication_result" //mqtt client订阅的车辆身份验证的主题
#define SUBSCRIBE_TOPIC_2   "payment_result"    //mqtt client订阅的支付结果的主题
#define QOS         2   
#define TIMEOUT     10000L
#define GATEWAYID   "201908280033"  //网关id

#define DATALEN 256

#define SOCK_PORT_AUTHENTICATION 9988  //车辆身份认证时与充电桩通信的socket的端口号
#define SOCK_PORT_PAY 9998  //支付时与充电桩通信的socket的端口号
#define BUFFER_LENGTH 1024
#define MAX_CONN_LIMIT 512     //MAX connection limit

#define END_FLAG "E_N_D"

SGD_UCHAR KEY[] = {
    0xe2, 0xaf, 0x9b, 0x77, 0xce, 0xb0, 0xc1, 0x6f, 0xcf, 0x21, 0xfb, 0x5e, 0xb5, 0x58, 0xb7, 0xd3 
};

typedef struct
{
    int sockfd;
    char * client_addr;
    int socket_port;
} extra_publish_message;    //网关在传输消息时额外封装的信息

typedef struct{
    char * client_addr;
    char * result;
} return_data;

volatile MQTTClient_deliveryToken deliveredtoken;

void socket_server(int port);

static void Data_handle(void * sock_fd);   //Only can be seen in the file

int mqtt_publish(unsigned char *payload);

void delivered(void *context, MQTTClient_deliveryToken dt);

int msgarrvd(void *context, char *topicName, int topicLen, MQTTClient_message *message);

void connlost(void *context, char *cause);

void mqtt_server();

char * encapsulation_payload(char *data_recv, char *client_addr);

return_data * parse_payload(char * payload);

unsigned char * SM4(char * put_data);

unsigned char * SM4_ENC_ECB(SGD_HANDLE hSessionHandle, char * put_data);

void put_result_to_socket_client(char* client_addr, char* result);

int main(int argc, char* argv[])
{
    char ch = '0';
    //开启一个线程用来启动一个mqtt client，该client用来接收无感支付平台发送的信息
    pthread_t mqtt_server_id;
    pthread_t socket_authentication;
    pthread_t socket_pay;
    if(pthread_create(&mqtt_server_id,NULL,(void *)(&mqtt_server),NULL))
        {
            fprintf(stderr,"pthread_create error!\n");
        }
    if(pthread_create(&socket_authentication, NULL, (void *)(&socket_server), SOCK_PORT_AUTHENTICATION)){
        fprintf(stderr,"pthread_create error!\n");
    }
    if(pthread_create(&socket_authentication, NULL, (void *)(&socket_server), SOCK_PORT_PAY)){
        fprintf(stderr,"pthread_create error!\n");
    }
    
    printf("输入Q或者q结束程序\n");
    do 
    {
        ch = getchar();
    } while(ch!='Q' && ch != 'q');

    return 0;
}

void socket_server(int port){
    //创建一个本地socket，用来接收充电桩发来的报文
    int sockfd_server;
    int sockfd;
    int fd_temp;
    struct sockaddr_in s_addr_in;
    struct sockaddr_in s_addr_client;
    int client_length;

    sockfd_server = socket(AF_INET,SOCK_STREAM,0);  //ipv4,TCP
    assert(sockfd_server != -1);

    //before bind(), set the attr of structure sockaddr.
    memset(&s_addr_in,0,sizeof(s_addr_in));
    s_addr_in.sin_family = AF_INET;
    s_addr_in.sin_addr.s_addr = htonl(INADDR_ANY);  //trans addr from uint32_t host byte order to network byte order.
    s_addr_in.sin_port = htons(port);          //trans port from uint16_t host byte order to network byte order.
    fd_temp = bind(sockfd_server,(struct scokaddr *)(&s_addr_in),sizeof(s_addr_in));
    if(fd_temp == -1)
    {
        fprintf(stderr,"bind error!\n");
        exit(1);
    }

    fd_temp = listen(sockfd_server,MAX_CONN_LIMIT);
    if(fd_temp == -1)
    {
        fprintf(stderr,"listen error!\n");
        exit(1);
    }

    while(1)
    {
        printf("waiting for new connection...\n");
        pthread_t thread_id;
        client_length = sizeof(s_addr_client);
        char client_addr[INET_ADDRSTRLEN];
        extra_publish_message extra_message;

        //Block here. Until server accpets a new connection.
        sockfd = accept(sockfd_server,(struct sockaddr_*)(&s_addr_client),(socklen_t *)(&client_length));
        if(sockfd == -1)
        {
            fprintf(stderr,"Accept error!\n");
            continue;                               //ignore current socket ,continue while loop.
        }
        printf("A new connection occurs!\n");

        if(getpeername(sockfd, (struct sockaddr *)&s_addr_client, &client_length) == -1){
            printf("get peername error\n");
            continue;
        }
        inet_ntop(AF_INET, &s_addr_client.sin_addr, client_addr, sizeof(client_addr));

        extra_message.client_addr = client_addr;
        extra_message.sockfd = sockfd;
        extra_message.socket_port = port;

        //每建立一个socket连接，相当于一个充电桩向网关发送报文，开启一个线程去进行报文的处理
        if(pthread_create(&thread_id,NULL,(void *)(&Data_handle),(void *)(&extra_message)) == -1)
        {
            fprintf(stderr,"pthread_create error!\n");
            break;                                  //break while loop
        }
    }

    //Clear
    int ret = shutdown(sockfd_server,SHUT_WR); //shut down the all or part of a full-duplex connection.
    assert(ret != -1);

    printf("Server shuts down\n");
}

/**
 * @description: 处理充电桩提交的报文，对信息进行加密并通过mqtt publish提交到无感支付平台
 * @author: ZMD
 * @LastEditTime: Do not edit
 * @Date: 2019-08-30 13:37:30
 */
static void Data_handle(void * message)
{
    extra_publish_message extra_message = *((extra_publish_message *)message);
    // int fd = *((int *)sock_fd);
    // char * addr = (char *)client_addr;
    int fd = extra_message.sockfd;
    char * client_addr = extra_message.client_addr;
    int i_recvBytes;
    char data_recv[BUFFER_LENGTH];
    unsigned char * data_recv_encrypted = NULL;
    // char payload[BUFFER_LENGTH];
    char * payload = NULL;
    unsigned char * payload_bytes = NULL;
    char * en_payload = NULL;

    // const char * data_send = "Server has received your request!\n";
    int i;

    MQTTClient client;
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    MQTTClient_message pubmsg = MQTTClient_message_initializer;
    MQTTClient_deliveryToken token;
    int rc;
    char * mqtt_topic = NULL;

    if (extra_message.socket_port == SOCK_PORT_AUTHENTICATION){
        mqtt_topic = "authentication";
    } else if (extra_message.socket_port == SOCK_PORT_PAY)
    {
        mqtt_topic = "payment";
    }
    

    // memset(payload,0,BUFFER_LENGTH);
    printf("waiting for request...\n");
    //Reset data.
    memset(data_recv,0,BUFFER_LENGTH);

    i_recvBytes = read(fd,data_recv,BUFFER_LENGTH);
    if(i_recvBytes == 0)
    {
        printf("Maybe the client has closed\n");
    }
    if(i_recvBytes == -1)
    {
        fprintf(stderr,"read error!\n");
    }
    printf("read from client : %s\n",data_recv);

    // data_recv_encrypted = SM4(data_recv);
    // printf("%s", *data_recv_encrypted);

    // strcat(data_recv, end_flag);

    payload = encapsulation_payload(data_recv, client_addr);
    // en_payload = encapsulation_payload(data_recv, client_addr);
    // strncpy(payload, encapsulation_payload(data_recv, client_addr), BUFFER_LENGTH);
    printf("明文是：\n%s\n", payload);
    printf("封装后报文长度：%d\n", strlen(payload));
    payload_bytes = SM4(payload);

    for (i = 0; i < BUFFER_LENGTH; i ++)
        {
                printf("%02x ", payload_bytes[i]);
        }
    printf("\n");

    // mqtt_publish(data_recv);
    // mqtt_publish(encapsulation_payload(data_recv_encrypted, client_addr));
    // mqtt_publish(payload_bytes);


    MQTTClient_create(&client, ADDRESS, CLIENTID,
        MQTTCLIENT_PERSISTENCE_NONE, NULL);
    conn_opts.keepAliveInterval = 20;
    conn_opts.cleansession = 1;

    if ((rc = MQTTClient_connect(client, &conn_opts)) != MQTTCLIENT_SUCCESS)
    {
        printf("Failed to connect, return code %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("发送前的报文：\n");
    for (i = 0; i < BUFFER_LENGTH; i ++)
        {
                printf("%02x ", payload_bytes[i]);
        }
    printf("\n");

    // pubmsg.payload = encapsulation_payload_publish(payload_message, strlen(payload));
    // pubmsg.payload = out;
    pubmsg.payload = payload_bytes;
    // pubmsg.payloadlen = (int)strlen(payload);
    pubmsg.payloadlen = BUFFER_LENGTH;
    pubmsg.qos = QOS;
    pubmsg.retained = 0;
    MQTTClient_publishMessage(client, mqtt_topic, &pubmsg, &token);
    // printf("Waiting for up to %d seconds for publication of %s\n"
    //         "on topic %s for client with ClientID: %s\n",
    //         (int)(TIMEOUT/1000), payload, AUTHENTICATION_TOPIC, CLIENTID);
    rc = MQTTClient_waitForCompletion(client, token, TIMEOUT);
    printf("Message with delivery token %d delivered\n", token);
    MQTTClient_disconnect(client, 10000);
    MQTTClient_destroy(&client);


    //Clear
    printf("terminating current client_connection...\n");
    close(fd);            //close a file descriptor.
    pthread_exit(NULL);   //terminate calling thread!
}

int mqtt_publish(unsigned char *payload_bytes){
    MQTTClient client;
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    MQTTClient_message pubmsg = MQTTClient_message_initializer;
    MQTTClient_deliveryToken token;
    int rc;
    int i;
    unsigned char payload[BUFFER_LENGTH] = {0};

    strncpy(payload, payload_bytes, BUFFER_LENGTH);

    MQTTClient_create(&client, ADDRESS, CLIENTID,
        MQTTCLIENT_PERSISTENCE_NONE, NULL);
    conn_opts.keepAliveInterval = 20;
    conn_opts.cleansession = 1;

    if ((rc = MQTTClient_connect(client, &conn_opts)) != MQTTCLIENT_SUCCESS)
    {
        printf("Failed to connect, return code %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("发送前的报文：\n");
    for (i = 0; i < BUFFER_LENGTH; i ++)
        {
                printf("%02x ", payload[i]);
        }
    printf("\n");

    pubmsg.payload = payload;
    // pubmsg.payloadlen = (int)strlen(payload);
    pubmsg.payloadlen = BUFFER_LENGTH;
    pubmsg.qos = QOS;
    pubmsg.retained = 0;
    MQTTClient_publishMessage(client, AUTHENTICATION_TOPIC, &pubmsg, &token);
    printf("Waiting for up to %d seconds for publication of %s\n"
            "on topic %s for client with ClientID: %s\n",
            (int)(TIMEOUT/1000), payload, AUTHENTICATION_TOPIC, CLIENTID);
    rc = MQTTClient_waitForCompletion(client, token, TIMEOUT);
    printf("Message with delivery token %d delivered\n", token);
    MQTTClient_disconnect(client, 10000);
    MQTTClient_destroy(&client);
    return rc;
}

void delivered(void *context, MQTTClient_deliveryToken dt)
{
    printf("Message with token value %d delivery confirmed\n", dt);
    deliveredtoken = dt;
}

int msgarrvd(void *context, char *topicName, int topicLen, MQTTClient_message *message)
{
    int i;
    char* payloadptr;

    SGD_HANDLE phDeviceHandle;
	SGD_HANDLE phSessionHandle;
	SGD_HANDLE phKeyHandle;
    SGD_UCHAR pucIV[16] ={0};
	memset(pucIV,1,16);
    SGD_UCHAR *data_encrypt = (SGD_UCHAR *)malloc(BUFFER_LENGTH);
    SGD_UCHAR *data_decrypt = (SGD_UCHAR *)malloc(BUFFER_LENGTH);
    SGD_UINT32 ucAlgId = SGD_SM4_ECB;
    SGD_UINT32 uiEncDataLength = BUFFER_LENGTH;
    SGD_UINT32 uiDataTmpLength = BUFFER_LENGTH;
    char data_decrypt_string[BUFFER_LENGTH];
    char* client_addr = NULL;
    char* result = NULL;

    return_data data;

    printf("Message arrived\n");
    printf("     topic: %s\n", topicName);
    printf("   message: ");

    payloadptr = message->payload;

    for(i=0; i<message->payloadlen; i++)
    {
        putchar(*payloadptr++);
    }
    putchar('\n');

    SGD_RV rv = HSF_ConnectDev(&phDeviceHandle);
	if(rv != SDR_OK)
	{
		printf("HSF_ConnectDev fail\n");
		return 0;
	}
	printf("HSF_ConnectDev success!\n");
	
	rv = HSF_OpenSession(phDeviceHandle, &phSessionHandle);
	if(rv != SDR_OK)
	{
		HSF_DisConnectDev(phDeviceHandle);
		printf("HSF_OpenSession fail\n");
		return 0;
	}
	printf("HSF_OpenSession success!\n");

    data_encrypt = (unsigned char *)message->payload;
    printf("收到的密文：\n");
    for (i = 0; i < uiEncDataLength; i ++)
    {
        printf("%02x ", data_encrypt[i]);
    }
    printf("\n");
    HSF_DecryptInit(phSessionHandle, 0, KEY, pucIV, ucAlgId);
    HSF_Decrypt(phSessionHandle, data_encrypt, uiEncDataLength, data_decrypt, &uiDataTmpLength);
    // HSF_Encrypt(hSessionHandle, data_encrypt, uiEncDataLength, data_decrypt, &uiEncDataLength);
    printf("解密数据：\n");
    for (i = 0; i < uiDataTmpLength; i ++)
    {
            printf("%02x ", data_decrypt[i]);
    }
    printf("\n");

    for(i=0;i<BUFFER_LENGTH;i++){
        data_decrypt_string[i] = (char)data_decrypt[i];
    }
    printf("明文：%s\n", data_decrypt_string);

    data = *parse_payload(data_decrypt_string);
    printf("result:%s\n",data.result);
    result = data.result;
    client_addr = data.client_addr;
    put_result_to_socket_client(client_addr, result);


    MQTTClient_freeMessage(&message);
    MQTTClient_free(topicName);
    return 1;
}

void connlost(void *context, char *cause)
{
    printf("\nConnection lost\n");
    printf("     cause: %s\n", cause);
}

void mqtt_server(){
    MQTTClient client;
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    int rc;
    int ch;

    MQTTClient_create(&client, ADDRESS, AUTHENTICATION_RESULT_CLIENTID,
        MQTTCLIENT_PERSISTENCE_NONE, NULL);
    conn_opts.keepAliveInterval = 20;
    conn_opts.cleansession = 1;

    MQTTClient_setCallbacks(client, NULL, connlost, msgarrvd, delivered);
    if ((rc = MQTTClient_connect(client, &conn_opts)) != MQTTCLIENT_SUCCESS)
    {
        printf("Failed to connect, return code %d\n", rc);
        exit(EXIT_FAILURE);
    }
    printf("Subscribing to topic %s\nfor client %s using QoS%d\n\n"
           "Press Q<Enter> to quit\n\n", SUBSCRIBE_TOPIC_1, CLIENTID, QOS);
    MQTTClient_subscribe(client, SUBSCRIBE_TOPIC_1, QOS);
    MQTTClient_subscribe(client, SUBSCRIBE_TOPIC_2, QOS);

    do 
    {
        ch = getchar();
    } while(ch!='Q' && ch != 'q');

    MQTTClient_unsubscribe(client, SUBSCRIBE_TOPIC_1);
    MQTTClient_disconnect(client, 10000);
    MQTTClient_destroy(&client);
}

char * encapsulation_payload(char *data_recv, char *client_addr){
    cJSON *root = NULL;
    char * out = NULL;
    printf("封装报文-data_recv长度：%d\n",strlen(data_recv));
    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "data_recv", data_recv);
    cJSON_AddStringToObject(root, "client_addr", client_addr);
    cJSON_AddStringToObject(root, "gateway_id", GATEWAYID);
    out = cJSON_Print(root);
    strcat(out, END_FLAG);
    return out;
}

return_data * parse_payload(char * payload){
    char * out;
    cJSON * json, *item;
    char * result;
    char * client_addr;
    return_data data;

    json = cJSON_Parse((char const *)payload);
    if(!json){
        printf("json parse error!");
    } else
    {
        item = cJSON_GetObjectItem(json, "result");
        result = item->valuestring;
        item = cJSON_GetObjectItem(json, "client_addr");
        client_addr = item->valuestring;
        printf("result:%s\n client_addr:%s\n", result, client_addr);
    }

    data.client_addr = client_addr;
    data.result = result;

    return &data;
    
}

unsigned char * SM4(char * put_data){
    SGD_HANDLE phDeviceHandle;
	SGD_HANDLE phSessionHandle;
	SGD_HANDLE phKeyHandle;
	

	SGD_RV rv = HSF_ConnectDev(&phDeviceHandle);
	if(rv != SDR_OK)
	{
		printf("HSF_ConnectDev fail\n");
		return 0;
	}
	printf("HSF_ConnectDev success!\n");
	
	rv = HSF_OpenSession(phDeviceHandle, &phSessionHandle);
	if(rv != SDR_OK)
	{
		HSF_DisConnectDev(phDeviceHandle);
		printf("HSF_OpenSession fail\n");
		return 0;
	}
	printf("HSF_OpenSession success!\n");

    printf("%s\n", put_data);

    return SM4_ENC_ECB(phSessionHandle, put_data);
}

unsigned char * SM4_ENC_ECB(SGD_HANDLE hSessionHandle, char * put_data){
    
	SGD_UCHAR pucIV[16] ={0};
	memset(pucIV,1,16);
    int data_length = strlen(put_data);
	SGD_UCHAR *pucData = (SGD_UCHAR *)malloc(BUFFER_LENGTH);
	memset(pucData,0x05,BUFFER_LENGTH);
	SGD_UINT32 uiDataLength = BUFFER_LENGTH;
	SGD_UCHAR *pucEncData = (SGD_UCHAR *)malloc(BUFFER_LENGTH);;;
	SGD_UINT32 uiEncDataLength = BUFFER_LENGTH;
	
	SGD_UCHAR *pucDataTmp = (SGD_UCHAR *)malloc(BUFFER_LENGTH);
	SGD_UINT32 uiDataTmpLength = BUFFER_LENGTH;
	
    SGD_UINT8 pucKey[16];
	memset(pucKey,2,16);
	SGD_UCHAR ucKeyID = 1;
	SGD_UINT32 ucAlgId = SGD_SM4_ECB;

    int i = 0;

    // HSF_GenerateRandom(hSessionHandle, pucData, DATALEN);

    printf("报文长度：%d\n", data_length);
    memset(pucEncData, 0, BUFFER_LENGTH);
    pucData = (SGD_UCHAR *)put_data;
	//rv = HSF_EncryptInit(hSessionHandle, ucKeyID, pucKey, pucIV, ucAlgId);
	HSF_EncryptInit(hSessionHandle, 0, KEY, pucIV, ucAlgId);;
	
	HSF_Encrypt(hSessionHandle, pucData, uiDataLength, pucEncData, &uiEncDataLength);

    printf("加密后的数据:\n");
    for (i = 0; i < uiEncDataLength; i ++)
        {
                printf("%02x ", pucEncData[i]);
        }
    printf("\n");

    return pucEncData;
}

void put_result_to_socket_client(char* client_addr, char* result){
    int sockfd;
    int tempfd;
    struct sockaddr_in s_addr_in;
    char data_send[BUFFER_LENGTH];
    // char data_recv[BUFFER_LENGTH];
    memset(data_send,0,BUFFER_LENGTH);
    // memset(data_recv,0,BUFFER_LENGTH);

    sockfd = socket(AF_INET,SOCK_STREAM,0);       //ipv4,TCP
    if(sockfd == -1)
    {
        fprintf(stderr,"socket error!\n");
        exit(1);
    }

    //before func connect, set the attr of structure sockaddr.
    memset(&s_addr_in,0,sizeof(s_addr_in));
    s_addr_in.sin_addr.s_addr = inet_addr(client_addr);      //trans char * to in_addr_t
    s_addr_in.sin_family = AF_INET;
    s_addr_in.sin_port = htons(9978);

    tempfd = connect(sockfd,(struct sockaddr *)(&s_addr_in),sizeof(s_addr_in));
    printf("建立socket连接");
    if(tempfd == -1)
    {
        fprintf(stderr,"Connect error! \n");
        exit(1);
    }

    strcpy(data_send, result);
    tempfd = write(sockfd, data_send, BUFFER_LENGTH);
    printf("发送回复报文");
    if(tempfd == -1){
        fprintf(stderr,"write error\n");
            exit(0);
    }

    // tempfd = read(sockfd,data_recv,BUFFER_LENGTH);
    // assert(tempfd != -1);
    // printf("%s\n",data_recv);
    // memset(data_send,0,BUFFER_LENGTH);
    // memset(data_recv,0,BUFFER_LENGTH);
    shutdown(sockfd,SHUT_WR);
    
    close(tempfd);
}