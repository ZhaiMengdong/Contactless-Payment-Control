/*
 * @Description: 模拟充电桩发送报文
 * @Autor: ZMD
 * @Date: 2019-08-22 20:01:50
 * @LastEditTime: 2019-09-11 17:00:06
 */
#include<stdlib.h>
#include<sys/socket.h>
#include<sys/types.h>       //pthread_t , pthread_attr_t and so on.
#include<stdio.h>
#include<netinet/in.h>      //structure sockaddr_in
#include<arpa/inet.h>       //Func : htonl; htons; ntohl; ntohs
#include<assert.h>          //Func :assert
#include<string.h>          //Func :memset
#include<unistd.h>          //Func :close,write,read

#define SOCK_PORT 9998
#define BUFFER_LENGTH 1024

int main()
{
    int sockfd;
    int tempfd;
    struct sockaddr_in s_addr_in;
    char data_send[BUFFER_LENGTH];
    char data_recv[BUFFER_LENGTH];
    memset(data_send,0,BUFFER_LENGTH);
    memset(data_recv,0,BUFFER_LENGTH);

    sockfd = socket(AF_INET,SOCK_STREAM,0);       //ipv4,TCP
    if(sockfd == -1)
    {
        fprintf(stderr,"socket error!\n");
        exit(1);
    }

    //before func connect, set the attr of structure sockaddr.
    memset(&s_addr_in,0,sizeof(s_addr_in));
    s_addr_in.sin_addr.s_addr = inet_addr("127.0.0.1");      //trans char * to in_addr_t
    s_addr_in.sin_family = AF_INET;
    s_addr_in.sin_port = htons(SOCK_PORT);

    tempfd = connect(sockfd,(struct sockaddr *)(&s_addr_in),sizeof(s_addr_in));
    printf("建立socket连接");
    if(tempfd == -1)
    {
        fprintf(stderr,"Connect error! \n");
        exit(1);
    }

    // strcpy(data_send, "LSGJA52U1BH003531");
    // strcpy(data_send, "{\"title\":\"payment\",\"data\":\"LSGJA52U1BH003531\"}");
    strcpy(data_send, "{\"title\":\"pay\",\"properties\":{\"meterStop\":\"30\",\"vendorId\":\"4179187517\",\"reason\":\"EVDisconnected\",\"transactionData\":{\"sampledValue\":{\"items\":{\"location\":\"114.064506,22.549258\"}}}}}");
    tempfd = write(sockfd, data_send, BUFFER_LENGTH);
    printf("发送模拟报文");
    if(tempfd == -1){
        fprintf(stderr,"write error\n");
            exit(0);
    }

    tempfd = read(sockfd,data_recv,BUFFER_LENGTH);
    assert(tempfd != -1);
    printf("%s\n",data_recv);
    memset(data_send,0,BUFFER_LENGTH);
    memset(data_recv,0,BUFFER_LENGTH);
    
    close(tempfd);

    // int ret = shutdown(sockfd,SHUT_WR);       //or you can use func close()--<unistd.h> to close the fd
    // assert(ret != -1);
    return 0;
}
