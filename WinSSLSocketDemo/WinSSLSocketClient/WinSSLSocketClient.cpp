

#include "pch.h"
#include <iostream>
#include <WinSock2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#define RECV_BUFFER_SIZE 8192
#define DEFAULT_PORT  2084
#define IP_ADDRESS  "192.168.43.204"
#pragma comment(lib, "ws2_32.lib")

#define BEGIN_NUM 19900711
#define DATA_NUM  20160113
#define END_NUM   11700991
#define BLOCK_DATA_SIZE (10 * 1024)
#define FILE_HEAD  4
#define BLOCK_HEAD 4

int main()
{

	SOCKADDR_IN clientService;
	SOCKET ConnectSocket;
	WSADATA wsaData;
	int bytesRecv = 0;
	char SendIdentical[128] = "{\"username\":\"test\",\"passwd\":\"testpasswd\"}"; //此处定义的char不是utf-8，服务端使用的是UTF-8

	SSL_CTX *ctx;
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(TLS_client_method());

	if (ctx == NULL) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}



	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != NO_ERROR)
	{
		;//to do
	}
	ConnectSocket = socket(AF_INET,
		SOCK_STREAM,
		IPPROTO_TCP
	);

	if (ConnectSocket == INVALID_SOCKET)
	{
		WSACleanup();
		return 1;

	}
	clientService.sin_family = AF_INET;
	clientService.sin_addr.s_addr = inet_addr(IP_ADDRESS);
	clientService.sin_port = htons(DEFAULT_PORT);
	if (connect(ConnectSocket,
		(SOCKADDR *)&clientService,
		sizeof(clientService)) == SOCKET_ERROR)
	{

		WSACleanup();
		return 1;
	}
	char ver[5];
	//recv(ConnectSocket, ver, (sizeof(ver) / sizeof(char)), 0);
	//printf("版本号：%s\n", ver);
	//ssl
	 /* 基于 ctx 产生一个新的 SSL */

	SSL *ssl;
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, ConnectSocket);
	/* 建立 SSL 连接 */
	if (SSL_connect(ssl) == -1)
		ERR_print_errors_fp(stderr);
	else {
		printf("使用 %s 加密方式\n", SSL_get_cipher(ssl));

	}




	X509 *cert;
	cert = SSL_get_peer_certificate(ssl);
	for (;;)
	{
		int len = SSL_write(ssl, SendIdentical, strlen(SendIdentical));
		if (len < 0)
		{

			printf
			("消息'%s'发送失败！错误代码是%d，错误信息是'%s'\n",
				SendIdentical, errno, strerror(errno));
		}
		else
		{

			printf("消息'%s'发送成功\n共发送了%d个字节！\n",
				SendIdentical, len);
		}
		Sleep(1000);
	}
	

	//接收文件

	char *eachBuf = new char[BLOCK_DATA_SIZE + 2 * FILE_HEAD];
	memset(eachBuf, 0, BLOCK_DATA_SIZE + 2 * FILE_HEAD);
	FILE *fp;
	UINT dwFileSize = 0;
	unsigned int RecvNum = 0, flag_status = 0, flag_recv = 1;
	fp = fopen("test", "wb+");


	recv(ConnectSocket, eachBuf, 2 * FILE_HEAD, 0);//////----------------recv
	char charFileSize[4] = { 0 };
	memcpy(charFileSize, eachBuf, FILE_HEAD); //拷贝前4个字节
	for (int i = 0; i < 4; i++)
	{
		flag_status += ((UCHAR)charFileSize[i]) << (8 * (4 - i - 1)); //获取文件起始符
	}
	memcpy(charFileSize, eachBuf + FILE_HEAD, FILE_HEAD); //拷贝第5-8个字节
	for (int i = 0; i < 4; i++)
	{
		dwFileSize += ((UCHAR)charFileSize[i]) << (8 * (4 - i - 1)); //获取文件大小
	}
	int start = clock();
	{
		
		//开辟接收内存
		int DataPos = 0;
		char *FileBuffer = new char[dwFileSize];
		memset(FileBuffer, 0, dwFileSize);
		while (1)
		{
			int ret = recv(ConnectSocket, eachBuf, BLOCK_DATA_SIZE, 0);
			if (ret <= 0)
				break;
			memcpy(FileBuffer + DataPos, eachBuf, ret);
			DataPos = DataPos + ret;
		}
		
		fwrite(FileBuffer, dwFileSize, 1, fp);
		
		fclose(fp);
	}
	int end = clock();
	std::cout << "time:" << end - start << "ms" << RecvNum << std::endl;


	/* 关闭连接 */
	SSL_shutdown(ssl);
	SSL_free(ssl);
	closesocket(ConnectSocket);
	SSL_CTX_free(ctx);



	printf("ok\n");
	system("pause");
	return 0;
}
