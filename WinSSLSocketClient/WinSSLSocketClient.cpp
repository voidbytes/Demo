

#include "pch.h"
#include <iostream>
#include <WinSock2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#define RECV_BUFFER_SIZE 8192
#define DEFAULT_PORT  2087
#define IP_ADDRESS  "127.0.0.1"
#pragma comment(lib, "ws2_32.lib")
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
	recv(ConnectSocket, ver, (sizeof(ver) / sizeof(char)), 0);
	printf("版本号：%s\n", ver);
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

	int len = SSL_write(ssl, SendIdentical, strlen(SendIdentical));
	if (len < 0)
	{
		
		printf
		("消息'%s'发送失败！错误代码是%d，错误信息是'%s'/n",
			SendIdentical, errno, strerror(errno));
	}
	else
	{
		
	printf("消息'%s'发送成功\n共发送了%d个字节！\n",
		SendIdentical, len);
}

	/* 关闭连接 */
	SSL_shutdown(ssl);
	SSL_free(ssl);
	closesocket(ConnectSocket);
	SSL_CTX_free(ctx);



	printf("ok\n");
	system("pause");
	return 0;
}
