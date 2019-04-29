
#pragma once
#define SINGLE_MOUDLE
#define DEBUG


#include <stdio.h>
#include <initguid.h>


#include <strsafe.h>
#include <intsafe.h>
#include <atlbase.h> 
#include <atlsync.h>
#include <vector>
#include<WINNT.H>
#ifndef SINGLE_MOUDLE
#include"CProvider.h"
#endif
#include <openssl/ssl.h>
#include <openssl/err.h>
#define CXN_INSTANCE_STRING L"RemoteFingerprint Bluetooth Server"
//#define CXN_TEST_DATA_STRING              (L"~!@#$%^&*()-_=+?<>1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
//#define CXN_TRANSFER_DATA_LENGTH          (sizeof(CXN_TEST_DATA_STRING))
#define CXN_TRANSFER_DATA_LENGTH          8192


#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable : 4996)

class CProvider;
class Connect
{
public:
	Connect();
	~Connect();
	void Initialize(CProvider *_pcpro);
	void Restart();
	HRESULT InitSSL(SSL_CTX *ctx);
	HRESULT UnInitSSL(SSL *ssl);
	HRESULT GetCredit();
	bool ConnectStatus() {

		return m_fConnected;
	}

	HRESULT GetUsername(PWSTR m_pwzUsername)
	{
		wcscpy(m_pwzUsername, pwzUsername);
		return S_OK;
	}
	HRESULT GetPassword(PWSTR m_pwzPassword)
	{
		wcscpy(m_pwzPassword, pwzPassword);

		return S_OK;
	}
	static DWORD WINAPI BluetoothConnectThread(
		LPVOID lpParameter);
	static DWORD WINAPI WlanConnectThread(
		LPVOID lpParameter);

	DWORD GetLastMainErrorCode()
	{
		return error_code[0];
	};
	DWORD GetLastDetailErrorCode()
	{
		return error_code[1];
	};

	DWORD SetLastMainErrorCode(int err)
	{
		error_code[0] = err;
	};
	DWORD SetLastDetailErrorCode(int err)
	{
		error_code[1] = err;
	};
	
private:

	bool InitBluetoothConnectThread();
	bool UnInitBluetoothConnectThread();
	bool InitWlanConnectThread();
	bool UnInitWlanConnectThread();

	int BluetoothConnect();
	ULONG  BluetoothServer(_In_ int iMaxCxnCycles);
	HRESULT WlanConnect();
	HRESULT NotifyDowork();
	char *    chCreditBuffer;// 同步数据
	bool  GetCreditEvent;

	ATL::CEvent m_BluetoothConnectThreadNotifyEvent;  // 通知事件
	ATL::CEvent m_WlanConnectThreadNotifyEvent;

	// 线程句柄
	HANDLE m_bThread;
	HANDLE m_wThread;
	BOOL m_fConnected;       // 是否准备好

	PWSTR pwzUsername;
	PWSTR pwzPassword;
	DWORD error_code[2];
#ifndef SINGLE_MOUDLE
    CProvider  *_provider;
#endif

};



