// WinSSLSocket.cpp :
//

#include "stdafx.h"
#include <windows.h>
#include <iostream>
#include"Connect.h"

int main()
{
	PWSTR testuser;
	PWSTR testpaswd;
	testuser = (PWSTR)malloc(CXN_TRANSFER_DATA_LENGTH);;
	testpaswd= (PWSTR)malloc(CXN_TRANSFER_DATA_LENGTH);
	Connect *test = new Connect();

	while (true)
	{
		Sleep(1000);
		if (test->ConnectStatus())
		{
			break;
		}


	}
	test->GetUsername(testuser);
	test->GetPassword(testpaswd);
	
	wprintf(L"用户名:");
	wprintf(L"%s\n", testuser);
	wprintf(L"密码:");
	wprintf(L"%s\n", testpaswd);
	system("pause");
}

