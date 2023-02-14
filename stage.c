#include"stage.h"
#include <Wininet.h>

#pragma comment(lib, "Wininet.lib")

#define BASE_SIZE 1024

bool GetStageless(unsigned char* urlStr, unsigned char** dst, unsigned int *size)
{
	char  buffer[BASE_SIZE];
	unsigned int dwReadSize = 0;
	unsigned int dwWriteSize =0;

	//初始化大小
	unsigned int dwAllocSize = BASE_SIZE * 10;
	*dst = malloc(dwAllocSize);
	if (*dst == 0) return false;

	memset(&buffer, 0, sizeof(buffer));
	HINTERNET hInternet = InternetOpen(0, INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0);
	if (0 != hInternet)
	{
		HINTERNET hOpenURL = InternetOpenUrl(hInternet,
			urlStr,
			0,
			0,
			INTERNET_FLAG_EXISTING_CONNECT | INTERNET_FLAG_NO_CACHE_WRITE,
			0);
		if (hOpenURL)
		{
			BOOL bSuccess = InternetReadFile(hOpenURL,buffer,sizeof(buffer),&dwReadSize);
			while (bSuccess && dwReadSize)
			{
				if (dwAllocSize > dwWriteSize && dwAllocSize - dwWriteSize >= dwReadSize)
				{
					memcpy(*dst + dwWriteSize, buffer, dwReadSize);
				}
				else
				{
					//重新申请空间
					dwAllocSize += dwReadSize * 5;
					*dst = realloc(*dst,dwAllocSize);
					if (*dst == 0) return false;
					memcpy(*dst + dwWriteSize, buffer, dwReadSize);
				}
				dwWriteSize += dwReadSize;
				memset(&buffer, NULL, sizeof(buffer) / sizeof(byte));
				bSuccess = InternetReadFile(hOpenURL, buffer, sizeof(buffer), &dwReadSize);
			}
			*size = dwWriteSize;
			InternetCloseHandle(hInternet);
			return true;
		}
		else
		{
			InternetCloseHandle(hInternet);
			return false;
		}
	}
	return false;
}

bool DecryptStageless(unsigned char* buffer, unsigned int size)
{
	return true;
}