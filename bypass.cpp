#include"bypass.h"
#include <ctime> 
#include <chrono>
#include <thread>

//阻止非签名的DLL注入
void ForBD()
{
	//系统需要>=win8系统
	//PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signature = { 0 };
	//GetProcessMitigationPolicy((HANDLE)(-1), (PROCESS_MITIGATION_POLICY)ProcessSignaturePolicy, &signature, sizeof(signature));
	//signature.MicrosoftSignedOnly = 1;
	//SetProcessMitigationPolicy((PROCESS_MITIGATION_POLICY)ProcessSignaturePolicy, &signature, sizeof(signature));
}

bool byTime()
{
	int v3;
	__int64 v4;
	v3 = GetTickCount64();
	////判断开机时间是否小于1小时
	//if (v3 < 3600000)
	//	return true;
	//else
	//	return false;
	Sleep(300u);
	v4 = (int)(-300 - v3 + GetTickCount64());
	if ((int)((HIDWORD(v4) ^ v4) - HIDWORD(v4)) > 100)
		return true;
	else
		return false;
}

bool byCPUID()
{
	DWORD dw_ecx;
	bool bFlag = true;
	_asm {
		pushad
		pushfd
		mov eax,1
		cpuid
		mov dw_ecx,ecx
		and ecx,0x80000000
		test ecx,ecx
		setz[bFlag]
		popfd
		popad
	}
	if (bFlag)
		return false;
	else
		return true;

}

void ForDelay()
{
	std::chrono::seconds t = std::chrono::seconds(60);
	//std::this_thread::sleep_for(t);
}


//检测沙箱
bool ForSD()
{
	return (byTime() || byCPUID());
}