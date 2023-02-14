#include"bypass.h"

//阻止非签名的DLL注入
void ForBD()
{
	//系统需要>=win8系统
	//PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signature = { 0 };
	//GetProcessMitigationPolicy((HANDLE)(-1), (PROCESS_MITIGATION_POLICY)ProcessSignaturePolicy, &signature, sizeof(signature));
	//signature.MicrosoftSignedOnly = 1;
	//SetProcessMitigationPolicy((PROCESS_MITIGATION_POLICY)ProcessSignaturePolicy, &signature, sizeof(signature));
}

//检测沙箱
bool ForSD()
{
	int v3;
	__int64 v4;
	v3 = GetTickCount64();
	Sleep(300u);
	v4 = (int)(-300 - v3 + GetTickCount64());
	if ((int)((HIDWORD(v4) ^ v4) - HIDWORD(v4)) > 100)
		return true;
	else
		return false;

}