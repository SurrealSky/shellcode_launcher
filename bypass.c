#include"bypass.h"

//��ֹ��ǩ����DLLע��
void ForBD()
{
	//ϵͳ��Ҫ>=win8ϵͳ
	//PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signature = { 0 };
	//GetProcessMitigationPolicy((HANDLE)(-1), (PROCESS_MITIGATION_POLICY)ProcessSignaturePolicy, &signature, sizeof(signature));
	//signature.MicrosoftSignedOnly = 1;
	//SetProcessMitigationPolicy((PROCESS_MITIGATION_POLICY)ProcessSignaturePolicy, &signature, sizeof(signature));
}

//���ɳ��
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