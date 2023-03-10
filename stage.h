#pragma once
#include<Windows.h>
#include<stdbool.h>

bool GetStageless(unsigned char *url,unsigned char** dst, unsigned int *size);

bool DecryptStageless(unsigned char* buffer, unsigned int size);