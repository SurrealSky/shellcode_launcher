#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include<stdbool.h>

#define htonl(x) ((x&0x000000ff) << 24 | (x&0x0000ff00) << 8 | (x&0x00ff0000) >> 8 | (x&0xff000000) >> 24)
#define HIDWORD(x)  (*((DWORD*)&(x)+1))

void ForDelay();
void ForBD();
bool ForSD();