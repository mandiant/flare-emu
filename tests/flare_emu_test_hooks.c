/*
Copyright (C) 2018 FireEye, Inc.

Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-BSD-3-CLAUSE or
https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be
copied, modified, or distributed except according to those terms.

Author: James T. Bennett

unit tests for flare-emu
tests for iterate and runtime/Windows API function hook features of flare-emu
*/

#include <stdio.h>
#include <Windows.h>

int main()
{
	char str[] = "this is a test";
	wchar_t wstr[50];
	char str2[50];
	char *str3, *str4;
	wchar_t *wstr2, *wstr3;
	int ret;
	BOOL flag;
	HANDLE hHandle;
	ret = MultiByteToWideChar(CP_ACP, 0, str, -1, wstr, 50);
	printf("%S is %d bytes from MultiByteToWideChar\r\n", wstr, ret);
	ret = WideCharToMultiByte(CP_ACP, 0, wstr, -1, str2, sizeof(str2), NULL, &flag);
	printf("%s is %d bytes from WideCharToMultiByte\r\n", str2, ret);
	ZeroMemory(wstr, sizeof(wstr));
	ZeroMemory(str2, sizeof(str2));
	ret = MultiByteToWideChar(CP_ACP, 0, str, 4, wstr, 50);
	printf("%S is %d bytes from truncated MultiByteToWideChar\r\n", wstr, ret);
	ret = WideCharToMultiByte(CP_ACP, 0, wstr, 4, str2, sizeof(str2), NULL, &flag);
	printf("%s is %d bytes from truncated WideCharToMultiByte\r\n", str2, ret);
	hHandle = GetProcessHeap();
	if (!hHandle)
		return -1;
	str3 = (char*)HeapAlloc(hHandle, NULL, 0x1000);
	strcpy(str3, str);
	printf("%s strcpy to HeapAlloc\r\n", str3);
	ZeroMemory(str3, 0x1000);
	lstrcpy(str3, str);
	printf("%s lstrcpy to HeapAlloc\r\n", str3);
	str3 = (char*)HeapReAlloc(hHandle, NULL, str3, 0x2000);
	printf("%s from HeapReAlloc\r\n", str3);
	HeapFree(hHandle, NULL, str3);
	str3 = (char*)LocalAlloc(LMEM_FIXED, 0x1000);
	strncpy(str3, str, sizeof(str));
	printf("%s strncpy to fixed LocalAlloc\r\n", str3);
	strncpy(str3, str2, sizeof(str2));
	printf("%s strncpy to fixed LocalAlloc with padding\r\n", str3);
	LocalFree(str3);
	hHandle = LocalAlloc(LMEM_MOVEABLE, 0x1000);
	str3 = (char*)LocalLock(hHandle);
	strncpy_s(str3, 0x1000, str, sizeof(str));
	printf("%s strncpy_s to movable LocalAlloc\r\n", str3);
	LocalUnlock(hHandle);
	hHandle = LocalReAlloc(hHandle, 0x2000, NULL);
	str3 = (char*)LocalLock(hHandle);
	printf("%s from LocalReAlloc\r\n", str3);
	LocalFree(hHandle);
	VirtualAlloc((LPVOID)0x99000, 0x2000, MEM_RESERVE, PAGE_READWRITE);
	wstr2 = (wchar_t*)VirtualAlloc((LPVOID)0x99000, 0x2000, MEM_COMMIT, PAGE_READWRITE);
	ret = mbstowcs(wstr2, str, sizeof(str));
	printf("%S mbstowcs (returned %d) to double VirtualAlloc\r\n", wstr2, ret);
	VirtualFree((LPVOID)wstr2, 0x2000, MEM_RELEASE);
	wstr2 = (wchar_t*)VirtualAlloc(NULL, 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	ret = mbtowc(wstr2, str, sizeof(str));
	printf("%S mbtowc (returned %d) to single VirtualAlloc\r\n", wstr2, ret);
	VirtualFree((LPVOID)wstr2, 0x2000, MEM_RELEASE);
	hHandle = GetCurrentProcess();
	wstr2 = (wchar_t*)VirtualAllocEx(hHandle, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	wcscpy(wstr2, wstr);
	printf("%S wcscpy to VirtualAllocEx\r\n", wstr2);
	VirtualFreeEx(hHandle, wstr2, 0x1000, MEM_RELEASE);
	wstr2 = (wchar_t*)malloc(0x1000);
	wcsncpy(wstr2, wstr, sizeof(wstr));
	printf("%S wcsncpy to malloc\r\n", wstr2);
	mbstowcs(wstr2, str, sizeof(str));
	wcsncpy(wstr2, L"test", 20);
	printf("%S wcsncpy to malloc with padding\r\n", wstr2);
	free(wstr2);
	wstr2 = (wchar_t*)calloc(0x1000, 2);
	wcsncpy_s(wstr2, 0x1000, wstr, sizeof(wstr));
	printf("%S wcsncpy_s to calloc\r\n", wstr2);
	memcpy(wstr2 + 20, str + 10, 5);
	printf("%s memcpy to offset\r\n", (char*)(wstr2 + 20));
	printf("%s is %d characters in strlen\r\n", str, strlen(str));
	printf("%s is not really %d characters in strnlen\r\n", str, strnlen(str, 2));
	wcsncpy(wstr2, wstr, sizeof(wstr));
	printf("%S is %d characters in wcslen\r\n", wstr2, wcslen(wstr2));
	printf("%S is not really %d characters in wcsnlen\r\n", wstr2, wcsnlen(wstr2, 2));
	free(wstr2);
	str3 = (char*)malloc(0x1000);
	strcpy(str3, str);
	printf("%s strcmp %s result is %d\r\n", str3, str, strcmp(str3, str));
	_strupr(str3);
	printf("%s stricmp %s result is %d\r\n", str3, str, _stricmp(str3, str));
	strcpy(str3, str);
	strcpy(str3 + 10, "mess");
	printf("%s strncmp %s 10 chars result is %d\r\n", str3, str, strncmp(str3, str, 10));
	_strupr(str3);
	printf("%s strnicmp %s 10 chars result is %d\r\n", str3, str, _strnicmp(str3, str, 10));
	free(str3);
	wstr2 = (wchar_t*)malloc(0x1000);
	mbstowcs(wstr, str, sizeof(str));
	mbstowcs(wstr2, str, sizeof(str));
	printf("%S wcscmp %S result is %d\r\n", wstr2, wstr, wcscmp(wstr2, wstr));
	_wcsupr(wstr2);
	printf("%S wcsicmp %S result is %d\r\n", wstr2, wstr, _wcsicmp(wstr2, wstr));
	wcscpy(wstr2, wstr);
	wcscpy(wstr2 + 10, L"mess");
	printf("%S wcsncmp %S 10 chars result is %d\r\n", wstr2, wstr, wcsncmp(wstr2, wstr, 10));
	_wcsupr(wstr2);
	printf("%S wcsnicmp %S 10 chars result is %d\r\n", wstr2, wstr, _wcsnicmp(wstr2, wstr, 10));
	printf("%c is strchr index %d in %s\r\n", 'a', ((unsigned int)strchr(str, 'a') - (unsigned int)str), str);
	printf("%C is wcschr index %d in %S\r\n", L'a', ((unsigned int)wcschr(wstr, L'a') - (unsigned int)wstr) / 2, wstr);
	printf("%c is strrchr index %d in %s\r\n", 't', ((unsigned int)strrchr(str, 't') - (unsigned int)str), str);
	printf("%C is wcsrchr index %d in %S\r\n", L't', ((unsigned int)wcsrchr(wstr, L't') - (unsigned int)wstr) / 2, wstr);
	free(wstr2);
	str3 = (char*)malloc(0x1000);
	memset(str3, 0, 0x1000);
	strcat(str3, "The Quick Brown Fox ");
	strncat(str3, "Jumps Over ", 100);
	strncat(str3, "The Lazy DogAAAAAAAAA", 12);
	printf("strcat %s\r\n", str3);
	printf("strlwr %s\r\n", _strlwr(str3));
	wstr2 = (wchar_t*)malloc(0x1000);
	memset(wstr2, 0, 0x1000);
	wcscat(wstr2, L"The Quick Brown Fox ");
	wcsncat(wstr2, L"Jumps Over ", 100);
	wcsncat(wstr2, L"The Lazy DogAAAAAAAAA", 12);
	printf("wcscat %S\r\n", wstr2);
	printf("wcslwr %S\r\n", _wcslwr(wstr2));
	str4 = _strdup(str3);
	memset(str3, 0, 0x1000);
	printf("strdup %s\r\n", str4);
	wstr3 = _wcsdup(wstr2);
	memset(wstr2, 0, 0x1000);
	printf("wcsdup %S\r\n", wstr3);
	free(str4);
	free(wstr3);
	free(str3);
	free(wstr2);
	return 0;
}

