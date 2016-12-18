#include <Windows.h>
#include <ImageHlp.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#pragma comment(lib, "ImageHlp")


static BOOL CALLBACK EnumResLangProc(HMODULE mod, LPCWSTR type, LPCWSTR name, WORD lang, LONG_PTR param)
{
	if (*(WORD*)param != 0xffff)
		return FALSE; // multiple lang IDs present
	*(WORD*)param = lang;
	return TRUE;
}

int UpdateResourceString(const char* filename, unsigned id, const char* value)
{
	HMODULE mod = LoadLibraryExA(filename, NULL, DONT_RESOLVE_DLL_REFERENCES|LOAD_LIBRARY_AS_DATAFILE);
	if (mod == NULL)
		return 0;
	unsigned name = 1 + id / 16;
	WORD lang = 0xffff;
	if (TRUE != EnumResourceLanguagesW(mod, (LPCWSTR)RT_STRING, MAKEINTRESOURCEW(name), EnumResLangProc, (LONG_PTR)&lang))
		return 0;
	HRSRC res = FindResourceExW(mod, (LPCWSTR)RT_STRING, MAKEINTRESOURCEW(name), lang);
	if (res == NULL)
		return 0;
	HGLOBAL glob = LoadResource(mod, res);
	if (glob == NULL)
		return 0;
	WORD* p = (WORD*)LockResource(glob);
	if (p == NULL)
		return 0;
	int valueLen = strlen(value);
	int strblockLen = SizeofResource(mod, res) + (10 + valueLen) * sizeof(WORD);
	WORD* strblock = (WORD*)malloc(strblockLen), *o = strblock;

	for (int i = 0; i < 16; ++i)
	{
		if (i == (id & 0xf))
		{
			assert(*p && "string didn't exist in strblock");
			*o = (WORD)valueLen;
			for (int i = 0; i < valueLen; ++i)
				o[1 + i] = value[i];
			o += valueLen + 1;
		}
		else
		{
			memcpy(o, p, (1 + *p) * sizeof(WORD));
			o += 1 + *p;
		}
		p += 1 + *p;
	}
	strblockLen = sizeof(WORD) * (o - strblock);
	BOOL fret = FreeLibrary(mod);
	HANDLE h = BeginUpdateResourceA(filename, FALSE);
	int ret = 0;
	if (TRUE != UpdateResourceW(h, (LPCWSTR)RT_STRING, MAKEINTRESOURCEW(name), lang, (LPVOID)strblock, (DWORD)strblockLen))
		EndUpdateResourceW(h, TRUE);
	else
		ret = (TRUE == EndUpdateResourceW(h, FALSE)) ? 1 : 0;
	free(strblock);
	return ret;
}

int UpdateChecksum(const char* filename)
{
	HANDLE fl = CreateFileA(filename, FILE_READ_DATA | FILE_WRITE_DATA, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (INVALID_HANDLE_VALUE == fl || NULL == fl)
		return 0;
	HANDLE flMapping = CreateFileMapping(fl, NULL, PAGE_READWRITE, 0, 0, NULL);
	if (!flMapping)
		return 0;
	void* baseAddr = MapViewOfFile(flMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (!baseAddr)
		return 0;
	LARGE_INTEGER fileSize = { 0, 0 };
	if (TRUE != GetFileSizeEx(fl, &fileSize))
		return 0;
	DWORD headerSum = 0, checkSum = 0;
	PIMAGE_NT_HEADERS headers = CheckSumMappedFile(baseAddr, fileSize.LowPart, &headerSum, &checkSum);
	if (!headers)
		return 0;

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)(baseAddr);
	if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((PBYTE)baseAddr + dosHeader->e_lfanew);
		if (ntHeader->Signature == IMAGE_NT_SIGNATURE)
			ntHeader->OptionalHeader.CheckSum = checkSum;
	}
	UnmapViewOfFile(baseAddr);
	CloseHandle(fl);
	return 1;
}

int main(int argc, const char **argv)
{
	if (argc < 4 || (argc & 1) != 0)
	{
		printf("rc_string.exe program.exe [id value]*\n\n"
			"  Where id is string ID and value is the new string value.\n"
			"  Multiple pairs of id/value can be specified. Example:\n"
			"  rc_string.exe program.exe 100 \"new value\" 101 \"example.com\"\n");
		return 1;
	}
	for (int i=2; i<argc; i+=2)
	{
		if (!UpdateResourceString(argv[1], atoi(argv[i]), argv[i+1]))
		{
			printf("failed to update string for id:%s value=\"%s\". GetLastError:%d\n", argv[i], argv[i+1], GetLastError());
			return 1;
		}
	}
	if (!UpdateChecksum(argv[1]))
	{
		printf("failed to update checksum. GetLastError:%d\n", GetLastError());
		return 1;
	}
	return 0;
}
