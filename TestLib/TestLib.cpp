// TestLib.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <vector>
#include <algorithm>
#include <list>
#include <memory>

#include <Windows.h>
#include <ImageHlp.h>
#include "PEParser.h"
#include "capstone/capstone.h";

#pragma comment(lib,"PEParser")
#pragma comment(lib,"Version")
#pragma comment(lib,"Dbghelp.lib")

#pragma comment(lib,"ntdll")

#ifdef _WIN64
#pragma comment(lib,"capstone-4.0.2-win64/capstone.lib")
#else
#pragma comment(lib,"capstone-4.0.2-win32/capstone.lib")
#endif // _WIN64

extern "C"
NTSTATUS
NTAPI
ZwQuerySystemInformation(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength OPTIONAL
);

struct SymbolEntry {
	std::wstring Name;
	DWORD64 Address;
};

std::list<SymbolEntry> g_Symbols;

void test() {
	int index;
	bool found;
	PEParser parser(L"win32u.dll");


	std::vector<std::pair<std::string, ULONG>> services;
	std::pair<std::string, ULONG> service;

	std::vector<ExportedSymbol> exports = parser.GetExports();
	for (const auto& symbol : exports) {
		if (symbol.ForwardName.length() > 0)
			std::cout << symbol.ForwardName << std::endl;
		if (symbol.Name.length() > 0) {
			found = false;
			int offset = parser.GetExportByName(symbol.Name.c_str());
			if (offset != 0) {
				unsigned char* exportData = (unsigned char*)parser.GetBaseAddress() + offset;
				for (int i = 0; i < 16; i++) {
					if (exportData[i] == 0xC2 || exportData[i] == 0xC3)  //RET
						break;
					if (exportData[i] == 0xB8)  //mov eax,X
					{
						ULONG* address = (ULONG*)(exportData + i + 1);
						index = *address;
						address += 1;
						auto opcode = *(unsigned short*)address;
						unsigned char* p = (unsigned char*)address + 5;
						auto code = *(unsigned char*)p;
						if (code != 0xFF &&// x86
							opcode != 0x04F6  // win10 x64
							&& opcode != 0x050F) { // win7 x64
							break;
						}
						found = true;
						//printf("%s's system service number is %x\n", symbol.Name.c_str(), index);
						service.first = symbol.Name;
						service.second = index;
						services.push_back(service);
						break;
					}
				}
			}
			if (!found) {
				//printf("%s's system service number not found...\n", symbol.Name.c_str());
			}
		}
	}

	std::sort(services.begin(), services.end(), [&](auto& i1, auto& i2) {
		return i1.second < i2.second;
		});

	int size = 0;
	printf("total services: %d\n", services.size());
	int count = 0;
	for (auto& item : services) {
		/* ++count;
		 if (count == 2) {
			 if (size != item.second)
				 printf("invalid number %x  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n", size++);
			 std::cout << item.first << ": " << std::hex << item.second << std::endl;
			 count = 0;
			 size++;
		 }*/
		printf("service: %s number: %x\r\n", item.first.c_str(), item.second);
	}
	printf("total size: %d", size);
}

bool GetWin32kBuildVersion(PDWORD buildNumber) {
	void* buffer = nullptr;
	WCHAR path[MAX_PATH];
	bool success;
	void* value;

	GetSystemDirectory(path, sizeof(path));
	wcscat_s(path, L"\\win32k.sys");
	DWORD handle;

	ULONG size = GetFileVersionInfoSize(path, &handle);
	if (size) {
		buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
		if (buffer) {
			if (GetFileVersionInfo(path, 0, size, buffer)) {
				// The root block. 
				UINT len;
				success = VerQueryValue(buffer, L"\\", &value, &len);
				if (success) {
					auto info = (VS_FIXEDFILEINFO*)value;
					*buildNumber = HIWORD(info->dwFileVersionLS);   // 19041
					HeapFree(GetProcessHeap(), 0, buffer);
					return true;
				}
			}
			HeapFree(GetProcessHeap(), 0, buffer);
		}
	}

	return false;
}


std::wstring Ansi2WChar(LPCSTR pszSrc, int nLen) {
	int nSize = MultiByteToWideChar(CP_ACP, 0, (LPCSTR)pszSrc, nLen, 0, 0);
	if (nSize <= 0) return NULL;

	WCHAR* pwszDst = new WCHAR[nSize + 1];
	if (NULL == pwszDst) return NULL;

	MultiByteToWideChar(CP_ACP, 0, (LPCSTR)pszSrc, nLen, pwszDst, nSize);
	pwszDst[nSize] = 0;

	if (pwszDst[0] == 0xFEFF) // skip Oxfeff
		for (int i = 0; i < nSize; i++)
			pwszDst[i] = pwszDst[i + 1];

	std::wstring wcharString(pwszDst);
	delete pwszDst;

	return wcharString;
}

extern "C"
BOOL CALLBACK SymEnumSymbolsProc(
	_In_ PSYMBOL_INFO pSymInfo,
	_In_ ULONG SymbolSize,
	_In_opt_ PVOID UserContext
) {
	UNREFERENCED_PARAMETER(UserContext);
	//printf("%I64X %4u %ws, %I64X\n", pSymInfo->Address, SymbolSize, pSymInfo->Name, pSymInfo->Value);
	SymbolEntry entry;
	entry.Name = Ansi2WChar(pSymInfo->Name, strlen(pSymInfo->Name) + 1);
	entry.Address = pSymInfo->Address;
	g_Symbols.push_back(entry);

	return TRUE;
}

DWORD64 GetSymbolAddressByName(LPCTSTR name) {
	for (const auto& symbol : g_Symbols) {
		if (!wcscmp(name, symbol.Name.c_str()))
			return symbol.Address;
	}
	return 0;
}

struct ShadowServiceEntry {
	ULONG Index;
	USHORT NameLength;
	WCHAR Name[ANYSIZE_ARRAY];
};

#define IOCTL_TEST_ADD_SERVICE_NAME \
	CTL_CODE(0x8000,0x803,METHOD_BUFFERED,FILE_ANY_ACCESS)

int Error(const char* text) {
	printf("%s (%d)\n", text, ::GetLastError());
	return 1;
}

void FindSSDT() {
	WCHAR path[MAX_PATH];
	::GetSystemDirectory(path, sizeof(path));
	wcscat_s(path, L"\\ntdll.dll");

	PEParser parser(path);
	std::vector<ExportedSymbol> exports = parser.GetExports();
	DWORD index;
	int ntCount = 0, zwCount = 0;
	struct SSDT {
		int Index;
		std::string Name;
	};

	std::vector<SSDT> ssdt;
	for (auto exported : exports) {
		unsigned char* exportData = (unsigned char*)parser.RVA2FA(exported.Address);
		std::string::size_type pos = exported.Name.find("Zw");
		if (pos == exported.Name.npos) {
			continue;
		}
		for (int i = 0; i < 16; i++) {
			if (exportData[i] == 0xC2 || exportData[i] == 0xC3)  //RET
				break;
			if (exportData[i] == 0xB8)  //mov eax,X
			{
				ULONG* address = (ULONG*)(exportData + i + 1);
				index = *address;
				address += 1;
				auto opcode = *(unsigned short*)address;
				unsigned char* p = (unsigned char*)address + 5;
				auto code = *(unsigned char*)p;
				if (code != 0xFF &&// x86
					opcode != 0x04F6  // win10 x64
					&& opcode != 0x050F) { // win7 x64
					break;
				}
				//printf("Address: %llX, Name: %s index: %x\n", exported.Address, exported.Name.c_str(), index);
				ntCount++;
				SSDT entry;
				entry.Name = exported.Name;
				entry.Index = index;
				ssdt.push_back(entry);
			}
		}
	}
	std::sort(ssdt.begin(), ssdt.end(), [&](auto& s1,auto& s2) {
		return s1.Index < s2.Index;
		});

	for (auto entry : ssdt) {
		printf("%d %s\n", entry.Index, entry.Name.c_str());
	}

	int x = 0;// 标识初值
	for (int i = 0; i < ssdt.size(); i++) {
		if (ssdt[i].Index != x) {
			printf("Miss number: %d\n", x);
			i--;// 如果此位置缺失则继续判断此位置的数
			ntCount++;
		}
		x++;// 增量
	}

	printf("NtCount: %d\n", ntCount);
}

int main() {
	FindSSDT();
	WCHAR path[MAX_PATH];
	::GetSystemDirectory(path, sizeof(path));
	wcscat_s(path, L"\\win32k.sys");

	CHAR imagePath[MAX_PATH];
	GetSystemDirectoryA(imagePath, sizeof(imagePath));
	strcat_s(imagePath, "\\win32k.sys");

	printf("%ws\n", path);
	PEParser parser(path);

	auto imageBase = parser.IsPe64() ? parser.GetOptionalHeader64().ImageBase : parser.GetOptionalHeader32().ImageBase;

	csh handle;
	cs_insn* insn;
	if (cs_open(CS_ARCH_X86, parser.IsPe64() ? CS_MODE_64 : CS_MODE_32, &handle))
		return -1;

	DWORD buildNumber;
	GetWin32kBuildVersion(&buildNumber);
	printf("buildNumber: %d\n", buildNumber);

	/*HANDLE hDevice = ::CreateFile(L"\\\\.\\KernelLibTest",
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, nullptr);
	if (hDevice == INVALID_HANDLE_VALUE) {
		return Error("Failed to open device");
	}*/
	if (buildNumber > 9600) {   // windows 8.1
		if (buildNumber >= 18936) { // windows 20h1
			test(); // win32u.dll
		}
		else {	// we can build table directly from win32k.sys without using symbols.
			ULONG_PTR base = (ULONG_PTR)parser.GetBaseAddress();
			ULONG_PTR pW32pServiceLimit = parser.GetExportByName("W32pServiceLimit") + base;
			if (pW32pServiceLimit == NULL) {
				printf("W32pServiceLimit not found.\n");
				return 0;
			}
			printf("pW32pServiceLimit: %p\n", pW32pServiceLimit);
			ULONG limit = *(ULONG*)pW32pServiceLimit;
			printf("limit %x\n", limit);

			ULONG_PTR* pW32pServiceTable = reinterpret_cast<ULONG_PTR*>(parser.GetExportByName("W32pServiceTable") + base);
			if (pW32pServiceTable == NULL) {
				printf("W32pServiceTable not found\n");
				return 0;
			}

			ULONG_PTR pfn = 0;
			PCHAR pServiceName = nullptr;
			DWORD rva = 0;

			for (int i = 0; i < limit; i++) {
				if (buildNumber > 10586) {
					DWORD* table = (DWORD*)pW32pServiceTable;
					rva = table[i];
					pfn = (ULONG_PTR)parser.GetAddress(rva);
				}
				else {
					pfn = pW32pServiceTable[i] - imageBase + base;
				}
				ULONG_PTR serviceAddress = 0;
				if (pfn) {
					auto address = (const uint8_t*)pfn;
					auto count = cs_disasm(handle, address, 32, imageBase + pW32pServiceTable[i], 1, &insn);
					if (count > 0) {
						if (buildNumber > 18885) {
							printf("not support build number\n");
							return 0;
							//serviceAddress = pfn + insn->size + *(DWORD*)(pfn - (insn->size - 4));
						}
						else {
							DWORD offset = *(DWORD*)(pfn + (insn->size - 4));
							ULONG_PTR funcAddr = rva + imageBase;
							ULONG_PTR indexAddress = funcAddr + insn->size + offset-imageBase;

							indexAddress = (ULONG_PTR)parser.RVA2FA(indexAddress);
							ULONG index = *(ULONG_PTR*)(indexAddress);
							serviceAddress = (ULONG_PTR)parser.RVA2FA(index);
							pServiceName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(serviceAddress)->Name;
						}

						if (pServiceName) {
							printf("SerivceName: %s	index: 0x%x\n", pServiceName, i);
						}
					}
				}
			}
		}
	}
	else {  // win7 x64
		do {
			SymSetOptions(SYMOPT_UNDNAME);
			CHAR symbolPath[] = "cache*D:\\kernel\\Win7;SRV*https://msdl.microsoft.com/download/symbols";
			if (!SymInitialize(GetCurrentProcess(), symbolPath, FALSE)) {
				return -1;
			}
			// read the file win32k.sys
			PLOADED_IMAGE pLoadImage = ImageLoad(imagePath, nullptr);

			// read pdb files 
			// symPath is the key 
			if (!SymLoadModule(GetCurrentProcess(), pLoadImage->hFile, nullptr, nullptr, pLoadImage->FileHeader->OptionalHeader.ImageBase,
				pLoadImage->SizeOfImage))
				break;

			// enumeration symbols
			if (!SymEnumSymbols(GetCurrentProcess(), pLoadImage->FileHeader->OptionalHeader.ImageBase, nullptr, SymEnumSymbolsProc, nullptr)) {
				break;
			}

			auto base = (ULONG_PTR)parser.GetBaseAddress();
			std::cout << std::hex << "file base: " << base << " " << "file base" << imageBase << std::endl;

			auto pW32pServiceLimit = GetSymbolAddressByName(L"W32pServiceLimit");
			printf("pW32pServiceLimit: %p\n", pW32pServiceLimit);
			pW32pServiceLimit = pW32pServiceLimit - imageBase;
			pW32pServiceLimit = parser.RvaToFileOffset((DWORD)pW32pServiceLimit) + base;
			if (pW32pServiceLimit == 0) {
				break;
			}

			auto pW32pServiceTable = GetSymbolAddressByName(L"W32pServiceTable");
			printf("pW32pServiceTable: %p\n", pW32pServiceTable);

			pW32pServiceTable = pW32pServiceTable - imageBase;
			pW32pServiceTable = parser.RvaToFileOffset((ULONG)pW32pServiceTable) + base;
			if (pW32pServiceTable == 0) {
				break;
			}
			printf("table: %p\n", pW32pServiceTable);
			printf("limit: %x\n", pW32pServiceLimit);
			printf("Parser table\n");
			ULONG_PTR* table = (ULONG_PTR*)pW32pServiceTable;
			ULONG limit = *(ULONG*)pW32pServiceLimit;
			printf("Limit: 0x%x\r\n", limit);
			for (ULONG i = 0; i < limit; i++) {
				DWORD64 pfn = table[i];
				for (auto& symbol : g_Symbols) {
					if (symbol.Address == pfn) {
						printf("%-50ws address: %p ", symbol.Name.c_str(), pfn);
						std::cout << std::hex << i + 0x1000 << std::endl;

						USHORT nameLen = (wcslen(symbol.Name.c_str()) + 1) * sizeof(WCHAR);
						USHORT len = sizeof(ShadowServiceEntry) + nameLen;
						ShadowServiceEntry* entry;
						entry = (ShadowServiceEntry*)malloc(len);
						if (entry) {
							entry->Index = i;
							memcpy_s(entry->Name, nameLen, symbol.Name.c_str(), nameLen);
							entry->NameLength = wcslen(entry->Name);

							DWORD returned;
							/*BOOL success = DeviceIoControl(hDevice,
								IOCTL_TEST_ADD_SERVICE_NAME,
								entry, len,
								nullptr, 0,
								&returned, nullptr);*/

							free(entry);
						}
					}
				}
			}

			ImageUnload(pLoadImage);
		} while (false);

		SymUnloadModule(GetCurrentProcess(), imageBase);
		SymCleanup(GetCurrentProcess());
	}
	cs_close(&handle);
	//CloseHandle(hDevice);
	printf("exit...\r\n");
	system("pause");
}


