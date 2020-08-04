#include <windows.h>
#include <iostream>
#include <stdio.h>

using namespace std;


IMAGE_DOS_HEADER DosHeader;
PIMAGE_DOS_HEADER pDosHeader;
IMAGE_NT_HEADERS NtHeader;
PIMAGE_NT_HEADERS pNtHeader;
IMAGE_FILE_HEADER FileHeader;
PIMAGE_FILE_HEADER pFileHeader;
IMAGE_OPTIONAL_HEADER OptionHeader;
PIMAGE_OPTIONAL_HEADER pOptionHeader;
PIMAGE_DATA_DIRECTORY pDataDirectory;
IMAGE_SECTION_HEADER SectionHeader;


bool bIsPe(PVOID pbFile);
void displayDosHeader(PVOID pbFile);
void displayNtHeader(PIMAGE_NT_HEADERS pNtHeader);
void displayFileHeader(PIMAGE_NT_HEADERS pNtHeader);
void displayOptionalHeader(PIMAGE_NT_HEADERS pNtHeader);
void displayDataDirtectory(PIMAGE_NT_HEADERS pNtHeader);
void displaySectionHeader(PIMAGE_NT_HEADERS pNtHeader);
void displayImportTable(PVOID pbFile);
void displayExportTable(PVOID pbFile);
void displayBaseRelocTable(PVOID pbFile);
DWORD RvaToRaw(PIMAGE_NT_HEADERS pNtHeader, DWORD Rva);


//文件路径
LPTSTR filepath = (LPTSTR)"E://CppWorkspace//MirInject//Release//MirInject.dll"; 
//LPTSTR filepath = (LPTSTR)"E://CppWorkspace//D3DX81ab.dll"; 


int main(int argc, char* agrv[])
{
	//获取到文件句柄
	HANDLE hFile = CreateFile(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	//创建一个新的文件映射对象
	HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);

	//将文件映射对象映射到内存, 并获取到指向该内存块第一个字节的指针
	PVOID pbFile = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);


	if (hFile == INVALID_HANDLE_VALUE || hMapping == NULL || pbFile == NULL)
	{
		printf("\n========THE FILE IS NOT EXISTING===========\n");
		if (hFile != INVALID_HANDLE_VALUE)
		{
			CloseHandle(hFile);
		}
		if (hMapping != NULL)
		{
			CloseHandle(hMapping);
		}
		if (pbFile != NULL)
		{
			UnmapViewOfFile(pbFile);
		}
		return -1;
	}

	if (!bIsPe(pbFile))
	{
		printf("\n========THE FILE IS A PE FILE===========\n");
		if (hFile != INVALID_HANDLE_VALUE)
		{
			CloseHandle(hFile);
		}
		if (hMapping != NULL)
		{
			CloseHandle(hMapping);
		}
		if (pbFile != NULL)
		{
			UnmapViewOfFile(pbFile);
		}
		return -1;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)pbFile;
	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pbFile + pDosHeader->e_lfanew);

	int opt;

	while (1)
	{
		system("cls");
		printf("================PE解析==================\n");
		printf("\t\t1.DOS头\n");
		printf("\t\t2.NT头\n");
		printf("\t\t3.FILE头\n");
		printf("\t\t4.OPTIONAL头\n");
		printf("\t\t5.数据目录\n");
		printf("\t\t6.SECTION头\n");
		printf("\t\t7.导出表\n");
		printf("\t\t8.导入表\n");
		printf("\t\t9.重定位表\n\n");
		printf("请输入序号（0退出）：\n");

		scanf_s("%d", &opt);

		switch (opt)
		{
		case 0:
			exit(0);

		case 1:
			displayDosHeader(pbFile);
			break;

		case 2:
			displayNtHeader(pNtHeader);	
			break;

		case 3:
			displayFileHeader(pNtHeader);
			break;

		case 4:
			displayOptionalHeader(pNtHeader);
			break;

		case 5:
			displayDataDirtectory(pNtHeader);
			break;

		case 6:
			displaySectionHeader(pNtHeader);
			break;

		case 7:
			displayExportTable(pbFile);
			break;

		case 8:
			displayImportTable(pbFile);
			break;

		case 9:
			displayBaseRelocTable(pbFile);
			break;

		default:
			break;
		}
		system("pause");
	}
	

	if (hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
	}
	if (hMapping != NULL)
	{
		CloseHandle(hMapping);
	}
	if (pbFile != NULL)
	{
		UnmapViewOfFile(pbFile);
	}

	getchar();
	return 0;

}

//判断是否为一个PE文件
bool bIsPe(PVOID pbFile)
{
	pDosHeader = (PIMAGE_DOS_HEADER)pbFile;
	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pbFile + pDosHeader->e_lfanew);
	if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE && pNtHeader->Signature == IMAGE_NT_SIGNATURE)
	{
		return true;
	}
	return false;
};


//打印DOS头
void displayDosHeader(PVOID pbFile)
{
	puts("====================PE DOS HEADER====================");

	pDosHeader = (PIMAGE_DOS_HEADER)pbFile;

	printf("\te_magic\t\t:%0X\n", pDosHeader->e_magic);			//打印"MZ"标志
	printf("\te_cblp\t\t:%04X\n", pDosHeader->e_cblp);
	printf("\te_cp\t\t:%04X\n", pDosHeader->e_cp);
	printf("\te_crlc\t\t:%04X\n", pDosHeader->e_crlc);
	printf("\te_cparhdr\t:%04X\n", pDosHeader->e_cparhdr);
	printf("\te_minalloc\t:%04X\n", pDosHeader->e_minalloc);
	printf("\te_maxalloc\t:%04X\n", pDosHeader->e_maxalloc);
	printf("\te_ss\t\t:%04X\n", pDosHeader->e_ss);
	printf("\te_sp\t\t:%04X\n", pDosHeader->e_sp);
	printf("\te_csum\t\t:%04X\n", pDosHeader->e_csum);
	printf("\te_ip\t\t:%04X\n", pDosHeader->e_ip);
	printf("\te_cs\t\t:%04X\n", pDosHeader->e_cs);
	printf("\te_lfarlc\t:%04X\n", pDosHeader->e_lfarlc);
	printf("\te_ovno\t\t:%04X\n", pDosHeader->e_ovno);
	printf("\te_res[4]\t:%016X\n", pDosHeader->e_res[1]);
	printf("\te_oemid\t\t:%04X\n", pDosHeader->e_oemid);
	printf("\te_oemid\t\t:%04X\n", pDosHeader->e_oeminfo);
	printf("\te_res[10]\t:%020X\n", pDosHeader->e_res[1]);
	printf("\te_lfanew\t:%08X\n", pDosHeader->e_lfanew);
}


//打印NT头
void displayNtHeader(PIMAGE_NT_HEADERS pNtHeader)
{
	puts("\n====================PE NT HEADER====================");

	printf("\tSignature\t:%0X\n", pNtHeader->Signature);		//打印"PE"标志
	printf("\tFileHeader\t:%0X\n", pNtHeader->FileHeader);		
	printf("\tOptionalHeader\t:%0X\n", pNtHeader->OptionalHeader);		

};


//打印FILE头
void displayFileHeader(PIMAGE_NT_HEADERS pNtHeader)
{
	//打印FILE头
	puts("\n====================PE FILE HEADER====================");

	printf("\tMachine\t\t\t:%04X\n", pNtHeader->FileHeader.Machine);
	printf("\tNumberOfSections\t:%04X\n", pNtHeader->FileHeader.NumberOfSections);
	printf("\tTimeDateStamp\t\t:%08X\n", pNtHeader->FileHeader.TimeDateStamp);
	printf("\tPointerToSymbolTable\t:%08X\n", pNtHeader->FileHeader.PointerToSymbolTable);
	printf("\tNumberOfSymbols\t\t:%08X\n", pNtHeader->FileHeader.NumberOfSymbols);
	printf("\tSizeOfOptionalHeader\t:%04X\n", pNtHeader->FileHeader.SizeOfOptionalHeader);
	printf("\tCharacteristics\t\t:%04X\n", pNtHeader->FileHeader.Characteristics);
};


//打印OPTIONAL头
void displayOptionalHeader(PIMAGE_NT_HEADERS pNtHeader)
{

	puts("\n====================PE OPTIONAL HEADER====================");

	printf("\tMachine\t\t\t\t:%04X\n", pNtHeader->OptionalHeader.Magic);
	printf("\tMajorLinkerVersion\t\t:%02X\n", pNtHeader->OptionalHeader.MajorLinkerVersion);
	printf("\tMinorLinkerVersion\t\t:%02X\n", pNtHeader->OptionalHeader.MinorLinkerVersion);
	printf("\tSizeOfCode\t\t\t:%08X\n", pNtHeader->OptionalHeader.SizeOfCode);
	printf("\tSizeOfInitializedData\t\t:%08X\n", pNtHeader->OptionalHeader.SizeOfInitializedData);
	printf("\tSizeOfUninitializedData\t\t:%08X\n", pNtHeader->OptionalHeader.SizeOfUninitializedData);
	printf("\tAddressOfEntryPoint\t\t:%08X\n", pNtHeader->OptionalHeader.AddressOfEntryPoint);
	printf("\tBaseOfCode\t\t\t:%08X\n", pNtHeader->OptionalHeader.BaseOfCode);
	printf("\tBaseOfData\t\t\t:%08X\n", pNtHeader->OptionalHeader.BaseOfData);
	printf("\tImageBase\t\t\t:%08X\n", pNtHeader->OptionalHeader.ImageBase);
	printf("\tSectionAlignment\t\t:%08X\n", pNtHeader->OptionalHeader.SectionAlignment);
	printf("\tFileAlignment\t\t\t:%08X\n", pNtHeader->OptionalHeader.FileAlignment);
	printf("\tMajorOperatingSystemVersion\t:%04X\n", pNtHeader->OptionalHeader.MajorOperatingSystemVersion);
	printf("\tMinorOperatingSystemVersion\t:%04X\n", pNtHeader->OptionalHeader.MinorOperatingSystemVersion);
	printf("\tMajorImageVersion\t\t:%04X\n", pNtHeader->OptionalHeader.MajorImageVersion);
	printf("\tMinorImageVersion\t\t:%04X\n", pNtHeader->OptionalHeader.MinorImageVersion);
	printf("\tMajorSubsystemVersion\t\t:%04X\n", pNtHeader->OptionalHeader.MajorSubsystemVersion);
	printf("\tMinorSubsystemVersion\t\t:%04X\n", pNtHeader->OptionalHeader.MinorSubsystemVersion);
	printf("\tWin32VersionValue\t\t:%08X\n", pNtHeader->OptionalHeader.Win32VersionValue);
	printf("\tSizeOfImage\t\t\t:%08X\n", pNtHeader->OptionalHeader.SizeOfImage);
	printf("\tSizeOfHeaders\t\t\t:%08X\n", pNtHeader->OptionalHeader.SizeOfHeaders);
	printf("\tCheckSum\t\t\t:%08X\n", pNtHeader->OptionalHeader.CheckSum);
	printf("\tSubsystem\t\t\t:%04X\n", pNtHeader->OptionalHeader.Subsystem);
	printf("\tDllCharacteristics\t\t:%04X\n", pNtHeader->OptionalHeader.DllCharacteristics);
	printf("\tSizeOfStackReserve\t\t:%08X\n", pNtHeader->OptionalHeader.SizeOfStackReserve);
	printf("\tSizeOfStackCommit\t\t:%08X\n", pNtHeader->OptionalHeader.SizeOfStackCommit);
	printf("\tSizeOfHeapReserve\t\t:%08X\n", pNtHeader->OptionalHeader.SizeOfHeapReserve);
	printf("\tSizeOfHeapCommit\t\t:%08X\n", pNtHeader->OptionalHeader.SizeOfHeapCommit);
	printf("\tLoaderFlags\t\t\t:%08X\n", pNtHeader->OptionalHeader.LoaderFlags);
	printf("\tNumberOfRvaAndSizes\t\t:%08X\n", pNtHeader->OptionalHeader.NumberOfRvaAndSizes);

};


//打印数据目录表
void displayDataDirtectory(PIMAGE_NT_HEADERS pNtHeader)
{

	puts("\n====================PE IMAGE_DATA_DIRECTORY HEADER====================");
	pDataDirectory = pNtHeader->OptionalHeader.DataDirectory;
	printf("\t-Table Name-\t\t\t-VirtualAddress-\t-Size-\n");
	printf("\tExport Table\t\t\t%08X\t\t%08X\n", pDataDirectory[0].VirtualAddress, pDataDirectory[0].Size);
	printf("\tImport Table\t\t\t%08X\t\t%08X\n", pDataDirectory[1].VirtualAddress, pDataDirectory[1].Size);
	printf("\tResources Table\t\t\t%08X\t\t%08X\n", pDataDirectory[2].VirtualAddress, pDataDirectory[2].Size);
	printf("\tException Table\t\t\t%08X\t\t%08X\n", pDataDirectory[3].VirtualAddress, pDataDirectory[3].Size);
	printf("\tSecurity Table\t\t\t%08X\t\t%08X\n", pDataDirectory[4].VirtualAddress, pDataDirectory[4].Size);
	printf("\tBase relocation Table\t\t%08X\t\t%08X\n", pDataDirectory[5].VirtualAddress, pDataDirectory[5].Size);
	printf("\tDebug Table\t\t\t%08X\t\t%08X\n", pDataDirectory[6].VirtualAddress, pDataDirectory[6].Size);
	printf("\tCopyrught Table\t\t\t%08X\t\t%08X\n", pDataDirectory[7].VirtualAddress, pDataDirectory[7].Size);
	printf("\tGlobal Ptr Table\t\t%08X\t\t%08X\n", pDataDirectory[8].VirtualAddress, pDataDirectory[8].Size);
	printf("\tTLS Table\t\t\t%08X\t\t%08X\n", pDataDirectory[9].VirtualAddress, pDataDirectory[9].Size);
	printf("\tLoad config Table\t\t%08X\t\t%08X\n", pDataDirectory[10].VirtualAddress, pDataDirectory[10].Size);
	printf("\tBound Import Table\t\t%08X\t\t%08X\n", pDataDirectory[11].VirtualAddress, pDataDirectory[11].Size);
	printf("\tIAT Table\t\t\t%08X\t\t%08X\n", pDataDirectory[12].VirtualAddress, pDataDirectory[12].Size);
	printf("\tDelay Import Table\t\t%08X\t\t%08X\n", pDataDirectory[13].VirtualAddress, pDataDirectory[13].Size);
	printf("\tCOM descriptor Table\t\t%08X\t\t%08X\n", pDataDirectory[14].VirtualAddress, pDataDirectory[14].Size);
	printf("\tRetention Table\t\t\t%08X\t\t%08X\n", pDataDirectory[15].VirtualAddress, pDataDirectory[15].Size);

};


//打印SECTION头
void displaySectionHeader(PIMAGE_NT_HEADERS pNtHeader)
{

	puts("\n====================PE SECTION HEADER====================");

	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(pNtHeader);

	for (int count = 0; count < pNtHeader->FileHeader.NumberOfSections; count++)
	{

		//打印节区标志
		printf("\n----------------%s----------------\n", pSectionHeader->Name);
		printf("\tName\t\t\t%s\n", pSectionHeader->Name);
		printf("\tVirtualSize\t\t:%08X\n", pSectionHeader->Misc.VirtualSize);
		printf("\tVirtualAddress\t\t:%08X\n", pSectionHeader->VirtualAddress);
		printf("\tSizeOfRawData\t\t:%08X\n", pSectionHeader->SizeOfRawData);
		printf("\tPointerToRawData\t:%08X\n", pSectionHeader->PointerToRawData);
		printf("\tPointerToRelocation\t:%08X\n", pSectionHeader->PointerToRelocations);
		printf("\tPointerToLinenumbers\t:%08X\n", pSectionHeader->PointerToLinenumbers);
		printf("\tNumberOfRelocations\t:%04X\n", pSectionHeader->NumberOfRelocations);
		printf("\tNumberOfLinenumbers\t:%04X\n", pSectionHeader->NumberOfLinenumbers);
		printf("\tCharacteristics\t\t:%08X\n", pSectionHeader->Characteristics);

		pSectionHeader++;
	}
};


//打印导入表
void displayImportTable(PVOID pbFile)
{
	//打印导入表
	puts("\n\n====================Import Table====================");

	pDosHeader = (PIMAGE_DOS_HEADER)pbFile;
	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pbFile + pDosHeader->e_lfanew);


	//定位到导入表的虚拟地址RVA， 并转换成文件偏移地址FOA
	DWORD Import_table_offset = RvaToRaw(pNtHeader, (DWORD)pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	//在FileBuffer中定位到导入表， 并指向导入表
	PIMAGE_IMPORT_DESCRIPTOR pImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pbFile + Import_table_offset);

	//循环打印
	while (1)
	{
		//遍历到结尾跳出循环
		if (pImportDirectory->OriginalFirstThunk == 0 && pImportDirectory->TimeDateStamp == 0 && pImportDirectory->ForwarderChain == 0 && pImportDirectory->Name == 0 && pImportDirectory->FirstThunk == 0)
		{
			break;
		}

		//导入的DLL文件名
		DWORD Import_table_offset_Name = (DWORD)pbFile + RvaToRaw(pNtHeader, pImportDirectory->Name);
		printf("\n\t------------------%s------------------\n", Import_table_offset_Name);

		printf("\tTrunk Rva\tTrunk Rwa\tTrunk value\tHint\tAPI名称\n");

		//导入名称表INT的文件偏移
		DWORD Import_table_offset_OriginalFirstThunk = (DWORD)pbFile + RvaToRaw(pNtHeader, pImportDirectory->OriginalFirstThunk);
		//指向FileBuffer中的INT
		DWORD* pTrunkData = (DWORD*)Import_table_offset_OriginalFirstThunk;

		//导入名称表INT的RVA		
		DWORD Trunk_RVA = pImportDirectory->OriginalFirstThunk;

		int n = 0;

		while (pTrunkData[n] != 0)
		{
			DWORD TrunkData = pTrunkData[n];

			/*
			*IMAGE_THUNK_DATA的最高位为0时，以函数名方式导入，是一个RVA，指向IMAGE_IMPORT_BY_NAME
			*IMAGE_THUNK_DATA的最高位为1时，以序号导入，低31位被看作一个函数序号
			*/

			//以函数名导入
			if (TrunkData < IMAGE_ORDINAL_FLAG32)
			{
				//函数名
				PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)pbFile + RvaToRaw(pNtHeader, TrunkData));
				printf("\n\t%08X\t%08X\t%08X\t%04X\t%s\n", Trunk_RVA, RvaToRaw(pNtHeader, Trunk_RVA), TrunkData, pImportByName->Hint, pImportByName->Name);
			}

			//以序号导入
			else
			{
				//函数序号
				DWORD funum = (DWORD)(TrunkData - IMAGE_ORDINAL_FLAG32);
				printf("\n\t%08X\t%08X\t%08X\t——%16X\n", Trunk_RVA, RvaToRaw(pNtHeader, Trunk_RVA), TrunkData, funum);
			}
			n++;

			//下一个INT
			Trunk_RVA = Trunk_RVA + sizeof(Trunk_RVA);
		}

		//下一个导入表
		pImportDirectory++;
	}

};


//打印导出表
void displayExportTable(PVOID pbFile)
{
	//打印导出表
	puts("\n====================Export Table====================\n");

	pDosHeader = (PIMAGE_DOS_HEADER)pbFile;
	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pbFile + pDosHeader->e_lfanew);

	//定位到导出表的虚拟地址RVA, 并转换成文件偏移地址FOA
	DWORD Export_table_offset = RvaToRaw(pNtHeader, (DWORD)pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	//在FileBuffer中定位到导出表,并指向导出表
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pbFile + Export_table_offset);

	/*
	* Name: 指向该导出表文件名的RVA
	* Base: 导出函数的起始序号
	* NumberOfNames: 以函数名字导出的函数个数
	* NumberOfFunctions: 所有导出函数的个数: 最大序号 - 最小序号 + 1
	* AddressOfNames: 导出函数名称表---RVA
	* AddressOfFunctions: 导出函数地址表---RVA
	* AddressOfNameOrdinals: 导出函数序号表---RVA
	*/

	DWORD Export_table_offset_Name = (DWORD)pbFile + RvaToRaw(pNtHeader, pExportDirectory->Name);
	DWORD* pNameOfAddress = (DWORD*)((DWORD)pbFile + RvaToRaw(pNtHeader, pExportDirectory->AddressOfNames));
	DWORD* pFunctionOfAddress = (DWORD*)((DWORD)pbFile + RvaToRaw(pNtHeader, pExportDirectory->AddressOfFunctions));
	WORD* pNameOrdinalOfAddress = (WORD*)((DWORD)pbFile + RvaToRaw(pNtHeader, pExportDirectory->AddressOfNameOrdinals));


	printf("\tName\t\t\t:%08X\n", pExportDirectory->Name);
	printf("\tNameOfDLL\t\t:%s\n", Export_table_offset_Name);
	printf("\tNameOfAddress\t\t:%08X\n", pExportDirectory->AddressOfNames);
	printf("\tFunctionOfAdress\t:%08X\n", pExportDirectory->AddressOfFunctions);
	printf("\tNameOrdinalOfAddress\t:%08X\n", pExportDirectory->AddressOfNameOrdinals);

	if (pExportDirectory->NumberOfFunctions == 0)
	{
		puts("!!!!!!!!!!!!!!!!!NO EXPORT!!!!!!!!!!!!!!!!!!!!!");
		return;

	}

	printf("\tNumberOfNames\t\t:%X\n", pExportDirectory->NumberOfNames);
	printf("\tNumberOfFunctions\t:%X\n", pExportDirectory->NumberOfFunctions);

	puts("\n\t----------------NAME EXPORT----------------\n");

	int NumberOfFounctions = (int)pExportDirectory->NumberOfFunctions;		//导出函数地址表的个数

	//pIsFound记录导出函数是否被遍历到
	int* pIsFound = (int*)malloc(sizeof(int) * NumberOfFounctions);
	int k;
	for (k = 0; k < pExportDirectory->NumberOfFunctions; k++)
	{
		pIsFound[k] = 0;
	}

	printf("\tExportNum\tRva\t\t\tName\n");
	for (int i = 0; i < pExportDirectory->NumberOfNames; i++)
	{

		DWORD FunctionAddress = pFunctionOfAddress[pNameOrdinalOfAddress[i]];		//pNameOrdinalOfAddress 导出函数序号表
		DWORD FunName = (DWORD)pbFile + RvaToRaw(pNtHeader, pNameOfAddress[i]);		//pNameOfAddress		导出函数名称表
		pIsFound[pNameOrdinalOfAddress[i]] = 1;

		//Base + 序号 ---> 真正的导出序号
		printf("\t%X\t\t%04X\t\t\t%-10s\n", pExportDirectory->Base + pNameOrdinalOfAddress[i], FunctionAddress, FunName);
	}


	//导出函数地址表和导出函数名称名不一一对应时, 按导出函数序号查找
	if (pExportDirectory->NumberOfFunctions != pExportDirectory->NumberOfNames)
	{
		puts("\n\t----------------NUMBER EXPORT----------------\n");

		for (int m = 0; m < pExportDirectory->NumberOfFunctions; m++)
		{
			if (pIsFound[m] != 1)
			{

				//Base + 序号 ---> 真正的导出序号
				printf("\tExportNum：\t%X\n", pExportDirectory->Base + m);
			}
		}
	}
	else
	{
		printf("\n\t--------------NO NUMBER EXPORT--------------\n");
	}

	free(pIsFound);
};


//打印重定位表
void displayBaseRelocTable(PVOID pbFile)
{

	/*
	IMAGE_BASE_RELOCATION
	{
		DWORD VirtualAddress
		DWORD SizeOfBlock
	}
	WORD TypeOffset[0]
	WORD TypeOffset[1]
	...
	WORD TypeOffset[Count]

	*/

	puts("\n====================Base Relocation Table====================\n");

	pDosHeader = (PIMAGE_DOS_HEADER)pbFile;
	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pbFile + pDosHeader->e_lfanew);

	typedef struct  _OFFSET_TYPE
	{
		WORD offset : 12;
		WORD type : 4;
	}OFFSET_TYPE, * POFFSET_TYPE;

	//定位到重定位表的虚拟地址RVA, 并转换成文件偏移地址FOA
	DWORD RelocRva = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

	if (!RelocRva)
	{
		printf("----------------NOT FOUND Base Relocation Table----------------");
		return;
	}

	//在FileBuffer中定位到重定位表, 并指向重定位表
	PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((DWORD)pbFile + RvaToRaw(pNtHeader, RelocRva));
	

	//循环遍历每个块
	while (pReloc->SizeOfBlock)
	{
		printf("\n\t----------VirtualAddress:%X-------------SizeOfBlock:%X----------\n", pReloc->VirtualAddress, pReloc->SizeOfBlock);

		//某块中所有重定位项的个数
		DWORD Count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		//重定位项:可以当做一个数组，宽度为2字节，每一个重定位项分为两个部分：高4位(重定位数据的类型)和低12位(重定位数据相对于VirtualAddress的偏移)
		//下移8个字节, 定位到每一块中的重定位项开端
		POFFSET_TYPE pOffset = (POFFSET_TYPE)(pReloc + 1);

		//循环遍历每个重定位项
		for (int i = 0; i < Count; ++i)
		{

			if (pOffset[i].type  == IMAGE_REL_BASED_HIGHLOW)
			{
				DWORD RelocDataRva = pReloc->VirtualAddress + pOffset[i].offset;
				DWORD RelocDataFoa = (DWORD)(RvaToRaw(pNtHeader, RelocDataRva));

				/*DWORD RealDataVA = *(DWORD*)RelocDataFoa;
				DWORD RealDataRva = RealDataVA - pNtHeader->OptionalHeader.ImageBase;
				DWORD RealDataFoa = (DWORD)((DWORD)pbFile + RvaToRaw(pNtHeader, RealDataRva));*/


				//printf("需要重定位的第%d个数据		RVA：%0X		偏移：%0X	改成：[%0X]\n", j, RelocDataRva, RelocDataFoa, RealDataFoa);
				printf("\t需要重定位的第%d个数据		RVA：%08X	  偏移：%08X    数据属性：[%d]\n", i + 1, RelocDataRva, RelocDataFoa, pOffset[i].type);

			}
		}

		//指向下一个重定向块
		pReloc = (PIMAGE_BASE_RELOCATION)((DWORD)pReloc + pReloc->SizeOfBlock);
	}
};


//相对虚拟地址RVA--->文件偏移地址FOA
DWORD RvaToRaw(PIMAGE_NT_HEADERS pNtHeader, DWORD Rva)
{
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(pNtHeader);

	for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
	{

		DWORD SectionBeginRva = pSectionHeader[i].VirtualAddress;
		DWORD SectionEndRva = pSectionHeader[i].VirtualAddress + pSectionHeader[i].SizeOfRawData;

		if (Rva >= SectionBeginRva && Rva <= SectionEndRva)
		{
			DWORD Temp = Rva - SectionBeginRva;						//偏移量
			DWORD Raw = Temp + pSectionHeader[i].PointerToRawData;	//偏移量 + 节区在硬盘上的地址
			return Raw;
		}
	}

}

