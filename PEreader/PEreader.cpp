#include <Windows.h>
#include <stdio.h>
#include <type_traits>
#include <time.h>
#pragma warning(disable : 4996)
#define SPLITTER  "++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"

int main(int argc, char* argv[]) {
	if (argc < 2) {
		printf("Usage: PEreader <filename>");
		return 1;
	}

	FILE* f = fopen(argv[1], "rb");
	if (f == NULL) return 1;
	fseek(f, 0, SEEK_END);
	DWORD fileSize = ftell(f);
	if (fileSize < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS)) {
		printf("Not PE file\n");
		return 1;
	}
	fseek(f, 0, SEEK_SET);
	char* dump = (char*)malloc(fileSize);
	fread(dump, 1, fileSize, f);

	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)dump;
	if (pImageDosHeader->e_magic != 0x5A4D) {
		printf("Not PE file\n");
		return 1;
	}
	PIMAGE_NT_HEADERS tmp_pImageNTHeader = (PIMAGE_NT_HEADERS)(dump + pImageDosHeader->e_lfanew);
	if (tmp_pImageNTHeader->Signature != 0x4550) {
		printf("Not PE file\n");
		return 1;
	}
	DWORD magic = tmp_pImageNTHeader->OptionalHeader.Magic;
	
	if (magic == 0x10b) {
		PIMAGE_NT_HEADERS32 pImageNTHeaders = (PIMAGE_NT_HEADERS32)(dump + pImageDosHeader->e_lfanew);
		PIMAGE_OPTIONAL_HEADER32 pImageOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)(&pImageNTHeaders->OptionalHeader);
		PIMAGE_FILE_HEADER pImageFileHeader = (PIMAGE_FILE_HEADER)(&pImageNTHeaders->FileHeader);

		printf(" Machine: 0x%.2X\n", pImageFileHeader->Machine);
		printf(" NumberOfSection: %d\n", pImageFileHeader->NumberOfSections);
		time_t t = pImageFileHeader->TimeDateStamp;
		printf(" TimeDateStamp: %s\n", asctime(gmtime(&t)));
		printf(" PointerToSymbol Table: 0x%p\n", pImageFileHeader->PointerToSymbolTable);
		printf(" NumberOfSymbol: %d\n", pImageFileHeader->NumberOfSymbols);
		printf(" SizeOfOptionalHeader: 0x%x\n", pImageFileHeader->SizeOfOptionalHeader);
		printf(" Characteristic: 0x%.2x\n", pImageFileHeader->Characteristics);

		printf(" Magic: 0x%x\n", pImageOptionalHeader->Magic);
		printf(" MajorLinkerVersion %d\n", pImageOptionalHeader->MajorLinkerVersion);
		printf(" MinorLinkerVersion %d\n", pImageOptionalHeader->MinorImageVersion);
		printf(" SizeOfCode: 0x%x\n", pImageOptionalHeader->SizeOfCode);
		printf(" SizeOfIninitalizedData: 0x%x\n", pImageOptionalHeader->SizeOfInitializedData);
		printf(" SizeOfUninitializedData: 0x%x\n", pImageOptionalHeader->SizeOfUninitializedData);
		printf(" AddressOfEntryPoint: 0x%p\n", pImageOptionalHeader->AddressOfEntryPoint);
		printf(" BaseOfCode: 0x%x\n", pImageOptionalHeader->BaseOfCode);
		printf(" BaseOfData: 0x%x\n", pImageOptionalHeader->BaseOfData);
		printf(" ImageBase: 0x%x\n", pImageOptionalHeader->ImageBase);
		printf(" SectionAlignment: 0x%x\n", pImageOptionalHeader->SectionAlignment);
		printf(" FileAlignment: 0x%x\n", pImageOptionalHeader->FileAlignment);
		printf(" MajorOperatingSystemVersion: %d\n", pImageOptionalHeader->MajorOperatingSystemVersion);
		printf(" MinorOperatingSystemVersion: %d\n", pImageOptionalHeader->MinorOperatingSystemVersion);
		printf(" MajorImageVersion: %d\n", pImageOptionalHeader->MajorImageVersion);
		printf(" MinorImageVersion: %d\n", pImageOptionalHeader->MinorImageVersion);
		printf(" Win32VersionValue: %d\n", pImageOptionalHeader->Win32VersionValue);
		printf(" SizeOfImage: 0x%x\n", pImageOptionalHeader->SizeOfImage);
		printf(" SizeOfHeaders: 0x%x\n", pImageOptionalHeader->SizeOfHeaders);
		printf(" Checksum: 0x%x\n", pImageOptionalHeader->CheckSum);
		printf(" Subsystem: 0x%x\n", pImageOptionalHeader->Subsystem);
		printf(" DLLCharacteristic: 0x%x\n", pImageOptionalHeader->DllCharacteristics);
		printf(" SizeOfStackReserve: 0x%x\n", pImageOptionalHeader->SizeOfStackReserve);
		printf(" SizeOfStackCommit: 0x%x\n", pImageOptionalHeader->SizeOfStackCommit);
		printf(" SizeOfHeapReserve: 0x%x\n", pImageOptionalHeader->SizeOfHeapReserve);
		printf(" SizeOfHeapCommit: 0x%x\n", pImageOptionalHeader->SizeOfHeapCommit);
		printf(" LoaderFlags: 0x%x\n", pImageOptionalHeader->LoaderFlags);
		printf(" NumberOfRvaAndSize: %d\n", pImageOptionalHeader->NumberOfRvaAndSizes);
		
		printf(SPLITTER);
		char* beginOfSectionTable = (char*)pImageOptionalHeader + sizeof(IMAGE_OPTIONAL_HEADER32);
		PIMAGE_SECTION_HEADER sectionHeaderList[100];
		PIMAGE_DATA_DIRECTORY pExportTable, pImportTable;
		for (int i = 0; i < pImageFileHeader->NumberOfSections; i++) {
			PIMAGE_SECTION_HEADER section_header = (PIMAGE_SECTION_HEADER)( beginOfSectionTable + i * sizeof(IMAGE_SECTION_HEADER));
			sectionHeaderList[i] = section_header;
			printf(" Section Name: %s\n", &section_header->Name);
			printf("\tVirtualSize: 0x%x\n", section_header->Misc);
			printf("\tVirtualAddress: 0x%x\n", section_header->VirtualAddress);
			printf("\tSizeOfRawData: 0x%x\n", section_header->SizeOfRawData);
			printf("\tPointerToRawData: 0x%p\n", section_header->PointerToRawData);
			printf("\tPointerToRelocation: 0x%p\n", section_header->PointerToRelocations);
			printf("\tPointerToLinenumbers: 0x%p\n", section_header->PointerToLinenumbers);
			printf("\tNumberOfRelocations: %d\n", section_header->NumberOfRelocations);
			printf("\tNumberOfLinenumbers: %d\n", section_header->NumberOfLinenumbers);
			printf("\tCharacteristic: 0x%x\n", section_header->Characteristics);
			printf("\n");

			
		}
		printf(SPLITTER);
		
		DWORD pImportTableRVA = (DWORD)(pImageOptionalHeader->DataDirectory[1].VirtualAddress);
		DWORD pExportTableRVA = (DWORD)(pImageOptionalHeader->DataDirectory[0].VirtualAddress);


		for (int i = 0; i < pImageFileHeader->NumberOfSections; i++) {
			if (sectionHeaderList[i]->VirtualAddress < pImportTableRVA && \
				sectionHeaderList[i]->VirtualAddress + sectionHeaderList[i]->Misc.VirtualSize > pImportTableRVA) {
				PIMAGE_IMPORT_DESCRIPTOR pImportTableDirectory = (PIMAGE_IMPORT_DESCRIPTOR)(dump + sectionHeaderList[i]->PointerToRawData + \
					pImportTableRVA - sectionHeaderList[i]->VirtualAddress);
				while (pImportTableDirectory->Name != NULL) {
					int j = 0;
					while (!(sectionHeaderList[j]->VirtualAddress < pImportTableDirectory->Name && \
						sectionHeaderList[j]->VirtualAddress + sectionHeaderList[j]->Misc.VirtualSize > pImportTableDirectory->Name)) j++;
					char* name = dump + sectionHeaderList[j]->PointerToRawData + pImportTableDirectory->Name - sectionHeaderList[j]->VirtualAddress;
					printf(" DLL Name: %s\n", name);
					DWORD * pImportLookupTableEntry = (DWORD*)(dump + (pImportTableDirectory->OriginalFirstThunk) + \
						sectionHeaderList[j]->PointerToRawData - sectionHeaderList[j]->VirtualAddress);
					
					while (*pImportLookupTableEntry != NULL) {
						DWORD temp = *pImportLookupTableEntry;
						if ((temp & 0x80000000) != 0) {
							printf("\tImport by ordinal\n");							
						}
						else {
							DWORD nameRVA = temp & 0x3fffffff;
							for (int j = 0; i < pImageFileHeader->NumberOfSections; j++) {
								if (sectionHeaderList[j]->VirtualAddress < nameRVA && nameRVA < \
									sectionHeaderList[j]->VirtualAddress + sectionHeaderList[j]->Misc.VirtualSize) {
									char* importName = dump + sectionHeaderList[j]->PointerToRawData + nameRVA - sectionHeaderList[j]->VirtualAddress;
									importName += 2;
									printf("\t%s\n", importName);
									break;
								}
							}
						}
						pImportLookupTableEntry++;
					}
					pImportTableDirectory++;
				}
			}
			if (sectionHeaderList[i]->VirtualAddress < pExportTableRVA && \
				sectionHeaderList[i]->VirtualAddress + sectionHeaderList[i]->Misc.VirtualSize > pExportTableRVA) {
				
				PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dump + sectionHeaderList[i]->PointerToRawData + \
					pExportTableRVA - sectionHeaderList[i]->VirtualAddress);
				DWORD numberOfName = pExportDirectory->NumberOfNames;
				
				int j = 0;
				while (!(sectionHeaderList[j]->VirtualAddress < pExportDirectory->AddressOfNames && \
					sectionHeaderList[j]->VirtualAddress + sectionHeaderList[j]->Misc.VirtualSize > pExportDirectory->Name)) j++;
				char ** nameTable = (char **)(dump + sectionHeaderList[j]->PointerToRawData + pExportDirectory->AddressOfNames - sectionHeaderList[j]->VirtualAddress);
				while (numberOfName--) {
					char* name = nameTable[numberOfName];
					printf("\t%s\n", name);
				}
				
			}
		}
	}
	else if (magic == 0x20b) {
		PIMAGE_NT_HEADERS64 pImageNTHeaders = (PIMAGE_NT_HEADERS64)(dump + pImageDosHeader->e_lfanew);
		PIMAGE_OPTIONAL_HEADER64 pImageOptionalHeader = (PIMAGE_OPTIONAL_HEADER64)(&pImageNTHeaders->OptionalHeader);
		PIMAGE_FILE_HEADER pImageFileHeader = (PIMAGE_FILE_HEADER)(&pImageNTHeaders->FileHeader);

		printf(" Machine: 0x%.2X\n", pImageFileHeader->Machine);
		printf(" NumberOfSection: %d\n", pImageFileHeader->NumberOfSections);
		time_t t = pImageFileHeader->TimeDateStamp;
		printf(" TimeDateStamp: %s\n", asctime(gmtime(&t)));
		printf(" PointerToSymbol Table: 0x%lx\n", pImageFileHeader->PointerToSymbolTable);
		printf(" NumberOfSymbol: %d\n", pImageFileHeader->NumberOfSymbols);
		printf(" SizeOfOptionalHeader: 0x%x\n", pImageFileHeader->SizeOfOptionalHeader);
		printf(" Characteristic: 0x%.2x\n", pImageFileHeader->Characteristics);

		printf(" Magic: 0x%x\n", pImageOptionalHeader->Magic);
		printf(" MajorLinkerVersion %d\n", pImageOptionalHeader->MajorLinkerVersion);
		printf(" MinorLinkerVersion %d\n", pImageOptionalHeader->MinorImageVersion);
		printf(" SizeOfCode: 0x%x\n", pImageOptionalHeader->SizeOfCode);
		printf(" SizeOfIninitalizedData: 0x%x\n", pImageOptionalHeader->SizeOfInitializedData);
		printf(" SizeOfUninitializedData: 0x%x\n", pImageOptionalHeader->SizeOfUninitializedData);
		printf(" AddressOfEntryPoint: 0x%I32x\n", pImageOptionalHeader->AddressOfEntryPoint);
		printf(" BaseOfCode: 0x%x\n", pImageOptionalHeader->BaseOfCode);
		printf(" ImageBase: 0x%I64x\n", pImageOptionalHeader->ImageBase);
		printf(" SectionAlignment: 0x%x\n", pImageOptionalHeader->SectionAlignment);
		printf(" FileAlignment: 0x%x\n", pImageOptionalHeader->FileAlignment);
		printf(" MajorOperatingSystemVersion: %d\n", pImageOptionalHeader->MajorOperatingSystemVersion);
		printf(" MinorOperatingSystemVersion: %d\n", pImageOptionalHeader->MinorOperatingSystemVersion);
		printf(" MajorImageVersion: %d\n", pImageOptionalHeader->MajorImageVersion);
		printf(" MinorImageVersion: %d\n", pImageOptionalHeader->MinorImageVersion);
		printf(" Win32VersionValue: %d\n", pImageOptionalHeader->Win32VersionValue);
		printf(" SizeOfImage: 0x%x\n", pImageOptionalHeader->SizeOfImage);
		printf(" SizeOfHeaders: 0x%x\n", pImageOptionalHeader->SizeOfHeaders);
		printf(" Checksum: 0x%x\n", pImageOptionalHeader->CheckSum);
		printf(" Subsystem: 0x%x\n", pImageOptionalHeader->Subsystem);
		printf(" DLLCharacteristic: 0x%x\n", pImageOptionalHeader->DllCharacteristics);
		printf(" SizeOfStackReserve: 0x%I64x\n", pImageOptionalHeader->SizeOfStackReserve);
		printf(" SizeOfStackCommit: 0x%I64x\n", pImageOptionalHeader->SizeOfStackCommit);
		printf(" SizeOfHeapReserve: 0x%I64x\n", pImageOptionalHeader->SizeOfHeapReserve);
		printf(" SizeOfHeapCommit: 0x%I64x\n", pImageOptionalHeader->SizeOfHeapCommit);
		printf(" LoaderFlags: 0x%x\n", pImageOptionalHeader->LoaderFlags);
		printf(" NumberOfRvaAndSize: %d\n", pImageOptionalHeader->NumberOfRvaAndSizes);

		printf(SPLITTER);
		char* beginOfSectionTable = (char*)pImageOptionalHeader + sizeof(IMAGE_OPTIONAL_HEADER64);
		PIMAGE_SECTION_HEADER sectionHeaderList[100];
		PIMAGE_DATA_DIRECTORY pExportTable, pImportTable;
		for (int i = 0; i < pImageFileHeader->NumberOfSections; i++) {
			PIMAGE_SECTION_HEADER section_header = (PIMAGE_SECTION_HEADER)(beginOfSectionTable + i * sizeof(IMAGE_SECTION_HEADER));
			sectionHeaderList[i] = section_header;
			printf(" Section Name: %s\n", &section_header->Name);
			printf("\tVirtualSize: 0x%x\n", section_header->Misc.VirtualSize);
			printf("\tVirtualAddress: 0x%x\n", section_header->VirtualAddress);
			printf("\tSizeOfRawData: 0x%x\n", section_header->SizeOfRawData);
			printf("\tPointerToRawData: 0x%I32x\n", section_header->PointerToRawData);
			printf("\tPointerToRelocation: 0x%I32x\n", section_header->PointerToRelocations);
			printf("\tPointerToLinenumbers: 0x%I32x\n", section_header->PointerToLinenumbers);
			printf("\tNumberOfRelocations: %d\n", section_header->NumberOfRelocations);
			printf("\tNumberOfLinenumbers: %d\n", section_header->NumberOfLinenumbers);
			printf("\tCharacteristic: 0x%x\n", section_header->Characteristics);
			printf("\n");


		}
		printf(SPLITTER);

		DWORD pImportTableRVA = (DWORD)(pImageOptionalHeader->DataDirectory[1].VirtualAddress);
		DWORD pExportTableRVA = (DWORD)(pImageOptionalHeader->DataDirectory[0].VirtualAddress);


		for (int i = 0; i < pImageFileHeader->NumberOfSections; i++) {
			if (sectionHeaderList[i]->VirtualAddress < pImportTableRVA && \
				sectionHeaderList[i]->VirtualAddress + sectionHeaderList[i]->Misc.VirtualSize > pImportTableRVA) {
				PIMAGE_IMPORT_DESCRIPTOR pImportTableDirectory = (PIMAGE_IMPORT_DESCRIPTOR)(dump + sectionHeaderList[i]->PointerToRawData + \
					pImportTableRVA - sectionHeaderList[i]->VirtualAddress);
				while (pImportTableDirectory->Name != NULL) {
					int j = 0;
					while (!(sectionHeaderList[j]->VirtualAddress < pImportTableDirectory->Name && \
						sectionHeaderList[j]->VirtualAddress + sectionHeaderList[j]->Misc.VirtualSize > pImportTableDirectory->Name)) j++;
					char* name = dump + sectionHeaderList[j]->PointerToRawData + pImportTableDirectory->Name - sectionHeaderList[j]->VirtualAddress;
					printf(" DLL Name: %s\n", name);
					UINT64* pImportLookupTableEntry = (UINT64*)(dump + (pImportTableDirectory->OriginalFirstThunk) + \
						sectionHeaderList[j]->PointerToRawData - sectionHeaderList[j]->VirtualAddress);

					while (*pImportLookupTableEntry != NULL) {
						UINT64 temp = *pImportLookupTableEntry;
						if ((temp & 0x8000000000000000) != 0) {
							printf("\tImport by ordinal\n");
						}
						else {
							DWORD nameRVA = temp & 0x3fffffff;
							for (int j = 0; i < pImageFileHeader->NumberOfSections; j++) {
								if (sectionHeaderList[j]->VirtualAddress < nameRVA && nameRVA < \
									sectionHeaderList[j]->VirtualAddress + sectionHeaderList[j]->Misc.VirtualSize) {
									char* importName = dump + sectionHeaderList[j]->PointerToRawData + nameRVA - sectionHeaderList[j]->VirtualAddress;
									importName += 2;
									printf("\t%s\n", importName);
									break;
								}
							}
						}
						pImportLookupTableEntry++;
					}
					pImportTableDirectory++;
				}
			}
			if (sectionHeaderList[i]->VirtualAddress < pExportTableRVA && \
				sectionHeaderList[i]->VirtualAddress + sectionHeaderList[i]->Misc.VirtualSize > pExportTableRVA) {

				PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dump + sectionHeaderList[i]->PointerToRawData + \
					pExportTableRVA - sectionHeaderList[i]->VirtualAddress);
				DWORD numberOfName = pExportDirectory->NumberOfNames;

				int j = 0;
				while (!(sectionHeaderList[j]->VirtualAddress < pExportDirectory->AddressOfNames && \
					sectionHeaderList[j]->VirtualAddress + sectionHeaderList[j]->Misc.VirtualSize > pExportDirectory->Name)) j++;
				char** nameTable = (char**)(dump + sectionHeaderList[j]->PointerToRawData + pExportDirectory->AddressOfNames - sectionHeaderList[j]->VirtualAddress);
				while (numberOfName--) {
					char* name = nameTable[numberOfName];
					printf("%s", name);
				}

			}
		}
	}
}