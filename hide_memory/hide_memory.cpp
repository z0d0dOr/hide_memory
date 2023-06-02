#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>
#include "hde\hde64.h"

#define MM_ZERO_ACCESS         0  // this value is not used.
#define MM_READONLY            1
#define MM_EXECUTE             2
#define MM_EXECUTE_READ        3
#define MM_READWRITE           4  // bit 2 is set if this is writable.
#define MM_WRITECOPY           5
#define MM_EXECUTE_READWRITE   6
#define MM_EXECUTE_WRITECOPY   7

#define MM_NOCACHE            0x8
#define MM_GUARD_PAGE         0x10
#define MM_DECOMMIT           0x10   // NO_ACCESS, Guard page
#define MM_NOACCESS           0x18   // NO_ACCESS, Guard_page, nocache.
#define MM_UNKNOWN_PROTECTION 0x100  // bigger than 5 bits!

struct _MMPTE
{
	ULONGLONG Valid : 1;                                                      //0x0
	ULONGLONG PageFileReserved : 1;                                           //0x0
	ULONGLONG PageFileAllocated : 1;                                          //0x0
	ULONGLONG ColdPage : 1;                                                   //0x0
	ULONGLONG SwizzleBit : 1;                                                 //0x0
	ULONGLONG Protection : 5;                                                 //0x0
	ULONGLONG Prototype : 1;                                                  //0x0
	ULONGLONG Transition : 1;                                                 //0x0
	ULONGLONG PageFileLow : 4;                                                //0x0
	ULONGLONG UsedPageTableEntries : 10;                                      //0x0
	ULONGLONG ShadowStack : 1;                                                //0x0
	ULONGLONG Unused : 5;                                                     //0x0
	ULONGLONG PageFileHigh : 32;                                              //0x0
};
//0x30 bytes (sizeof)
struct _MMPFN
{
	void* padding1;
	void* pte_address;
	struct _MMPTE OriginalPte;                                      //0x10
	char padding2[0x18];															//0x28
};

_MMPFN* get_MmPfnDataBase() {

	UNICODE_STRING func_name{ 0 };
	RtlInitUnicodeString(&func_name, L"MmGetVirtualForPhysical");

	auto start = (unsigned char*)MmGetSystemRoutineAddress(&func_name);

	int index = 0;

	hde64s hde64{ 0 };

	while (hde64_disasm(&start[index],&hde64)) {


		if (hde64.len == 10) break;
		index += hde64.len;
	}

	ULONG64 tmp = *(PULONG64)(&start[index + 2]);
	return (_MMPFN*)(tmp-8);


}

uint64_t va_to_pa(void* va) {

	return MmGetPhysicalAddress(va).QuadPart;

}

bool hide_mem(HANDLE pid,void* va, ULONG attribute) {

	PEPROCESS process{ 0 };
	KAPC_STATE apc{ 0 };
	NTSTATUS status;

	DbgBreakPoint();
	status = PsLookupProcessByProcessId(pid, &process);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(77, 0, "[+]failed to get process errcode->0x%x", status);
		return false;
	}

	KeStackAttachProcess(process, &apc);

	void* align_va = PAGE_ALIGN(va);

	uint64_t pa = va_to_pa(align_va);
	if (pa == 0) {

		DbgPrintEx(77, 0, "[+]va err\r\n");
		ObDereferenceObject(process);
		KeUnstackDetachProcess(&apc);
		return false;
	}


	uint64_t pfn = pa >> 12;

	auto MmPfnDataBase = get_MmPfnDataBase();

	auto mmpfn = &MmPfnDataBase[pfn];

	mmpfn->OriginalPte.Protection = attribute;

	ObDereferenceObject(process);
	KeUnstackDetachProcess(&apc);
	return true;
}

void drv_unload(PDRIVER_OBJECT) {

}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT drv_obj, PUNICODE_STRING)
{
	NTSTATUS status = STATUS_SUCCESS;

	drv_obj->DriverUnload = drv_unload;

	auto MmPfnDataBase = get_MmPfnDataBase();

	DbgPrintEx(77,0,"MmPfnDataBase->0x%llx\r\n", MmPfnDataBase);


	hide_mem((HANDLE)6480, (void*)0x1595B87CC3C, MM_NOACCESS);
	
	return status;

}