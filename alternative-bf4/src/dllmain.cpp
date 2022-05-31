#include "alternative.h"

class CShellCodeHelper
{
private:
	BYTE* m_saved_original_bytes;
	BYTE* m_jmp_bytes;
	void* m_start_address;
	void* m_shellcode_allocated_memory;
	int m_replace_byte_instruction_length;
	bool status_ok;

	bool patch_instruction(void* instruction_address, void* instruction_bytes, int sizeof_instruction_byte)
	{
		DWORD old_proctection = NULL;

		if (VirtualProtect(instruction_address, sizeof_instruction_byte, PAGE_EXECUTE_READWRITE, &old_proctection))
		{
			memcpy(instruction_address, instruction_bytes, sizeof_instruction_byte);

			VirtualProtect(instruction_address, sizeof_instruction_byte, old_proctection, NULL);

			FlushInstructionCache(GetCurrentProcess(), instruction_address, sizeof_instruction_byte);

			return true;
		}
		return false;
	}
public:
	bool setup(void* address, void* my_heap = NULL)
	{
		if (address == NULL)
			return false;

		m_start_address = address;

		if (my_heap != NULL)
		{
			m_shellcode_allocated_memory = my_heap;
		}
		else
		{
			DWORD_PTR search_offset = 0x10000000;
			DWORD_PTR allocation_address = (DWORD_PTR)address - search_offset;
			DWORD_PTR end = (DWORD_PTR)address;

			if ((DWORD_PTR)address < search_offset)
			{
				search_offset = (DWORD_PTR)address;
				allocation_address = (DWORD_PTR)address - search_offset;
			}

			MEMORY_BASIC_INFORMATION mbi{};
			ZeroMemory(&mbi, sizeof(MEMORY_BASIC_INFORMATION));
		retry:
			while (allocation_address < end && VirtualQuery((void*)allocation_address, &mbi, sizeof(mbi)))
			{
				if (mbi.State == MEM_FREE)
				{
#ifdef _WIN64
					printf("[+]%s. Found free memory region: 0x%I64X\n", __FUNCTION__, mbi.BaseAddress);
#else
					printf("[+]%s. Found free memory region: 0x%I32X\n", __FUNCTION__, mbi.BaseAddress);
#endif // _WIN64
					allocation_address = (DWORD64)mbi.BaseAddress;
					break;
				}
				allocation_address += mbi.RegionSize;
			}

			m_shellcode_allocated_memory = VirtualAlloc((void*)allocation_address, 1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

			if (m_shellcode_allocated_memory == NULL)
			{
				if (allocation_address < end)
				{
					printf("[+]%s. Failed allocate memory, retry...\n", __FUNCTION__);
					allocation_address += mbi.RegionSize;
					goto retry;
				}
				printf("[+]%s. Failed allocate memory\n", __FUNCTION__);
				return false;
			}
		}

#ifdef _WIN64
		printf("[+]%s. Shellcode allocated page: 0x%I64X\n", __FUNCTION__, (DWORD_PTR)m_shellcode_allocated_memory);
#else
		printf("[+]%s. Shellcode allocated page: 0x%I32X\n", __FUNCTION__, (DWORD_PTR)m_shellcode_allocated_memory);
#endif // _WIN64

		status_ok = true;
		return true;
	}

	bool patch(void* shellcode, int sizeof_shellcode, int replace_byte_instruction_length)
	{
		if (shellcode == NULL || replace_byte_instruction_length == NULL || !status_ok)
		{
			printf("[+]%s. U are autistic\n", __FUNCTION__);
			return false;
		}

		m_replace_byte_instruction_length = replace_byte_instruction_length;

		memcpy(m_shellcode_allocated_memory, shellcode, sizeof_shellcode);

		memset((void*)((DWORD_PTR)m_shellcode_allocated_memory + sizeof_shellcode), 0xe9, 1);
		DWORD relative_addr_jmp_back = (((DWORD)m_start_address - (DWORD)m_shellcode_allocated_memory) - (DWORD)(sizeof_shellcode)+(DWORD)(replace_byte_instruction_length - 5));
		memcpy((void*)((DWORD_PTR)m_shellcode_allocated_memory + sizeof_shellcode + 1), &relative_addr_jmp_back, 4);

		m_jmp_bytes = new BYTE[replace_byte_instruction_length];
		m_saved_original_bytes = new BYTE[replace_byte_instruction_length];

		memcpy(m_saved_original_bytes, m_start_address, replace_byte_instruction_length);
		if (replace_byte_instruction_length > 5)
		{
			memset(m_jmp_bytes + 0x5, 0x90, (int)(replace_byte_instruction_length - 5));
			memcpy(m_saved_original_bytes + 0x5, (void*)((DWORD_PTR)m_start_address + 0x5), (int)(replace_byte_instruction_length - 5));
		}

		m_jmp_bytes[0] = 0xe9;
		DWORD relative_address = (((DWORD)m_shellcode_allocated_memory - (DWORD)m_start_address) - (DWORD)5);
		memcpy(m_jmp_bytes + 0x1, &relative_address, 4);

		return patch_instruction(m_start_address, m_jmp_bytes, replace_byte_instruction_length);
	}

	bool disable()
	{
		if (m_jmp_bytes == NULL || m_saved_original_bytes == NULL || !status_ok)
			return false;

		return patch_instruction(m_start_address, m_saved_original_bytes, m_replace_byte_instruction_length);
	}

	void cleanup()
	{
		m_saved_original_bytes = NULL;
		m_jmp_bytes = NULL;
		m_start_address = NULL;
	}

	void* get_allocated_memory_address()
	{
		return m_shellcode_allocated_memory;
	}
};

CShellCodeHelper* g_pEntityListGrabber;

void* g_RAX_REGISTER_SPECIAL = 0;

bool CreateHack()
{
	g_pEntityListGrabber = new CShellCodeHelper();

	/*
		Address of signature = bf4.exe + 0x002ACF25
		"\x48\x8B\x00\x48\x3B\x00\x00\x74\x00\x66\x00\x48\x8B\x00\x48\x3B", "xx?xx??x?x?xx?xx"
		"48 8B ? 48 3B ? ? 74 ? 66 ? 48 8B ? 48 3B"
	*/
	auto PatchAddress = memory_utils::pattern_scanner_module(memory_utils::get_base(), "\x48\x8B\x00\x48\x3B\x00\x00\x74\x00\x66\x00\x48\x8B\x00\x48\x3B", "xx?xx??x?x?xx?xx");

	if (!PatchAddress)
		return false;

	if (!g_pEntityListGrabber->setup((void*)PatchAddress))
		return false;

	BYTE Patch[] = {

		0x48, 0x8B, 0x18, //mov rbx, [rax]
		0x48, 0x3B, 0x58, 0x08, //cmp rbx, [rax+0x8]
		0x48, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 //mov [ADDRESS], rax 
	};

	*(std::uintptr_t*)((std::uintptr_t)Patch + 0x9) = (std::uintptr_t)&g_RAX_REGISTER_SPECIAL;

	return g_pEntityListGrabber->patch(Patch, sizeof(Patch), 7);
}

void VehicleEspHack()
{
	/*
		Address of signature = bf4.exe + 0x002A9493
		"\x83\x79\x50\x00\x0F\x94", "xxx?xx"
		"83 79 50 ? 0F 94"
	*/

	auto p1 = memory_utils::pattern_scanner_module(memory_utils::get_base(), "\x83\x79\x50\x00\x0F\x94", "xxx?xx");

	if (!p1)
		return;

	p1 += 0x3;

	memory_utils::patch_instruction(p1, "\x00", 1);

	/*
		Address of signature = bf4.exe + 0x002A949F
		"\x83\xF8\x00\x74\x00\x40\x84\x00\x74\x00\x83\xF8", "xx?x?xx?x?xx"
		"83 F8 ? 74 ? 40 84 ? 74 ? 83 F8"
	*/

	auto p2 = memory_utils::pattern_scanner_module(memory_utils::get_base(), "\x83\xF8\x00\x74\x00\x40\x84\x00\x74\x00\x83\xF8", "xx?x?xx?x?xx");

	if (!p2)
		return;

	p2 += 0x2;

	memory_utils::patch_instruction(p2, "\x00", 1);
}

void SoldierEspHack()
{
	/*
		Address of signature = bf4.exe + 0x002AD66A
		"\x75\x00\x41\x8B\x00\x00\x89\x43", "x?xx??xx"
		"75 ? 41 8B ? ? 89 43"
	*/

	auto p = memory_utils::pattern_scanner_module(memory_utils::get_base(), "\x75\x00\x41\x8B\x00\x00\x89\x43", "x?xx??xx");

	if (!p)
		return;

	memory_utils::fill_memory_region(p, 0x90, 2);

	/*
		Address of signature = bf4.exe + 0x002924E7
		"\x41\x0F\x00\x00\x00\x00\x00\x00\x0F\x94\x00\x88\x44", "xx??????xx?xx"
		"41 0F ? ? ? ? ? ? 0F 94 ? 88 44"
	*/

	/*auto vischeck = memory_utils::pattern_scanner_module(memory_utils::get_base(), "\x41\x0F\x00\x00\x00\x00\x00\x00\x0F\x94\x00\x88\x44", "xx??????xx?xx");

	if (!vischeck)
		return;

	memory_utils::patch_instruction(vischeck, "\xB8\x00\x00\x00\x00\x90\x90\x90", 8);*/
}

std::uintptr_t GetEntityList()
{
	if (!g_RAX_REGISTER_SPECIAL)
		return 0;

	return (std::uintptr_t)(g_RAX_REGISTER_SPECIAL) + 0x28;
}

void HackThread(void* arg)
{
	if (!Console::Attach("debug"))
		return;

	printf("[+] Attach successfully\n");

	if (!CreateHack())
	{
		printf("[-] Hack not installed\n");
		return;
	}

	VehicleEspHack();

	SoldierEspHack();

	while (!GetAsyncKeyState(VK_DELETE))
	{
		auto entlist = GetEntityList();

		if (!entlist)
			continue;

		printf("\n/////////////// START //////////////////\n");

		printf("\n\nEntity list start: %p\n\n", entlist);

		for (auto i = 0; i < 64; i++)
		{
			auto entity = *(std::uintptr_t*)(entlist + (0x8 * i));

			if (!entity)
				continue;

			auto name = (char*)(entity + 0x40);

			if (!*name || strlen(name) > 50)
				continue;

			printf("%I64x | %s\n", entity, name);
		}

		printf("\n\n/////////////// END //////////////////\n");

		Sleep(1);
	}

	FreeLibraryAndExitThread((HMODULE)arg, 0);
}

BOOL APIENTRY DllMain( HMODULE hModule,
					   DWORD  ul_reason_for_call,
					   LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)HackThread, hModule, 0, nullptr);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}