#include "alternative.h"

struct Matrix_s { float m[4][4]; };
struct Coords_s { float x, y, z; };

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
			while (allocation_address < end)
			{
				if (!VirtualQuery((void*)allocation_address, &mbi, sizeof(mbi)))
					return false;

				if (mbi.State == MEM_FREE)
				{
					printf("[+] %s. Found free memory region: 0x%p\n", __FUNCTION__, mbi.BaseAddress);
					allocation_address = (DWORD64)mbi.BaseAddress;
					break;
				}

				allocation_address += mbi.RegionSize;
			}

			m_shellcode_allocated_memory = VirtualAlloc((void*)allocation_address, 1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

			if (m_shellcode_allocated_memory == NULL)
			{
				printf("[+] %s. Failed allocate memory, retry...\n", __FUNCTION__);
				allocation_address += mbi.RegionSize;
				goto retry;
			}
		}

		printf("[+] %s. Shellcode allocated page: 0x%p\n", __FUNCTION__, m_shellcode_allocated_memory);
		status_ok = true;
		return true;
	}

	bool patch(void* shellcode, int sizeof_shellcode, int replace_byte_instruction_length)
	{
		if (shellcode == NULL || replace_byte_instruction_length == NULL || !status_ok)
		{
			printf("[+] %s. U are autistic\n", __FUNCTION__);
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
CShellCodeHelper* g_pViewmatrixGrabber;

void* g_RAX_REGISTER_SPECIAL = 0;
void* g_ViewMatrixAddress = 0;

int g_MyTeamID = 1;

std::uintptr_t GetLocalPlayer()
{
	if (!g_RAX_REGISTER_SPECIAL)
		return 0;

	return *(std::uintptr_t*)((std::uintptr_t)(g_RAX_REGISTER_SPECIAL) + 0x470);
}

std::uintptr_t GetEntityList()
{
	if (!g_RAX_REGISTER_SPECIAL)
		return 0;

	return (std::uintptr_t)(g_RAX_REGISTER_SPECIAL) + 0x28;
}

void CreateEntityListHack()
{
	g_pEntityListGrabber = new CShellCodeHelper();

	/*
		Address of signature = bf4.exe + 0x002ACF25
		"\x48\x8B\x00\x48\x3B\x00\x00\x74\x00\x66\x00\x48\x8B\x00\x48\x3B", "xx?xx??x?x?xx?xx"
		"48 8B ? 48 3B ? ? 74 ? 66 ? 48 8B ? 48 3B"
	*/
	auto PatchAddress = memory_utils::pattern_scanner_module(memory_utils::get_base(), "\x48\x8B\x00\x48\x3B\x00\x00\x74\x00\x66\x00\x48\x8B\x00\x48\x3B", "xx?xx??x?x?xx?xx");

	if (!PatchAddress)
	{
		printf("[-] %s -> not found\n", __FUNCTION__);
		return;
	}

	if (!g_pEntityListGrabber->setup((void*)PatchAddress))
		return;

	BYTE Patch[] = {

		0x48, 0x8B, 0x18, //mov rbx, [rax]
		0x48, 0x3B, 0x58, 0x08, //cmp rbx, [rax+0x8]
		0x48, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 //mov [ADDRESS], rax 
	};

	*(std::uintptr_t*)((std::uintptr_t)Patch + 0x9) = (std::uintptr_t)&g_RAX_REGISTER_SPECIAL;

	g_pEntityListGrabber->patch(Patch, sizeof(Patch), 7);
}

void CreateViewmatrixHack()
{
	g_pViewmatrixGrabber = new CShellCodeHelper();

	/*
		Address of signature = bf4.exe + 0x00C02D18
		"\x0F\x28\x00\x00\x00\x00\x00\x0F\x29\x00\x00\x0F\x28\x00\x00\x00\x00\x00\x0F\x29\x00\x00\x0F\x29\x00\x00\x0F\x28\x00\x00\x00\x00\x00\x0F\x29\x00\x00\x41\x0F", "xx?????xx??xx?????xx??xx??xx?????xx??xx"
		"0F 28 ? ? ? ? ? 0F 29 ? ? 0F 28 ? ? ? ? ? 0F 29 ? ? 0F 29 ? ? 0F 28 ? ? ? ? ? 0F 29 ? ? 41 0F"
	*/

	auto PatchAddress = memory_utils::pattern_scanner_module(memory_utils::get_base(), 
		"\x0F\x28\x00\x00\x00\x00\x00\x0F\x29\x00\x00\x0F\x28\x00\x00\x00\x00\x00\x0F\x29\x00\x00\x0F\x29\x00\x00\x0F\x28\x00\x00\x00\x00\x00\x0F\x29\x00\x00\x41\x0F", 
		"xx?????xx??xx?????xx??xx??xx?????xx??xx");

	if (!PatchAddress)
	{
		printf("[-] %s -> not found\n", __FUNCTION__);
		return;
	}

	if (!g_pViewmatrixGrabber->setup((void*)PatchAddress))
		return;

	BYTE Patch[] = {
		0x0F, 0x28, 0x86, 0x20, 0x04, 0x00, 0x00, //movaps xmm0, [rsi+420]
		0x4C, 0x8B, 0xC0, //mov r8, rax
		0x48, 0x8D, 0x86, 0x20, 0x04, 0x00, 0x00, //lea rax, [rsi+420]
		0x48, 0xA3, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //mov [MY_ADDRESS_VIEWMATRIX], rax
		0x49, 0x8B, 0xC0, //mov rax, r8
		0x4D, 0x31, 0xC0, //xor r8, r8
	};

	*(std::uintptr_t*)((std::uintptr_t)Patch + 0x13) = (std::uintptr_t)&g_ViewMatrixAddress;

	g_pViewmatrixGrabber->patch(Patch, sizeof(Patch), 7);
}

void VehicleEspHack()
{
	/*
		Address of signature = bf4.exe + 0x002A9493
		"\x83\x79\x50\x00\x0F\x94", "xxx?xx"
		"83 79 50 ? 0F 94"
	*/

	auto checkSpottedInstruction = memory_utils::pattern_scanner_module(memory_utils::get_base(), "\x83\x79\x50\x00\x0F\x94", "xxx?xx");

	if (!checkSpottedInstruction)
	{
		printf("[-] %s -> not found checkSpottedInstruction\n", __FUNCTION__);
		return;
	}

	memory_utils::patch_instruction(checkSpottedInstruction, "\xB0\x01\x90\x90\x90\x90\x90", 7); //mov al, 1 ... nop

	/*
		Address of signature = bf4.exe + 0x002A949F
		"\x83\xF8\x00\x74\x00\x40\x84\x00\x74\x00\x83\xF8", "xx?x?xx?x?xx"
		"83 F8 ? 74 ? 40 84 ? 74 ? 83 F8"
	*/

	auto checkSpottedInstruction2 = memory_utils::pattern_scanner_module(memory_utils::get_base(), "\x83\xF8\x00\x74\x00\x40\x84\x00\x74\x00\x83\xF8", "xx?x?xx?x?xx");

	if (!checkSpottedInstruction2)
	{
		printf("[-] %s -> not found checkSpottedInstruction2\n", __FUNCTION__);
		return;
	}

	checkSpottedInstruction2 += 0x3;

	memory_utils::patch_instruction(checkSpottedInstruction2, "\xEB", 1);
}

CShellCodeHelper* g_pVisibleCheckPatch;

void SoldierEspHack()
{
	/*
		Address of signature = bf4.exe + 0x002AD66A
		"\x75\x00\x41\x8B\x00\x00\x89\x43", "x?xx??xx"
		"75 ? 41 8B ? ? 89 43"
	*/

	auto checkSpottedInstruction = memory_utils::pattern_scanner_module(memory_utils::get_base(), "\x75\x00\x41\x8B\x00\x00\x89\x43", "x?xx??xx");

	if (!checkSpottedInstruction)
	{
		printf("[-] %s -> not found checkSpottedInstruction\n", __FUNCTION__);
		return;
	}

	memory_utils::fill_memory_region(checkSpottedInstruction, 0x90, 2);

	/*
		Address of signature = bf4.exe + 0x002924E7
		"\x41\x0F\x00\x00\x00\x00\x00\x00\x0F\x94\x00\x88\x44", "xx??????xx?xx"
		"41 0F ? ? ? ? ? ? 0F 94 ? 88 44"
	*/

	//auto visibleCheckInstruction = memory_utils::pattern_scanner_module(memory_utils::get_base(), "\x41\x0F\x00\x00\x00\x00\x00\x00\x0F\x94\x00\x88\x44", "xx??????xx?xx");

	//if (!visibleCheckInstruction)
	//{
	//	printf("[-] %s -> not found visibleCheckInstruction\n", __FUNCTION__);
	//	return;
	//}

	//g_pVisibleCheckPatch = new CShellCodeHelper();

	//g_pVisibleCheckPatch->setup((void*)visibleCheckInstruction);

	//BYTE Patch[] = {
	//	0x49, 0x8B, 0x97, 0xE0, 0x01, 0x00, 0x00, //mov rdx, [r15+1e0] !(Copy ClientPlayer from ClientSoldierEntity + 0x1E0)
	//	0x48, 0x85, 0xD2, //test rdx, rdx !(Check ClientPlayer for nullptr)
	//	0x0F, 0x84, 0x24, 0x00, 0x00, 0x00, //je 36 bytes
	//	0xA1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //mov eax, [g_MyTeamID_ADDRESS] !(Copy my team id to eax)
	//	0x39, 0x82, 0xCC, 0x13, 0x00, 0x00, //cmp [rdx+0x13cc], eax !(check for team)
	//	0x0F, 0x84, 0x0A, 0x00, 0x00, 0x00, //je 10 bytes
	//	0xB8, 0x00, 0x00, 0x00, 0x00, //mov eax, 1 !(Set invisible)
	//	0xE9, 0x05, 0x00, 0x00, 0x00, //jmp 5 bytes !(exit from condition)
	//	0xB8, 0x01, 0x00, 0x00, 0x00, //mov eax, 0 !(Set visible)
	//	0x48, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //mov rdx, 1 !(restore rdx to 1 (info from debugger, maybe required))
	//	0x48, 0x3B, 0x77, 0x08, //cmp rsi, [rdi+08] !(Кestoring instructions from the original, the result of which was replaced by our checks)
	//};

	//*(std::uintptr_t*)(Patch + 0x11) = (std::uintptr_t)&g_MyTeamID;

	//g_pVisibleCheckPatch->patch(Patch, sizeof(Patch), 8);
}

void NoSpreadHack()
{
	/*
		Address of signature = bf4.exe + 0x002D39D0
		"\xF3\x0F\x00\x00\x00\x00\x00\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x89\x00\x00\x00\x48\x89\x00\x00\x00\x48\x89\x00\x00\x00\x57\x48\x83\xEC\x00\xC6\x81\x19\x03\x00\x00", "xx??????xxxxxxxxxx???xx???xx???xxxx?xxxxxx"
		"F3 0F ? ? ? ? ? ? C3 CC CC CC CC CC CC CC 48 89 ? ? ? 48 89 ? ? ? 48 89 ? ? ? 57 48 83 EC ? C6 81 19 03 00 00"
	*/

	auto crosshairReadSpread = memory_utils::pattern_scanner_module(memory_utils::get_base(),
		"\xF3\x0F\x00\x00\x00\x00\x00\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x89\x00\x00\x00\x48\x89\x00\x00\x00\x48\x89\x00\x00\x00\x57\x48\x83\xEC\x00\xC6\x81\x19\x03\x00\x00", 
		"xx??????xxxxxxxxxx???xx???xx???xxxx?xxxxxx");

	if (!crosshairReadSpread)
	{
		printf("[-] %s -> not found crosshairReadSpread\n", __FUNCTION__);
		return;
	}

	memory_utils::patch_instruction(crosshairReadSpread, "\xB8\xCD\xCC\x4C\x3E\x66\x0F\x6E\xC0\xC3", 10);

	/*
		Address of signature = bf4.exe + 0x002D5530
		"\xF3\x0F\x00\x00\x00\x00\x00\x00\xF3\x0F\x00\x00\x00\x00\x00\x00\xF3\x0F\x00\x00\x00\x00\x00\x00\xF3\x0F\x00\x00\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xF3\x0F\x00\x00\xF3\x0F\x00\x00\x00\x00\x00\x00\xF3\x0F\x00\x00\x00\x00\x00\x00\xE8", "xx??????xx??????xx??????xx??????x????xx??xx??????xx??????x"
		"F3 0F ? ? ? ? ? ? F3 0F ? ? ? ? ? ? F3 0F ? ? ? ? ? ? F3 0F ? ? ? ? ? ? E8 ? ? ? ? F3 0F ? ? F3 0F ? ? ? ? ? ? F3 0F ? ? ? ? ? ? E8"
	*/

	auto multiplicationBySpreadValue = memory_utils::pattern_scanner_module(memory_utils::get_base(), 
		"\xF3\x0F\x00\x00\x00\x00\x00\x00\xF3\x0F\x00\x00\x00\x00\x00\x00\xF3\x0F\x00\x00\x00\x00\x00\x00\xF3\x0F\x00\x00\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xF3\x0F\x00\x00\xF3\x0F\x00\x00\x00\x00\x00\x00\xF3\x0F\x00\x00\x00\x00\x00\x00\xE8", 
		"xx??????xx??????xx??????xx??????x????xx??xx??????xx??????x");

	if (!multiplicationBySpreadValue)
	{
		printf("[-] %s -> not found readAndMultiplicationSpreadValue\n", __FUNCTION__);
		return;
	}

	memory_utils::fill_memory_region(multiplicationBySpreadValue, 0x90, 16);
}

void AllowReloadInScope()
{
	/*
		Address of signature = bf4.exe + 0x00FA9923
		"\x44\x89\x00\x00\x00\x00\x00\xE9\x00\x00\x00\x00\xA8", "xx?????x????x"
		"44 89 ? ? ? ? ? E9 ? ? ? ? A8"
	*/

	auto ScopedCheckAddress = memory_utils::pattern_scanner_module(memory_utils::get_base(), "\x44\x89\x00\x00\x00\x00\x00\xE9\x00\x00\x00\x00\xA8", "xx?????x????x");

	if (!ScopedCheckAddress)
	{
		printf("[-] %s -> not found ScopedCheckAddress\n", __FUNCTION__);
		return;
	}

	memory_utils::fill_memory_region(ScopedCheckAddress, 0x90, 12);
}

void AllowFireInJump()
{
	/*
		Address of signature = bf4.exe + 0x00F9CBD0
		"\xC7\x83\xB0\x02\x00\x00\x00\x00\x00\x00\x48\x83\xC4\x20", "xxxxxxxxxxxxxx"
		"C7 83 B0 02 00 00 00 00 00 00 48 83 C4 20"
	*/

	auto WriteInJumpMovement = memory_utils::pattern_scanner_module(memory_utils::get_base(), "\xC7\x83\xB0\x02\x00\x00\x00\x00\x00\x00\x48\x83\xC4\x20", "xxxxxxxxxxxxxx");

	if (!WriteInJumpMovement)
	{
		printf("[-] %s -> not found WriteInJumpMovement\n", __FUNCTION__);
		return;
	}

	memory_utils::fill_memory_region(WriteInJumpMovement, 0x90, 10);

	/*
		Address of signature = bf4.exe + 0x00F9CBE0
		"\xC7\x83\xB0\x02\x00\x00\x03\x00\x00\x00\x48\x83\xC4\x20", "xxxxxxxxxxxxxx"
		"C7 83 B0 02 00 00 03 00 00 00"
	*/

	auto CameraShakeAfterLanding = memory_utils::pattern_scanner_module(memory_utils::get_base(), "\xC7\x83\xB0\x02\x00\x00\x03\x00\x00\x00\x48\x83\xC4\x20", "xxxxxxxxxxxxxx");

	if (!CameraShakeAfterLanding)
	{
		printf("[-] %s -> not found NoCameraShakeAfterLanding\n", __FUNCTION__);
		return;
	}

	memory_utils::fill_memory_region(CameraShakeAfterLanding, 0x90, 10);
}

void CallOfDutyGunplayMod()
{
	//AllowReloadInScope();

	AllowFireInJump();
}

inline bool WorldToScreen(Matrix_s Matrix, const Coords_s& vIn, float* flOut);

namespace FrostbiteRender
{
	using fDrawLine = void(__fastcall*)(__int64 pYaNeZnayuChtoEtoTakoe, float* pPoint1, float* pPoint2, int Color);
	fDrawLine pfDrawLine = nullptr;

	using fDrawFilledRect = void(__fastcall*)(__int64 pYaNeZnayuChtoEtoTakoe, float* pPoint1, float* pPoint2, int Color);
	fDrawFilledRect pfDrawFilledRect = nullptr;

	using fGetScreenSize = int* (__fastcall*)(__int64 pYaNeZnayuChtoEtoTakoe/*A nahuya?*/, int* pOutScreenSize);
	fGetScreenSize pfGetScreenSize = nullptr;

	void DrawLine(__int64 pYaNeZnayuChtoEtoTakoe, int x, int y, int x1, int y1, std::uint8_t r, std::uint8_t g, std::uint8_t b, std::uint8_t a = 255)
	{
		if (!pfDrawLine)
			return;

		float P1[2]{ x, y };
		float P2[2]{ x1, y1 };

		int Color = 0x000000FF;
		auto pColor = (std::uint8_t*)&Color;
		pColor[0] = r;
		pColor[1] = g;
		pColor[2] = b;
		pColor[3] = a;

		pfDrawLine(pYaNeZnayuChtoEtoTakoe, P1, P2, Color);
	}

	void DrawRect(__int64 pYaNeZnayuChtoEtoTakoe, float x, float y, float x1, float y1, std::uint8_t r, std::uint8_t g, std::uint8_t b, std::uint8_t a = 255)
	{
		DrawLine(pYaNeZnayuChtoEtoTakoe, x, y, x1, y, r, g, b, a);
		DrawLine(pYaNeZnayuChtoEtoTakoe, x, y, x, y1, r, g, b, a);
		DrawLine(pYaNeZnayuChtoEtoTakoe, x, y1, x1, y1, r, g, b, a);
		DrawLine(pYaNeZnayuChtoEtoTakoe, x1, y, x1, y1, r, g, b, a);
	}

	void DrawFilledRect(__int64 pYaNeZnayuChtoEtoTakoe, int x, int y, int x1, int y1, std::uint8_t r, std::uint8_t g, std::uint8_t b, std::uint8_t a = 255)
	{
		if (!pfDrawFilledRect)
			return;

		float P1[2]{ x, y };
		float P2[2]{ x1, y1 };

		int Color = 0x000000FF;
		auto pColor = (std::uint8_t*)&Color;
		pColor[0] = r;
		pColor[1] = g;
		pColor[2] = b;
		pColor[3] = a;

		pfDrawFilledRect(pYaNeZnayuChtoEtoTakoe, P1, P2, Color);
	}

	int* GetScreenSize()
	{
		int ScreenSize[2]{ 0, 0 };

		if (!pfGetScreenSize)
			return ScreenSize;
		
		return pfGetScreenSize(0, ScreenSize);
	}

	using fGetRenderBaseFunction = __int64(__fastcall*)(__int64 param_1, __int64 param_2, __int64 param_3, __int64 param_4);
	fGetRenderBaseFunction pfGetRenderBaseFunction = nullptr;

	__int64 __fastcall GetRenderBase_proxy(__int64 param_1, __int64 param_2, __int64 param_3, __int64 param_4)
	{
		auto ret = pfGetRenderBaseFunction(param_1, param_2, param_3, param_4);

		if (ret && !param_2 && !param_3 && !param_4)
		{
			auto ESP = [&]() -> void {

				auto LocalPlayer = GetLocalPlayer();

				if (!LocalPlayer)
					return;

				auto EntityList = GetEntityList();

				if (!EntityList)
					return;

				auto LocalName = (char*)(LocalPlayer + 0x40);

				g_MyTeamID = *(int*)(LocalPlayer + 0x13CC);

				Matrix_s matrix{};
				
				if (g_ViewMatrixAddress)
					matrix = *(Matrix_s*)(g_ViewMatrixAddress);

				for (auto i = 0; i < 64; i++)
				{
					auto Entity = *(std::uintptr_t*)(EntityList + (0x8 * i));

					if (!Entity || Entity == LocalPlayer)
						continue;

					auto TeamID = *(int*)(Entity + 0x13CC);

					if (g_MyTeamID == TeamID)
						continue;

					auto Name = (char*)(Entity + 0x40);

					if (!*Name || strlen(Name) > 50)
						continue;

					auto Soldier = *(std::uintptr_t*)(Entity + 0x14D0);

					if (!Soldier)
						continue;

					auto Coords = *(Coords_s*)(Soldier + 0x1890);
					
					float ScreenBot[2]{}, ScreenTop[2]{};
					if (WorldToScreen(matrix, Coords, ScreenBot) && WorldToScreen(matrix, Coords_s{ Coords.x, Coords.y + 1.5f, Coords.z }, ScreenTop))
					{
						float h = ScreenBot[1] - ScreenTop[1];
						float w = h / 2;
						float x = ScreenBot[0] - w / 2;
						float y = ScreenTop[1];

						DrawRect(ret, x, y, x + w, y + h, 255, 0, 0);
					}
				}
			};

			ESP();
		}

		return ret;
	}

	void InitializeRender()
	{
		/*
			Address of signature = bf4.exe + 0x0063D0C0
			"\x48\x8B\x00\x00\x00\x00\x00\x48\x85\x00\x75\x00\x33\xC0\xC3\xE9\x00\x00\x00\x00\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x40\x00\x48\x83\xEC", "xx?????xx?x?xxxx????xxxxxxxxxxxxx?xxx"
			"48 8B ? ? ? ? ? 48 85 ? 75 ? 33 C0 C3 E9 ? ? ? ? CC CC CC CC CC CC CC CC CC CC CC CC 40 ? 48 83 EC"
		*/

		auto GetRenderBase = (void*)memory_utils::pattern_scanner_module(
			memory_utils::get_base(),
			"\x48\x8B\x00\x00\x00\x00\x00\x48\x85\x00\x75\x00\x33\xC0\xC3\xE9\x00\x00\x00\x00\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x40\x00\x48\x83\xEC",
			"xx?????xx?x?xxxx????xxxxxxxxxxxxx?xxx");

		MH_CreateHook(GetRenderBase, GetRenderBase_proxy, (LPVOID*)&pfGetRenderBaseFunction);
		MH_EnableHook(GetRenderBase);

		/*
			Address of signature = bf4.exe + 0x0063DEB0
			"\x48\x89\x00\x00\x00\x44\x89\x00\x00\x00\x57\x48\x83\xEC\x00\x48\x8B\x00\xBA", "xx???xx???xxxx?xx?x"
			"48 89 ? ? ? 44 89 ? ? ? 57 48 83 EC ? 48 8B ? BA"
		*/

		pfDrawLine = (fDrawLine)memory_utils::pattern_scanner_module(
			memory_utils::get_base(),
			"\x48\x89\x00\x00\x00\x44\x89\x00\x00\x00\x57\x48\x83\xEC\x00\x48\x8B\x00\xBA",
			"xx???xx???xxxx?xx?x");

		/*
			Address of signature = bf4.exe + 0x0063E0B0
			"\x48\x8B\x00\x48\x89\x00\x00\x48\x89\x00\x00\x44\x89\x00\x00\x57\x48\x83\xEC\x00\x0F\x29", "xx?xx??xx??xx??xxxx?xx"
			"48 8B ? 48 89 ? ? 48 89 ? ? 44 89 ? ? 57 48 83 EC ? 0F 29"
		*/

		pfDrawFilledRect = (fDrawFilledRect)memory_utils::pattern_scanner_module(
			memory_utils::get_base(),
			"\x48\x8B\x00\x48\x89\x00\x00\x48\x89\x00\x00\x44\x89\x00\x00\x57\x48\x83\xEC\x00\x0F\x29",
			"xx?xx??xx??xx??xxxx?xx");

		/*
			Address of signature = bf4.exe + 0x0063F8B0
			"\x8B\x05\x00\x00\x00\x00\x89\x02\x8B\x05\x00\x00\x00\x00\x89\x42\x00\x48\x8B", "xx????xxxx????xx?xx"
			"8B 05 ? ? ? ? 89 02 8B 05 ? ? ? ? 89 42 ? 48 8B"
		*/

		pfGetScreenSize = (fGetScreenSize)memory_utils::pattern_scanner_module(
			memory_utils::get_base(),
			"\x8B\x05\x00\x00\x00\x00\x89\x02\x8B\x05\x00\x00\x00\x00\x89\x42\x00\x48\x8B", 
			"xx????xxxx????xx?xx");
	}
}

inline bool WorldToScreen(Matrix_s Matrix, const Coords_s& vIn, float* flOut)
{
	auto view_projection = Matrix;

	float w = view_projection.m[0][3] * vIn.x + view_projection.m[1][3] * vIn.y + view_projection.m[2][3] * vIn.z + view_projection.m[3][3];

	if (w < 0.01)
		return false;

	flOut[0] = view_projection.m[0][0] * vIn.x + view_projection.m[1][0] * vIn.y + view_projection.m[2][0] * vIn.z + view_projection.m[3][0];
	flOut[1] = view_projection.m[0][1] * vIn.x + view_projection.m[1][1] * vIn.y + view_projection.m[2][1] * vIn.z + view_projection.m[3][1];

	float invw = 1.0f / w;

	flOut[0] *= invw;
	flOut[1] *= invw;

	int width, height;

	auto disp = FrostbiteRender::GetScreenSize();
	width = disp[0];
	height = disp[1];

	float x = (float)width / 2;
	float y = (float)height / 2;

	x += 0.5 * flOut[0] * (float)width + 0.5;
	y -= 0.5 * flOut[1] * (float)height + 0.5;

	flOut[0] = x;
	flOut[1] = y;

	return true;
}

void HackThread(void* arg)
{
	if (!Console::Attach("debug"))
		return;

	MH_Initialize();

	printf("[+] Attach successfully\n");

	CreateEntityListHack();

	CreateViewmatrixHack();

	VehicleEspHack();

	SoldierEspHack();

	NoSpreadHack();

	CallOfDutyGunplayMod();

	FrostbiteRender::InitializeRender();

	while (true)
	{
		/*auto LocalPlayer = GetLocalPlayer();

		if (!LocalPlayer)
			continue;
		
		auto entlist = GetEntityList();

		if (!entlist)
			continue;

		printf("\n/////////////// START ///////////////\n");

		auto LocalName = (char*)(LocalPlayer + 0x40);

		g_MyTeamID = *(int*)(LocalPlayer + 0x13CC);

		printf("\nLocal Player: %p | %s | teamid: %d\n", LocalPlayer, LocalName, g_MyTeamID);

		printf("\nEntity list start: %p\n\n", entlist);

		for (auto i = 0; i < 64; i++)
		{
			auto entity = *(std::uintptr_t*)(entlist + (0x8 * i));

			if (!entity || entity == LocalPlayer)
				continue;

			auto name = (char*)(entity + 0x40);

			if (!*name || strlen(name) > 50)
				continue;

			printf("%p | %s\n", entity, name);
		}

		printf("\n\n/////////////// END ///////////////\n");

		Sleep(1000);*/
	}
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