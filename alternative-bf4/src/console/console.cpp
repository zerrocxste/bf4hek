#include "../alternative.h"

bool Console::Attach(const char* szTitle)
{
	if (!AllocConsole())
		return false;

	SetConsoleTitle(szTitle);

	freopen("conout$", "w", stdout);

	return true;
}
