#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <iostream>
#include <direct.h>
#include <vector>
#include <thread>
#include <chrono>
#include <intrin.h>

#include "../libs/minhook/minhook.h"
#pragma comment (lib, "libs/minhook/minhook.lib")

#include "memory_utils/memory_utils.h"

#include "console/console.h"