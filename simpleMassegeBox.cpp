#include <Windows.h>

int main()
{
    // Expected to tell "Hooked!".
    MessageBoxW(NULL, L"Not hooked...", L"MinHook Sample", MB_OK);

    return 0;
}
