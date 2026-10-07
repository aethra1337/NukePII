// zig-cc.exe: forwards `zig-cc.exe <cargo link args>` to
// `zig cc -target x86_64-windows-msvc <same args>`.
// Lets cargo build MSVC-target cdylibs without VS Build Tools.
// Compiled with zig itself: zig cc -target x86_64-windows-msvc -O2 -o zig-cc.exe zig-cc.c
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    const char *zig =
        "C:\\Users\\talha\\.zig\\zig-x86_64-windows-0.16.0\\zig.exe";
    // NOTE: zig 0.13 rejects `-Wl,--disable-auto-image-base` (rust passes it
    // for windows-gnu build scripts). It only affects the link of short-lived
    // build-script helpers; `--dynamicbase`/`--high-entropy-va` (ASLR) are kept.
    LPCWSTR cmdline = GetCommandLineW();
    // Skip our own argv[0] (possibly quoted).
    int i = 0, quoted = 0;
    while (cmdline[i] == L' ' || cmdline[i] == L'\t') i++;
    if (cmdline[i] == L'"') { quoted = 1; i++; }
    while (cmdline[i]) {
        if (quoted) { if (cmdline[i] == L'"') { i++; break; } }
        else if (cmdline[i] == L' ' || cmdline[i] == L'\t') break;
        i++;
    }
    while (cmdline[i] == L' ' || cmdline[i] == L'\t') i++;
    const wchar_t *rest = cmdline + i;

    // Filter args zig 0.13 rejects (exact-token match, quotes respected loosely).
    static const wchar_t *denied[] = {
        L"-Wl,--disable-auto-image-base",
        NULL
    };
    size_t rest_len = wcslen(rest);
    wchar_t *filtered = (wchar_t *)malloc((rest_len + 1) * sizeof(wchar_t));
    if (!filtered) return 1;
    {
        size_t o = 0, p = 0;
        while (rest[p]) {
            while (rest[p] == L' ' || rest[p] == L'\t') filtered[o++] = rest[p++];
            size_t start = p;
            int quoted2 = 0;
            while (rest[p] && (quoted2 || (rest[p] != L' ' && rest[p] != L'\t'))) {
                if (rest[p] == L'"') quoted2 = !quoted2;
                p++;
            }
            size_t len = p - start;
            int drop = 0;
            for (int k = 0; denied[k]; k++) {
                if (wcslen(denied[k]) == len && wcsncmp(rest + start, denied[k], len) == 0) {
                    drop = 1;
                    break;
                }
            }
            if (!drop) {
                wcsncpy(filtered + o, rest + start, len);
                o += len;
            } else {
                // also drop the separator we just copied
                while (o > 0 && (filtered[o-1] == L' ' || filtered[o-1] == L'\t')) o--;
            }
        }
        filtered[o] = 0;
        rest = filtered;
    }

    wchar_t wzig[MAX_PATH * 2];
    MultiByteToWideChar(CP_UTF8, 0, zig, -1, wzig, MAX_PATH * 2);
    size_t need = wcslen(wzig) + 64 + wcslen(rest) + 8;
    wchar_t *full = (wchar_t *)malloc(need * sizeof(wchar_t));
    if (!full) return 1;
    _snwprintf(full, need, L"\"%s\" cc -target x86_64-windows-gnu %s",
               wzig, rest);

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessW(NULL, full, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "zig-cc: CreateProcess failed (%lu)\n", GetLastError());
        free(full);
        return 1;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    free(full);
    return (int)code;
}
