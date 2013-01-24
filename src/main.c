/* -----------------------------------------------------------------------------
 * main.c defines the Windows entry point.
 *
 * Author: Frank Balluffi and Markus Moeller
 *
 * Copyright (C) 2002-2007 Frank Balluffi and Markus Moeller. All rights
 * reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * -----------------------------------------------------------------------------
 */
#define WIN32_LEAN_AND_MEAN

#include <stdio.h>
#include <windows.h>

BOOL WINAPI DllMain(
    HINSTANCE hInstance,
    DWORD reason,
    LPVOID reserved)
{
    LPCSTR reasonString = NULL;
    OutputDebugString("mod_spnego: entering DllMain for ");

    switch (reason) {
        case DLL_PROCESS_ATTACH:
            reasonString = "DLL_PROCESS_ATTACH\n";
            break;
        case DLL_PROCESS_DETACH:
            reasonString = "DLL_PROCESS_DETACH\n";
            break;
        case DLL_THREAD_ATTACH:
            reasonString = "DLL_THREAD_ATTACH\n";
            break;
        case DLL_THREAD_DETACH:
            reasonString = "DLL_THREAD_DETACH\n";
            break;
    }

    OutputDebugString(reasonString);
    return TRUE;
}
