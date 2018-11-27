/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       EXTRASSSDT.C
*
*  VERSION:     1.61
*
*  DATE:        23 Nov 2018
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "hde\hde64.h"
#include "extras.h"
#include "extrasSSDT.h"

PSERVICETABLEENTRY g_pSDT = NULL;
ULONG g_SDTLimit = 0;

PSERVICETABLEENTRY g_pSDTShadow = NULL;
ULONG g_SDTShadowLimit = 0;

EXTRASCONTEXT SSTDlgContext[SST_Max];

/*
* SdtDlgCompareFunc
*
* Purpose:
*
* KiServiceTable Dialog listview comparer function.
*
*/
INT CALLBACK SdtDlgCompareFunc(
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort //pointer to EXTRASCALLBACK
)
{
    INT       nResult = 0;

    EXTRASCONTEXT *pDlgContext;
    EXTRASCALLBACK *CallbackParam = (EXTRASCALLBACK*)lParamSort;

    if (CallbackParam == NULL)
        return 0;

    pDlgContext = &SSTDlgContext[CallbackParam->Value];

    switch (pDlgContext->lvColumnToSort) {
    case 0: //index
        return supGetMaxOfTwoULongFromString(
            pDlgContext->ListView,
            lParam1,
            lParam2,
            pDlgContext->lvColumnToSort,
            pDlgContext->bInverseSort);
    case 2: //address (hex)
        return supGetMaxOfTwoU64FromHex(
            pDlgContext->ListView,
            lParam1,
            lParam2,
            pDlgContext->lvColumnToSort,
            pDlgContext->bInverseSort);
    case 1: //string (fixed size)
    case 3: //string (fixed size)
        return supGetMaxCompareTwoFixedStrings(
            pDlgContext->ListView,
            lParam1,
            lParam2,
            pDlgContext->lvColumnToSort,
            pDlgContext->bInverseSort);
    }

    return nResult;
}

/*
* SdtHandlePopupMenu
*
* Purpose:
*
* Table list popup construction
*
*/
VOID SdtHandlePopupMenu(
    _In_ HWND hwndDlg
)
{
    POINT pt1;
    HMENU hMenu;

    if (GetCursorPos(&pt1) == FALSE)
        return;

    hMenu = CreatePopupMenu();
    if (hMenu) {
        InsertMenu(hMenu, 0, MF_BYCOMMAND, ID_OBJECT_COPY, T_SAVETOFILE);
        TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, pt1.x, pt1.y, 0, hwndDlg, NULL);
        DestroyMenu(hMenu);
    }
}

WCHAR output[0x2000];

/*
* SdtSaveListToFile
*
* Purpose:
*
* Dump table to the selected file
*
*/
VOID SdtSaveListToFile(
    _In_ HWND hwndDlg,
    _In_ EXTRASCONTEXT *pDlgContext
)
{
    WCHAR   ch;
    INT	    row, subitem, numitems, BufferSize = 0;
    SIZE_T  sz, k;
    LPWSTR  pItem = NULL;
    HCURSOR hSaveCursor, hHourGlass;
    WCHAR   szTempBuffer[MAX_PATH + 1];

    RtlSecureZeroMemory(szTempBuffer, sizeof(szTempBuffer));

    _strcpy(szTempBuffer, TEXT("list.txt"));
    if (supSaveDialogExecute(hwndDlg, (LPWSTR)&szTempBuffer, TEXT("Text files\0*.txt\0\0"))) {

        hHourGlass = LoadCursor(NULL, IDC_WAIT);

        ch = (WCHAR)0xFEFF;
        supWriteBufferToFile(szTempBuffer, &ch, sizeof(WCHAR), FALSE, FALSE);

        SetCapture(hwndDlg);
        hSaveCursor = SetCursor(hHourGlass);

        numitems = ListView_GetItemCount(pDlgContext->ListView);
        for (row = 0; row < numitems; row++) {

            output[0] = 0;
            for (subitem = 0; subitem < pDlgContext->lvColumnCount; subitem++) {

                sz = 0;
                pItem = supGetItemText(pDlgContext->ListView, row, subitem, &sz);
                if (pItem) {
                    _strcat(output, pItem);
                    supHeapFree(pItem);
                }
                if (subitem == 1) {
                    for (k = 54; k > sz / sizeof(WCHAR); k--) {
                        _strcat(output, TEXT(" "));
                    }
                }
                else {
                    _strcat(output, TEXT("\t"));
                }
            }
            _strcat(output, L"\r\n");
            BufferSize = (INT)_strlen(output);
            supWriteBufferToFile(szTempBuffer, output, (SIZE_T)(BufferSize * sizeof(WCHAR)), FALSE, TRUE);
        }

        SetCursor(hSaveCursor);
        ReleaseCapture();
    }
}

/*
* SdtDlgHandleNotify
*
* Purpose:
*
* WM_NOTIFY processing for dialog listview.
*
*/
VOID SdtDlgHandleNotify(
    _In_ LPARAM lParam,
    _In_ EXTRASCONTEXT *pDlgContext
)
{
    LPNMHDR  nhdr = (LPNMHDR)lParam;
    INT      nImageIndex;

    EXTRASCALLBACK CallbackParam;

    if (nhdr == NULL)
        return;

    if (nhdr->hwndFrom != pDlgContext->ListView)
        return;

    switch (nhdr->code) {

    case LVN_COLUMNCLICK:
        pDlgContext->bInverseSort = !pDlgContext->bInverseSort;
        pDlgContext->lvColumnToSort = ((NMLISTVIEW *)lParam)->iSubItem;
        CallbackParam.lParam = (LPARAM)pDlgContext->lvColumnToSort;
        CallbackParam.Value = pDlgContext->DialogMode;
        ListView_SortItemsEx(pDlgContext->ListView, &SdtDlgCompareFunc, (LPARAM)&CallbackParam);

        nImageIndex = ImageList_GetImageCount(g_ListViewImages);
        if (pDlgContext->bInverseSort)
            nImageIndex -= 2;
        else
            nImageIndex -= 1;

        supUpdateLvColumnHeaderImage(
            pDlgContext->ListView,
            pDlgContext->lvColumnCount,
            pDlgContext->lvColumnToSort,
            nImageIndex);

        break;

    default:
        break;
    }

}

/*
* SdtDialogProc
*
* Purpose:
*
* KiServiceTable Dialog window procedure.
*
*/
INT_PTR CALLBACK SdtDialogProc(
    _In_  HWND hwndDlg,
    _In_  UINT uMsg,
    _In_  WPARAM wParam,
    _In_  LPARAM lParam
)
{
    INT dlgIndex;
    EXTRASCONTEXT *pDlgContext;

    switch (uMsg) {

    case WM_INITDIALOG:
        SetProp(hwndDlg, T_DLGCONTEXT, (HANDLE)lParam);
        supCenterWindow(hwndDlg);
        break;

    case WM_GETMINMAXINFO:
        if (lParam) {
            ((PMINMAXINFO)lParam)->ptMinTrackSize.x = 640;
            ((PMINMAXINFO)lParam)->ptMinTrackSize.y = 480;
        }
        break;

    case WM_NOTIFY:
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            SdtDlgHandleNotify(lParam, pDlgContext);
        }
        break;

    case WM_SIZE:
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            extrasSimpleListResize(hwndDlg, pDlgContext->SizeGrip);
        }
        break;

    case WM_CLOSE:
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            if (pDlgContext->SizeGrip) DestroyWindow(pDlgContext->SizeGrip);

            dlgIndex = 0;

            if (pDlgContext->DialogMode == SST_Ntos)
                dlgIndex = wobjKSSTDlgId;
            else if (pDlgContext->DialogMode == SST_Win32k)
                dlgIndex = wobjW32SSTDlgId;

            if ((dlgIndex == wobjKSSTDlgId)
                || (dlgIndex == wobjW32SSTDlgId))
            {
                g_WinObj.AuxDialogs[dlgIndex] = NULL;
            }
            RtlSecureZeroMemory(pDlgContext, sizeof(EXTRASCONTEXT));
        }
        return DestroyWindow(hwndDlg);

    case WM_COMMAND:
        if (LOWORD(wParam) == IDCANCEL) {
            SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            return TRUE;
        }
        if (LOWORD(wParam) == ID_OBJECT_COPY) {
            pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
            if (pDlgContext) {
                SdtSaveListToFile(hwndDlg, pDlgContext);
            }
            return TRUE;
        }
        break;

    case WM_DESTROY:
        RemoveProp(hwndDlg, T_DLGCONTEXT);
        break;

    case WM_CONTEXTMENU:
        SdtHandlePopupMenu(hwndDlg);
        break;
    }

    return FALSE;
}

/*
* SdtOutputTable
*
* Purpose:
*
* Output dumped and converted syscall table to listview.
*
*/
VOID SdtOutputTable(
    _In_ HWND hwndDlg,
    _In_ PRTL_PROCESS_MODULES Modules,
    _In_ PSERVICETABLEENTRY Table,
    _In_ ULONG Count
)
{
    INT index, number;
    ULONG i;
    EXTRASCONTEXT *Context = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);

    LVITEM lvitem;
    WCHAR szBuffer[MAX_PATH + 1];

    szBuffer[0] = 0;

    switch (Context->DialogMode) {
    case SST_Ntos:
        _strcpy(szBuffer, TEXT("KiServiceTable 0x"));
        u64tohex(g_kdctx.KiServiceTableAddress, _strend(szBuffer));
        _strcat(szBuffer, TEXT(" / KiServiceLimit 0x"));
        ultohex(g_kdctx.KiServiceLimit, _strend(szBuffer));
        _strcat(szBuffer, TEXT(" ("));
        ultostr(g_kdctx.KiServiceLimit, _strend(szBuffer));
        _strcat(szBuffer, TEXT(")"));
        break;
    case SST_Win32k:
        _strcpy(szBuffer, TEXT("W32pServiceTable 0x"));
        u64tohex(g_kdctx.W32pServiceTableAddress, _strend(szBuffer));
        _strcat(szBuffer, TEXT(" / W32pServiceLimit 0x"));
        ultohex(g_kdctx.W32pServiceLimit, _strend(szBuffer));
        _strcat(szBuffer, TEXT(" ("));
        ultostr(g_kdctx.W32pServiceLimit, _strend(szBuffer));
        _strcat(szBuffer, TEXT(")"));
        break;
    default:
        break;
    }
    SetWindowText(hwndDlg, szBuffer);

    //list table
    for (i = 0; i < Count; i++) {

        //ServiceId
        RtlSecureZeroMemory(&lvitem, sizeof(lvitem));
        lvitem.mask = LVIF_TEXT | LVIF_IMAGE;
        lvitem.iSubItem = 0;
        lvitem.iItem = MAXINT;
        lvitem.iImage = ObjectTypeDevice; //imagelist id
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        ultostr(Table[i].ServiceId, szBuffer);
        lvitem.pszText = szBuffer;
        index = ListView_InsertItem(Context->ListView, &lvitem);

        //Name
        lvitem.mask = LVIF_TEXT;
        lvitem.iSubItem = 1;
        lvitem.pszText = (LPWSTR)Table[i].Name;
        lvitem.iItem = index;
        ListView_SetItem(Context->ListView, &lvitem);

        //Address
        lvitem.iSubItem = 2;
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        szBuffer[0] = L'0';
        szBuffer[1] = L'x';
        u64tohex(Table[i].Address, &szBuffer[2]);
        lvitem.pszText = szBuffer;
        lvitem.iItem = index;
        ListView_SetItem(Context->ListView, &lvitem);

        //Module
        lvitem.iSubItem = 3;
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

        number = supFindModuleEntryByAddress(Modules, (PVOID)Table[i].Address);
        if (number == (ULONG)-1) {
            _strcpy(szBuffer, TEXT("Unknown Module"));
        }
        else {

            MultiByteToWideChar(
                CP_ACP,
                0,
                (LPCSTR)&Modules->Modules[number].FullPathName,
                (INT)_strlen_a((char*)Modules->Modules[number].FullPathName),
                szBuffer,
                MAX_PATH);
        }

        lvitem.pszText = szBuffer;
        lvitem.iItem = index;
        ListView_SetItem(Context->ListView, &lvitem);
    }
}

/*
* SdtListTable
*
* Purpose:
*
* KiServiceTable query and list routine.
*
*/
VOID SdtListTable(
    _In_ HWND hwndDlg
)
{
    ULONG                   EntrySize = 0;
    SIZE_T                  memIO;
    PUTable                 TableDump = NULL;
    PRTL_PROCESS_MODULES    pModules = NULL;
    PBYTE                   Module = NULL;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PDWORD                  names, functions;
    PWORD                   ordinals;

    char *name;
    void *addr;
    ULONG number, i;

#ifndef _DEBUG
    HWND hwndBanner;

    hwndBanner = supDisplayLoadBanner(hwndDlg,
        TEXT("Loading service table dump, please wait"));
#endif

    __try {

        if ((g_kdctx.KiServiceTableAddress == 0) ||
            (g_kdctx.KiServiceLimit == 0))
        {
            if (!kdFindKiServiceTables(
                (ULONG_PTR)g_kdctx.NtOsImageMap,
                (ULONG_PTR)g_kdctx.NtOsBase,
                &g_kdctx.KiServiceTableAddress,
                &g_kdctx.KiServiceLimit,
                NULL,
                NULL))
            {
                __leave;
            }
        }

        pModules = (PRTL_PROCESS_MODULES)supGetSystemInfo(SystemModuleInformation);
        if (pModules == NULL)
            __leave;

        //if table empty, dump and prepare table
        if (g_pSDT == NULL) {

            Module = (PBYTE)GetModuleHandle(TEXT("ntdll.dll"));

            if (Module == NULL)
                __leave;

            memIO = sizeof(SERVICETABLEENTRY) * g_kdctx.KiServiceLimit;
            g_pSDT = (PSERVICETABLEENTRY)supHeapAlloc(memIO);
            if (g_pSDT == NULL)
                __leave;

            if (!supDumpSyscallTableConverted(
                g_kdctx.KiServiceTableAddress,
                g_kdctx.KiServiceLimit,
                &TableDump))
            {
                supHeapFree(g_pSDT);
                g_pSDT = NULL;
                __leave;
            }

            ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(
                Module,
                TRUE,
                IMAGE_DIRECTORY_ENTRY_EXPORT,
                &EntrySize);

            if (ExportDirectory == NULL) {
                supHeapFree(g_pSDT);
                g_pSDT = NULL;
                __leave;
            }

            names = (PDWORD)((PBYTE)Module + ExportDirectory->AddressOfNames);
            functions = (PDWORD)((PBYTE)Module + ExportDirectory->AddressOfFunctions);
            ordinals = (PWORD)((PBYTE)Module + ExportDirectory->AddressOfNameOrdinals);

            //
            // Walk for Nt stubs.
            //
            g_SDTLimit = 0;
            for (i = 0; i < ExportDirectory->NumberOfNames; i++) {

                name = ((CHAR *)Module + names[i]);
                addr = (PVOID *)((CHAR *)Module + functions[ordinals[i]]);

                if (*(USHORT*)name == 'tN') {

                    number = *(ULONG*)((UCHAR*)addr + 4);

                    if (number < g_kdctx.KiServiceLimit) {

                        MultiByteToWideChar(
                            CP_ACP,
                            0,
                            name,
                            (INT)_strlen_a(name),
                            g_pSDT[g_SDTLimit].Name,
                            MAX_PATH);

                        g_pSDT[g_SDTLimit].ServiceId = number;
                        g_pSDT[g_SDTLimit].Address = TableDump[number];
                        TableDump[number] = 0;
                        g_SDTLimit += 1;
                    }

                }//tN
            }//for

            //
            // Temporary workaround for NtQuerySystemTime.
            // (not implemented in user mode as syscall only as query to shared data, still exist in SSDT)
            //  
            //  This will produce incorrect result if more like that services will be added.
            //
            for (i = 0; i < g_kdctx.KiServiceLimit; i++) {
                if (TableDump[i] != 0) {
                    g_pSDT[g_SDTLimit].ServiceId = i;
                    g_pSDT[g_SDTLimit].Address = TableDump[i];
                    _strcpy(g_pSDT[g_SDTLimit].Name, L"NtQuerySystemTime");
                    g_SDTLimit += 1;
                    break;
                }
            }

            supHeapFree(TableDump);
            TableDump = NULL;
        }

        SdtOutputTable(
            hwndDlg,
            pModules,
            g_pSDT,
            g_SDTLimit);

    }
    __finally {

#ifndef _DEBUG
        SendMessage(hwndBanner, WM_CLOSE, 0, 0);
#endif

        if (pModules) {
            supHeapFree(pModules);
        }

        if (TableDump) {
            supHeapFree(TableDump);
        }
    }
}

/*
* SdtListTableShadow
*
* Purpose:
*
* W32pServiceTable query and list routine.
*
* Note: weird KdSystemDebugControl behavior after RS1~RS3
*
*/
VOID SdtListTableShadow(
    _In_ HWND hwndDlg
)
{
    ULONG                   EntrySize = 0;
    SIZE_T                  memIO;
    DWORD                   rel;
    DWORD_PTR               offset;
    ULONG_PTR               syscallTableAddress, vaddr;
    PUTable                 TableDump = NULL;
    PRTL_PROCESS_MODULES    pModules = NULL;
    PBYTE                   hWin32u = NULL;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PDWORD                  names, functions;
    PWORD                   ordinals;
    WCHAR                   szBuffer[MAX_PATH + 1];

    char *name;
    void *addr;
    ULONG number, i;

    BYTE dumpBuffer[16];
    hde64s hs;

#ifndef _DEBUG
    HWND hwndBanner;

    hwndBanner = supDisplayLoadBanner(hwndDlg,
        TEXT("Loading service table dump, please wait"));
#endif

    __try {

        if ((g_kdctx.W32pServiceTableAddress == 0) ||
            (g_kdctx.W32pServiceLimit == 0))
        {
            if (!kdFindKiServiceTables(
                (ULONG_PTR)g_kdctx.NtOsImageMap,
                (ULONG_PTR)g_kdctx.NtOsBase,
                NULL,
                NULL,
                &g_kdctx.W32pServiceTableAddress,
                &g_kdctx.W32pServiceLimit))
            {
                MessageBox(hwndDlg, TEXT("Could not query W32pServiceTable, abort."), NULL, MB_TOPMOST | MB_ICONERROR);
                __leave;
            }
        }

        pModules = (PRTL_PROCESS_MODULES)supGetSystemInfo(SystemModuleInformation);
        if (pModules == NULL) {
            __leave;
        }

        if (g_pSDTShadow == NULL) {

            _strcpy(szBuffer, g_WinObj.szSystemDirectory);
            _strcat(szBuffer, TEXT("\\win32u.dll"));

            hWin32u = (PBYTE)LoadLibraryEx(szBuffer, NULL, DONT_RESOLVE_DLL_REFERENCES);
            if (hWin32u == NULL) {
                MessageBox(hwndDlg, TEXT("Could not load win32u.dll, abort."), NULL, MB_TOPMOST | MB_ICONERROR);
                __leave;
            }

            memIO = sizeof(SERVICETABLEENTRY) * g_kdctx.W32pServiceLimit;
            g_pSDTShadow = (PSERVICETABLEENTRY)supHeapAlloc(memIO);
            if (g_pSDTShadow == NULL) {
                __leave;
            }

            if (!supDumpSyscallTableConverted(
                g_kdctx.W32pServiceTableAddress,
                g_kdctx.W32pServiceLimit,
                &TableDump))
            {
                supHeapFree(g_pSDTShadow);
                g_pSDTShadow = NULL;
                MessageBox(hwndDlg, TEXT("Could not convert service table"), NULL, MB_TOPMOST | MB_ICONERROR);
                __leave;
            }

            ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(
                hWin32u,
                TRUE,
                IMAGE_DIRECTORY_ENTRY_EXPORT,
                &EntrySize);

            if (ExportDirectory == NULL) {
                supHeapFree(g_pSDTShadow);
                g_pSDTShadow = NULL;

                MessageBox(hwndDlg, TEXT("Export Directory not found in win32u.dll"), NULL, MB_TOPMOST | MB_ICONERROR);
                __leave;
            }

            names = (PDWORD)((PBYTE)hWin32u + ExportDirectory->AddressOfNames);
            functions = (PDWORD)((PBYTE)hWin32u + ExportDirectory->AddressOfFunctions);
            ordinals = (PWORD)((PBYTE)hWin32u + ExportDirectory->AddressOfNameOrdinals);

            //walk for Nt stubs
            g_SDTShadowLimit = 0;
            for (i = 0; i < ExportDirectory->NumberOfNames; i++) {

                name = ((CHAR *)hWin32u + names[i]);
                addr = (PVOID *)((CHAR *)hWin32u + functions[ordinals[i]]);

                if (*(USHORT*)name == 'tN') {

                    number = *(ULONG*)((UCHAR*)addr + 4);

                    number -= 0x1000;

                    if (number < g_kdctx.W32pServiceLimit) {

                        //
                        // Remember service name.
                        //
                        MultiByteToWideChar(
                            CP_ACP,
                            0,
                            name,
                            (INT)_strlen_a(name),
                            g_pSDTShadow[g_SDTShadowLimit].Name,
                            MAX_PATH);

                        //
                        // Remember service index (converted to win32k range).
                        //
                        g_pSDTShadow[g_SDTShadowLimit].ServiceId = number + 0x1000;

                        //
                        // Remember service kernel address.
                        //
                        // Valid for Windows 10.
                        // Decode jmp, on error W32pServiceTable entry address will be used.
                        //
                        syscallTableAddress = TableDump[number];

                        RtlSecureZeroMemory(dumpBuffer, sizeof(dumpBuffer));
                        if (kdReadSystemMemoryEx(
                            syscallTableAddress,
                            dumpBuffer,
                            sizeof(dumpBuffer),
                            NULL))
                        {
                            hde64_disasm((void*)dumpBuffer, &hs);
                            if (hs.flags & F_ERROR) {
#ifdef _DEBUG
                                OutputDebugStringA("HDE error");
                                OutputDebugStringA(__FUNCTION__);
#endif
                            }
                            else
                            {
                                rel = 0;
                                offset = syscallTableAddress + (hs.len - 4);
                                if (kdReadSystemMemoryEx(
                                    offset,
                                    &rel,
                                    sizeof(DWORD),
                                    NULL))
                                {
                                    vaddr = syscallTableAddress + hs.len + rel;
                                    if (kdReadSystemMemoryEx(
                                        vaddr,
                                        &vaddr,
                                        sizeof(ULONG_PTR),
                                        NULL))
                                    {
                                        if (vaddr > g_kdctx.SystemRangeStart)
                                            syscallTableAddress = vaddr;
                                    }
                                }
                            }
                            }

                        g_pSDTShadow[g_SDTShadowLimit].Address = syscallTableAddress;
                        g_SDTShadowLimit += 1;
                        }
                    else {
#ifdef _DEBUG
                        OutputDebugStringA("[!] Unexpected win32k service number\r\n");
#endif
                    }

                }//tN
                    }//for

            supHeapFree(TableDump);
            TableDump = NULL;
                }

        SdtOutputTable(
            hwndDlg,
            pModules,
            g_pSDTShadow,
            g_SDTShadowLimit);

            }
    __finally {
#ifndef _DEBUG
        SendMessage(hwndBanner, WM_CLOSE, 0, 0);
#endif
        if (pModules) {
            supHeapFree(pModules);
        }

        if (TableDump) {
            supHeapFree(TableDump);
        }

        if (hWin32u) {
            FreeLibrary((HMODULE)hWin32u);
        }
    }
        }

/*
* extrasCreateSSDTDialog
*
* Purpose:
*
* Create and initialize SSDT Dialog.
*
*/
VOID extrasCreateSSDTDialog(
    _In_ HWND hwndParent,
    _In_ SSDT_DLG_MODE Mode
)
{
    INT         dlgIndex;
    HWND        hwndDlg;
    LVCOLUMN    col;

    EXTRASCONTEXT  *pDlgContext;

    EXTRASCALLBACK CallbackParam;

    switch (Mode) {
    case SST_Ntos:
        dlgIndex = wobjKSSTDlgId;
        break;
    case SST_Win32k:
        dlgIndex = wobjW32SSTDlgId;
        break;
    default:
        return;

    }

    //allow only one dialog
    if (g_WinObj.AuxDialogs[dlgIndex]) {
        if (IsIconic(g_WinObj.AuxDialogs[dlgIndex]))
            ShowWindow(g_WinObj.AuxDialogs[dlgIndex], SW_RESTORE);
        else
            SetActiveWindow(g_WinObj.AuxDialogs[dlgIndex]);
        return;
    }

    RtlSecureZeroMemory(&SSTDlgContext[Mode], sizeof(EXTRASCONTEXT));

    pDlgContext = &SSTDlgContext[Mode];
    pDlgContext->DialogMode = Mode;

    hwndDlg = CreateDialogParam(
        g_WinObj.hInstance,
        MAKEINTRESOURCE(IDD_DIALOG_EXTRASLIST),
        hwndParent,
        &SdtDialogProc,
        (LPARAM)pDlgContext);

    if (hwndDlg == NULL) {
        return;
    }

    pDlgContext->hwndDlg = hwndDlg;
    g_WinObj.AuxDialogs[dlgIndex] = hwndDlg;
    pDlgContext->SizeGrip = supCreateSzGripWindow(hwndDlg);

    extrasSetDlgIcon(hwndDlg);

    pDlgContext->ListView = GetDlgItem(hwndDlg, ID_EXTRASLIST);
    if (pDlgContext->ListView) {

        //
        // Set listview imagelist, style flags and theme.
        //
        ListView_SetImageList(
            pDlgContext->ListView,
            g_ListViewImages,
            LVSIL_SMALL);

        ListView_SetExtendedListViewStyle(
            pDlgContext->ListView,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);

        SetWindowTheme(pDlgContext->ListView, TEXT("Explorer"), NULL);

        //columns
        RtlSecureZeroMemory(&col, sizeof(col));
        col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_FMT | LVCF_WIDTH | LVCF_ORDER | LVCF_IMAGE;
        col.iSubItem++;
        col.pszText = TEXT("Id");
        col.cx = 80;
        col.fmt = LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT;
        col.iImage = ImageList_GetImageCount(g_ListViewImages) - 1;
        ListView_InsertColumn(pDlgContext->ListView, col.iSubItem, &col);

        col.iImage = I_IMAGENONE;

        col.iSubItem++;
        col.pszText = TEXT("Service Name");
        col.iOrder++;
        col.cx = 220;
        ListView_InsertColumn(pDlgContext->ListView, col.iSubItem, &col);

        col.iSubItem++;
        col.pszText = TEXT("Address");
        col.iOrder++;
        col.cx = 130;
        ListView_InsertColumn(pDlgContext->ListView, col.iSubItem, &col);

        col.iSubItem++;
        col.pszText = TEXT("Module");
        col.iOrder++;
        col.cx = 220;
        ListView_InsertColumn(pDlgContext->ListView, col.iSubItem, &col);

        //remember column count
        pDlgContext->lvColumnCount = col.iSubItem;

        switch (Mode) {

        case SST_Ntos:
            SdtListTable(hwndDlg);
            break;
        case SST_Win32k:
            SdtListTableShadow(hwndDlg);
            break;

        default:
            break;
        }

        SendMessage(hwndDlg, WM_SIZE, 0, 0);
        CallbackParam.lParam = 0;
        CallbackParam.Value = Mode;
        ListView_SortItemsEx(pDlgContext->ListView, &SdtDlgCompareFunc, (LPARAM)&CallbackParam);
        SetFocus(pDlgContext->ListView);
    }
}
