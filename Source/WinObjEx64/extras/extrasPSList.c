/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018
*
*  TITLE:       EXTRASPSLIST.C
*
*  VERSION:     1.61
*
*  DATE:        16 Nov 2018
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "extras.h"
#include "extrasPSList.h"
#include "treelist\treelist.h"

ATOM g_PsTreeListAtom;

EXTRASCONTEXT PsDlgContext;

/*
* PsListDialogResize
*
* Purpose:
*
* WM_SIZE handler.
*
*/
INT_PTR PsListDialogResize(
    VOID
)
{
    RECT r1;
    INT  cy;

    RtlSecureZeroMemory(&r1, sizeof(r1));

    GetClientRect(PsDlgContext.hwndDlg, &r1);

    cy = r1.bottom - 24;
    if (PsDlgContext.SizeGrip != 0)
        cy -= GRIPPER_SIZE;

    SetWindowPos(PsDlgContext.TreeList, 0, 0, 0,
        r1.right - 24,
        cy,
        SWP_NOMOVE | SWP_NOZORDER);

    supSzGripWindowOnResize(PsDlgContext.hwndDlg, PsDlgContext.SizeGrip);

    return 1;
}

/*
* PsListDialogProc
*
* Purpose:
*
* Drivers Dialog window procedure.
*
*/
INT_PTR CALLBACK PsListDialogProc(
    _In_  HWND hwndDlg,
    _In_  UINT uMsg,
    _In_  WPARAM wParam,
    _In_  LPARAM lParam
)
{
    UNREFERENCED_PARAMETER(wParam);

    switch (uMsg) {

    case WM_INITDIALOG:
        supCenterWindow(hwndDlg);
        break;

    case WM_GETMINMAXINFO:
        if (lParam) {
            ((PMINMAXINFO)lParam)->ptMinTrackSize.x = 640;
            ((PMINMAXINFO)lParam)->ptMinTrackSize.y = 480;
        }
        break;

    case WM_SIZE:
        return PsListDialogResize();

    case WM_CLOSE:
        DestroyWindow(PsDlgContext.TreeList);
        UnregisterClass(MAKEINTATOM(g_PsTreeListAtom), g_WinObj.hInstance);

        if (PsDlgContext.SizeGrip) DestroyWindow(PsDlgContext.SizeGrip);
        DestroyWindow(hwndDlg);
        g_WinObj.AuxDialogs[wobjPsListDlgId] = NULL;
        return TRUE;
    }

    return FALSE;
}

/*
* PsListAddEntry
*
* Purpose:
*
* Output process list entry.
*
*/
VOID PsListAddEntry(
    _In_ OBEX_PROCESS_LOOKUP_ENTRY* Entry,
    _In_ PSYSTEM_HANDLE_INFORMATION_EX HandleList
)
{
    BOOL        InJob = FALSE;
    BOOL        bJobInfoPresent = FALSE, bBasicInfoPresent = FALSE, bIsCriticalInfoPresent = FALSE, bPsProtectInfoPresent = FALSE;
    NTSTATUS    Status;
    DWORD       CurrentProcessId = GetCurrentProcessId();
    ULONG       BreakOnTermination = 0, r;
    HTREEITEM   hRootItem, hSubItem;
    ULONG_PTR   ObjectAddress = 0;
    PWCHAR      Name;

    TL_SUBITEMS_FIXED subitems;
    PSYSTEM_PROCESSES_INFORMATION entry;
    PROCESS_EXTENDED_BASIC_INFORMATION exbi;
    PS_PROTECTION PsProtection;

    WCHAR szBuffer[200], szPid[10];

    //
    // Find EPROCESS value.
    //
    for (r = 0; r < HandleList->NumberOfHandles; r++)
        if (HandleList->Handles[r].UniqueProcessId == (ULONG_PTR)CurrentProcessId) {
            if (HandleList->Handles[r].HandleValue == (ULONG_PTR)Entry->hProcess) {
                ObjectAddress = (ULONG_PTR)HandleList->Handles[r].Object;
                break;
            }
        }

    entry = (PSYSTEM_PROCESSES_INFORMATION)Entry->EntryPtr;

    //
    // Set name with case for Idle.
    //
    if ((entry->UniqueProcessId == 0) &&
        (entry->ImageName.Length == 0))
        Name = L"Idle";
    else
        Name = entry->ImageName.Buffer;

    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    subitems.Count = 2;

    //
    // Output EPROCESS value if determinated.
    //
    if (ObjectAddress) {
        szBuffer[0] = L'0';
        szBuffer[1] = L'x';
        u64tohex(ObjectAddress, &szBuffer[2]);
        subitems.Text[0] = szBuffer;
    }
    else {
        subitems.Text[0] = NULL;
    }

    szPid[0] = 0;
    u64tostr((ULONG_PTR)entry->UniqueProcessId, szPid);

    subitems.Text[1] = Name;

    //
    // Add entry to list.
    //
    hRootItem = TreeListAddItem(
        PsDlgContext.TreeList,
        NULL,
        TVIF_TEXT,
        0,
        0,
        szPid,
        (PVOID)&subitems);

    if (hRootItem) {

        //
        // Query all info.
        //

        //
        // Job status.
        //
        Status = NtIsProcessInJob(
            Entry->hProcess,
            NULL);

        if (NT_SUCCESS(Status)) {
            bJobInfoPresent = TRUE;
            InJob = !(Status == STATUS_PROCESS_NOT_IN_JOB);
        }

        //
        // Critical process flag.
        //
        bIsCriticalInfoPresent = (NT_SUCCESS(NtQueryInformationProcess(
            Entry->hProcess,
            ProcessBreakOnTermination,
            &BreakOnTermination,
            sizeof(ULONG),
            &r)));

        //
        // Extended process flags.
        //
        bBasicInfoPresent = (NT_SUCCESS(NtQueryInformationProcess(
            Entry->hProcess,
            ProcessBasicInformation,
            &exbi,
            sizeof(PROCESS_EXTENDED_BASIC_INFORMATION),
            &r)));


        //
        // Protection information.
        //
        PsProtection.Level = 0;
        bPsProtectInfoPresent = (NT_SUCCESS(NtQueryInformationProcess(
            Entry->hProcess,
            ProcessProtectionInformation,
            &PsProtection,
            sizeof(ULONG),
            &r)));

        //
        // Output info.
        //

        //
        // Job status.
        //
        if (bJobInfoPresent) {
            RtlSecureZeroMemory(&subitems, sizeof(subitems));
            subitems.Count = 2;
            subitems.Text[0] = TEXT("ProcessInJob");
            subitems.Text[1] = (InJob) ? L"TRUE" : L"FALSE";

            TreeListAddItem(
                PsDlgContext.TreeList,
                hRootItem,
                TVIF_TEXT,
                0,
                0,
                NULL,
                &subitems);
        }

        //
        // Critical process flag.
        //
        if (bIsCriticalInfoPresent) {
            RtlSecureZeroMemory(&subitems, sizeof(subitems));
            subitems.Count = 2;
            subitems.Text[0] = TEXT("IsCritical");
            subitems.Text[1] = (BreakOnTermination != 0) ? L"TRUE" : L"FALSE";

            TreeListAddItem(
                PsDlgContext.TreeList,
                hRootItem,
                TVIF_TEXT,
                0,
                0,
                NULL,
                &subitems);
        }

        //
        // Extended process flags.
        //
        if (bBasicInfoPresent) {

            hSubItem = TreeListAddItem(
                PsDlgContext.TreeList,
                hRootItem,
                TVIF_TEXT,
                0,
                0,
                TEXT("Flags"),
                NULL);

            if (hSubItem) {

                for (r = 0; r < MAX_KNOWN_PEXBI_PROCESS_FLAGS; r++) {

                    RtlSecureZeroMemory(&subitems, sizeof(subitems));
                    subitems.Count = 2;
                    subitems.Text[0] = T_PEXBI_PROCESS_FLAGS[r];
                    subitems.Text[1] = szBuffer;

                    szBuffer[0] = 0;
                    ultostr(GET_BIT(exbi.Flags, r), szBuffer);

                    TreeListAddItem(
                        PsDlgContext.TreeList,
                        hSubItem,
                        TVIF_TEXT,
                        0,
                        0,
                        NULL,
                        &subitems);
                }

            }
        }

        //
        // Protection information.
        //
        if (bPsProtectInfoPresent) {

            if (PsProtection.Level) {

                RtlSecureZeroMemory(&subitems, sizeof(subitems));
                subitems.Count = 2;
                subitems.Text[0] = NULL;
                subitems.Text[1] = TEXT("PS_PROTECTION");

                hSubItem = TreeListAddItem(
                    PsDlgContext.TreeList,
                    hRootItem,
                    TVIF_TEXT,
                    0,
                    0,
                    TEXT("PsProtection"),
                    &subitems);

                if (hSubItem) {


                    //
                    // PsProtection.Signer
                    //
                    if (PsProtection.Signer < MAX_KNOWN_PS_PROTECTED_SIGNER)
                        Name = T_PSPROTECTED_SIGNER[PsProtection.Signer];
                    else
                        Name = T_Unknown;

                    RtlSecureZeroMemory(&subitems, sizeof(subitems));
                    subitems.Count = 2;
                    subitems.Text[0] = TEXT("Signer");
                    subitems.Text[1] = Name;

                    TreeListAddItem(
                        PsDlgContext.TreeList,
                        hSubItem,
                        TVIF_TEXT,
                        0,
                        0,
                        NULL,
                        &subitems);

                    //
                    // PsProtection.Type
                    //
                    if (PsProtection.Type < MAX_KNOWN_PS_PROTECTED_TYPE)
                        Name = T_PSPROTECTED_TYPE[PsProtection.Type];
                    else
                        Name = T_Unknown;

                    RtlSecureZeroMemory(&subitems, sizeof(subitems));
                    subitems.Count = 2;
                    subitems.Text[0] = TEXT("Type");
                    subitems.Text[1] = Name;

                    TreeListAddItem(
                        PsDlgContext.TreeList,
                        hSubItem,
                        TVIF_TEXT,
                        0,
                        0,
                        NULL,
                        &subitems);

                    //
                    // PsProtection.Audit
                    //
                    RtlSecureZeroMemory(&subitems, sizeof(subitems));
                    subitems.Count = 2;
                    subitems.Text[0] = TEXT("Audit");
                    subitems.Text[1] = szBuffer;

                    szBuffer[0] = 0;
                    ultostr(PsProtection.Audit, _strend(szBuffer));

                    TreeListAddItem(
                        PsDlgContext.TreeList,
                        hSubItem,
                        TVIF_TEXT,
                        0,
                        0,
                        NULL,
                        &subitems);
                }
            }
        }
    }
}

/*
* PsList
*
* Purpose:
*
* Build and output process list.
*
*/
VOID PsList()
{
    ULONG NextEntryDelta = 0, NumberOfProcesses = 0;

    HANDLE hProcess = NULL;
    PVOID InfoBuffer = NULL;
    PSYSTEM_HANDLE_INFORMATION_EX pHandles = NULL;

    OBEX_PROCESS_LOOKUP_ENTRY *spl = NULL, *tmp;

    OBJECT_ATTRIBUTES obja = RTL_INIT_OBJECT_ATTRIBUTES(NULL, 0);

    union {
        PSYSTEM_PROCESSES_INFORMATION Processes;
        PBYTE ListRef;
    } List;

    __try {

        InfoBuffer = supGetSystemInfo(SystemProcessInformation);
        if (InfoBuffer == NULL)
            __leave;

        List.ListRef = InfoBuffer;

        //
        // Calculate process handle list size.
        //
        do {

            List.ListRef += NextEntryDelta;

            if (List.Processes->ThreadCount)
                NumberOfProcesses += 1;

            NextEntryDelta = List.Processes->NextEntryDelta;

        } while (NextEntryDelta);

        //
        // Build process handle list.
        //
        spl = supHeapAlloc(NumberOfProcesses * sizeof(OBEX_PROCESS_LOOKUP_ENTRY));
        if (spl == NULL)
            __leave;

        tmp = spl;

        NextEntryDelta = 0;
        List.ListRef = InfoBuffer;

        do {
            List.ListRef += NextEntryDelta;
            hProcess = NULL;

            if (List.Processes->ThreadCount) {
                NtOpenProcess(
                    &hProcess,
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    &obja,
                    &List.Processes->Threads[0].ClientId);
            }

            tmp->hProcess = hProcess;
            tmp->EntryPtr = List.ListRef;
            tmp = (OBEX_PROCESS_LOOKUP_ENTRY*)RtlOffsetToPointer(tmp, sizeof(OBEX_PROCESS_LOOKUP_ENTRY));

            NextEntryDelta = List.Processes->NextEntryDelta;

        } while (NextEntryDelta);

        pHandles = (PSYSTEM_HANDLE_INFORMATION_EX)supGetSystemInfo(SystemExtendedHandleInformation);
        if (pHandles == NULL)
            __leave;

        //
        // Output all process entries.
        //
        tmp = spl;

        do {

            PsListAddEntry(tmp, pHandles);
            if (tmp->hProcess) NtClose(tmp->hProcess);
            tmp = (OBEX_PROCESS_LOOKUP_ENTRY*)RtlOffsetToPointer(tmp, sizeof(OBEX_PROCESS_LOOKUP_ENTRY));
            NumberOfProcesses--;

        } while (NumberOfProcesses);

    }
    __finally {
        if (InfoBuffer) supHeapFree(InfoBuffer);
        if (pHandles) supHeapFree(pHandles);
        if (spl) supHeapFree(spl);
    }
}

/*
* extrasCreatePsListDialog
*
* Purpose:
*
* Create and initialize Process List Dialog.
*
*/
VOID extrasCreatePsListDialog(
    _In_ HWND hwndParent
)
{
    HDITEM   hdritem;
    RECT     rc;

    //allow only one dialog
    if (g_WinObj.AuxDialogs[wobjPsListDlgId]) {
        if (IsIconic(g_WinObj.AuxDialogs[wobjPsListDlgId]))
            ShowWindow(g_WinObj.AuxDialogs[wobjPsListDlgId], SW_RESTORE);
        else
            SetActiveWindow(g_WinObj.AuxDialogs[wobjPsListDlgId]);
        return;
    }

    RtlSecureZeroMemory(&PsDlgContext, sizeof(PsDlgContext));
    PsDlgContext.hwndDlg = CreateDialogParam(g_WinObj.hInstance, MAKEINTRESOURCE(IDD_DIALOG_PSLIST),
        hwndParent, &PsListDialogProc, 0);

    if (PsDlgContext.hwndDlg == NULL) {
        return;
    }

    g_WinObj.AuxDialogs[wobjPsListDlgId] = PsDlgContext.hwndDlg;

    PsDlgContext.SizeGrip = supCreateSzGripWindow(PsDlgContext.hwndDlg);

    extrasSetDlgIcon(PsDlgContext.hwndDlg);

    GetClientRect(hwndParent, &rc);
    g_PsTreeListAtom = InitializeTreeListControl();
    PsDlgContext.TreeList = CreateWindowEx(WS_EX_CLIENTEDGE, WC_TREELIST, NULL,
        WS_VISIBLE | WS_CHILD | WS_TABSTOP | TLSTYLE_COLAUTOEXPAND, 12, 14,
        rc.right - 24, rc.bottom - 24, PsDlgContext.hwndDlg, NULL, NULL, NULL);

    if (PsDlgContext.TreeList) {
        RtlSecureZeroMemory(&hdritem, sizeof(hdritem));
        hdritem.mask = HDI_FORMAT | HDI_TEXT | HDI_WIDTH;
        hdritem.fmt = HDF_LEFT | HDF_BITMAP_ON_RIGHT | HDF_STRING;
        hdritem.cxy = 130;
        hdritem.pszText = TEXT("Id");
        TreeList_InsertHeaderItem(PsDlgContext.TreeList, 0, &hdritem);

        hdritem.cxy = 130;
        hdritem.pszText = TEXT("Value");
        TreeList_InsertHeaderItem(PsDlgContext.TreeList, 1, &hdritem);

        hdritem.cxy = 400;
        hdritem.pszText = TEXT("Additional information");
        TreeList_InsertHeaderItem(PsDlgContext.TreeList, 2, &hdritem);
    }

    PsList();

    PsListDialogResize();
}
