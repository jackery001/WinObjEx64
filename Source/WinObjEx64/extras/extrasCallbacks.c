/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018
*
*  TITLE:       EXTRASCALLBACKS.C
*
*  VERSION:     1.61
*
*  DATE:        26 Nov 2018
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "extras.h"
#include "extrasCallbacks.h"
#include "hde/hde64.h"

/*
* GetObjectTypeCallbackListHeadByType
*
* Purpose:
*
* Return address of object type callback list head.
*
*/
ULONG_PTR GetObjectTypeCallbackListHeadByType(
    _In_ ULONG Type
)
{
    ULONG_PTR ListHead = 0;
    ULONG ObjectSize, ObjectVersion = 0, CallbackListOffset = 0;
    LPWSTR lpType = NULL;
    POBJINFO CurrentObject = NULL;
    PVOID ObjectTypeInformation = NULL;

    union {
        union {
            OBJECT_TYPE_7 *ObjectType_7;
            OBJECT_TYPE_8 *ObjectType_8;
            OBJECT_TYPE_RS1 *ObjectType_RS1;
            OBJECT_TYPE_RS2 *ObjectType_RS2;
        } Versions;
        PVOID Ref;
    } ObjectType;

    switch (Type) {
    case 0: //PsProcessType
        lpType = TEXT("Process");
        break;
    case 1: //PsThreadType
        lpType = TEXT("Thread");
        break;
    default:
        //ExDesktopObjectType
        lpType = TEXT("Desktop");
        break;
    }

    //
    // Get the reference to the object.
    //
    CurrentObject = ObQueryObject(T_OBJECTTYPES, lpType);
    if (CurrentObject == NULL)
        return 0;

    //
    // Dump object information version aware.
    //
    ObjectTypeInformation = ObDumpObjectTypeVersionAware(
        CurrentObject->ObjectAddress,
        &ObjectSize,
        &ObjectVersion);

    if (ObjectTypeInformation == NULL) {
        supHeapFree(CurrentObject);
        return 0;
    }

    ObjectType.Ref = ObjectTypeInformation;

    //
    // Flags in compat fields.
    //
    if (ObjectType.Versions.ObjectType_7->TypeInfo.SupportsObjectCallbacks) {

        //
        // Calculate offset to structure field.
        //
        switch (ObjectVersion) {
        case 1:
            CallbackListOffset = FIELD_OFFSET(OBJECT_TYPE_7, CallbackList);
            break;

        case 2:
            CallbackListOffset = FIELD_OFFSET(OBJECT_TYPE_8, CallbackList);
            break;

        case 3:
            CallbackListOffset = FIELD_OFFSET(OBJECT_TYPE_RS1, CallbackList);
            break;

        default:
            CallbackListOffset = FIELD_OFFSET(OBJECT_TYPE_RS2, CallbackList);
            break;
        }

        ListHead = CurrentObject->ObjectAddress + CallbackListOffset;
    }

    supHeapFree(CurrentObject);
    supVirtualFree(ObjectTypeInformation);
    return ListHead;
}

/*
* FindIopNotifyShutdownQueueHeadHead
*
* Purpose:
*
* Locate pointer to IopNotifyShutdownQueueHead/IopNotifyLastChanceShutdownQueueHead in the ntoskrnl.
*
*/
ULONG_PTR FindIopNotifyShutdownQueueHeadHead(
    _In_ BOOL bLastChance)
{
    ULONG Index;
    LONG Rel = 0;
    ULONG_PTR Address = 0;
    PBYTE ptrCode;
    hde64s hs;

    ULONG_PTR NtOsBase = (ULONG_PTR)g_kdctx.NtOsBase;
    HMODULE hNtOs = (HINSTANCE)g_kdctx.NtOsImageMap;

    //
    // Routines have similar design.
    //
    if (bLastChance) {
        ptrCode = (PBYTE)GetProcAddress(hNtOs, "IoRegisterLastChanceShutdownNotification");
    }
    else {
        ptrCode = (PBYTE)GetProcAddress(hNtOs, "IoRegisterShutdownNotification");
    }

    if (ptrCode == NULL)
        return 0;

    Index = 0;
    Rel = 0;

    do {
        hde64_disasm(ptrCode + Index, &hs);
        if (hs.flags & F_ERROR)
            break;

        if (hs.len == 7) { //check if lea

            if (((ptrCode[Index] == 0x48) || (ptrCode[Index] == 0x4C)) &&
                (ptrCode[Index + 1] == 0x8D))
            {
                Rel = *(PLONG)(ptrCode + Index + 3);
                break;
            }

        }

        Index += hs.len;

    } while (Index < 128);

    if (Rel == 0)
        return 0;

    Address = (ULONG_PTR)ptrCode + Index + hs.len + Rel;
    Address = NtOsBase + Address - (ULONG_PTR)hNtOs;

    if (!kdAddressInNtOsImage((PVOID)Address))
        return 0;

    return Address;
}

/*
* FindCmCallbackHead
*
* Purpose:
*
* Locate pointer to CallbackListHead in the ntoskrnl.
*
*/
ULONG_PTR FindCmCallbackHead(
    VOID)
{
    ULONG Index, resultOffset;
    LONG Rel = 0, FirstInstructionLength;
    ULONG_PTR Address = 0;
    PBYTE ptrCode;
    hde64s hs, hs_next;

    ULONG_PTR NtOsBase = (ULONG_PTR)g_kdctx.NtOsBase;
    HMODULE hNtOs = (HMODULE)g_kdctx.NtOsImageMap;

    ptrCode = (PBYTE)GetProcAddress(hNtOs, "CmUnRegisterCallback");
    if (ptrCode == NULL)
        return 0;

    Index = 0;
    Rel = 0;
    resultOffset = 0;

    do {
        hde64_disasm(ptrCode + Index, &hs);
        if (hs.flags & F_ERROR)
            break;

        if (hs.len == 5) {
            /*
            ** lea     rdx, [rsp+20h] <-
            ** lea     rcx, CallbackListHead
            */
            if ((ptrCode[Index] == 0x48) &&
                (ptrCode[Index + 1] == 0x8D) &&
                (ptrCode[Index + 2] == 0x54))
            {
                hde64_disasm(ptrCode + Index + hs.len, &hs_next);
                if (hs_next.flags & F_ERROR)
                    break;
                if (hs_next.len == 7) {

                    /*
                    ** lea     rdx, [rsp+20h]
                    ** lea     rcx, CallbackListHead <-
                    */
                    FirstInstructionLength = hs.len;

                    if ((ptrCode[Index + FirstInstructionLength] == 0x48) &&
                        (ptrCode[Index + FirstInstructionLength + 1] == 0x8D) &&
                        (ptrCode[Index + FirstInstructionLength + 2] == 0x0D))
                    {
                        resultOffset = Index + FirstInstructionLength + hs_next.len;
                        Rel = *(PLONG)(ptrCode + Index + FirstInstructionLength + 3);
                        break;
                    }
                }
            }
        }

        Index += hs.len;

    } while (Index < 256);

    if (Rel == 0)
        return 0;

    Address = (ULONG_PTR)ptrCode + resultOffset + Rel;
    Address = NtOsBase + Address - (ULONG_PTR)hNtOs;

    if (!kdAddressInNtOsImage((PVOID)Address))
        return 0;

    return Address;
}

/*
* FindKeBugCheckReasonCallbackHead
*
* Purpose:
*
* Locate pointer to KeBugCheckReasonCallbackListHead in the ntoskrnl.
*
*/
ULONG_PTR FindKeBugCheckReasonCallbackHead(
    VOID)
{
    ULONG Index;
    LONG Rel = 0;
    ULONG_PTR Address = 0;
    PBYTE ptrCode;
    hde64s hs;

    ULONG_PTR NtOsBase = (ULONG_PTR)g_kdctx.NtOsBase;
    HMODULE hNtOs = (HMODULE)g_kdctx.NtOsImageMap;

    ptrCode = (PBYTE)GetProcAddress(hNtOs, "KeRegisterBugCheckReasonCallback");
    if (ptrCode == NULL)
        return 0;

    Index = 0;
    Rel = 0;

    do {
        hde64_disasm(ptrCode + Index, &hs);
        if (hs.flags & F_ERROR)
            break;

        if (hs.len == 7) { //check if lea

            if (((ptrCode[Index] == 0x48) || (ptrCode[Index] == 0x4C)) &&
                (ptrCode[Index + 1] == 0x8D) &&
                ((ptrCode[Index + hs.len] == 0x48) || (ptrCode[Index + hs.len] == 0x83)))
            {
                Rel = *(PLONG)(ptrCode + Index + 3);
                break;
            }

        }

        Index += hs.len;

    } while (Index < 512);

    if (Rel == 0)
        return 0;

    Address = (ULONG_PTR)ptrCode + Index + hs.len + Rel;
    Address = NtOsBase + Address - (ULONG_PTR)hNtOs;

    if (!kdAddressInNtOsImage((PVOID)Address))
        return 0;

    return Address;
}

/*
* FindKeBugCheckCallbackHead
*
* Purpose:
*
* Locate pointer to KeBugCheckCallbackListHead in the ntoskrnl.
*
*/
ULONG_PTR FindKeBugCheckCallbackHead(
    VOID)
{
    ULONG Index;
    LONG Rel = 0;
    ULONG_PTR Address = 0;
    PBYTE ptrCode;
    hde64s hs;

    ULONG_PTR NtOsBase = (ULONG_PTR)g_kdctx.NtOsBase;
    HMODULE hNtOs = (HMODULE)g_kdctx.NtOsImageMap;

    ptrCode = (PBYTE)GetProcAddress(hNtOs, "KeRegisterBugCheckCallback");
    if (ptrCode == NULL)
        return 0;

    Index = 0;
    Rel = 0;

    do {
        hde64_disasm(ptrCode + Index, &hs);
        if (hs.flags & F_ERROR)
            break;

        if (hs.len == 7) { //check if lea + mov

            if (((ptrCode[Index] == 0x48) || (ptrCode[Index] == 0x4C)) &&
                (ptrCode[Index + 1] == 0x8D) &&
                (ptrCode[Index + hs.len] == 0x48))
            {
                Rel = *(PLONG)(ptrCode + Index + 3);
                break;
            }

        }

        Index += hs.len;

    } while (Index < 512);

    if (Rel == 0)
        return 0;

    Address = (ULONG_PTR)ptrCode + Index + hs.len + Rel;
    Address = NtOsBase + Address - (ULONG_PTR)hNtOs;

    if (!kdAddressInNtOsImage((PVOID)Address))
        return 0;

    return Address;
}

/*
* FindPspLoadImageNotifyRoutine
*
* Purpose:
*
* Locate pointer to LoadImageNotify EX_FAST_REF array in the ntoskrnl.
*
*/
ULONG_PTR FindPspLoadImageNotifyRoutine(
    VOID)
{
    ULONG Index;
    LONG Rel = 0;
    ULONG_PTR Address = 0;
    PBYTE ptrCode;
    hde64s hs;

    ULONG_PTR NtOsBase = (ULONG_PTR)g_kdctx.NtOsBase;
    HMODULE hNtOs = (HMODULE)g_kdctx.NtOsImageMap;

    ptrCode = (PBYTE)GetProcAddress(hNtOs, "PsRemoveLoadImageNotifyRoutine");
    if (ptrCode == NULL)
        return 0;

    Index = 0;
    Rel = 0;

    do {
        hde64_disasm(ptrCode + Index, &hs);
        if (hs.flags & F_ERROR)
            break;

        if (hs.len == 7) { //check if lea

            if (((ptrCode[Index] == 0x48) || (ptrCode[Index] == 0x4C)) &&
                (ptrCode[Index + 1] == 0x8D))
            {
                Rel = *(PLONG)(ptrCode + Index + 3);
                break;
            }

        }

        Index += hs.len;

    } while (Index < 128);

    if (Rel == 0)
        return 0;

    Address = (ULONG_PTR)ptrCode + Index + hs.len + Rel;
    Address = NtOsBase + Address - (ULONG_PTR)hNtOs;

    if (!kdAddressInNtOsImage((PVOID)Address))
        return 0;

    return Address;
}

/*
* FindPspCreateThreadNotifyRoutine
*
* Purpose:
*
* Locate pointer to CreateThreadNotify EX_FAST_REF array in the ntoskrnl.
*
*/
ULONG_PTR FindPspCreateThreadNotifyRoutine(
    VOID)
{
    ULONG Index;
    LONG Rel = 0;
    ULONG_PTR Address = 0;
    PBYTE ptrCode;
    hde64s hs;

    ULONG_PTR NtOsBase = (ULONG_PTR)g_kdctx.NtOsBase;
    HMODULE hNtOs = (HMODULE)g_kdctx.NtOsImageMap;

    ptrCode = (PBYTE)GetProcAddress(hNtOs, "PsRemoveCreateThreadNotifyRoutine");
    if (ptrCode == NULL)
        return 0;

    Index = 0;
    Rel = 0;

    do {
        hde64_disasm(ptrCode + Index, &hs);
        if (hs.flags & F_ERROR)
            break;

        if (hs.len == 7) { //check if lea

            if (((ptrCode[Index] == 0x48) || (ptrCode[Index] == 0x4C)) &&
                (ptrCode[Index + 1] == 0x8D))
            {
                Rel = *(PLONG)(ptrCode + Index + 3);
                break;
            }

        }

        Index += hs.len;

    } while (Index < 128);

    if (Rel == 0)
        return 0;

    Address = (ULONG_PTR)ptrCode + Index + hs.len + Rel;
    Address = NtOsBase + Address - (ULONG_PTR)hNtOs;

    if (!kdAddressInNtOsImage((PVOID)Address))
        return 0;

    return Address;
}

/*
* FindPspCreateProcessNotifyRoutine
*
* Purpose:
*
* Locate pointer to CreateProcessNotify EX_FAST_REF array in the ntoskrnl.
*
*/
ULONG_PTR FindPspCreateProcessNotifyRoutine(
    VOID)
{
    ULONG Index;
    LONG Rel = 0;
    ULONG_PTR Address = 0;
    PBYTE ptrCode;
    hde64s hs;

    ULONG_PTR NtOsBase = (ULONG_PTR)g_kdctx.NtOsBase;
    HMODULE hNtOs = (HMODULE)g_kdctx.NtOsImageMap;

    ptrCode = (PBYTE)GetProcAddress(hNtOs, "PsSetCreateProcessNotifyRoutine");
    if (ptrCode == NULL)
        return 0;

    //
    // Find PspSetCreateProcessNotifyRoutine pointer.
    //
    Index = 0;
    do {

        hde64_disasm(ptrCode + Index, &hs);
        if (hs.flags & F_ERROR)
            break;

        //jmp/call PspSetCreateProcessNotifyRoutine
        if ((ptrCode[Index] == 0xE9) ||
            (ptrCode[Index] == 0xE8) ||
            (ptrCode[Index] == 0xEB))
        {
            Rel = *(PLONG)(ptrCode + Index + 1);
            break;
        }

        Index += hs.len;

    } while (Index < 64);

    if (Rel == 0)
        return 0;

    ptrCode = ptrCode + Index + (hs.len) + Rel;
    Index = 0;
    Rel = 0;

    do {
        hde64_disasm(ptrCode + Index, &hs);
        if (hs.flags & F_ERROR)
            break;

        if (hs.len == 7) { //check if lea

            if ((ptrCode[Index] == 0x4C) &&
                (ptrCode[Index + 1] == 0x8D))
            {
                Rel = *(PLONG)(ptrCode + Index + 3);
                break;
            }

        }

        Index += hs.len;

    } while (Index < 128);

    if (Rel == 0)
        return 0;

    Address = (ULONG_PTR)ptrCode + Index + hs.len + Rel;
    Address = NtOsBase + Address - (ULONG_PTR)hNtOs;

    if (!kdAddressInNtOsImage((PVOID)Address))
        return 0;

    return Address;
}

/*
* AddEntryToList
*
* Purpose:
*
* Adds callback entry to the listview.
*
*/
VOID AddEntryToList(
    _In_ HWND ListView,
    _In_ ULONG_PTR Function,
    _In_ LPWSTR lpCallbackType,
    _In_opt_ LPWSTR lpAdditionalInfo,
    _In_ PRTL_PROCESS_MODULES Modules
)
{
    INT index, number;
    LVITEM lvitem;
    WCHAR szBuffer[MAX_PATH + 1];

    RtlSecureZeroMemory(&lvitem, sizeof(lvitem));
    lvitem.mask = LVIF_TEXT | LVIF_IMAGE;
    lvitem.iSubItem = 0;
    lvitem.iImage = ObjectTypeCallback;
    lvitem.iItem = MAXINT;

    szBuffer[0] = L'0';
    szBuffer[1] = L'x';
    szBuffer[2] = 0;
    u64tohex(Function, &szBuffer[2]);
    lvitem.pszText = szBuffer;

    index = ListView_InsertItem(ListView, &lvitem);

    //Type
    lvitem.mask = LVIF_TEXT;
    lvitem.iSubItem = 1;
    lvitem.pszText = lpCallbackType;
    lvitem.iItem = index;
    ListView_SetItem(ListView, &lvitem);

    //Module
    lvitem.iSubItem = 2;
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

    number = supFindModuleEntryByAddress(Modules, (PVOID)Function);
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
    ListView_SetItem(ListView, &lvitem);

    //Additional Info
    lvitem.mask = LVIF_TEXT;
    lvitem.iSubItem = 3;
    lvitem.pszText = lpAdditionalInfo;
    lvitem.iItem = index;
    ListView_SetItem(ListView, &lvitem);
}

/*
* DumpPsCallbacks
*
* Purpose:
*
* Read Psp* callback data from kernel and send it to output window.
*
*/
VOID DumpPsCallbacks(
    _In_ HWND ListView,
    _In_ LPWSTR lpCallbackType,
    _In_ ULONG_PTR RoutinesArrayAddress
)
{
    ULONG c;
    ULONG_PTR Address, Function;
    EX_FAST_REF Callbacks[PspNotifyRoutinesLimit];
    PRTL_PROCESS_MODULES Modules;

    Modules = (PRTL_PROCESS_MODULES)supGetSystemInfo(SystemModuleInformation);
    if (Modules == NULL)
        return;

    RtlSecureZeroMemory(Callbacks, sizeof(Callbacks));
    if (kdReadSystemMemory(RoutinesArrayAddress,
        &Callbacks, sizeof(Callbacks)))
    {
        for (c = 0; c < PspNotifyRoutinesLimit; c++) {

            if (Callbacks[c].Value) {

                Address = (ULONG_PTR)ObGetObjectFastReference(Callbacks[c]);
                Function = (ULONG_PTR)ObGetCallbackBlockRoutine((PVOID)Address);
                if (Function < g_kdctx.SystemRangeStart)
                    continue;

                AddEntryToList(ListView,
                    Function,
                    lpCallbackType,
                    NULL,
                    Modules);
            }
        }
    }

    supHeapFree(Modules);
}

/*
* DumpKeBugCheckCallbacks
*
* Purpose:
*
* Read KeBugCheck callback data from kernel and send it to output window.
*
*/
VOID DumpKeBugCheckCallbacks(
    _In_ HWND ListView,
    _In_ LPWSTR lpCallbackType,
    _In_ ULONG_PTR ListHead
)
{
    LIST_ENTRY ListEntry;

    PRTL_PROCESS_MODULES Modules;

    KBUGCHECK_CALLBACK_RECORD CallbackRecord;

    ListEntry.Flink = ListEntry.Blink = NULL;

    //
    // Read head.
    //
    if (!kdReadSystemMemoryEx(
        ListHead,
        &ListEntry,
        sizeof(LIST_ENTRY),
        NULL))
    {
        return;
    }

    Modules = (PRTL_PROCESS_MODULES)supGetSystemInfo(SystemModuleInformation);
    if (Modules == NULL)
        return;

    //
    // Walk list entries.
    //
    while ((ULONG_PTR)ListEntry.Flink != ListHead) {

        RtlSecureZeroMemory(&CallbackRecord, sizeof(CallbackRecord));

        if (!kdReadSystemMemoryEx((ULONG_PTR)ListEntry.Flink,
            &CallbackRecord,
            sizeof(CallbackRecord),
            NULL))
        {
            break;
        }

        AddEntryToList(ListView,
            (ULONG_PTR)CallbackRecord.CallbackRoutine,
            lpCallbackType,
            NULL,
            Modules);

        ListEntry.Flink = CallbackRecord.Entry.Flink;
    }

    supHeapFree(Modules);
}

LPWSTR KeBugCheckReasonToString(
    _In_ KBUGCHECK_CALLBACK_REASON Reason)
{
    switch (Reason) {
    case KbCallbackInvalid:
        return TEXT("KbCallbackInvalid");

    case KbCallbackReserved1:
        return TEXT("KbCallbackReserved1");

    case KbCallbackSecondaryDumpData:
        return TEXT("KbCallbackSecondaryDumpData");

    case KbCallbackDumpIo:
        return TEXT("KbCallbackDumpIo");

    case KbCallbackAddPages:
        return TEXT("KbCallbackAddPages");

    case KbCallbackSecondaryMultiPartDumpData:
        return TEXT("KbCallbackSecondaryMultiPartDumpData");

    case KbCallbackRemovePages:
        return TEXT("KbCallbackRemovePages");
    case KbCallbackTriageDumpData:
        return TEXT("KbCallbackTriageDumpData");

    }
    return NULL;
}

/*
* DumpKeBugCheckReasonCallbacks
*
* Purpose:
*
* Read KeBugCheckReason callback data from kernel and send it to output window.
*
*/
VOID DumpKeBugCheckReasonCallbacks(
    _In_ HWND ListView,
    _In_ LPWSTR lpCallbackType,
    _In_ ULONG_PTR ListHead
)
{
    LIST_ENTRY ListEntry;

    PRTL_PROCESS_MODULES Modules;

    KBUGCHECK_REASON_CALLBACK_RECORD CallbackRecord;

    ListEntry.Flink = ListEntry.Blink = NULL;

    //
    // Read head.
    //
    if (!kdReadSystemMemoryEx(
        ListHead,
        &ListEntry,
        sizeof(LIST_ENTRY),
        NULL))
    {
        return;
    }

    Modules = (PRTL_PROCESS_MODULES)supGetSystemInfo(SystemModuleInformation);
    if (Modules == NULL)
        return;

    //
    // Walk list entries.
    //
    while ((ULONG_PTR)ListEntry.Flink != ListHead) {

        RtlSecureZeroMemory(&CallbackRecord, sizeof(CallbackRecord));

        if (!kdReadSystemMemoryEx((ULONG_PTR)ListEntry.Flink,
            &CallbackRecord,
            sizeof(CallbackRecord),
            NULL))
        {
            break;
        }

        AddEntryToList(ListView,
            (ULONG_PTR)CallbackRecord.CallbackRoutine,
            lpCallbackType,
            KeBugCheckReasonToString(CallbackRecord.Reason),
            Modules);

        ListEntry.Flink = CallbackRecord.Entry.Flink;
    }

    supHeapFree(Modules);
}

/*
* DumpCmCallbacks
*
* Purpose:
*
* Read Cm Registry callback data from kernel and send it to output window.
*
*/
VOID DumpCmCallbacks(
    _In_ HWND ListView,
    _In_ LPWSTR lpCallbackType,
    _In_ ULONG_PTR ListHead
)
{
    LIST_ENTRY ListEntry;

    PRTL_PROCESS_MODULES Modules;

    CM_CALLBACK_CONTEXT_BLOCK CallbackRecord;

    ListEntry.Flink = ListEntry.Blink = NULL;

    //
    // Read head.
    //
    if (!kdReadSystemMemoryEx(
        ListHead,
        &ListEntry,
        sizeof(LIST_ENTRY),
        NULL))
    {
        return;
    }

    Modules = (PRTL_PROCESS_MODULES)supGetSystemInfo(SystemModuleInformation);
    if (Modules == NULL)
        return;

    //
    // Walk list entries.
    //
    while ((ULONG_PTR)ListEntry.Flink != ListHead) {

        RtlSecureZeroMemory(&CallbackRecord, sizeof(CallbackRecord));

        if (!kdReadSystemMemoryEx((ULONG_PTR)ListEntry.Flink,
            &CallbackRecord,
            sizeof(CallbackRecord),
            NULL))
        {
            break;
        }

        AddEntryToList(ListView,
            (ULONG_PTR)CallbackRecord.Function,
            lpCallbackType,
            NULL,
            Modules);

        ListEntry.Flink = CallbackRecord.CallbackListEntry.Flink;
    }

    supHeapFree(Modules);
}

/*
* DumpIoCallbacks
*
* Purpose:
*
* Read Io related callback data from kernel and send it to output window.
*
*/
VOID DumpIoCallbacks(
    _In_ HWND ListView,
    _In_ LPWSTR lpCallbackType,
    _In_ ULONG_PTR ListHead
)
{
    LIST_ENTRY ListEntry;

    PRTL_PROCESS_MODULES Modules;

    SHUTDOWN_PACKET EntryPacket;

    DEVICE_OBJECT DeviceObject;

    DRIVER_OBJECT DriverObject;

    PVOID Routine;
    LPWSTR lpDescription;


    ListEntry.Flink = ListEntry.Blink = NULL;

    //
    // Read head.
    //
    if (!kdReadSystemMemoryEx(
        ListHead,
        &ListEntry,
        sizeof(LIST_ENTRY),
        NULL))
    {
        return;
    }

    Modules = (PRTL_PROCESS_MODULES)supGetSystemInfo(SystemModuleInformation);
    if (Modules == NULL)
        return;

    //
    // Walk list entries.
    //
    while ((ULONG_PTR)ListEntry.Flink != ListHead) {

        RtlSecureZeroMemory(&EntryPacket, sizeof(EntryPacket));

        if (!kdReadSystemMemoryEx((ULONG_PTR)ListEntry.Flink,
            &EntryPacket,
            sizeof(EntryPacket),
            NULL))
        {
            break;
        }

        Routine = EntryPacket.DeviceObject;
        lpDescription = TEXT("PDEVICE_OBJECT");

        //
        // Attempt to query owner of the device object.
        //
        if ((ULONG_PTR)EntryPacket.DeviceObject > g_kdctx.SystemRangeStart) {

            //
            // Read DEVICE_OBJECT.
            //
            RtlSecureZeroMemory(&DeviceObject, sizeof(DeviceObject));

            if (kdReadSystemMemoryEx((ULONG_PTR)EntryPacket.DeviceObject,
                (PVOID)&DeviceObject,
                sizeof(DeviceObject),
                NULL))
            {
                //
                // Read DRIVER_OBJECT.
                //
                RtlSecureZeroMemory(&DriverObject, sizeof(DriverObject));
                if (kdReadSystemMemoryEx((ULONG_PTR)DeviceObject.DriverObject,
                    (PVOID)&DriverObject,
                    sizeof(DriverObject),
                    NULL))
                {
                    Routine = DriverObject.MajorFunction[IRP_MJ_SHUTDOWN];
                    lpDescription = TEXT("IRP_MJ_SHUTDOWN");
                }
            }

        }

        AddEntryToList(ListView,
            (ULONG_PTR)Routine,
            lpCallbackType,
            lpDescription,
            Modules);

        ListEntry.Flink = EntryPacket.ListEntry.Flink;
    }

    supHeapFree(Modules);
}

/*
* DumpObCallbacks
*
* Purpose:
*
* Read Ob callback data from kernel and send it to output window.
*
*/
VOID DumpObCallbacks(
    _In_ HWND ListView,
    _In_ LPWSTR lpCallbackType,
    _In_ ULONG_PTR ListHead
)
{
    BOOL bAltitudeRead, bNeedFree;

    LPWSTR lpInfoBuffer = NULL, lpType;

    SIZE_T Size, AltitudeSize = 0;

    LIST_ENTRY ListEntry;

    PRTL_PROCESS_MODULES Modules;

    OB_CALLBACK_CONTEXT_BLOCK CallbackRecord;

    OB_REGISTRATION Registration;


    ListEntry.Flink = ListEntry.Blink = NULL;

    //
    // Read head.
    //
    if (!kdReadSystemMemoryEx(
        ListHead,
        &ListEntry,
        sizeof(LIST_ENTRY),
        NULL))
    {
        return;
    }

    Modules = (PRTL_PROCESS_MODULES)supGetSystemInfo(SystemModuleInformation);
    if (Modules == NULL)
        return;

    //
    // Walk list entries.
    //
    while ((ULONG_PTR)ListEntry.Flink != ListHead) {

        RtlSecureZeroMemory(&CallbackRecord, sizeof(CallbackRecord));

        if (!kdReadSystemMemoryEx((ULONG_PTR)ListEntry.Flink,
            &CallbackRecord,
            sizeof(CallbackRecord),
            NULL))
        {
            break;
        }

        //
        // Read Altitude.
        //
        bAltitudeRead = FALSE;

        RtlSecureZeroMemory(&Registration, sizeof(Registration));
        if (kdReadSystemMemoryEx((ULONG_PTR)CallbackRecord.Registration,
            (PVOID)&Registration,
            sizeof(Registration),
            NULL))
        {
            AltitudeSize = 8 + Registration.Altitude.Length;
            lpInfoBuffer = (LPWSTR)supHeapAlloc(AltitudeSize);
            if (lpInfoBuffer) {
                
                bAltitudeRead = kdReadSystemMemoryEx((ULONG_PTR)Registration.Altitude.Buffer,
                    (PVOID)lpInfoBuffer,
                    Registration.Altitude.Length,
                    NULL);
            }
        }

        //
        // Output PreCallback.
        //
        if ((ULONG_PTR)CallbackRecord.PreCallback > g_kdctx.SystemRangeStart) {

            bNeedFree = FALSE;

            if (bAltitudeRead) {
                Size = AltitudeSize + MAX_PATH;
                lpType = (LPWSTR)supHeapAlloc(Size);
                if (lpType) {
                    _strcpy(lpType, TEXT("PreCallback, Altitude: "));
                    _strcat(lpType, lpInfoBuffer);
                    bNeedFree = TRUE;
                }
            }
            else
                lpType = TEXT("PreCallback");

            AddEntryToList(ListView,
                (ULONG_PTR)CallbackRecord.PreCallback,
                lpCallbackType,
                lpType,
                Modules);

            if (bNeedFree) supHeapFree(lpType);
        }

        //
        // Output PostCallback.
        //
        if ((ULONG_PTR)CallbackRecord.PostCallback > g_kdctx.SystemRangeStart) {
            
            bNeedFree = FALSE;

            if (bAltitudeRead) {
                Size = AltitudeSize + MAX_PATH;
                lpType = (LPWSTR)supHeapAlloc(Size);
                if (lpType) {
                    _strcpy(lpType, TEXT("PostCallback, Altitude: "));
                    _strcat(lpType, lpInfoBuffer);
                    bNeedFree = TRUE;
                }
            }
            else
                lpType = TEXT("PostCallback");

            AddEntryToList(ListView,
                (ULONG_PTR)CallbackRecord.PostCallback,
                lpCallbackType,
                lpType,
                Modules);

            if (bNeedFree) supHeapFree(lpType);
        }
        ListEntry.Flink = CallbackRecord.CallbackListEntry.Flink;

        if (lpInfoBuffer) supHeapFree(lpInfoBuffer);
    }

    supHeapFree(Modules);
}

/*
* CallbacksList
*
* Purpose:
*
* Find callbacks pointers and list them to output window.
*
*/
VOID CallbacksList(
    _In_ HWND ListView)
{
    //
    // List process callbacks.
    //
    if (g_NotifyCallbacks.PspCreateProcessNotifyRoutine == 0)
        g_NotifyCallbacks.PspCreateProcessNotifyRoutine = FindPspCreateProcessNotifyRoutine();

    if (g_NotifyCallbacks.PspCreateProcessNotifyRoutine) {

        DumpPsCallbacks(ListView,
            TEXT("CreateProcess"),
            g_NotifyCallbacks.PspCreateProcessNotifyRoutine);

    }

    //
    // List thread callbacks.
    //
    if (g_NotifyCallbacks.PspCreateThreadNotifyRoutine == 0)
        g_NotifyCallbacks.PspCreateThreadNotifyRoutine = FindPspCreateThreadNotifyRoutine();
    if (g_NotifyCallbacks.PspCreateThreadNotifyRoutine) {

        DumpPsCallbacks(ListView,
            TEXT("CreateThread"),
            g_NotifyCallbacks.PspCreateThreadNotifyRoutine);

    }

    //
    // List load image callbacks.
    //
    if (g_NotifyCallbacks.PspLoadImageNotifyRoutine == 0)
        g_NotifyCallbacks.PspLoadImageNotifyRoutine = FindPspLoadImageNotifyRoutine();
    if (g_NotifyCallbacks.PspLoadImageNotifyRoutine) {

        DumpPsCallbacks(ListView,
            TEXT("LoadImage"),
            g_NotifyCallbacks.PspLoadImageNotifyRoutine);

    }

    //
    // List KeBugCheck callbacks.
    //
    if (g_NotifyCallbacks.KeBugCheckCallbackHead == 0)
        g_NotifyCallbacks.KeBugCheckCallbackHead = FindKeBugCheckCallbackHead();
    if (g_NotifyCallbacks.KeBugCheckCallbackHead) {

        DumpKeBugCheckCallbacks(ListView,
            TEXT("BugCheck"),
            g_NotifyCallbacks.KeBugCheckCallbackHead);

    }

    if (g_NotifyCallbacks.KeBugCheckReasonCallbackHead == 0)
        g_NotifyCallbacks.KeBugCheckReasonCallbackHead = FindKeBugCheckReasonCallbackHead();
    if (g_NotifyCallbacks.KeBugCheckReasonCallbackHead) {
        DumpKeBugCheckReasonCallbacks(ListView,
            TEXT("BugCheckReason"),
            g_NotifyCallbacks.KeBugCheckReasonCallbackHead);

    }

    //
    // List Cm callbacks
    //
    if (g_NotifyCallbacks.CmCallbackListHead == 0)
        g_NotifyCallbacks.CmCallbackListHead = FindCmCallbackHead();
    if (g_NotifyCallbacks.CmCallbackListHead) {

        DumpCmCallbacks(ListView,
            TEXT("CmRegistry"),
            g_NotifyCallbacks.CmCallbackListHead);

    }

    //
    // List Io Shutdown callbacks.
    //
    if (g_NotifyCallbacks.IopNotifyShutdownQueueHead == 0)
        g_NotifyCallbacks.IopNotifyShutdownQueueHead = FindIopNotifyShutdownQueueHeadHead(FALSE);
    if (g_NotifyCallbacks.IopNotifyShutdownQueueHead) {

        DumpIoCallbacks(ListView,
            TEXT("Shutdown"),
            g_NotifyCallbacks.IopNotifyShutdownQueueHead);
    }
    if (g_NotifyCallbacks.IopNotifyLastChanceShutdownQueueHead == 0)
        g_NotifyCallbacks.IopNotifyLastChanceShutdownQueueHead = FindIopNotifyShutdownQueueHeadHead(TRUE);
    if (g_NotifyCallbacks.IopNotifyLastChanceShutdownQueueHead) {

        DumpIoCallbacks(ListView,
            TEXT("LastChanceShutdown"),
            g_NotifyCallbacks.IopNotifyLastChanceShutdownQueueHead);
    }

    //
    // List Ob callbacks.
    //
    if (g_NotifyCallbacks.ObProcessCallbackHead == 0)
        g_NotifyCallbacks.ObProcessCallbackHead = GetObjectTypeCallbackListHeadByType(0);
    if (g_NotifyCallbacks.ObProcessCallbackHead) {

        DumpObCallbacks(ListView,
            TEXT("ObProcess"),
            g_NotifyCallbacks.ObProcessCallbackHead);

    }
    if (g_NotifyCallbacks.ObThreadCallbackHead == 0)
        g_NotifyCallbacks.ObThreadCallbackHead = GetObjectTypeCallbackListHeadByType(1);
    if (g_NotifyCallbacks.ObThreadCallbackHead) {

        DumpObCallbacks(ListView,
            TEXT("ObThread"),
            g_NotifyCallbacks.ObThreadCallbackHead);

    }
    if (g_NotifyCallbacks.ObDesktopCallbackHead == 0)
        g_NotifyCallbacks.ObDesktopCallbackHead = GetObjectTypeCallbackListHeadByType(2);
    if (g_NotifyCallbacks.ObDesktopCallbackHead) {

        DumpObCallbacks(ListView,
            TEXT("ObDesktop"),
            g_NotifyCallbacks.ObDesktopCallbackHead);

    }
}

/*
* CallbacksCompareFunc
*
* Purpose:
*
* Callbacks Dialog listview comparer function.
*
*/
INT CALLBACK CallbacksCompareFunc(
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort //pointer to EXTRASCALLBACK
)
{
    INT nResult = 0;
    LPARAM SortColumn;

    EXTRASCONTEXT *pDlgContext;
    EXTRASCALLBACK *CallbackParam = (EXTRASCALLBACK*)lParamSort;

    if (CallbackParam == NULL)
        return 0;

    pDlgContext = (EXTRASCONTEXT*)CallbackParam->Value;
    SortColumn = CallbackParam->lParam;

    switch (SortColumn) {
    case 0: //Address
        return supGetMaxOfTwoU64FromHex(
            pDlgContext->ListView,
            lParam1,
            lParam2,
            SortColumn,
            pDlgContext->bInverseSort);

    case 1: //Type
    case 2: //Module
    case 3: //Additional Info
        return supGetMaxCompareTwoFixedStrings(
            pDlgContext->ListView,
            lParam1,
            lParam2,
            SortColumn,
            pDlgContext->bInverseSort);
    }

    return nResult;
}

/*
* CallbacksHandleNotify
*
* Purpose:
*
* WM_NOTIFY processing for dialog listview.
*
*/
VOID CallbacksHandleNotify(
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
        CallbackParam.Value = (ULONG_PTR)pDlgContext;
        ListView_SortItemsEx(pDlgContext->ListView, &CallbacksCompareFunc, (LPARAM)&CallbackParam);

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
* CallbacksDialogProc
*
* Purpose:
*
* Callbacks Dialog window procedure.
*
*/
INT_PTR CALLBACK CallbacksDialogProc(
    _In_  HWND hwndDlg,
    _In_  UINT uMsg,
    _In_  WPARAM wParam,
    _In_  LPARAM lParam
)
{
    EXTRASCONTEXT *pDlgContext;

    switch (uMsg) {

    case WM_INITDIALOG:
        SetProp(hwndDlg, T_DLGCONTEXT, (HANDLE)lParam);
        supCenterWindow(hwndDlg);
        break;

    case WM_GETMINMAXINFO:
        if (lParam) {
            ((PMINMAXINFO)lParam)->ptMinTrackSize.x = 800;
            ((PMINMAXINFO)lParam)->ptMinTrackSize.y = 600;
        }
        break;

    case WM_NOTIFY:
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            CallbacksHandleNotify(lParam, pDlgContext);
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

            g_WinObj.AuxDialogs[wobjCallbacksDlgId] = NULL;

            supHeapFree(pDlgContext);
        }
        return DestroyWindow(hwndDlg);

    case WM_COMMAND:
        if (LOWORD(wParam) == IDCANCEL) {
            SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            return TRUE;
        }
        break;

    case WM_DESTROY:
        RemoveProp(hwndDlg, T_DLGCONTEXT);
        break;

    case WM_CONTEXTMENU:
        //FIXME
        break;
    }

    return FALSE;
}

/*
* extrasCreateCallbacksDialog
*
* Purpose:
*
* Create and initialize Callbacks Dialog.
*
*/
VOID extrasCreateCallbacksDialog(
    _In_ HWND hwndParent
)
{
    HWND        hwndDlg;
    LVCOLUMN    col;

    EXTRASCONTEXT  *pDlgContext;

    EXTRASCALLBACK CallbackParam;

    //allow only one dialog
    if (g_WinObj.AuxDialogs[wobjCallbacksDlgId]) {
        if (IsIconic(g_WinObj.AuxDialogs[wobjCallbacksDlgId]))
            ShowWindow(g_WinObj.AuxDialogs[wobjCallbacksDlgId], SW_RESTORE);
        else
            SetActiveWindow(g_WinObj.AuxDialogs[wobjCallbacksDlgId]);
        return;
    }

    pDlgContext = (EXTRASCONTEXT*)supHeapAlloc(sizeof(EXTRASCONTEXT));
    if (pDlgContext == NULL)
        return;

    hwndDlg = CreateDialogParam(
        g_WinObj.hInstance,
        MAKEINTRESOURCE(IDD_DIALOG_EXTRASLIST),
        hwndParent,
        &CallbacksDialogProc,
        (LPARAM)pDlgContext);

    if (hwndDlg == NULL) {
        return;
    }

    pDlgContext->hwndDlg = hwndDlg;
    g_WinObj.AuxDialogs[wobjCallbacksDlgId] = hwndDlg;
    pDlgContext->SizeGrip = supCreateSzGripWindow(hwndDlg);

    extrasSetDlgIcon(hwndDlg);
    SetWindowText(hwndDlg, TEXT("Notification Callbacks"));

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
        col.pszText = TEXT("Routine Address");
        col.cx = 150;
        col.fmt = LVCFMT_CENTER | LVCFMT_BITMAP_ON_RIGHT;
        col.iImage = ImageList_GetImageCount(g_ListViewImages) - 1;
        ListView_InsertColumn(pDlgContext->ListView, col.iSubItem, &col);

        col.iImage = I_IMAGENONE;

        col.fmt = LVCFMT_CENTER | LVCFMT_BITMAP_ON_RIGHT;
        col.iSubItem++;
        col.pszText = TEXT("Type");
        col.iOrder++;
        col.cx = 120;
        ListView_InsertColumn(pDlgContext->ListView, col.iSubItem, &col);

        col.fmt = LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT;
        col.iSubItem++;
        col.pszText = TEXT("Module");
        col.iOrder++;
        col.cx = 300;
        col.fmt = LVCFMT_LEFT;
        ListView_InsertColumn(pDlgContext->ListView, col.iSubItem, &col);

        col.fmt = LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT;
        col.iSubItem++;
        col.pszText = TEXT("Additional Info");
        col.iOrder++;
        col.cx = 200;
        col.fmt = LVCFMT_LEFT;
        ListView_InsertColumn(pDlgContext->ListView, col.iSubItem, &col);

        //remember column count
        pDlgContext->lvColumnCount = col.iSubItem;

        SendMessage(hwndDlg, WM_SIZE, 0, 0);

        CallbacksList(pDlgContext->ListView);

        CallbackParam.lParam = 1; //sort by callback type
        CallbackParam.Value = (ULONG_PTR)pDlgContext;
        ListView_SortItemsEx(pDlgContext->ListView, &CallbacksCompareFunc, (LPARAM)&CallbackParam);
        SetFocus(pDlgContext->ListView);
    }
}
