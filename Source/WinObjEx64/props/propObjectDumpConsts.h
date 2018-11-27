/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       PROPOBJECTDUMPCONSTS.H
*
*  VERSION:     1.61
*
*  DATE:        25 Nov 2018
*
*  Consts header file for Object Dump module.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#define FORMAT_HEXBYTE      L"0x%02x"
#define FORMAT_HEXUSHORT    L"0x%04X"
#define FORMAT_HEXDWORD     L"0x%08X"
#define FORMAT_ULONG        L"%u"
#define FORMAT_USHORT       L"0x%04u"
#define FORMAT_POINTER      L"0x%p"
#define T_NULL              L"NULL"
#define T_UNNAMED           L"Unnamed"

#define T_LDR_DATA_TABLE_ENTRY      L"LDR_DATA_TABLE_ENTRY"
#define T_LIST_ENTRY                L"LIST_ENTRY"
#define T_PLIST_ENTRY               L"PLIST_ENTRY"
#define T_EX_PUSH_LOCK              L"EX_PUSH_LOCK"
#define T_PDEVICE_MAP               L"PDEVICE_MAP"
#define T_OBJ_INVALID_SESSION_ID    L"OBJ_INVALID_SESSION_ID"
#define T_POBJECT_DIRECTORY_ENTRY   L"POBJECT_DIRECTORY_ENTRY"
#define T_POBJECT_DIRECTORY         L"POBJECT_DIRECTORY"
#define T_OBJECT_DIRECTORY          L"OBJECT_DIRECTORY"
#define T_OBJECT_TYPE               L"OBJECT_TYPE"
#define T_OBJECT_TYPE_INITIALIZER   L"OBJECT_TYPE_INITIALIZER"
#define T_PUNICODE_STRING           L"PUNICODE_STRING"
#define T_PKTHREAD                  L"PKTHREAD"
#define T_KEVENT                    L"KEVENT"
#define T_KMUTANT                   L"KMUTANT"
#define T_KSEMAPHORE                L"KSEMAPHORE"
#define T_KTIMER                    L"KTIMER"
#define T_KQUEUE                    L"KQUEUE"
#define T_PKDPC                     L"PKDPC"
#define T_GENERIC_MAPPING           L"GENERIC_MAPPING"
#define T_EX_RUNDOWN_REF            L"EX_RUNDOWN_REF"

#define T_FLT_SERVER_PORT_OBJECT    L"FLT_SERVER_PORT_OBJECT"
#define T_PFLT_FILTER               L"PFLT_FILTER"
#define T_FLT_OBJECT                L"FLT_OBJECT"
#define T_FLT_FILTER_FLAGS          L"FLT_FILTER_FLAGS"

#define T_ALPC_PORT_OBJECT          L"ALPC_PORT"
#define T_PALPC_PORT_OBJECT         L"PALPC_PORT"
#define T_ALPC_HANDLE_TABLE         L"ALPC_HANDLE_TABLE"

#define T_EVENT_NOTIFICATION        L"NotificationEvent"
#define T_EVENT_SYNC                L"SynchronizationEvent"
#define T_SIGNALED                  L"Signaled"
#define T_NONSIGNALED               L"Nonsignaled"
#define T_OBJECT_TYPE_FLAGS         L"ObjectTypeFlags"
#define T_OBJECT_TYPE_FLAGS2        L"ObjectTypeFlags2"

#define T_TIMER_NOTIFICATION        L"NotificationTimer"
#define T_TIMER_SYNC                L"SynchronizationTimer"
#define T_CHARACTERISTICS           L"Characteristics"
#define T_FLAGS                     L"Flags"
#define T_LENGTH                    L"Length"
#define T_TYPEINDEX                 L"Index"
#define T_REFNOTFOUND               L"! Reference not found"


#define MAX_KNOWN_DRV_FLAGS 8
static VALUE_DESC drvFlags[MAX_KNOWN_DRV_FLAGS] = {
    { L"DRVO_UNLOAD_INVOKED", DRVO_UNLOAD_INVOKED },
    { L"DRVO_LEGACY_DRIVER", DRVO_LEGACY_DRIVER },
    { L"DRVO_BUILTIN_DRIVER", DRVO_BUILTIN_DRIVER },
    { L"DRVO_REINIT_REGISTERED", DRVO_REINIT_REGISTERED },
    { L"DRVO_INITIALIZED", DRVO_INITIALIZED },
    { L"DRVO_BOOTREINIT_REGISTERED", DRVO_BOOTREINIT_REGISTERED },
    { L"DRVO_LEGACY_RESOURCES", DRVO_LEGACY_RESOURCES },
    { L"DRVO_BASE_FILESYSTEM_DRIVER", DRVO_BASE_FILESYSTEM_DRIVER }
};

#define MAX_KNOWN_DEV_FLAGS 17
static VALUE_DESC devFlags[MAX_KNOWN_DEV_FLAGS] = {
    { L"DO_VERIFY_VOLUME", DO_VERIFY_VOLUME },
    { L"DO_BUFFERED_IO", DO_BUFFERED_IO },
    { L"DO_EXCLUSIVE", DO_EXCLUSIVE },
    { L"DO_DIRECT_IO", DO_DIRECT_IO },
    { L"DO_MAP_IO_BUFFER", DO_MAP_IO_BUFFER },
    { L"DO_DEVICE_HAS_NAME", DO_DEVICE_HAS_NAME },
    { L"DO_DEVICE_INITIALIZING", DO_DEVICE_INITIALIZING },
    { L"DO_SYSTEM_BOOT_PARTITION", DO_SYSTEM_BOOT_PARTITION },
    { L"DO_LONG_TERM_REQUESTS", DO_LONG_TERM_REQUESTS },
    { L"DO_NEVER_LAST_DEVICE", DO_NEVER_LAST_DEVICE },
    { L"DO_SHUTDOWN_REGISTERED", DO_SHUTDOWN_REGISTERED },
    { L"DO_BUS_ENUMERATED_DEVICE", DO_BUS_ENUMERATED_DEVICE },
    { L"DO_POWER_PAGABLE", DO_POWER_PAGABLE },
    { L"DO_POWER_INRUSH", DO_POWER_INRUSH },
    { L"DO_POWER_NOOP", DO_POWER_NOOP },
    { L"DO_LOW_PRIORITY_FILESYSTEM", DO_LOW_PRIORITY_FILESYSTEM },
    { L"DO_XIP", DO_XIP }
};

#define MAX_KNOWN_CHR_FLAGS 15
static VALUE_DESC devChars[MAX_KNOWN_CHR_FLAGS] = {
    { L"FILE_REMOVABLE_MEDIA", FILE_REMOVABLE_MEDIA },
    { L"FILE_READ_ONLY_DEVICE", FILE_READ_ONLY_DEVICE },
    { L"FILE_FLOPPY_DISKETTE", FILE_FLOPPY_DISKETTE },
    { L"FILE_WRITE_ONCE_MEDIA", FILE_WRITE_ONCE_MEDIA },
    { L"FILE_REMOTE_DEVICE", FILE_REMOTE_DEVICE },
    { L"FILE_DEVICE_IS_MOUNTED", FILE_DEVICE_IS_MOUNTED },
    { L"FILE_VIRTUAL_VOLUME", FILE_VIRTUAL_VOLUME },
    { L"FILE_AUTOGENERATED_DEVICE_NAME", FILE_AUTOGENERATED_DEVICE_NAME },
    { L"FILE_DEVICE_SECURE_OPEN", FILE_DEVICE_SECURE_OPEN },
    { L"FILE_CHARACTERISTIC_PNP_DEVICE", FILE_CHARACTERISTIC_PNP_DEVICE },
    { L"FILE_CHARACTERISTIC_TS_DEVICE", FILE_CHARACTERISTIC_TS_DEVICE },
    { L"FILE_CHARACTERISTIC_WEBDAV_DEVICE", FILE_CHARACTERISTIC_WEBDAV_DEVICE },
    { L"FILE_CHARACTERISTIC_CSV", FILE_CHARACTERISTIC_CSV },
    { L"FILE_DEVICE_ALLOW_APPCONTAINER_TRAVERSAL", FILE_DEVICE_ALLOW_APPCONTAINER_TRAVERSAL },
    { L"FILE_PORTABLE_DEVICE", FILE_PORTABLE_DEVICE }
};

static LPWSTR T_IRP_MJ_FUNCTION[] = {
    L"IRP_MJ_CREATE",                   //0x00
    L"IRP_MJ_CREATE_NAMED_PIPE",        //0x01
    L"IRP_MJ_CLOSE",                    //0x02
    L"IRP_MJ_READ",                     //0x03
    L"IRP_MJ_WRITE",                    //0x04
    L"IRP_MJ_QUERY_INFORMATION",        //0x05
    L"IRP_MJ_SET_INFORMATION",          //0x06
    L"IRP_MJ_QUERY_EA",                 //0x07
    L"IRP_MJ_SET_EA",                   //0x08
    L"IRP_MJ_FLUSH_BUFFERS",            //0x09
    L"IRP_MJ_QUERY_VOLUME_INFORMATION", //0x0a
    L"IRP_MJ_SET_VOLUME_INFORMATION",   //0x0b
    L"IRP_MJ_DIRECTORY_CONTROL",        //0x0c
    L"IRP_MJ_FILE_SYSTEM_CONTROL",      //0x0d
    L"IRP_MJ_DEVICE_CONTROL",           //0x0e
    L"IRP_MJ_INTERNAL_DEVICE_CONTROL",  //0x0f
    L"IRP_MJ_SHUTDOWN",                 //0x10
    L"IRP_MJ_LOCK_CONTROL",             //0x11
    L"IRP_MJ_CLEANUP",                  //0x12
    L"IRP_MJ_CREATE_MAILSLOT",          //0x13
    L"IRP_MJ_QUERY_SECURITY",           //0x14
    L"IRP_MJ_SET_SECURITY",             //0x15
    L"IRP_MJ_POWER",                    //0x16
    L"IRP_MJ_SYSTEM_CONTROL",           //0x17
    L"IRP_MJ_DEVICE_CHANGE",            //0x18
    L"IRP_MJ_QUERY_QUOTA",              //0x19
    L"IRP_MJ_SET_QUOTA",                //0x1a
    L"IRP_MJ_PNP"                       //0x1b
};

static LPWSTR T_FAST_IO_DISPATCH[] = {
    L"FastIoCheckIfPossible",
    L"FastIoRead",
    L"FastIoWrite",
    L"FastIoQueryBasicInfo",
    L"FastIoQueryStandardInfo",
    L"FastIoLock",
    L"FastIoUnlockSingle",
    L"FastIoUnlockAll",
    L"FastIoUnlockAllByKey",
    L"FastIoDeviceControl",
    L"AcquireFileForNtCreateSection",
    L"ReleaseFileForNtCreateSection",
    L"FastIoDetachDevice",
    L"FastIoQueryNetworkOpenInfo",
    L"AcquireForModWrite",
    L"MdlRead",
    L"MdlReadComplete",
    L"PrepareMdlWrite",
    L"MdlWriteComplete",
    L"FastIoReadCompressed",
    L"FastIoWriteCompressed",
    L"MdlReadCompleteCompressed",
    L"MdlWriteCompleteCompressed",
    L"FastIoQueryOpen",
    L"ReleaseForModWrite",
    L"AcquireForCcFlush",
    L"ReleaseForCcFlush"
};

static LPWSTR T_ALPC_PORT_STATE[] = {
    L"Initialized",
    L"Type",
    L"ConnectionPending",
    L"ConnectionRefused",
    L"Disconnected",
    L"Closed",
    L"NoFlushOnClose",
    L"ReturnExtendedInfo",
    L"Waitable",
    L"DynamicSecurity",
    L"Wow64CompletionList",
    L"Lpc",
    L"LpcToLpc",
    L"HasCompletionList",
    L"HadCompletionList",
    L"EnableCompletionList"
};

#define MAX_DEVOBJ_CHARS 76
static VALUE_DESC devObjChars[MAX_DEVOBJ_CHARS] = {
    { L"FILE_DEVICE_BEEP", FILE_DEVICE_BEEP },
    { L"FILE_DEVICE_CD_ROM", FILE_DEVICE_CD_ROM },
    { L"FILE_DEVICE_CD_ROM_FILE_SYSTEM", FILE_DEVICE_CD_ROM_FILE_SYSTEM },
    { L"FILE_DEVICE_CONTROLLER", FILE_DEVICE_CONTROLLER },
    { L"FILE_DEVICE_DATALINK", FILE_DEVICE_DATALINK },
    { L"FILE_DEVICE_DFS", FILE_DEVICE_DFS },
    { L"FILE_DEVICE_DISK", FILE_DEVICE_DISK },
    { L"FILE_DEVICE_DISK_FILE_SYSTEM", FILE_DEVICE_DISK_FILE_SYSTEM },
    { L"FILE_DEVICE_FILE_SYSTEM", FILE_DEVICE_FILE_SYSTEM },
    { L"FILE_DEVICE_INPORT_PORT", FILE_DEVICE_INPORT_PORT },
    { L"FILE_DEVICE_KEYBOARD", FILE_DEVICE_KEYBOARD },
    { L"FILE_DEVICE_MAILSLOT", FILE_DEVICE_MAILSLOT },
    { L"FILE_DEVICE_MIDI_IN", FILE_DEVICE_MIDI_IN },
    { L"FILE_DEVICE_MIDI_OUT", FILE_DEVICE_MIDI_OUT },
    { L"FILE_DEVICE_MOUSE", FILE_DEVICE_MOUSE },
    { L"FILE_DEVICE_MULTI_UNC_PROVIDER", FILE_DEVICE_MULTI_UNC_PROVIDER },
    { L"FILE_DEVICE_NAMED_PIPE", FILE_DEVICE_NAMED_PIPE },
    { L"FILE_DEVICE_NETWORK", FILE_DEVICE_NETWORK },
    { L"FILE_DEVICE_NETWORK_BROWSER", FILE_DEVICE_NETWORK_BROWSER },
    { L"FILE_DEVICE_NETWORK_FILE_SYSTEM", FILE_DEVICE_NETWORK_FILE_SYSTEM },
    { L"FILE_DEVICE_NULL", FILE_DEVICE_NULL },
    { L"FILE_DEVICE_PARALLEL_PORT", FILE_DEVICE_PARALLEL_PORT },
    { L"FILE_DEVICE_PHYSICAL_NETCARD", FILE_DEVICE_PHYSICAL_NETCARD },
    { L"FILE_DEVICE_PRINTER", FILE_DEVICE_PRINTER },
    { L"FILE_DEVICE_SCANNER", FILE_DEVICE_SCANNER },
    { L"FILE_DEVICE_SERIAL_MOUSE_PORT", FILE_DEVICE_SERIAL_MOUSE_PORT },
    { L"FILE_DEVICE_SERIAL_PORT", FILE_DEVICE_SERIAL_PORT },
    { L"FILE_DEVICE_SCREEN", FILE_DEVICE_SCREEN },
    { L"FILE_DEVICE_SOUND", FILE_DEVICE_SOUND },
    { L"FILE_DEVICE_STREAMS", FILE_DEVICE_STREAMS },
    { L"FILE_DEVICE_TAPE", FILE_DEVICE_TAPE },
    { L"FILE_DEVICE_TAPE_FILE_SYSTEM", FILE_DEVICE_TAPE_FILE_SYSTEM },
    { L"FILE_DEVICE_TRANSPORT", FILE_DEVICE_TRANSPORT },
    { L"FILE_DEVICE_UNKNOWN", FILE_DEVICE_UNKNOWN },
    { L"FILE_DEVICE_VIDEO", FILE_DEVICE_VIDEO },
    { L"FILE_DEVICE_VIRTUAL_DISK", FILE_DEVICE_VIRTUAL_DISK },
    { L"FILE_DEVICE_WAVE_IN", FILE_DEVICE_WAVE_IN },
    { L"FILE_DEVICE_WAVE_OUT", FILE_DEVICE_WAVE_OUT },
    { L"FILE_DEVICE_8042_PORT", FILE_DEVICE_8042_PORT },
    { L"FILE_DEVICE_NETWORK_REDIRECTOR", FILE_DEVICE_NETWORK_REDIRECTOR },
    { L"FILE_DEVICE_BATTERY", FILE_DEVICE_BATTERY },
    { L"FILE_DEVICE_BUS_EXTENDER", FILE_DEVICE_BUS_EXTENDER },
    { L"FILE_DEVICE_MODEM", FILE_DEVICE_MODEM },
    { L"FILE_DEVICE_VDM", FILE_DEVICE_VDM },
    { L"FILE_DEVICE_MASS_STORAGE", FILE_DEVICE_MASS_STORAGE },
    { L"FILE_DEVICE_SMB", FILE_DEVICE_SMB },
    { L"FILE_DEVICE_KS", FILE_DEVICE_KS },
    { L"FILE_DEVICE_CHANGER", FILE_DEVICE_CHANGER },
    { L"FILE_DEVICE_SMARTCARD", FILE_DEVICE_SMARTCARD },
    { L"FILE_DEVICE_ACPI", FILE_DEVICE_ACPI },
    { L"FILE_DEVICE_DVD", FILE_DEVICE_DVD },
    { L"FILE_DEVICE_FULLSCREEN_VIDEO", FILE_DEVICE_FULLSCREEN_VIDEO },
    { L"FILE_DEVICE_DFS_FILE_SYSTEM", FILE_DEVICE_DFS_FILE_SYSTEM },
    { L"FILE_DEVICE_DFS_VOLUME", FILE_DEVICE_DFS_VOLUME },
    { L"FILE_DEVICE_SERENUM", FILE_DEVICE_SERENUM },
    { L"FILE_DEVICE_TERMSRV", FILE_DEVICE_TERMSRV },
    { L"FILE_DEVICE_KSEC", FILE_DEVICE_KSEC },
    { L"FILE_DEVICE_FIPS", FILE_DEVICE_FIPS },
    { L"FILE_DEVICE_INFINIBAND", FILE_DEVICE_INFINIBAND },
    { L"FILE_DEVICE_VMBUS", FILE_DEVICE_VMBUS },
    { L"FILE_DEVICE_CRYPT_PROVIDER", FILE_DEVICE_CRYPT_PROVIDER },
    { L"FILE_DEVICE_WPD", FILE_DEVICE_WPD },
    { L"FILE_DEVICE_BLUETOOTH", FILE_DEVICE_BLUETOOTH },
    { L"FILE_DEVICE_MT_COMPOSITE", FILE_DEVICE_MT_COMPOSITE },
    { L"FILE_DEVICE_MT_TRANSPORT", FILE_DEVICE_MT_TRANSPORT },
    { L"FILE_DEVICE_BIOMETRIC", FILE_DEVICE_BIOMETRIC },
    { L"FILE_DEVICE_PMI", FILE_DEVICE_PMI },
    { L"FILE_DEVICE_EHSTOR", FILE_DEVICE_EHSTOR },
    { L"FILE_DEVICE_DEVAPI", FILE_DEVICE_DEVAPI },
    { L"FILE_DEVICE_GPIO", FILE_DEVICE_GPIO },
    { L"FILE_DEVICE_USBEX", FILE_DEVICE_USBEX },
    { L"FILE_DEVICE_CONSOLE", FILE_DEVICE_CONSOLE },
    { L"FILE_DEVICE_NFP", FILE_DEVICE_NFP },
    { L"FILE_DEVICE_SYSENV", FILE_DEVICE_SYSENV },
    { L"FILE_DEVICE_VIRTUAL_BLOCK", FILE_DEVICE_VIRTUAL_BLOCK },
    { L"FILE_DEVICE_POINT_OF_SERVICE", FILE_DEVICE_POINT_OF_SERVICE }
};

#define MAX_KNOWN_FILEALIGN 10
static VALUE_DESC fileAlign[MAX_KNOWN_FILEALIGN] = {
    { L"FILE_BYTE_ALIGNMENT", FILE_BYTE_ALIGNMENT },
    { L"FILE_WORD_ALIGNMENT", FILE_WORD_ALIGNMENT },
    { L"FILE_LONG_ALIGNMENT", FILE_LONG_ALIGNMENT },
    { L"FILE_QUAD_ALIGNMENT", FILE_QUAD_ALIGNMENT },
    { L"FILE_OCTA_ALIGNMENT", FILE_OCTA_ALIGNMENT },
    { L"FILE_32_BYTE_ALIGNMENT", FILE_32_BYTE_ALIGNMENT },
    { L"FILE_64_BYTE_ALIGNMENT", FILE_64_BYTE_ALIGNMENT },
    { L"FILE_128_BYTE_ALIGNMENT", FILE_128_BYTE_ALIGNMENT },
    { L"FILE_256_BYTE_ALIGNMENT", FILE_256_BYTE_ALIGNMENT },
    { L"FILE_512_BYTE_ALIGNMENT", FILE_512_BYTE_ALIGNMENT }
};

COLORREF CLR_HOOK = 0x80ff80; //light green
COLORREF CLR_WARN = 0x5050ff; //red
COLORREF CLR_INVL = 0xa9a9a9; //silver
COLORREF CLR_LGRY = 0xd3d3d3; //light grey
