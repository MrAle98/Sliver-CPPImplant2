#pragma once
#include "sliver.pb.h"
namespace sliverpb {
	enum MsgType {
		MsgRegister = 1,

		// MsgTaskReq - A local shellcode injection task,
		MsgTaskReq,

		// MsgPing - Confirm connection is open used as req/resp,
		MsgPing,

		// MsgKillSessionReq - Kill request to the sliver process,
		MsgKillSessionReq,

		// MsgLsReq - Request a directory listing from the remote system,
		MsgLsReq,
		// MsgLs - Directory listing (resp to MsgDirListReq),
		MsgLs,

		// MsgDownloadReq - Request to download a file from the remote system,
		MsgDownloadReq,
		// MsgDownload - File contents for download (resp to DownloadReq),
		MsgDownload,

		// MsgUploadReq - Upload a file to the remote file system,
		MsgUploadReq,
		// MsgUpload - Confirms the success/failure of the file upload (resp to MsgUploadReq),
		MsgUpload,

		// MsgCdReq - Request a change directory on the remote system,
		MsgCdReq,

		// MsgPwdReq - A request to get the CWD from the remote process,
		MsgPwdReq,
		// MsgPwd - The CWD of the remote process (resp to MsgPwdReq),
		MsgPwd,

		// MsgRmReq - Request to delete remote file,
		MsgRmReq,
		// MsgRm - Confirms the success/failure of delete request (resp to MsgRmReq),
		MsgRm,

		// MsgMkdirReq - Request to create a directory on the remote system,
		MsgMkdirReq,
		// MsgMkdir - Confirms the success/failure of the mkdir request (resp to MsgMkdirReq),
		MsgMkdir,

		// MsgPsReq - List processes req,
		MsgPsReq,
		// MsgPs - List processes resp,
		MsgPs,

		// MsgShellReq - Request to open a shell tunnel,
		MsgShellReq,
		// MsgShell - Response on starting shell,
		MsgShell,

		// MsgTunnelData - Data for duplex tunnels,
		MsgTunnelData,
		// MsgTunnelClose - Close a duplex tunnel,
		MsgTunnelClose,

		// MsgProcessDumpReq - Request to create a process dump,
		MsgProcessDumpReq,
		// MsgProcessDump - Dump of process),
		MsgProcessDump,
		// MsgImpersonateReq - Request for process impersonation,
		MsgImpersonateReq,
		// MsgImpersonate - Output of the impersonation command,
		MsgImpersonate,
		// MsgRunAsReq - Request to run process as user,
		MsgRunAsReq,
		// MsgRunAs - Run process as user,
		MsgRunAs,
		// MsgRevToSelf - Revert to self,
		MsgRevToSelf,
		// MsgRevToSelfReq - Request to revert to self,
		MsgRevToSelfReq,
		// MsgInvokeGetSystemReq - Elevate as SYSTEM user,
		MsgInvokeGetSystemReq,
		// MsgGetSystem - Response to getsystem request,
		MsgGetSystem,
		// MsgInvokeExecuteAssemblyReq - Request to load and execute a .NET assembly,
		MsgInvokeExecuteAssemblyReq,
		// MsgExecuteAssemblyReq - Request to load and execute a .NET assembly,
		MsgExecuteAssemblyReq,
		// MsgExecuteAssembly - Output of the assembly execution,
		MsgExecuteAssembly,
		// MsgInvokeMigrateReq - Spawn a new sliver in a designated process,
		MsgInvokeMigrateReq,

		// MsgSideloadReq - request to sideload a binary,
		MsgSideloadReq,
		// MsgSideload - output of the binary,
		MsgSideload,

		// MsgSpawnDllReq - Reflective DLL injection request,
		MsgSpawnDllReq,
		// MsgSpawnDll - Reflective DLL injection output,
		MsgSpawnDll,

		// MsgIfconfigReq - Ifconfig (network interface config) request,
		MsgIfconfigReq,
		// MsgIfconfig - Ifconfig response,
		MsgIfconfig,

		// MsgExecuteReq - Execute a command on the remote system,
		MsgExecuteReq,

		// MsgTerminateReq - Request to kill a remote process,
		MsgTerminateReq,

		// MsgTerminate - Kill a remote process,
		MsgTerminate,

		// MsgScreenshotReq - Request to take a screenshot,
		MsgScreenshotReq,

		// MsgScreenshot - Response with the screenshots,
		MsgScreenshot,

		// MsgNetstatReq - Netstat request,
		MsgNetstatReq,

		// *** Pivots ***

		// MsgPivotStartListenerReq - Start a listener,
		MsgPivotStartListenerReq,
		// MsgPivotStopListenerReq - Stop a listener,
		MsgPivotStopListenerReq,
		// MsgPivotListenersReq - List listeners request,
		MsgPivotListenersReq,
		// MsgPivotListeners - List listeners response,
		MsgPivotListeners,
		// MsgPivotPeerPing - Pivot peer ping message,
		MsgPivotPeerPing,
		// MsgPivotServerPing - Pivot peer ping message,
		MsgPivotServerPing,
		// PivotServerKeyExchange - Pivot to server key exchange
		MsgPivotServerKeyExchange,
		// MsgPivotPeerEnvelope - An envelope from a pivot peer,
		MsgPivotPeerEnvelope,
		// MsgPivotPeerFailure - Failure to send an envelope to a pivot peer,
		MsgPivotPeerFailure,
		// MsgPivotSessionEnvelope,
		MsgPivotSessionEnvelope,

		// MsgStartServiceReq - Request to start a service,
		MsgStartServiceReq,
		// MsgStartService - Response to start service request,
		MsgStartService,
		// MsgStopServiceReq - Request to stop a remote service,
		MsgStopServiceReq,
		// MsgRemoveServiceReq - Request to remove a remote service,
		MsgRemoveServiceReq,
		// MsgMakeTokenReq - Request for MakeToken,
		MsgMakeTokenReq,
		// MsgMakeToken - Response for MakeToken,
		MsgMakeToken,
		// MsgEnvReq - Request to get environment variables,
		MsgEnvReq,
		// MsgEnvInfo - Response to environment variable request,
		MsgEnvInfo,
		// MsgSetEnvReq,
		MsgSetEnvReq,
		// MsgSetEnv,
		MsgSetEnv,
		// MsgExecuteWindowsReq - Execute request executed with the current (Windows) token,
		MsgExecuteWindowsReq,
		// MsgRegistryReadReq,
		MsgRegistryReadReq,
		// MsgRegistryWriteReq,
		MsgRegistryWriteReq,
		// MsgRegistryCreateKeyReq,
		MsgRegistryCreateKeyReq,

		// MsgWGStartPortFwdReq - Request to start a port forwarding in a WG transport,
		MsgWGStartPortFwdReq,
		// MsgWGStopPortFwdReq - Request to stop a port forwarding in a WG transport,
		MsgWGStopPortFwdReq,
		// MsgWGStartSocks - Request to start a socks server in a WG transport,
		MsgWGStartSocksReq,
		// MsgWGStopSocks - Request to stop a socks server in a WG transport,
		MsgWGStopSocksReq,
		// MsgWGListForwarders,
		MsgWGListForwardersReq,
		// MsgWGListSocks,
		MsgWGListSocksReq,

		// MsgPortfwdReq - Establish a port forward,
		MsgPortfwdReq,
		// MsgPortfwd - Response of port forward,
		MsgPortfwd,

		// MsgSocksData - Response of SocksData,
		MsgSocksData,

		// MsgReconfigureReq,
		MsgReconfigureReq,

		// MsgReconfigure - Set Reconfigure,
		MsgReconfigure,

		// MsgUnsetEnvReq,
		MsgUnsetEnvReq,

		// MsgSSHCommandReq - Run a SSH command,
		MsgSSHCommandReq,

		// MsgGetPrivsReq - Get privileges (Windows),
		MsgGetPrivsReq,

		// MsgRegistryListReq - List registry sub keys,
		MsgRegistrySubKeysListReq,
		// MsgRegistryListValuesReq - List registry values,
		MsgRegistryListValuesReq,
		// MsgRegisterExtensionReq - Register a new extension,
		MsgRegisterExtensionReq,

		// MsgCallExtensionReq - Run an extension command,
		MsgCallExtensionReq,
		// MsgListExtensionsReq - List loaded extensions,
		MsgListExtensionsReq,

		// MsgBeaconRegister - Register a new beacon,
		MsgBeaconRegister,
		// MsgBeaconTasks - Send/recv batches of beacon tasks,
		MsgBeaconTasks,

		// MsgOpenSession - Open a new session,
		MsgOpenSession,
		// MsgCloseSession - Close the active session,
		MsgCloseSession,

		// MsgRegistryDeleteKeyReq,
		MsgRegistryDeleteKeyReq,

		// MsgMvReq - Request to move or rename a file,
		MsgMvReq,
		// MsgMv - Confirms the success/failure of the mv request (resp to MsgMvReq),
		MsgMv,

		// MsgCurrentTokenOwnerReq - Request to query the thread token owner,
		MsgCurrentTokenOwnerReq,
		// MsgCurrentTokenOwner - Replies with the current thread owner (resp to MsfCurrentToken),
		MsgCurrentTokenOwner,
		// MsgInvokeInProcExecuteAssemblyReq - Request to load and execute a .NET assembly in-process,
		MsgInvokeInProcExecuteAssemblyReq,

		MsgRportFwdStopListenerReq,

		MsgRportFwdStartListenerReq,

		MsgRportFwdListener,

		MsgRportFwdListeners,

		MsgRportFwdListenersReq,

		MsgRPortfwdReq,

		MsgPivotPeerEnvelopeNoResponse
	};

	MsgType MsgNumber(google::protobuf::Message& msg);

}