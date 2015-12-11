//
// 	NetFilterSDK 
// 	Copyright (C) 2009 Vitaly Sidorov
//	All rights reserved.
//
//	This file is a part of the NetFilter SDK.
//	The code and information is provided "as-is" without
//	warranty of any kind, either expressed or implied.
//

#ifndef _NF_UTIL_H
#define _NF_UTIL_H

#include <tchar.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

#ifndef _C_API
namespace nfapi
{
#else
#ifdef __cplusplus
extern "C" 
{
#endif
#endif

	typedef BOOL (WINAPI *tQueryFullProcessImageNameA)(
				HANDLE hProcess,
				DWORD dwFlags,
				LPSTR lpExeName,
				PDWORD lpdwSize
	);

	typedef BOOL (WINAPI *tQueryFullProcessImageNameW)(
				HANDLE hProcess,
				DWORD dwFlags,
				LPWSTR lpExeName,
				PDWORD lpdwSize
	);

#ifdef __cplusplus
#ifdef UNICODE
	__declspec(selectany) tQueryFullProcessImageNameW pQueryFullProcessImageNameW =
				(tQueryFullProcessImageNameW)GetProcAddress(
								GetModuleHandle(_T("kernel32")), "QueryFullProcessImageNameW");
#else
	__declspec(selectany) tQueryFullProcessImageNameA pQueryFullProcessImageNameA =
				(tQueryFullProcessImageNameA)GetProcAddress(
								GetModuleHandle(_T("kernel32")), "QueryFullProcessImageNameA");
#endif
#else
#ifdef UNICODE
	__declspec(selectany) tQueryFullProcessImageNameW pQueryFullProcessImageNameW = NULL;
#else
	__declspec(selectany) tQueryFullProcessImageNameA pQueryFullProcessImageNameA = NULL;
#endif
	__declspec(selectany) BOOL g_QueryFullProcessImageNameInitialized = FALSE;
#endif

	#ifdef UNICODE
	#define QueryFullProcessImageName pQueryFullProcessImageNameW
	#else
	#define QueryFullProcessImageName pQueryFullProcessImageNameA
	#endif 

	/**
	* Returns the process name for given process id
	* @param processId Process identifier
	* @param buf Buffer
	* @param len Buffer length
	**/
	BOOL nf_getProcessName(DWORD processId, TCHAR * buf, DWORD len)
	{
		BOOL res = FALSE;
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
		if (hProcess)
		{
#ifndef __cplusplus
			if (!g_QueryFullProcessImageNameInitialized)
			{
				#ifdef UNICODE
					pQueryFullProcessImageNameW = 
						(tQueryFullProcessImageNameW)GetProcAddress(
								GetModuleHandle(_T("kernel32")), "QueryFullProcessImageNameW");
				#else
					pQueryFullProcessImageNameA = 
						(tQueryFullProcessImageNameA)GetProcAddress(
								GetModuleHandle(_T("kernel32")), "QueryFullProcessImageNameA");
				#endif
				g_QueryFullProcessImageNameInitialized = TRUE;
			}
#endif

			if (QueryFullProcessImageName)
			{
				res = QueryFullProcessImageName(hProcess, 0, buf, &len);
			} else
			{
				res = GetModuleFileNameEx(hProcess, NULL, buf, len);
			}

			CloseHandle(hProcess);
		}

		return res;
	}


	/**
	*	Allows the current process to see the names of all processes in system
	**/
	void nf_adjustProcessPriviledges()
	{
		// Set the necessary privileges for accessing token info for all system processes
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
		if (hProcess)
		{
			HANDLE hToken;
					
			if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
			{
				TOKEN_PRIVILEGES tp;
				LUID luid;

				if ( !LookupPrivilegeValue( 
						NULL,            // lookup privilege on local system
						SE_DEBUG_NAME,   // privilege to lookup 
						&luid ) )        // receives LUID of privilege
				{
					CloseHandle(hToken);
					CloseHandle(hProcess);
					return; 
				}

				tp.PrivilegeCount = 1;
				tp.Privileges[0].Luid = luid;
				tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

				if ( !AdjustTokenPrivileges(
					   hToken, 
					   FALSE,  
					   &tp, 
					   sizeof(TOKEN_PRIVILEGES), 
					   (PTOKEN_PRIVILEGES) NULL, 
					   (PDWORD) NULL) )
				{ 
					  CloseHandle(hToken);
					  CloseHandle(hProcess);
					  return; 
				} 

				CloseHandle(hToken);
			}

			CloseHandle(hProcess);
		}
	}

#ifdef __cplusplus
}
#endif

#endif