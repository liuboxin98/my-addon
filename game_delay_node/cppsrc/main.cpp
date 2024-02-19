#include <node_api.h>
#include <Windows.h>
#include <Iphlpapi.h>
#include <string>
#include <assert.h>
#include <stdio.h>
#include <vector>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
  
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"Iphlpapi.lib")

static int Utf82Unicode(const std::string& utf8string, std::wstring& dst)
{
   int widesize = ::MultiByteToWideChar(CP_UTF8, 0, utf8string.c_str(), -1, NULL, 0);
	if (widesize == ERROR_NO_UNICODE_TRANSLATION || widesize <= 0)
	{
		return -1;
	}

	std::vector<wchar_t> resultstring(widesize);

	int convresult = ::MultiByteToWideChar(CP_UTF8, 0, utf8string.c_str(), -1, &resultstring[0], widesize);

	if (convresult != widesize)
	{
		return -1;
	}

	dst = std::wstring(&resultstring[0]);

	return 0; 
}

//unicode to ascii
int WideByte2Acsi(std::wstring& wstrcode, std::string& dst)
{
    int asciisize = ::WideCharToMultiByte(CP_OEMCP, 0, wstrcode.c_str(), -1, NULL, 0, NULL, NULL);
	if (asciisize == ERROR_NO_UNICODE_TRANSLATION || asciisize <= 0)
	{
		return -1;
	}

	std::vector<char> resultstring(asciisize);
	int convresult = ::WideCharToMultiByte(CP_OEMCP, 0, wstrcode.c_str(), -1, &resultstring[0], asciisize, NULL, NULL);

	if (convresult != asciisize)
	{
		return -1;
	}

	dst = std::string(&resultstring[0]);

	return 0;
}

//utf-8 to ascii
int UTF8_2ASCII(std::string& strUtf8Code, std::string& dst)
{
	std::wstring wstr;
	if (Utf82Unicode(strUtf8Code, wstr))
	{
		return -1;
	}
	return WideByte2Acsi(wstr, dst);
}

//ascii to Unicode
int Acsi2WideByte(std::string& strascii, std::wstring& dst)
{
    int widesize = MultiByteToWideChar(CP_ACP, 0, (char*)strascii.c_str(), -1, NULL, 0);
	if (widesize == ERROR_NO_UNICODE_TRANSLATION || widesize <= 0)
	{
		return -1;
	}

	std::vector<wchar_t> resultstring(widesize);
	int convresult = MultiByteToWideChar(CP_ACP, 0, (char*)strascii.c_str(), -1, &resultstring[0], widesize);

	if (convresult != widesize)
	{
		return -1;
	}

	dst = std::wstring(&resultstring[0]);

	return 0;
}

//Unicode to Utf8
int Unicode2Utf8(const std::wstring& widestring, std::string& dst)
{
    int utf8size = ::WideCharToMultiByte(CP_UTF8, 0, widestring.c_str(), -1, NULL, 0, NULL, NULL);
	if (utf8size <= 0 || utf8size == ERROR_NO_UNICODE_TRANSLATION)
	{
		return -1;
	}

	std::vector<char> resultstring(utf8size);

	int convresult = ::WideCharToMultiByte(CP_UTF8, 0, widestring.c_str(), -1, &resultstring[0], utf8size, NULL, NULL);

	if (convresult != utf8size)
	{
		return -1;
	}

	dst = std::string(&resultstring[0]);

	return 0;
}

//ascii to Utf8
int ASCII2UTF_8(std::string& strAsciiCode, std::string& dst)
{
	std::wstring wstr;
	if (Acsi2WideByte(strAsciiCode, wstr))
	{
		return -1;
	}
	return Unicode2Utf8(wstr, dst);
}

static BOOL PipeCmd(char *pszCmd, char *pszResultBuffer, DWORD dwResultBufferSize)
{
	HANDLE hReadPipe = NULL;
	HANDLE hWritePipe = NULL;
	SECURITY_ATTRIBUTES securityAttributes = {0};
	BOOL bRet = FALSE;
	STARTUPINFO si = {0};
	PROCESS_INFORMATION pi = {0};

	securityAttributes.bInheritHandle = TRUE;
	securityAttributes.nLength = sizeof(securityAttributes);
	securityAttributes.lpSecurityDescriptor = NULL;
	bRet = ::CreatePipe(&hReadPipe, &hWritePipe, &securityAttributes, 0);
	if (!bRet)
	{
		printf("create pipe failed:%d.\n", GetLastError());
		return FALSE;
	}
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	si.wShowWindow = SW_HIDE;
	si.hStdError = hWritePipe;
	si.hStdOutput = hWritePipe;

	std::wstring wsz_cmd;
	if(Acsi2WideByte(std::string(pszCmd), wsz_cmd) < 0)
	{
		printf("to wide byte failed.\n");
		return FALSE;
	}

	bRet = ::CreateProcess(NULL, const_cast<WCHAR*>(wsz_cmd.c_str()), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
	if (!bRet)
	{
		printf("create process failed:%d.\n", GetLastError());
		return FALSE;
	}

	::WaitForSingleObject(pi.hProcess, 5000);
	::WaitForSingleObject(pi.hThread, 5000);
	
	CloseHandle(hWritePipe);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	::RtlZeroMemory(pszResultBuffer, dwResultBufferSize);

	DWORD bytesRead = 0;
	if (!ReadFile(hReadPipe, pszResultBuffer, dwResultBufferSize, &bytesRead, NULL))
	{
		printf("read file failed:%d.\n", GetLastError());
		return FALSE;
	}

	::CloseHandle(hReadPipe);

	return TRUE;
}

static std::string getCmdResult(const std::string &strCmd)
{
	char buf[10240] = { 0 };
	FILE *pf = NULL;

	if ((pf = _popen(strCmd.c_str(), "r")) == NULL)
	{
		return "";
	}

	std::string strResult;
	while (fgets(buf, sizeof(buf), pf))
	{
		strResult += buf;
	}

	_pclose(pf);

	unsigned int iSize = strResult.size();
	if (iSize > 0 && strResult[iSize - 1] == '\n') 
	{
		strResult = strResult.substr(0, iSize - 1);
	}

	return strResult;
}

static DWORD MyGetIpForwardTable(PMIB_IPFORWARDTABLE& pIpRouteTab, BOOL fOrder)
{
	DWORD status = NO_ERROR;
	DWORD statusRetry = NO_ERROR;
	DWORD dwActualSize = 0;

	// query for buffer size needed
	status = GetIpForwardTable(pIpRouteTab, &dwActualSize, fOrder);

	if (status == NO_ERROR)
	{
		return status;
	}
	else if (status == ERROR_INSUFFICIENT_BUFFER)
	{
		// need more space
		pIpRouteTab = (PMIB_IPFORWARDTABLE)malloc(dwActualSize);

		statusRetry = GetIpForwardTable(pIpRouteTab, &dwActualSize, fOrder);
		return statusRetry;
	}
	else
	{
		return status;
	}
}

static DWORD MyGetIpAddrTable(PMIB_IPADDRTABLE& pIpAddrTable, BOOL fOrder)
{
	DWORD status = NO_ERROR;
	DWORD statusRetry = NO_ERROR;
	DWORD dwActualSize = 0;

	// query for buffer size needed
	status = GetIpAddrTable(pIpAddrTable, &dwActualSize, fOrder);

	if (status == NO_ERROR)
	{
		return status;
	}
	else if (status == ERROR_INSUFFICIENT_BUFFER)
	{
		// need more space
		pIpAddrTable = (PMIB_IPADDRTABLE)malloc(dwActualSize);

		statusRetry = GetIpAddrTable(pIpAddrTable, &dwActualSize, fOrder);
		return statusRetry;
	}
	else
	{
		return status;
	}
}

static bool InterfaceIdxToInterfaceIp(PMIB_IPADDRTABLE pIpAddrTable, DWORD dwIndex, std::string& out)
{
	struct in_addr inadTmp;
	char* szIpAddr2;

	if (pIpAddrTable == NULL)
	{
		return false;
	}

	for (DWORD dwIdx = 0; dwIdx < pIpAddrTable->dwNumEntries; dwIdx++)
	{
		if (dwIndex == pIpAddrTable->table[dwIdx].dwIndex)
		{
			inadTmp.s_addr = pIpAddrTable->table[dwIdx].dwAddr;
			szIpAddr2 = inet_ntoa(inadTmp);
			if (szIpAddr2)
			{
				out = std::string(szIpAddr2);
				return true;
			}
			else
			{
				return false;
			}
		}
	}

	return false;
}

static int get_default_gateway(std::string& default_gateway, std::string& default_Ip)
{
	PMIB_IPFORWARDTABLE pIpForwardtable = NULL;
	int ret = MyGetIpForwardTable(pIpForwardtable, FALSE);
	if (0 != ret)
	{
		return -1;
	}

	for (DWORD i = 0; i < pIpForwardtable->dwNumEntries; ++i)
	{
		if (0 == pIpForwardtable->table[i].dwForwardMask)
		{
			PMIB_IPADDRTABLE pPMIB_IPADDRTABLE = NULL;
			MyGetIpAddrTable(pPMIB_IPADDRTABLE, FALSE);
			InterfaceIdxToInterfaceIp(pPMIB_IPADDRTABLE, pIpForwardtable->table[i].dwForwardIfIndex, default_Ip);
			default_gateway = std::string(inet_ntoa(*(in_addr *)&pIpForwardtable->table[i].dwForwardNextHop));
			break;
		}
	}
	free(pIpForwardtable);
	return 0;
}

static int get_value_string(napi_env env, napi_value va, char** buf)
{
    napi_status status;
    napi_valuetype valuetype_;
    status = napi_typeof(env, va, &valuetype_);
    assert(status == napi_ok);

    if (valuetype_ != napi_string) {
        printf("param is not string\n");
        return -1;
    } 

    size_t res_szie;
    status = napi_get_value_string_utf8(env, va, NULL, 0, &res_szie);
    assert(status == napi_ok);
    if(res_szie <= 0)
    {
        printf("get value string size error.\n");
        return -1;
    }

    size_t out_size;
    *buf = (char*)malloc(res_szie + 1);
    memset(*buf, 0, res_szie + 1);
    status = napi_get_value_string_utf8(env, va, *buf, res_szie + 1, &out_size);
    if(status != napi_ok)
    {
        printf("napi_get_value_string_utf8 error.\n");
        free(*buf);
        return -1;
    }

    return 0;
}

static int get_value_int(napi_env env, napi_value va, int* out)
{
    napi_status status;
    napi_valuetype valuetype_;
    status = napi_typeof(env, va, &valuetype_);
    assert(status == napi_ok);

    if (valuetype_ != napi_number) {
        printf("param is not number\n");
        return -1;
    }

    status = napi_get_value_int32(env, va, out);
    assert(status == napi_ok);

    return 0; 
}

static int get_value_array_string(napi_env env, napi_value va, std::vector<std::string>& out)
{
    napi_status status;
    uint32_t length;
    status = napi_get_array_length(env, va, &length);
    assert(status == napi_ok);

    for(uint32_t i = 0; i < length; i++)
    {
        char* process_name = NULL;
        napi_value e;
        status = napi_get_element(env, va, i, &e); 
        assert(status == napi_ok);

        if(get_value_string(env, e, &process_name))
        {
            printf("get value arry string error.\n");
            continue;
        }
        assert(process_name != NULL);
        out.push_back(std::string(process_name));

		free(process_name);
    } 

    return 0; 
}

std::string get_gateway_ping_delay()
{
    std::string default_gateway, default_ip;
	if (get_default_gateway(default_gateway, default_ip) < 0 || default_gateway.empty())
	{
		printf("get default gateway error\n");
		return "";
	}

	char szResultBuffer[4096] = { 0 };
	DWORD dwResultBufferSize = 4096;
    std::string cmd = "ping -n 2 -w 1000 " + default_gateway;

	if(!PipeCmd(const_cast<char *>(cmd.c_str()), szResultBuffer, dwResultBufferSize))
	{
		printf("pipe cmd error\n");
		return "";
	}

	std::string res(szResultBuffer);
    std::string utf8_res;

    ASCII2UTF_8(res, utf8_res);

    return utf8_res;
}

std::string get_nslookup(std::string domain)
{
	char szResultBuffer[4096] = { 0 };
	DWORD dwResultBufferSize = 4096;
    std::string cmd = "nslookup " + domain;

	if(!PipeCmd(const_cast<char *>(cmd.c_str()), szResultBuffer, dwResultBufferSize))
	{
		printf("pipe cmd error\n");
		return "";
	}

	std::string res(szResultBuffer);
    std::string utf8_res;

    ASCII2UTF_8(res, utf8_res);

    return utf8_res;
}

static int get_default_network_type()
{
	std::string default_gateway, default_ip;
	if (get_default_gateway(default_gateway, default_ip) < 0 || default_ip.empty())
	{
		return -1;
	}

	int ret = -1;
	bool flag = false;

	PIP_ADAPTER_INFO ptmp = NULL;
	PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
	unsigned long stSize = sizeof(IP_ADAPTER_INFO);
	int nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
	if (ERROR_BUFFER_OVERFLOW == nRel)
	{
		delete pIpAdapterInfo;
		pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
		nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
	}
    ptmp = pIpAdapterInfo;
	if (ERROR_SUCCESS == nRel)
	{
		while (pIpAdapterInfo)
		{
			ret = (int)pIpAdapterInfo->Type;
			IP_ADDR_STRING *pIpAddrString = &(pIpAdapterInfo->IpAddressList);
			do
			{
				std::string ip = pIpAddrString->IpAddress.String;
				if (ip == default_ip)
				{
					flag = true;
					break;
				}
				pIpAddrString = pIpAddrString->Next;
			} while (pIpAddrString);

			pIpAdapterInfo = pIpAdapterInfo->Next;

			if (flag == true)
			{
				break;
			}
		}
	}

	if (ptmp)
	{
		delete ptmp;
	}

	return ret;
}

int get_game_delay(char* ip)
{
    int ret = -1;
    WSAData wsaData;
    if (0 != WSAStartup(MAKEWORD(2, 2), &wsaData))
    {
        printf("wsastartup failed:%d\n", GetLastError());
        return ret;
    }

    SOCKET tmp_socket;

    tmp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (INVALID_SOCKET == tmp_socket)
    {
        printf("socket error:%d\n", GetLastError());
        return ret;
    }

    sockaddr_in server_addr;
    memset((void *)&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(9666);
    server_addr.sin_addr.s_addr = inet_addr(ip);

    clock_t start, finish;
    double duration;

    const char *buf = "client";

    start = clock();
    if (SOCKET_ERROR == sendto(tmp_socket, buf, 6, 0, (sockaddr *)&server_addr, sizeof(server_addr)))
    {
        printf("sendto error:%d\n", GetLastError());
        goto end;
    }

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(tmp_socket, &fds);
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    ret = select(tmp_socket, &fds, NULL, NULL, &tv);
    if (ret < 0)
    {
        printf("select error:%d\n", GetLastError());
        goto end;
    }
    else if (ret == 0)
    {
        printf("select timeout\n");
        goto end;
    }

    sockaddr_in remote_addr;
    memset((void *)&remote_addr, 0, sizeof(remote_addr));
    char recv_buf[256] = {0};
    int remote_len = sizeof(remote_addr);

    if (SOCKET_ERROR == recvfrom(tmp_socket, recv_buf, 255, 0, (sockaddr *)&remote_addr, &remote_len))
    {
        printf("recvfrom error:%d\n", GetLastError());
        goto end;
    }

    finish = clock();
    duration = (double)(finish - start);

    ret = (int)duration;

    closesocket(tmp_socket);
    return ret;
end:
    ret = -1;
    closesocket(tmp_socket);
    return ret;
}

static napi_value nget_delay(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value res;
    char* ip = NULL;
    status = napi_create_int32(env, -1, &res);
    assert(status == napi_ok);

    size_t argc = 1;
    napi_value args[1];
    status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
    assert(status == napi_ok);

    if(argc < 1)
    {
        printf("get delay param error.\n");
        return res;
    }

    if(get_value_string(env, args[0], &ip))
    {
        printf("get delay param ip error.\n");
        return res;
    }

    int ret = get_game_delay(ip);
    free(ip);
    ip = NULL;

    status = napi_create_int32(env, ret, &res);
    assert(status == napi_ok);

    return res; 
}

static napi_value nget_default_network_type(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value res;
    status = napi_create_int32(env, -1, &res);
    assert(status == napi_ok);

    int ret = get_default_network_type();

    status = napi_create_int32(env, ret, &res);
    assert(status == napi_ok);

    return res;
}

static napi_value nget_gateway_ping_delay(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value res;
    status = napi_create_string_utf8(env, "", NAPI_AUTO_LENGTH, &res);
    assert(status == napi_ok);

    std::string ping_res_str = get_gateway_ping_delay();

    status = napi_create_string_utf8(env, ping_res_str.c_str(), NAPI_AUTO_LENGTH, &res);
    assert(status == napi_ok);

    return res;
}

static napi_value nget_nslookup(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value res;
    status = napi_create_string_utf8(env, "", NAPI_AUTO_LENGTH, &res);
    assert(status == napi_ok);
	char* domain = NULL;

    size_t argc = 1;
    napi_value args[1];
    status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
    assert(status == napi_ok);

	if(argc < 1)
    {
        printf("get nslookup param error.\n");
        return res;
    }

    if(get_value_string(env, args[0], &domain))
    {
        printf("get nslookup param domain error.\n");
        return res;
    }

    std::string res_str = get_nslookup(domain);

    status = napi_create_string_utf8(env, res_str.c_str(), NAPI_AUTO_LENGTH, &res);
    assert(status == napi_ok);

	if(domain)
	{
		free(domain);
		domain = NULL;
	}

	return res;
}

#define DECLARE_NAPI_METHOD(name, func)                                        \
  { name, 0, func, 0, 0, 0, napi_default, 0 }

static napi_value InitAll(napi_env env, napi_value exports)
{
    napi_status status;
    napi_property_descriptor desc = DECLARE_NAPI_METHOD("nget_delay", nget_delay);
    status = napi_define_properties(env, exports, 1, &desc);
    assert(status == napi_ok);

    desc = DECLARE_NAPI_METHOD("nget_default_network_type", nget_default_network_type);
    status = napi_define_properties(env, exports, 1, &desc);
    assert(status == napi_ok);

    desc = DECLARE_NAPI_METHOD("nget_gateway_ping_delay", nget_gateway_ping_delay);
    status = napi_define_properties(env, exports, 1, &desc);
    assert(status == napi_ok);

    desc = DECLARE_NAPI_METHOD("nget_nslookup", nget_nslookup);
    status = napi_define_properties(env, exports, 1, &desc);
    assert(status == napi_ok);

    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, InitAll)