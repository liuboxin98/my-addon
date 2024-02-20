#include <napi.h>
#include <windows.h>

Napi::Boolean SetProxy(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "String expected").ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }

    std::string proxyServer = info[0].As<Napi::String>();

    HKEY hKey;
    LONG lResult;

    lResult = RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", 0, KEY_WRITE, &hKey);
    if (lResult != ERROR_SUCCESS) {
        return Napi::Boolean::New(env, false);
    }

    DWORD enable = 1;
    lResult = RegSetValueEx(hKey, "ProxyEnable", 0, REG_DWORD, (const BYTE*)&enable, sizeof(enable));
    if (lResult != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return Napi::Boolean::New(env, false);
    }

    lResult = RegSetValueEx(hKey, "ProxyServer", 0, REG_SZ, (const BYTE*)proxyServer.c_str(), proxyServer.size() + 1);
    RegCloseKey(hKey);

    return Napi::Boolean::New(env, lResult == ERROR_SUCCESS);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("setProxy", Napi::Function::New(env, SetProxy));
    return exports;
}

NODE_API_MODULE(proxyaddon, Init)