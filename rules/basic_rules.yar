rule Massive_Malicious_Patterns
{
    meta:
        author = "ig.masio"
        description = "Extensive catch-all malicious pattern detection"
        date = "2025-05-23"
        severity = "critical"
        category = "generic malware detection"

    strings:
        // Windows API functions often used in malware
        $api_CreateProcessA = "CreateProcessA" ascii nocase
        $api_CreateProcessW = "CreateProcessW" ascii nocase
        $api_VirtualAlloc = "VirtualAlloc" ascii nocase
        $api_VirtualProtect = "VirtualProtect" ascii nocase
        $api_WriteProcessMemory = "WriteProcessMemory" ascii nocase
        $api_LoadLibraryA = "LoadLibraryA" ascii nocase
        $api_LoadLibraryW = "LoadLibraryW" ascii nocase
        $api_GetProcAddress = "GetProcAddress" ascii nocase
        $api_WinExec = "WinExec" ascii nocase
        $api_URLDownloadToFileA = "URLDownloadToFileA" ascii nocase
        $api_RegSetValueExA = "RegSetValueExA" ascii nocase
        $api_RegOpenKeyExA = "RegOpenKeyExA" ascii nocase
        $api_CreateFileA = "CreateFileA" ascii nocase
        $api_WriteFile = "WriteFile" ascii nocase
        $api_Sleep = "Sleep" ascii nocase
        $api_InternetOpenA = "InternetOpenA" ascii nocase
        $api_InternetConnectA = "InternetConnectA" ascii nocase
        $api_HttpOpenRequestA = "HttpOpenRequestA" ascii nocase
        $api_HttpSendRequestA = "HttpSendRequestA" ascii nocase
        $api_HttpReadData = "HttpReadData" ascii nocase
        $api_GetHostName = "gethostname" ascii nocase
        $api_CreateThread = "CreateThread" ascii nocase
        $api_TerminateProcess = "TerminateProcess" ascii nocase

        // Scripting and obfuscation strings
        $str_powershell = "powershell" ascii nocase
        $str_cmd = "cmd.exe /c" ascii nocase
        $str_base64_decode = "base64_decode" ascii nocase
        $str_eval = "eval(" ascii nocase
        $str_eval_regex = /eval\(.{1,100}\)/ nocase ascii
        $str_exec = "exec(" ascii nocase
        $str_system = "system(" ascii nocase
        $str_shell = "shell" ascii nocase
        $str_encoded_ps = "-EncodedCommand" ascii nocase
        $str_jscript = "<script" ascii nocase
        $str_javascript = "javascript:" ascii nocase
        $str_vbscript = "vbscript" ascii nocase
        $str_regsvr32 = "regsvr32" ascii nocase
        $str_microsoft_wmi = "wmic" ascii nocase
        $str_certutil = "certutil" ascii nocase

        // Persistence & autorun indicators
        $str_run_once = "RunOnce" ascii nocase
        $str_autorun_inf = "autorun.inf" ascii nocase
        $str_startup_folder = "\\startup\\" ascii nocase
        $str_task_scheduler = "schtasks" ascii nocase
        $str_reg_persistence = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase

        // Ransomware related strings
        $str_ransom_note = "Your files have been encrypted" ascii nocase
        $str_ransom_ext1 = ".locked" ascii nocase
        $str_ransom_ext2 = ".encrypted" ascii nocase
        $str_ransom_ext3 = ".crypt" ascii nocase
        $str_ransom_ext4 = ".wallet" ascii nocase
        $str_ransom_ext5 = ".vault" ascii nocase

        // Botnet, backdoor, trojan indicators
        $str_botnet = "botnet" ascii nocase
        $str_backdoor = "backdoor" ascii nocase
        $str_trojan = "trojan" ascii nocase
        $str_dropper = "dropper" ascii nocase
        $str_cnc = "C&C" ascii nocase
        $str_c2 = "C2" ascii nocase
        $str_command_and_control = "command and control" ascii nocase

        // Hex shellcode and exploit stubs
        $hex_shellcode1 = { FC E8 ?? ?? ?? ?? 60 89 E5 31 C0 64 8B 50 30 8B 52 0C }
        $hex_shellcode2 = { 55 8B EC 83 EC 14 53 56 57 8B F1 }
        $hex_xor_stub = { 31 C9 31 C0 80 36 ?? 46 80 3E ?? 74 05 80 3E ?? 75 EF }

        // Network Indicators (URLs, IPs)
        $regex_http_url = /https?:\/\/[^\s'"<>]{5,}/
        $regex_ip_address = /(\d{1,3}\.){3}\d{1,3}/

        // Obfuscation and encryption keywords
        $str_xor = "xor" ascii nocase
        $str_encode = "encode" ascii nocase
        $str_decode = "decode" ascii nocase
        $str_encrypt = "encrypt" ascii nocase
        $str_decrypt = "decrypt" ascii nocase
        $str_unpack = "unpack" ascii nocase
        $str_unpacker = "unpacker" ascii nocase

        // Common malware packers and crypters signatures
        $str_upx0 = "UPX0" ascii
        $str_upx1 = "UPX1" ascii
        $str_mpress = "MPRESS1" ascii nocase
        $str_aspack = "ASPACK" ascii nocase
        $str_fsg = "FSG!" ascii nocase
        $str_pez = "PEZ0" ascii nocase
        $str_pestudio = "PEStudio" ascii nocase

        // Common exploit kit strings
        $str_exploitkit = "ExploitKit" ascii nocase
        $str_angler = "Angler" ascii nocase
        $str_nuclear = "Nuclear" ascii nocase
        $str_neutrino = "Neutrino" ascii nocase
        $str_sundown = "Sundown" ascii nocase

        // Common cryptocurrency miner strings
        $str_miner = "cryptonight" ascii nocase
        $str_miner2 = "xmr-stak" ascii nocase
        $str_miner3 = "xmrig" ascii nocase

        // Known malicious file names
        $str_malware_dll = "malicious.dll" ascii nocase
        $str_loader_exe = "loader.exe" ascii nocase
        $str_dropper_exe = "dropper.exe" ascii nocase
        $str_ransomware_exe = "ransom.exe" ascii nocase

        // Miscellaneous malicious strings
        $str_debug = "debug" ascii nocase
        $str_hook = "hook" ascii nocase
        $str_keylogger = "keylogger" ascii nocase
        $str_inject = "inject" ascii nocase
        $str_bot = "bot" ascii nocase
        $str_shellcode = "shellcode" ascii nocase
        $str_cobaltstrike = "cobaltstrike" ascii nocase
        $str_mimikatz = "mimikatz" ascii nocase
        $str_rundll32 = "rundll32.exe" ascii nocase
        $str_psexec = "psexec" ascii nocase
        $str_msfconsole = "msfconsole" ascii nocase
        $str_meterpreter = "meterpreter" ascii nocase

    condition:
        filesize < 15MB and
        6 of (
            $api_CreateProcessA,
            $api_CreateProcessW,
            $api_VirtualAlloc,
            $api_VirtualProtect,
            $api_WriteProcessMemory,
            $api_LoadLibraryA,
            $api_LoadLibraryW,
            $api_GetProcAddress,
            $api_WinExec,
            $api_URLDownloadToFileA,
            $api_RegSetValueExA,
            $api_RegOpenKeyExA,
            $api_CreateFileA,
            $api_WriteFile,
            $api_Sleep,
            $api_InternetOpenA,
            $api_InternetConnectA,
            $api_HttpOpenRequestA,
            $api_HttpSendRequestA,
            $api_HttpReadData,
            $api_GetHostName,
            $api_CreateThread,
            $api_TerminateProcess,
            $str_powershell,
            $str_cmd,
            $str_base64_decode,
            $str_eval,
            $str_eval_regex,
            $str_exec,
            $str_system,
            $str_shell,
            $str_encoded_ps,
            $str_jscript,
            $str_javascript,
            $str_vbscript,
            $str_regsvr32,
            $str_microsoft_wmi,
            $str_certutil,
            $str_run_once,
            $str_autorun_inf,
            $str_startup_folder,
            $str_task_scheduler,
            $str_reg_persistence,
            $str_ransom_note,
            $str_ransom_ext1,
            $str_ransom_ext2,
            $str_ransom_ext3,
            $str_ransom_ext4,
            $str_ransom_ext5,
            $str_botnet,
            $str_backdoor,
            $str_trojan,
            $str_dropper,
            $str_cnc,
            $str_c2,
            $str_command_and_control,
            $hex_shellcode1,
            $hex_shellcode2,
            $hex_xor_stub,
            $regex_http_url,
            $regex_ip_address,
            $str_xor,
            $str_encode,
            $str_decode,
            $str_encrypt,
            $str_decrypt,
            $str_unpack,
            $str_unpacker,
            $str_upx0,
            $str_upx1,
            $str_mpress,
            $str_aspack,
            $str_fsg,
            $str_pez,
            $str_pestudio,
            $str_exploitkit,
            $str_angler,
            $str_nuclear,
            $str_neutrino,
            $str_sundown,
            $str_miner,
            $str_miner2,
            $str_miner3,
            $str_malware_dll,
            $str_loader_exe,
            $str_dropper_exe,
            $str_ransomware_exe,
            $str_debug,
            $str_hook,
            $str_keylogger,
            $str_inject,
            $str_bot,
            $str_shellcode,
            $str_cobaltstrike,
            $str_mimikatz,
            $str_rundll32,
            $str_psexec,
            $str_msfconsole,
            $str_meterpreter
        )
}

