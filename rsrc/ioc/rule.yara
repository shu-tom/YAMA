rule APT_CobaltStrike_Beacon_Indicator {
   meta:
      description = "Detects CobaltStrike beacons"
      author = "JPCERT"
      reference = "https://github.com/JPCERTCC/aa-tools/blob/master/cobaltstrikescan.py"
      date = "2018-11-09"
      id = "8508c7a0-0131-59b1-b537-a6d1c6cb2b35"
   strings:
      $v1 = { 73 70 72 6E 67 00 }
      $v2 = { 69 69 69 69 69 69 69 69 }
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule HKTL_CobaltStrike_Beacon_Strings {
   meta:
      author = "Elastic"
      description = "Identifies strings used in Cobalt Strike Beacon DLL"
      reference = "https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures"
      date = "2021-03-16"
      id = "af558aa2-a3dc-5a7a-bc74-42bb2246091c"
   strings:
      $s1 = "%02d/%02d/%02d %02d:%02d:%02d"
      $s2 = "Started service %s on %s"
      $s3 = "%s as %s\\%s: %d"
   condition:
      2 of them
}

rule HKTL_CobaltStrike_Beacon_XOR_Strings {
   meta:
      author = "Elastic"
      description = "Identifies XOR'd strings used in Cobalt Strike Beacon DLL"
      reference = "https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures"
      date = "2021-03-16"
      /* Used for beacon config decoding in THOR */
      xor_s1 = "%02d/%02d/%02d %02d:%02d:%02d"
      xor_s2 = "Started service %s on %s"
      xor_s3 = "%s as %s\\%s: %d"
      id = "359160a8-cf1c-58a8-bf7f-c09a8d661308"
   strings:
      $s1 = "%02d/%02d/%02d %02d:%02d:%02d" xor(0x01-0xff)
      $s2 = "Started service %s on %s" xor(0x01-0xff)
      $s3 = "%s as %s\\%s: %d" xor(0x01-0xff)

      $fp1 = "MalwareRemovalTool"
   condition:
      2 of ($s*) and not 1 of ($fp*)
}

rule HKTL_CobaltStrike_Beacon_4_2_Decrypt {
   meta:
      author = "Elastic"
      description = "Identifies deobfuscation routine used in Cobalt Strike Beacon DLL version 4.2"
      reference = "https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures"
      date = "2021-03-16"
      id = "63b71eef-0af5-5765-b957-ccdc9dde053b"
   strings:
      $a_x64 = {4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 75 05 45 85 DB 74 33 45 3B CB 73 E6 49 8B F9 4C 8B 03}
      $a_x86 = {8B 46 04 8B 08 8B 50 04 83 C0 08 89 55 08 89 45 0C 85 C9 75 04 85 D2 74 23 3B CA 73 E6 8B 06 8D 3C 08 33 D2}
   condition:
      any of them
}

rule HKTL_Win_CobaltStrike : Commodity {
   meta:
      author = "threatintel@volexity.com"
      date = "2021-05-25"
      description = "The CobaltStrike malware family."
      hash = "b041efb8ba2a88a3d172f480efa098d72eef13e42af6aa5fb838e6ccab500a7c"
      reference = "https://www.volexity.com/blog/2021/05/27/suspected-apt29-operation-launches-election-fraud-themed-phishing-campaigns/"
      id = "113ba304-261f-5c59-bc56-57515c239b6d"
   strings:
      $s1 = "%s (admin)" fullword
      $s2 = {48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F 4B 0D 0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 61 70 70 6C 69 63 61 74 69 6F 6E 2F 6F 63 74 65 74 2D 73 74 72 65 61 6D 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 25 64 0D 0A 0D 0A 00}
      $s3 = "%02d/%02d/%02d %02d:%02d:%02d" fullword
      $s4 = "%s as %s\\%s: %d" fullword
      $s5 = "%s&%s=%s" fullword
      $s6 = "rijndael" fullword
      $s7 = "(null)"
   condition:
      all of them
}

rule Windows_Trojan_CobaltStrike_c851687a {
    meta:
        author = "Elastic Security"
        id = "c851687a-aac6-43e7-a0b6-6aed36dcf12e"
        fingerprint = "70224e28a223d09f2211048936beb9e2d31c0312c97a80e22c85e445f1937c10"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies UAC Bypass module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "bypassuac.dll" ascii fullword
        $a2 = "bypassuac.x64.dll" ascii fullword
        $a3 = "\\\\.\\pipe\\bypassuac" ascii fullword
        $b1 = "\\System32\\sysprep\\sysprep.exe" wide fullword
        $b2 = "[-] Could not write temp DLL to '%S'" ascii fullword
        $b3 = "[*] Cleanup successful" ascii fullword
        $b4 = "\\System32\\cliconfg.exe" wide fullword
        $b5 = "\\System32\\eventvwr.exe" wide fullword
        $b6 = "[-] %S ran too long. Could not terminate the process." ascii fullword
        $b7 = "[*] Wrote hijack DLL to '%S'" ascii fullword
        $b8 = "\\System32\\sysprep\\" wide fullword
        $b9 = "[-] COM initialization failed." ascii fullword
        $b10 = "[-] Privileged file copy failed: %S" ascii fullword
        $b11 = "[-] Failed to start %S: %d" ascii fullword
        $b12 = "ReflectiveLoader"
        $b13 = "[-] '%S' exists in DLL hijack location." ascii fullword
        $b14 = "[-] Cleanup failed. Remove: %S" ascii fullword
        $b15 = "[+] %S ran and exited." ascii fullword
        $b16 = "[+] Privileged file copy success! %S" ascii fullword
    condition:
        2 of ($a*) or 10 of ($b*)
}

rule Windows_Trojan_CobaltStrike_0b58325e {
    meta:
        author = "Elastic Security"
        id = "0b58325e-2538-434d-9a2c-26e2c32db039"
        fingerprint = "8ecd5bdce925ae5d4f90cecb9bc8c3901b54ba1c899a33354bcf529eeb2485d4"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Keylogger module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "keylogger.dll" ascii fullword
        $a2 = "keylogger.x64.dll" ascii fullword
        $a3 = "\\\\.\\pipe\\keylogger" ascii fullword
        $a4 = "%cE=======%c" ascii fullword
        $a5 = "[unknown: %02X]" ascii fullword
        $b1 = "ReflectiveLoader"
        $b2 = "%c2%s%c" ascii fullword
        $b3 = "[numlock]" ascii fullword
        $b4 = "%cC%s" ascii fullword
        $b5 = "[backspace]" ascii fullword
        $b6 = "[scroll lock]" ascii fullword
        $b7 = "[control]" ascii fullword
        $b8 = "[left]" ascii fullword
        $b9 = "[page up]" ascii fullword
        $b10 = "[page down]" ascii fullword
        $b11 = "[prtscr]" ascii fullword
        $b12 = "ZRich9" ascii fullword
        $b13 = "[ctrl]" ascii fullword
        $b14 = "[home]" ascii fullword
        $b15 = "[pause]" ascii fullword
        $b16 = "[clear]" ascii fullword
    condition:
        1 of ($a*) and 14 of ($b*)
}

rule Windows_Trojan_CobaltStrike_2b8cddf8 {
    meta:
        author = "Elastic Security"
        id = "2b8cddf8-ca7a-4f85-be9d-6d8534d0482e"
        fingerprint = "0d7d28d79004ca61b0cfdcda29bd95e3333e6fc6e6646a3f6ba058aa01bee188"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies dll load module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\dllload.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\dllload.x86.o" ascii fullword
        $b1 = "__imp_BeaconErrorDD" ascii fullword
        $b2 = "__imp_BeaconErrorNA" ascii fullword
        $b3 = "__imp_BeaconErrorD" ascii fullword
        $b4 = "__imp_BeaconDataInt" ascii fullword
        $b5 = "__imp_KERNEL32$WriteProcessMemory" ascii fullword
        $b6 = "__imp_KERNEL32$OpenProcess" ascii fullword
        $b7 = "__imp_KERNEL32$CreateRemoteThread" ascii fullword
        $b8 = "__imp_KERNEL32$VirtualAllocEx" ascii fullword
        $c1 = "__imp__BeaconErrorDD" ascii fullword
        $c2 = "__imp__BeaconErrorNA" ascii fullword
        $c3 = "__imp__BeaconErrorD" ascii fullword
        $c4 = "__imp__BeaconDataInt" ascii fullword
        $c5 = "__imp__KERNEL32$WriteProcessMemory" ascii fullword
        $c6 = "__imp__KERNEL32$OpenProcess" ascii fullword
        $c7 = "__imp__KERNEL32$CreateRemoteThread" ascii fullword
        $c8 = "__imp__KERNEL32$VirtualAllocEx" ascii fullword
    condition:
        1 of ($a*) or 5 of ($b*) or 5 of ($c*)
}

rule Windows_Trojan_CobaltStrike_59b44767 {
    meta:
        author = "Elastic Security"
        id = "59b44767-c9a5-42c0-b177-7fe49afd7dfb"
        fingerprint = "882886a282ec78623a0d3096be3d324a8a1b8a23bcb88ea0548df2fae5e27aa5"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies getsystem module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\getsystem.x86.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\getsystem.x64.o" ascii fullword
        $b1 = "getsystem failed." ascii fullword
        $b2 = "_isSystemSID" ascii fullword
        $b3 = "__imp__NTDLL$NtQuerySystemInformation@16" ascii fullword
        $c1 = "getsystem failed." ascii fullword
        $c2 = "$pdata$isSystemSID" ascii fullword
        $c3 = "$unwind$isSystemSID" ascii fullword
        $c4 = "__imp_NTDLL$NtQuerySystemInformation" ascii fullword
    condition:
        1 of ($a*) or 3 of ($b*) or 3 of ($c*)
}

rule Windows_Trojan_CobaltStrike_7efd3c3f {
    meta:
        author = "Elastic Security"
        id = "7efd3c3f-1104-4b46-9d1e-dc2c62381b8c"
        fingerprint = "9e7c7c9a7436f5ee4c27fd46d6f06e7c88f4e4d1166759573cedc3ed666e1838"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Hashdump module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 70
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "hashdump.dll" ascii fullword
        $a2 = "hashdump.x64.dll" ascii fullword
        $a3 = "\\\\.\\pipe\\hashdump" ascii fullword
        $a4 = "ReflectiveLoader"
        $a5 = "Global\\SAM" ascii fullword
        $a6 = "Global\\FREE" ascii fullword
        $a7 = "[-] no results." ascii fullword
    condition:
        4 of ($a*)
}

rule Windows_Trojan_CobaltStrike_6e971281 {
    meta:
        author = "Elastic Security"
        id = "6e971281-3ee3-402f-8a72-745ec8fb91fb"
        fingerprint = "62d97cf73618a1b4d773d5494b2761714be53d5cda774f9a96eaa512c8d5da12"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Interfaces module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\interfaces.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\interfaces.x86.o" ascii fullword
        $b1 = "__imp_BeaconFormatAlloc" ascii fullword
        $b2 = "__imp_BeaconFormatPrintf" ascii fullword
        $b3 = "__imp_BeaconOutput" ascii fullword
        $b4 = "__imp_KERNEL32$LocalAlloc" ascii fullword
        $b5 = "__imp_KERNEL32$LocalFree" ascii fullword
        $b6 = "__imp_LoadLibraryA" ascii fullword
        $c1 = "__imp__BeaconFormatAlloc" ascii fullword
        $c2 = "__imp__BeaconFormatPrintf" ascii fullword
        $c3 = "__imp__BeaconOutput" ascii fullword
        $c4 = "__imp__KERNEL32$LocalAlloc" ascii fullword
        $c5 = "__imp__KERNEL32$LocalFree" ascii fullword
        $c6 = "__imp__LoadLibraryA" ascii fullword
    condition:
        1 of ($a*) or 4 of ($b*) or 4 of ($c*)
}

rule Windows_Trojan_CobaltStrike_09b79efa {
    meta:
        author = "Elastic Security"
        id = "09b79efa-55d7-481d-9ee0-74ac5f787cef"
        fingerprint = "04ef6555e8668c56c528dc62184331a6562f47652c73de732e5f7c82779f2fd8"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Invoke Assembly module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "invokeassembly.x64.dll" ascii fullword
        $a2 = "invokeassembly.dll" ascii fullword
        $b1 = "[-] Failed to get default AppDomain w/hr 0x%08lx" ascii fullword
        $b2 = "[-] Failed to load the assembly w/hr 0x%08lx" ascii fullword
        $b3 = "[-] Failed to create the runtime host" ascii fullword
        $b4 = "[-] Invoke_3 on EntryPoint failed." ascii fullword
        $b5 = "[-] CLR failed to start w/hr 0x%08lx" ascii fullword
        $b6 = "ReflectiveLoader"
        $b7 = ".NET runtime [ver %S] cannot be loaded" ascii fullword
        $b8 = "[-] No .NET runtime found. :(" ascii fullword
        $b9 = "[-] ICorRuntimeHost::GetDefaultDomain failed w/hr 0x%08lx" ascii fullword
        $c1 = { FF 57 0C 85 C0 78 40 8B 45 F8 8D 55 F4 8B 08 52 50 }
    condition:
        1 of ($a*) or 3 of ($b*) or 1 of ($c*)
}

rule Windows_Trojan_CobaltStrike_6e77233e {
    meta:
        author = "Elastic Security"
        id = "6e77233e-7fb4-4295-823d-f97786c5d9c4"
        fingerprint = "cef2949eae78b1c321c2ec4010749a5ac0551d680bd5eb85493fc88c5227d285"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Kerberos module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\kerberos.x64.o" ascii fullword
        $a2 = "$unwind$command_kerberos_ticket_use" ascii fullword
        $a3 = "$pdata$command_kerberos_ticket_use" ascii fullword
        $a4 = "command_kerberos_ticket_use" ascii fullword
        $a5 = "$pdata$command_kerberos_ticket_purge" ascii fullword
        $a6 = "command_kerberos_ticket_purge" ascii fullword
        $a7 = "$unwind$command_kerberos_ticket_purge" ascii fullword
        $a8 = "$unwind$kerberos_init" ascii fullword
        $a9 = "$unwind$KerberosTicketUse" ascii fullword
        $a10 = "KerberosTicketUse" ascii fullword
        $a11 = "$unwind$KerberosTicketPurge" ascii fullword
        $b1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\kerberos.x86.o" ascii fullword
        $b2 = "_command_kerberos_ticket_use" ascii fullword
        $b3 = "_command_kerberos_ticket_purge" ascii fullword
        $b4 = "_kerberos_init" ascii fullword
        $b5 = "_KerberosTicketUse" ascii fullword
        $b6 = "_KerberosTicketPurge" ascii fullword
        $b7 = "_LsaCallKerberosPackage" ascii fullword
    condition:
        5 of ($a*) or 3 of ($b*)
}

rule Windows_Trojan_CobaltStrike_de42495a {
    meta:
        author = "Elastic Security"
        id = "de42495a-0002-466e-98b9-19c9ebb9240e"
        fingerprint = "dab3c25809ec3af70df5a8a04a2efd4e8ecb13a4c87001ea699e7a1512973b82"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Mimikatz module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "\\\\.\\pipe\\mimikatz" ascii fullword
        $b1 = "ERROR kuhl_m_dpapi_chrome ; Input 'Login Data' file needed (/in:\"%%localappdata%%\\Google\\Chrome\\User Data\\Default\\Login Da" wide
        $b2 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x%08x)" wide fullword
        $b3 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kuhl_m_lsadump_getSamKey KO" wide fullword
        $b4 = "ERROR kuhl_m_lsadump_getComputerAndSyskey ; kull_m_registry_RegOpenKeyEx LSA KO" wide fullword
        $b5 = "ERROR kuhl_m_lsadump_lsa_getHandle ; OpenProcess (0x%08x)" wide fullword
        $b6 = "ERROR kuhl_m_lsadump_enumdomains_users ; SamLookupNamesInDomain: %08x" wide fullword
        $b7 = "mimikatz(powershell) # %s" wide fullword
        $b8 = "powershell_reflective_mimikatz" ascii fullword
        $b9 = "mimikatz_dpapi_cache.ndr" wide fullword
        $b10 = "mimikatz.log" wide fullword
        $b11 = "ERROR mimikatz_doLocal" wide
        $b12 = "mimikatz_x64.compressed" wide
    condition:
        1 of ($a*) and 7 of ($b*)
}

rule Windows_Trojan_CobaltStrike_72f68375 {
    meta:
        author = "Elastic Security"
        id = "72f68375-35ab-49cc-905d-15302389a236"
        fingerprint = "ecc28f414b2c347722b681589da8529c6f3af0491845453874f8fd87c2ae86d7"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Netdomain module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\net_domain.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\net_domain.x86.o" ascii fullword
        $b1 = "__imp_BeaconPrintf" ascii fullword
        $b2 = "__imp_NETAPI32$NetApiBufferFree" ascii fullword
        $b3 = "__imp_NETAPI32$DsGetDcNameA" ascii fullword
        $c1 = "__imp__BeaconPrintf" ascii fullword
        $c2 = "__imp__NETAPI32$NetApiBufferFree" ascii fullword
        $c3 = "__imp__NETAPI32$DsGetDcNameA" ascii fullword
    condition:
        1 of ($a*) or 2 of ($b*) or 2 of ($c*)
}

rule Windows_Trojan_CobaltStrike_15f680fb {
    meta:
        author = "Elastic Security"
        id = "15f680fb-a04f-472d-a182-0b9bee111351"
        fingerprint = "0ecb8e41c01bf97d6dea4cf6456b769c6dd2a037b37d754f38580bcf561e1d2c"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Netview module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "netview.x64.dll" ascii fullword
        $a2 = "netview.dll" ascii fullword
        $a3 = "\\\\.\\pipe\\netview" ascii fullword
        $b1 = "Sessions for \\\\%s:" ascii fullword
        $b2 = "Account information for %s on \\\\%s:" ascii fullword
        $b3 = "Users for \\\\%s:" ascii fullword
        $b4 = "Shares at \\\\%s:" ascii fullword
        $b5 = "ReflectiveLoader" ascii fullword
        $b6 = "Password changeable" ascii fullword
        $b7 = "User's Comment" wide fullword
        $b8 = "List of hosts for domain '%s':" ascii fullword
        $b9 = "Password changeable" ascii fullword
        $b10 = "Logged on users at \\\\%s:" ascii fullword
    condition:
        2 of ($a*) or 6 of ($b*)
}

rule Windows_Trojan_CobaltStrike_5b4383ec {
    meta:
        author = "Elastic Security"
        id = "5b4383ec-3c93-4e91-850e-d43cc3a86710"
        fingerprint = "283d3d2924e92b31f26ec4fc6b79c51bd652fb1377b6985b003f09f8c3dba66c"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Portscan module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "portscan.x64.dll" ascii fullword
        $a2 = "portscan.dll" ascii fullword
        $a3 = "\\\\.\\pipe\\portscan" ascii fullword
        $b1 = "(ICMP) Target '%s' is alive. [read %d bytes]" ascii fullword
        $b2 = "(ARP) Target '%s' is alive. " ascii fullword
        $b3 = "TARGETS!12345" ascii fullword
        $b4 = "ReflectiveLoader" ascii fullword
        $b5 = "%s:%d (platform: %d version: %d.%d name: %S domain: %S)" ascii fullword
        $b6 = "Scanner module is complete" ascii fullword
        $b7 = "pingpong" ascii fullword
        $b8 = "PORTS!12345" ascii fullword
        $b9 = "%s:%d (%s)" ascii fullword
        $b10 = "PREFERENCES!12345" ascii fullword
    condition:
        2 of ($a*) or 6 of ($b*)
}

rule Windows_Trojan_CobaltStrike_91e08059 {
    meta:
        author = "Elastic Security"
        id = "91e08059-46a8-47d0-91c9-e86874951a4a"
        fingerprint = "d8baacb58a3db00489827275ad6a2d007c018eaecbce469356b068d8a758634b"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Post Ex module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "postex.x64.dll" ascii fullword
        $a2 = "postex.dll" ascii fullword
        $a3 = "RunAsAdminCMSTP" ascii fullword
        $a4 = "KerberosTicketPurge" ascii fullword
        $b1 = "GetSystem" ascii fullword
        $b2 = "HelloWorld" ascii fullword
        $b3 = "KerberosTicketUse" ascii fullword
        $b4 = "SpawnAsAdmin" ascii fullword
        $b5 = "RunAsAdmin" ascii fullword
        $b6 = "NetDomain" ascii fullword
    condition:
        2 of ($a*) or 4 of ($b*)
}

rule Windows_Trojan_CobaltStrike_ee756db7 {
    meta:
        author = "Elastic Security"
        id = "ee756db7-e177-41f0-af99-c44646d334f7"
        fingerprint = "e589cc259644bc75d6c4db02a624c978e855201cf851c0d87f0d54685ce68f71"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Attempts to detect Cobalt Strike based on strings found in BEACON"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a2 = "%s.3%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a3 = "ppid %d is in a different desktop session (spawned jobs may fail). Use 'ppid' to reset." ascii fullword
        $a4 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" ascii fullword
        $a5 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/')" ascii fullword
        $a6 = "%s.2%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a7 = "could not run command (w/ token) because of its length of %d bytes!" ascii fullword
        $a8 = "%s.2%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a9 = "%s.2%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a10 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" ascii fullword
        $a11 = "Could not open service control manager on %s: %d" ascii fullword
        $a12 = "%d is an x64 process (can't inject x86 content)" ascii fullword
        $a13 = "%d is an x86 process (can't inject x64 content)" ascii fullword
        $a14 = "Failed to impersonate logged on user %d (%u)" ascii fullword
        $a15 = "could not create remote thread in %d: %d" ascii fullword
        $a16 = "%s.1%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a17 = "could not write to process memory: %d" ascii fullword
        $a18 = "Could not create service %s on %s: %d" ascii fullword
        $a19 = "Could not delete service %s on %s: %d" ascii fullword
        $a20 = "Could not open process token: %d (%u)" ascii fullword
        $a21 = "%s.1%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a22 = "Could not start service %s on %s: %d" ascii fullword
        $a23 = "Could not query service %s on %s: %d" ascii fullword
        $a24 = "Could not connect to pipe (%s): %d" ascii fullword
        $a25 = "%s.1%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a26 = "could not spawn %s (token): %d" ascii fullword
        $a27 = "could not open process %d: %d" ascii fullword
        $a28 = "could not run %s as %s\\%s: %d" ascii fullword
        $a29 = "%s.1%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a30 = "kerberos ticket use failed:" ascii fullword
        $a31 = "Started service %s on %s" ascii fullword
        $a32 = "%s.1%08x%08x%08x.%x%x.%s" ascii fullword
        $a33 = "I'm already in SMB mode" ascii fullword
        $a34 = "could not spawn %s: %d" ascii fullword
        $a35 = "could not open %s: %d" ascii fullword
        $a36 = "%s.1%08x%08x.%x%x.%s" ascii fullword
        $a37 = "Could not open '%s'" ascii fullword
        $a38 = "%s.1%08x.%x%x.%s" ascii fullword
        $a39 = "%s as %s\\%s: %d" ascii fullword
        $a40 = "%s.1%x.%x%x.%s" ascii fullword
        $a41 = "beacon.x64.dll" ascii fullword
        $a42 = "%s on %s: %d" ascii fullword
        $a43 = "www6.%x%x.%s" ascii fullword
        $a44 = "cdn.%x%x.%s" ascii fullword
        $a45 = "api.%x%x.%s" ascii fullword
        $a46 = "%s (admin)" ascii fullword
        $a47 = "beacon.dll" ascii fullword
        $a48 = "%s%s: %s" ascii fullword
        $a49 = "@%d.%s" ascii fullword
        $a50 = "%02d/%02d/%02d %02d:%02d:%02d" ascii fullword
        $a51 = "Content-Length: %d" ascii fullword
    condition:
        6 of ($a*)
}

rule Windows_Trojan_CobaltStrike_9c0d5561 {
    meta:
        author = "Elastic Security"
        id = "9c0d5561-5b09-44ae-8e8c-336dee606199"
        fingerprint = "01d53fcdb320f0cd468a2521c3e96dcb0b9aa00e7a7a9442069773c6b3759059"
        creation_date = "2021-03-23"
        last_modified = "2021-10-04"
        description = "Identifies PowerShell Runner module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "PowerShellRunner.dll" wide fullword
        $a2 = "powershell.x64.dll" ascii fullword
        $a3 = "powershell.dll" ascii fullword
        $a4 = "\\\\.\\pipe\\powershell" ascii fullword
        $b1 = "PowerShellRunner.PowerShellRunner" ascii fullword
        $b2 = "Failed to invoke GetOutput w/hr 0x%08lx" ascii fullword
        $b3 = "Failed to get default AppDomain w/hr 0x%08lx" ascii fullword
        $b4 = "ICLRMetaHost::GetRuntime (v4.0.30319) failed w/hr 0x%08lx" ascii fullword
        $b5 = "CustomPSHostUserInterface" ascii fullword
        $b6 = "RuntimeClrHost::GetCurrentAppDomainId failed w/hr 0x%08lx" ascii fullword
        $b7 = "ICorRuntimeHost::GetDefaultDomain failed w/hr 0x%08lx" ascii fullword
        $c1 = { 8B 08 50 FF 51 08 8B 7C 24 1C 8D 4C 24 10 51 C7 }
        $c2 = "z:\\devcenter\\aggressor\\external\\PowerShellRunner\\obj\\Release\\PowerShellRunner.pdb" ascii fullword
    condition:
        (1 of ($a*) and 4 of ($b*)) or 1 of ($c*)
}

rule Windows_Trojan_CobaltStrike_59ed9124 {
    meta:
        author = "Elastic Security"
        id = "59ed9124-bc20-4ea6-b0a7-63ee3359e69c"
        fingerprint = "7823e3b98e55a83bf94b0f07e4c116dbbda35adc09fa0b367f8a978a80c2efff"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies PsExec module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\psexec_command.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\psexec_command.x86.o" ascii fullword
        $b1 = "__imp_BeaconDataExtract" ascii fullword
        $b2 = "__imp_BeaconDataParse" ascii fullword
        $b3 = "__imp_BeaconDataParse" ascii fullword
        $b4 = "__imp_BeaconDataParse" ascii fullword
        $b5 = "__imp_ADVAPI32$StartServiceA" ascii fullword
        $b6 = "__imp_ADVAPI32$DeleteService" ascii fullword
        $b7 = "__imp_ADVAPI32$QueryServiceStatus" ascii fullword
        $b8 = "__imp_ADVAPI32$CloseServiceHandle" ascii fullword
        $c1 = "__imp__BeaconDataExtract" ascii fullword
        $c2 = "__imp__BeaconDataParse" ascii fullword
        $c3 = "__imp__BeaconDataParse" ascii fullword
        $c4 = "__imp__BeaconDataParse" ascii fullword
        $c5 = "__imp__ADVAPI32$StartServiceA" ascii fullword
        $c6 = "__imp__ADVAPI32$DeleteService" ascii fullword
        $c7 = "__imp__ADVAPI32$QueryServiceStatus" ascii fullword
        $c8 = "__imp__ADVAPI32$CloseServiceHandle" ascii fullword
    condition:
        1 of ($a*) or 5 of ($b*) or 5 of ($c*)
}

rule Windows_Trojan_CobaltStrike_8a791eb7 {
    meta:
        author = "Elastic Security"
        id = "8a791eb7-dc0c-4150-9e5b-2dc21af0c77d"
        fingerprint = "4967886ba5e663f2e2dc0631939308d7d8f2194a30590a230973e1b91bd625e1"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Registry module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\registry.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\registry.x86.o" ascii fullword
        $b1 = "__imp_ADVAPI32$RegOpenKeyExA" ascii fullword
        $b2 = "__imp_ADVAPI32$RegEnumKeyA" ascii fullword
        $b3 = "__imp_ADVAPI32$RegOpenCurrentUser" ascii fullword
        $b4 = "__imp_ADVAPI32$RegCloseKey" ascii fullword
        $b5 = "__imp_BeaconFormatAlloc" ascii fullword
        $b6 = "__imp_BeaconOutput" ascii fullword
        $b7 = "__imp_BeaconFormatFree" ascii fullword
        $b8 = "__imp_BeaconDataPtr" ascii fullword
        $c1 = "__imp__ADVAPI32$RegOpenKeyExA" ascii fullword
        $c2 = "__imp__ADVAPI32$RegEnumKeyA" ascii fullword
        $c3 = "__imp__ADVAPI32$RegOpenCurrentUser" ascii fullword
        $c4 = "__imp__ADVAPI32$RegCloseKey" ascii fullword
        $c5 = "__imp__BeaconFormatAlloc" ascii fullword
        $c6 = "__imp__BeaconOutput" ascii fullword
        $c7 = "__imp__BeaconFormatFree" ascii fullword
        $c8 = "__imp__BeaconDataPtr" ascii fullword
    condition:
        1 of ($a*) or 5 of ($b*) or 5 of ($c*)
}

rule Windows_Trojan_CobaltStrike_d00573a3 {
    meta:
        author = "Elastic Security"
        id = "d00573a3-db26-4e6b-aabf-7af4a818f383"
        fingerprint = "b6fa0792b99ea55f359858d225685647f54b55caabe53f58b413083b8ad60e79"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Screenshot module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "screenshot.x64.dll" ascii fullword
        $a2 = "screenshot.dll" ascii fullword
        $a3 = "\\\\.\\pipe\\screenshot" ascii fullword
        $b1 = "1I1n1Q3M5Q5U5Y5]5a5e5i5u5{5" ascii fullword
        $b2 = "GetDesktopWindow" ascii fullword
        $b3 = "CreateCompatibleBitmap" ascii fullword
        $b4 = "GDI32.dll" ascii fullword
        $b5 = "ReflectiveLoader"
        $b6 = "Adobe APP14 marker: version %d, flags 0x%04x 0x%04x, transform %d" ascii fullword
    condition:
        2 of ($a*) or 5 of ($b*)
}

rule Windows_Trojan_CobaltStrike_7bcd759c {
    meta:
        author = "Elastic Security"
        id = "7bcd759c-8e3d-4559-9381-1f4fe8b3dd95"
        fingerprint = "553085f1d1ca8dcd797360b287951845753eee7370610a1223c815a200a5ed20"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies SSH Agent module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "sshagent.x64.dll" ascii fullword
        $a2 = "sshagent.dll" ascii fullword
        $b1 = "\\\\.\\pipe\\sshagent" ascii fullword
        $b2 = "\\\\.\\pipe\\PIPEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii fullword
    condition:
        1 of ($a*) and 1 of ($b*)
}

rule Windows_Trojan_CobaltStrike_a56b820f {
    meta:
        author = "Elastic Security"
        id = "a56b820f-0a20-4054-9c2d-008862646a78"
        fingerprint = "5418e695bcb1c37e72a7ff24a39219dc12b3fe06c29cedefd500c5e82c362b6d"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Timestomp module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\timestomp.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\timestomp.x86.o" ascii fullword
        $b1 = "__imp_KERNEL32$GetFileTime" ascii fullword
        $b2 = "__imp_KERNEL32$SetFileTime" ascii fullword
        $b3 = "__imp_KERNEL32$CloseHandle" ascii fullword
        $b4 = "__imp_KERNEL32$CreateFileA" ascii fullword
        $b5 = "__imp_BeaconDataExtract" ascii fullword
        $b6 = "__imp_BeaconPrintf" ascii fullword
        $b7 = "__imp_BeaconDataParse" ascii fullword
        $b8 = "__imp_BeaconDataExtract" ascii fullword
        $c1 = "__imp__KERNEL32$GetFileTime" ascii fullword
        $c2 = "__imp__KERNEL32$SetFileTime" ascii fullword
        $c3 = "__imp__KERNEL32$CloseHandle" ascii fullword
        $c4 = "__imp__KERNEL32$CreateFileA" ascii fullword
        $c5 = "__imp__BeaconDataExtract" ascii fullword
        $c6 = "__imp__BeaconPrintf" ascii fullword
        $c7 = "__imp__BeaconDataParse" ascii fullword
        $c8 = "__imp__BeaconDataExtract" ascii fullword
    condition:
        1 of ($a*) or 5 of ($b*) or 5 of ($c*)
}

rule Windows_Trojan_CobaltStrike_92f05172 {
    meta:
        author = "Elastic Security"
        id = "92f05172-f15c-4077-a958-b8490378bf08"
        fingerprint = "09b1f7087d45fb4247a33ae3112910bf5426ed750e1e8fe7ba24a9047b76cc82"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies UAC cmstp module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uaccmstp.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uaccmstp.x86.o" ascii fullword
        $b1 = "elevate_cmstp" ascii fullword
        $b2 = "$pdata$elevate_cmstp" ascii fullword
        $b3 = "$unwind$elevate_cmstp" ascii fullword
        $c1 = "_elevate_cmstp" ascii fullword
        $c2 = "__imp__OLE32$CoGetObject@16" ascii fullword
        $c3 = "__imp__KERNEL32$GetModuleFileNameA@12" ascii fullword
        $c4 = "__imp__KERNEL32$GetSystemWindowsDirectoryA@8" ascii fullword
        $c5 = "OLDNAMES"
        $c6 = "__imp__BeaconDataParse" ascii fullword
        $c7 = "_willAutoElevate" ascii fullword
    condition:
        1 of ($a*) or 3 of ($b*) or 4 of ($c*)
}

rule Windows_Trojan_CobaltStrike_417239b5 {
    meta:
        author = "Elastic Security"
        id = "417239b5-cf2d-4c85-a022-7a8459c26793"
        fingerprint = "292afee829e838f9623547f94d0561e8a9115ce7f4c40ae96c6493f3cc5ffa9b"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies UAC token module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken.x86.o" ascii fullword
        $a3 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken2.x64.o" ascii fullword
        $a4 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken2.x86.o" ascii fullword
        $b1 = "$pdata$is_admin_already" ascii fullword
        $b2 = "$unwind$is_admin" ascii fullword
        $b3 = "$pdata$is_admin" ascii fullword
        $b4 = "$unwind$is_admin_already" ascii fullword
        $b5 = "$pdata$RunAsAdmin" ascii fullword
        $b6 = "$unwind$RunAsAdmin" ascii fullword
        $b7 = "is_admin_already" ascii fullword
        $b8 = "is_admin" ascii fullword
        $b9 = "process_walk" ascii fullword
        $b10 = "get_current_sess" ascii fullword
        $b11 = "elevate_try" ascii fullword
        $b12 = "RunAsAdmin" ascii fullword
        $b13 = "is_ctfmon" ascii fullword
        $c1 = "_is_admin_already" ascii fullword
        $c2 = "_is_admin" ascii fullword
        $c3 = "_process_walk" ascii fullword
        $c4 = "_get_current_sess" ascii fullword
        $c5 = "_elevate_try" ascii fullword
        $c6 = "_RunAsAdmin" ascii fullword
        $c7 = "_is_ctfmon" ascii fullword
        $c8 = "_reg_query_dword" ascii fullword
        $c9 = ".drectve" ascii fullword
        $c10 = "_is_candidate" ascii fullword
        $c11 = "_SpawnAsAdmin" ascii fullword
        $c12 = "_SpawnAsAdminX64" ascii fullword
    condition:
        1 of ($a*) or 9 of ($b*) or 7 of ($c*)
}

rule Windows_Trojan_CobaltStrike_29374056 {
    meta:
        author = "Elastic Security"
        id = "29374056-03ce-484b-8b2d-fbf75be86e27"
        fingerprint = "4cd7552a499687ac0279fb2e25722f979fc5a22afd1ea4abba14a2ef2002dd0f"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Cobalt Strike MZ Reflective Loader."
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 4D 5A 41 52 55 48 89 E5 48 81 EC 20 00 00 00 48 8D 1D ?? FF FF FF 48 81 C3 ?? ?? 00 00 FF D3 }
        $a2 = { 4D 5A E8 00 00 00 00 5B 89 DF 52 45 55 89 E5 }
    condition:
        1 of ($a*)
}

rule Windows_Trojan_CobaltStrike_949f10e3 {
    meta:
        author = "Elastic Security"
        id = "949f10e3-68c9-4600-a620-ed3119e09257"
        fingerprint = "34e04901126a91c866ebf61a61ccbc3ce0477d9614479c42d8ce97a98f2ce2a7"
        creation_date = "2021-03-25"
        last_modified = "2021-08-23"
        description = "Identifies the API address lookup function used by Cobalt Strike along with XOR implementation by Cobalt Strike."
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF 31 C0 AC 3C 61 }
        $a2 = { 8B 07 01 C3 85 C0 75 E5 58 C3 E8 [2] FF FF 31 39 32 2E 31 36 38 2E ?? 2E }
    condition:
        all of them
}

rule Windows_Trojan_CobaltStrike_8751cdf9 {
    meta:
        author = "Elastic Security"
        id = "8751cdf9-4038-42ba-a6eb-f8ac579a4fbb"
        fingerprint = "0988386ef4ba54dd90b0cf6d6a600b38db434e00e569d69d081919cdd3ea4d3f"
        creation_date = "2021-03-25"
        last_modified = "2021-08-23"
        description = "Identifies Cobalt Strike wininet reverse shellcode along with XOR implementation by Cobalt Strike."
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 99
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 68 6E 65 74 00 68 77 69 6E 69 54 68 4C 77 26 07 }
        $a2 = { 8B 07 01 C3 85 C0 75 E5 58 C3 E8 [2] FF FF 31 39 32 2E 31 36 38 2E ?? 2E }
    condition:
        all of them
}

rule Windows_Trojan_CobaltStrike_663fc95d {
    meta:
        author = "Elastic Security"
        id = "663fc95d-2472-4d52-ad75-c5d86cfc885f"
        fingerprint = "d0f781d7e485a7ecfbbfd068601e72430d57ef80fc92a993033deb1ddcee5c48"
        creation_date = "2021-04-01"
        last_modified = "2021-12-17"
        description = "Identifies CobaltStrike via unidentified function code"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 48 89 5C 24 08 57 48 83 EC 20 48 8B 59 10 48 8B F9 48 8B 49 08 FF 17 33 D2 41 B8 00 80 00 00 }
    condition:
        all of them
}

rule Windows_Trojan_CobaltStrike_b54b94ac {
    meta:
        author = "Elastic Security"
        id = "b54b94ac-6ef8-4ee9-a8a6-f7324c1974ca"
        fingerprint = "2344dd7820656f18cfb774a89d89f5ab65d46cc7761c1f16b7e768df66aa41c8"
        creation_date = "2021-10-21"
        last_modified = "2022-01-13"
        description = "Rule for beacon sleep obfuscation routine"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a_x64 = { 4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 75 05 45 85 DB 74 33 45 3B CB 73 E6 49 8B F9 4C 8B 03 }
        $a_x64_smbtcp = { 4C 8B 07 B8 4F EC C4 4E 41 F7 E1 41 8B C1 C1 EA 02 41 FF C1 6B D2 0D 2B C2 8A 4C 38 10 42 30 0C 06 48 }
        $a_x86 = { 8B 46 04 8B 08 8B 50 04 83 C0 08 89 55 08 89 45 0C 85 C9 75 04 85 D2 74 23 3B CA 73 E6 8B 06 8D 3C 08 33 D2 }
        $a_x86_2 = { 8B 06 8D 3C 08 33 D2 6A 0D 8B C1 5B F7 F3 8A 44 32 08 30 07 41 3B 4D 08 72 E6 8B 45 FC EB C7 }
        $a_x86_smbtcp = { 8B 07 8D 34 08 33 D2 6A 0D 8B C1 5B F7 F3 8A 44 3A 08 30 06 41 3B 4D 08 72 E6 8B 45 FC EB }
    condition:
        any of them
}

rule Windows_Trojan_CobaltStrike_f0b627fc {
    meta:
        author = "Elastic Security"
        id = "f0b627fc-97cd-42cb-9eae-1efb0672762d"
        fingerprint = "fbc94bedd50b5b943553dd438a183a1e763c098a385ac3a4fc9ff24ee30f91e1"
        creation_date = "2021-10-21"
        last_modified = "2022-01-13"
        description = "Rule for beacon reflective loader"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "b362951abd9d96d5ec15d281682fa1c8fe8f8e4e2f264ca86f6b061af607f79b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $beacon_loader_x64 = { 25 FF FF FF 00 3D 41 41 41 00 75 [5-10] 25 FF FF FF 00 3D 42 42 42 00 75 }
        $beacon_loader_x86 = { 25 FF FF FF 00 3D 41 41 41 00 75 [4-8] 81 E1 FF FF FF 00 81 F9 42 42 42 00 75 }
        $beacon_loader_x86_2 = { 81 E1 FF FF FF 00 81 F9 41 41 41 00 75 [4-8] 81 E2 FF FF FF 00 81 FA 42 42 42 00 75 }
        $generic_loader_x64 = { 89 44 24 20 48 8B 44 24 40 0F BE 00 8B 4C 24 20 03 C8 8B C1 89 44 24 20 48 8B 44 24 40 48 FF C0 }
        $generic_loader_x86 = { 83 C4 04 89 45 FC 8B 4D 08 0F BE 11 03 55 FC 89 55 FC 8B 45 08 83 C0 01 89 45 08 8B 4D 08 0F BE }
    condition:
        any of them
}

rule Windows_Trojan_CobaltStrike_dcdcdd8c {
    meta:
        author = "Elastic Security"
        id = "dcdcdd8c-7395-4453-a74a-60ab8e251a5a"
        fingerprint = "8aed1ae470d06a7aac37896df22b2f915c36845099839a85009212d9051f71e9"
        creation_date = "2021-10-21"
        last_modified = "2022-01-13"
        description = "Rule for beacon sleep PDB"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask.x86.o" ascii fullword
        $a3 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask_smb.x64.o" ascii fullword
        $a4 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask_smb.x86.o" ascii fullword
        $a5 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask_tcp.x64.o" ascii fullword
        $a6 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask_tcp.x86.o" ascii fullword
    condition:
        any of them
}

rule Windows_Trojan_CobaltStrike_a3fb2616 {
    meta:
        author = "Elastic Security"
        id = "a3fb2616-b03d-4399-9342-0fc684fb472e"
        fingerprint = "c15cf6aa7719dac6ed21c10117f28eb4ec56335f80a811b11ab2901ad36f8cf0"
        creation_date = "2021-10-21"
        last_modified = "2022-01-13"
        description = "Rule for browser pivot "
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "browserpivot.dll" ascii fullword
        $a2 = "browserpivot.x64.dll" ascii fullword
        $b1 = "$$$THREAD.C$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" ascii fullword
        $b2 = "COBALTSTRIKE" ascii fullword
    condition:
        1 of ($a*) and 2 of ($b*)
}

rule Windows_Trojan_CobaltStrike_8ee55ee5 {
    meta:
        author = "Elastic Security"
        id = "8ee55ee5-67f1-4f94-ab93-62bb5cfbeee9"
        fingerprint = "7e7ed4f00d0914ce0b9f77b6362742a9c8b93a16a6b2a62b70f0f7e15ba3a72b"
        creation_date = "2021-10-21"
        last_modified = "2022-01-13"
        description = "Rule for wmi exec module"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\wmiexec.x64.o" ascii fullword
        $a2 = "z:\\devcenter\\aggressor\\external\\pxlib\\bin\\wmiexec.x86.o" ascii fullword
    condition:
        1 of ($a*)
}

rule Windows_Trojan_CobaltStrike_8d5963a2 {
    meta:
        author = "Elastic Security"
        id = "8d5963a2-54a9-4705-9f34-0d5f8e6345a2"
        fingerprint = "228cd65380cf4b04f9fd78e8c30c3352f649ce726202e2dac9f1a96211925e1c"
        creation_date = "2022-08-10"
        last_modified = "2022-09-29"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "9fe43996a5c4e99aff6e2a1be743fedec35e96d1e6670579beb4f7e7ad591af9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 D8 48 81 EC 28 01 00 00 45 33 F6 48 8B D9 48 }
    condition:
        all of them
}

rule Windows_Trojan_CobaltStrike_1787eef5 {
    meta:
        author = "Elastic Security"
        id = "1787eef5-ff00-4e19-bd22-c5dfc9488c7b"
        fingerprint = "292f15bdc978fc29670126f1bdc72ade1e7faaf1948653f70b6789a82dbee67f"
        creation_date = "2022-08-29"
        last_modified = "2022-09-29"
        description = "CS shellcode variants"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 89 E5 83 EC ?? A1 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? 89 44 24 ?? E8 ?? ?? ?? ?? 31 C0 C9 C3 55 }
        $a2 = { 55 89 E5 83 EC ?? A1 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 31 C0 C9 C3 55 89 E5 83 EC ?? 83 7D ?? ?? }
        $a3 = { 55 89 E5 8B 45 ?? 5D FF E0 55 8B 15 ?? ?? ?? ?? 89 E5 8B 45 ?? 85 D2 7E ?? 83 3D ?? ?? ?? ?? ?? }
        $a4 = { 55 89 E5 8B 45 ?? 5D FF E0 55 89 E5 83 EC ?? 8B 15 ?? ?? ?? ?? 8B 45 ?? 85 D2 7E ?? 83 3D ?? ?? ?? ?? ?? }
        $a5 = { 4D 5A 41 52 55 48 89 E5 48 81 EC ?? ?? ?? ?? 48 8D 1D ?? ?? ?? ?? 48 89 DF 48 81 C3 ?? ?? ?? ?? }
    condition:
        1 of ($a*)
}

rule Windows_Trojan_CobaltStrike_4106070a {
    meta:
        author = "Elastic Security"
        id = "4106070a-24e2-421b-ab83-67b817a9f019"
        fingerprint = "c12b919064a9cd2a603c134c5f73f6d05ffbf4cbed1e5b5246687378102e4338"
        creation_date = "2023-05-09"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "98789a11c06c1dfff7e02f66146afca597233c17e0d4900d6a683a150f16b3a4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 48 8B 44 24 48 0F B7 00 66 C1 E8 0C 66 83 E0 0F 0F B7 C0 83 }
        $a2 = { 44 24 48 0F B7 00 66 C1 E8 0C 66 83 E0 0F 0F B7 C0 83 F8 0A }
    condition:
        all of them
}

rule Windows_Trojan_CobaltStrike_3dc22d14 {
    meta:
        author = "Elastic Security"
        id = "3dc22d14-a2f4-49cd-a3a8-3f071eddf028"
        fingerprint = "0e029fac50ffe8ea3fc5bc22290af69e672895eaa8a1b9f3e9953094c133392c"
        creation_date = "2023-05-09"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "7898194ae0244611117ec948eb0b0a5acbc15cd1419b1ecc553404e63bc519f9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "%02d/%02d/%02d %02d:%02d:%02d" fullword
        $a2 = "%s as %s\\%s: %d" fullword
    condition:
        all of them
}

rule Windows_Trojan_CobaltStrike_7f8da98a {
    meta:
        author = "Elastic Security"
        id = "7f8da98a-3336-482b-91da-82c7cef34c62"
        fingerprint = "c375492960a6277bf665bea86302cec774c0d79506e5cb2e456ce59f5e68aa2e"
        creation_date = "2023-05-09"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "e3bc2bec4a55ad6cfdf49e5dbd4657fc704af1758ca1d6e31b83dcfb8bf0f89d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 4D 53 53 45 2D 25 64 2D 73 65 72 76 65 72 }
    condition:
        all of them
}

rule CobaltStrike_Resources_Artifact32_and_Resources_Dropper_v1_49_to_v3_14
{
	meta:
		description = "Cobalt Strike's resources/artifact32{.exe,.dll,big.exe,big.dll} and resources/dropper.exe signature for versions 1.49 to 3.14"
		hash =  "40fc605a8b95bbd79a3bd7d9af73fbeebe3fada577c99e7a111f6168f6a0d37a"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
  // Decoder function for the embedded payload
	$payloadDecoder = { 8B [2] 89 ?? 03 [2] 8B [2] 03 [2] 0F B6 18 8B [2] 89 ?? C1 ?? 1F C1 ?? 1E 01 ?? 83 ?? 03 29 ?? 03 [2] 0F B6 00 31 ?? 88 ?? 8B [2] 89 ?? 03 [2] 8B [2] 03 [2] 0F B6 12 }

	condition:
		any of them
}

rule CobaltStrike_Resources_Artifact32_v3_1_and_v3_2
{
	meta:
		description = "Cobalt Strike's resources/artifact32{.dll,.exe,svc.exe,big.exe,big.dll,bigsvc.exe} and resources/artifact32uac(alt).dll signature for versions 3.1 and 3.2"
		hash =  "4f14bcd7803a8e22e81e74d6061d0df9e8bac7f96f1213d062a29a8523ae4624"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		89 ??           mov     eax, ecx
		B? 04 00 00 00  mov     edi, 4
		99              cdq
		F7 FF           idiv    edi
		8B [2]          mov     edi, [ebp+arg_8]
		8A [2]          mov     al, [edi+edx]
		30 ??           xor     [ebx], al
		8A ??           mov     al, [ebx]
		4?              inc     ebx
		88 [2]          mov     [esi+ecx], al
	*/

	$decoderFunc = { 89 ?? B? 04 00 00 00 99 F7 FF 8B [2] 8A [2] 30 ?? 8A ?? 4? 88 }
	condition:
		all of them
}

rule CobaltStrike_Resources_Artifact32_v3_14_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/artifact32{.dll,.exe,big.exe,big.dll,bigsvc.exe} signature for versions 3.14 to 4.x and resources/artifact32svc.exe for 3.14 to 4.x and resources/artifact32uac.dll for v3.14 and v4.0"
		hash =  "888bae8d89c03c1d529b04f9e4a051140ce3d7b39bc9ea021ad9fc7c9f467719"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		C7 [3] 5C 00 00 00  mov     dword ptr [esp+28h], 5Ch ; '\'
		C7 [3] 65 00 00 00  mov     dword ptr [esp+24h], 65h ; 'e'
		C7 [3] 70 00 00 00  mov     dword ptr [esp+20h], 70h ; 'p'
		C7 [3] 69 00 00 00  mov     dword ptr [esp+1Ch], 69h ; 'i'
		C7 [3] 70 00 00 00  mov     dword ptr [esp+18h], 70h ; 'p'
		F7 F1               div     ecx
		C7 [3] 5C 00 00 00  mov     dword ptr [esp+14h], 5Ch ; '\'
		C7 [3] 2E 00 00 00  mov     dword ptr [esp+10h], 2Eh ; '.'
		C7 [3] 5C 00 00 00  mov     dword ptr [esp+0Ch], 5Ch ; '\'
	*/

	$pushFmtStr = {	C7 [3] 5C 00 00 00 C7 [3] 65 00 00 00 C7 [3] 70 00 00 00 C7 [3] 69 00 00 00 C7 [3] 70 00 00 00 F7 F1 C7 [3] 5C 00 00 00  C7 [3] 2E 00 00 00 C7 [3] 5C 00 00 00 }
  $fmtStr = "%c%c%c%c%c%c%c%c%cMSSE-%d-server"
		
	condition:
		all of them
}

rule CobaltStrike_Resources_Artifact32svc_Exe_v1_49_to_v3_14
{
	meta:
		description = "Cobalt Strike's resources/artifact32svc(big).exe and resources/artifact32uac(alt).exe signature for versions v1.49 to v3.14"
		hash =  "323ddf9623368b550def9e8980fde0557b6fe2dcd945fda97aa3b31c6c36d682"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		8B [2]   mov     eax, [ebp+var_C]
		89 ??    mov     ecx, eax
		03 [2]   add     ecx, [ebp+lpBuffer]
		8B [2]   mov     eax, [ebp+var_C]
		03 [2]   add     eax, [ebp+lpBuffer]
		0F B6 18 movzx   ebx, byte ptr [eax]
		8B [2]   mov     eax, [ebp+var_C]
		89 ??    mov     edx, eax
		C1 [2]   sar     edx, 1Fh
		C1 [2]   shr     edx, 1Eh
		01 ??    add     eax, edx
		83 [2]   and     eax, 3
		29 ??    sub     eax, edx
		03 [2]   add     eax, [ebp+arg_8]
		0F B6 00 movzx   eax, byte ptr [eax]
		31 ??    xor     eax, ebx
		88 ??    mov     [ecx], al
	*/

	$decoderFunc = { 8B [2] 89 ?? 03 [2] 8B [2] 03 [5] 8B [2] 89 ?? C1 [2] C1 [2] 01 ?? 83 [2] 29 ?? 03 [5] 31 ?? 88 }
	
	condition:
		any of them
}

rule CobaltStrike_Resources_Artifact32svc_Exe_v3_1_v3_2_v3_14_and_v4_x
{
	meta:
		description = "Cobalt Strike's resources/artifact32svc(big).exe signature for versions 3.1 and 3.2 (with overlap with v3.14 through v4.x)"
		hash =  "871390255156ce35221478c7837c52d926dfd581173818620b738b4b029e6fd9"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		89 ??           mov     eax, ecx
		B? 04 00 00 00  mov     edi, 4
		99              cdq
		F7 FF           idiv    edi
		8B [2]          mov     edi, [ebp+var_20]
		8A [2]          mov     al, [edi+edx]
		30 [2]          xor     [ebx+ecx], al
	*/

	$decoderFunc  = { 89 ?? B? 04 00 00 00 99 F7 FF 8B [2] 8A [2] 30 }

	condition:
		$decoderFunc
}

rule CobaltStrike_Resources_Artifact64_v1_49_v2_x_v3_0_v3_3_thru_v3_14
{
	meta:
		description = "Cobalt Strike's resources/artifact64{.dll,.exe,big.exe,big.dll,bigsvc.exe,big.x64.dll} and resources/rtifactuac(alt)64.dll signature for versions v1.49, v2.x, v3.0, and v3.3 through v3.14"
		hash =  "9ec57d306764517b5956b49d34a3a87d4a6b26a2bb3d0fdb993d055e0cc9920d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		8B [2]      mov     eax, [rbp+var_4]
		48 98       cdqe
		48 89 C1    mov     rcx, rax
		48 03 4D 10 add     rcx, [rbp+arg_0]
		8B 45 FC    mov     eax, [rbp+var_4]
		48 98       cdqe
		48 03 45 10 add     rax, [rbp+arg_0]
		44 0F B6 00 movzx   r8d, byte ptr [rax]
		8B 45 FC    mov     eax, [rbp+var_4]
		89 C2       mov     edx, eax
		C1 FA 1F    sar     edx, 1Fh
		C1 EA 1E    shr     edx, 1Eh
		01 D0       add     eax, edx
		83 E0 03    and     eax, 3
		29 D0       sub     eax, edx
		48 98       cdqe
		48 03 45 20 add     rax, [rbp+arg_10]
		0F B6 00    movzx   eax, byte ptr [rax]
		44 31 C0    xor     eax, r8d
		88 01       mov     [rcx], al
	*/

	$a = { 8B [2] 48 98 48 [2] 48 [3] 8B [2] 48 98 48 [3] 44 [3] 8B [2] 89 ?? C1 ?? 1F C1 ?? 1E 01 ?? 83 ?? 03 29 ?? 48 98 48 [3] 0F B6 00 44 [2] 88 }
		
	condition:
		$a
}

rule CobaltStrike_Resources_Artifact64_v3_1_v3_2_v3_14_and_v4_0
{
	meta:
		description = "Cobalt Strike's resources/artifact64{svcbig.exe,.dll,big.dll,svc.exe} and resources/artifactuac(big)64.dll signature for versions 3.14 to 4.x and resources/artifact32svc.exe for 3.14 to 4.x"
		hash =  "2e7a39bd6ac270f8f548855b97c4cef2c2ce7f54c54dd4d1aa0efabeecf3ba90"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		31 C0                xor     eax, eax
		EB 0F                jmp     short loc_6BAC16B5
		41 83 E1 03          and     r9d, 3
		47 8A 0C 08          mov     r9b, [r8+r9]
		44 30 0C 01          xor     [rcx+rax], r9b
		48 FF C0             inc     rax
		39 D0                cmp     eax, edx
		41 89 C1             mov     r9d, eax
		7C EA                jl      short loc_6BAC16A6
		4C 8D 05 53 29 00 00 lea     r8, aRundll32Exe; "rundll32.exe"
		E9 D1 FE FF FF       jmp     sub_6BAC1599
	*/

	$decoderFunction = { 31 ?? EB 0F 41 [2] 03 47 [3] 44 [3] 48 [2] 39 ?? 41 [2] 7C EA 4C [6] E9 }

	condition:
		$decoderFunction
}

rule CobaltStrike_Resources_Artifact64_v3_14_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/artifact64{.exe,.dll,svc.exe,svcbig.exe,big.exe,big.dll,.x64.dll,big.x64.dll} and resource/artifactuac(alt)64.exe signature for versions v3.14 through v4.x"
		hash =  "decfcca0018f2cec4a200ea057c804bb357300a67c6393b097d52881527b1c44"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		41 B8 5C 00 00 00       mov     r8d, 5Ch ; '\'
		C7 44 24 50 5C 00 00 00 mov     [rsp+68h+var_18], 5Ch ; '\'
		C7 44 24 48 65 00 00 00 mov     [rsp+68h+var_20], 65h ; 'e'
		C7 44 24 40 70 00 00 00 mov     [rsp+68h+var_28], 70h ; 'p'
		C7 44 24 38 69 00 00 00 mov     [rsp+68h+var_30], 69h ; 'i'
		C7 44 24 30 70 00 00 00 mov     [rsp+68h+var_38], 70h ; 'p'
		C7 44 24 28 5C 00 00 00 mov     dword ptr [rsp+68h+lpThreadId], 5Ch ; '\'
		C7 44 24 20 2E 00 00 00 mov     [rsp+68h+dwCreationFlags], 2Eh ; '.'
		89 54 24 58             mov     [rsp+68h+var_10], edx
		48 8D 15 22 38 00 00    lea     rdx, Format; Format
		E8 0D 17 00 00          call    sprintf
	*/

	$fmtBuilder = {
			41 ?? 5C 00 00 00
			C7 [3] 5C 00 00 00
			C7 [3] 65 00 00 00
			C7 [3] 70 00 00 00
			C7 [3] 69 00 00 00
			C7 [3] 70 00 00 00
			C7 [3] 5C 00 00 00
			C7 [3] 2E 00 00 00
			89 [3]
			48 [6]
			E8
		}

  $fmtString = "%c%c%c%c%c%c%c%c%cMSSE-%d-server"
		
	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_44
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Version 1.44"
    hash = "75102e8041c58768477f5f982500da7e03498643b6ece86194f4b3396215f9c2"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      0F B7 D2  movzx   edx, dx
      4A        dec     edx; switch 5 cases
      53        push    ebx
      8B D9     mov     ebx, ecx; a2
      83 FA 04  cmp     edx, 4
      77 36     ja      short def_1000106C; jumptable 1000106C default case
      FF 24 ??  jmp     ds:jpt_1000106C[edx*4]; switch jump
    */
    $version_sig = { 0F B7 D2 4A 53 8B D9 83 FA 04 77 36 FF 24 }
    
    /*
      B1 69          mov     cl, 69h ; 'i'
      30 88 [4]      xor     byte ptr word_10018F20[eax], cl
      40             inc     eax
      3D 28 01 00 00 cmp     eax, 128h
      7C F2          jl      short loc_10001AD4
    */
    $decode = { B1 ?? 30 88 [4] 40 3D 28 01 00 00 7C F2 }    
  
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_45
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Version 1.45"
    hash = "1a92b2024320f581232f2ba1e9a11bef082d5e9723429b3e4febb149458d1bb1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      51        push    ecx
      0F B7 D2  movzx   edx, dx
      4A        dec     edx; switch 9 cases
      53        push    ebx
      56        push    esi
      83 FA 08  cmp     edx, 8
      77 6B     ja      short def_1000106C; jumptable 1000106C default case
      FF 24 ??  jmp     ds:jpt_1000106C[edx*4]; switch jump
    */
    $version_sig = { 51 0F B7 D2 4A 53 56 83 FA 08 77 6B FF 24 }

    /*
      B1 69          mov     cl, 69h ; 'i'
      30 88 [4]      xor     byte ptr word_10019F20[eax], cl
      40             inc     eax
      3D 28 01 00 00 cmp     eax, 128h
      7C F2          jl      short loc_10002664
    */
    $decode = { B1 ?? 30 88 [4] 40 3D 28 01 00 00 7C F2 }
  
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_46
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Version 1.46"
    hash = "44e34f4024878024d4804246f57a2b819020c88ba7de160415be38cd6b5e2f76"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      8B F2             mov     esi, edx
      83 F9 0C          cmp     ecx, 0Ch
      0F 87 8E 00 00 00 ja      def_1000107F; jumptable 1000107F default case, case 8
      FF 24 ??          jmp     ds:jpt_1000107F[ecx*4]; switch jump
    */   
    $version_sig = { 8B F2 83 F9 0C 0F 87 8E 00 00 00 FF 24 }

    /*
      B1 69          mov     cl, 69h ; 'i'
      30 88 [4]      xor     byte ptr word_1001D040[eax], cl
      40             inc     eax
      3D A8 01 00 00 cmp     eax, 1A8h
      7C F2          jl      short loc_10002A04
    */
    $decode = { B1 ?? 30 88 [4] 40 3D A8 01 00 00 7C F2 }
  
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_47
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Version 1.47"
    hash = "8ff6dc80581804391183303bb39fca2a5aba5fe13d81886ab21dbd183d536c8d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      83 F8 12  cmp     eax, 12h
      77 10     ja      short def_100010BB; jumptable 100010BB default case, case 8
      FF 24 ??  jmp     ds:jpt_100010BB[eax*4]; switch jump
    */
    $version_sig = { 83 F8 12 77 10 FF 24 }

    /*
      B1 69          mov     cl, 69h ; 'i'
      30 88 [4]      xor     byte ptr word_1001E040[eax], cl
      40             inc     eax
      3D A8 01 00 00 cmp     eax, 1A8h
    */
    $decode = { B1 ?? 30 88 [4] 40 3D A8 01 00 00 }
  
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_48
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Version 1.48"
    hash = "dd4e445572cd5e32d7e9cc121e8de337e6f19ff07547e3f2c6b7fce7eafd15e4"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48        dec     eax; switch 24 cases
      57        push    edi
      8B F1     mov     esi, ecx
      8B DA     mov     ebx, edx
      83 F8 17  cmp     eax, 17h
      77 12     ja      short def_1000115D; jumptable 1000115D default case, case 8
      FF 24 ??  jmp     ds:jpt_1000115D[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F1 8B DA 83 F8 17 77 12 FF 24 }
    
    /*
      B1 69          mov     cl, 69h ; 'i'
      30 88 [4]      xor     byte ptr word_1001F048[eax], cl
      40             inc     eax
      3D A8 01 00 00 cmp     eax, 1A8h
      7C F2          jl      short loc_100047B4
    */
    $decode = { B1 ?? 30 88 [4] 40 3D A8 01 00 00 7C F2 }
  
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_49
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Version 1.49"
    hash = "52b4bd87e21ee0cbaaa0fc007fd3f894c5fc2c4bae5cbc2a37188de3c2c465fe"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                   dec     eax; switch 31 cases
      56                   push    esi
      83 F8 1E             cmp     eax, 1Eh
      0F 87 23 01 00 00    ja      def_1000115B; jumptable 1000115B default case, cases 8,30
      FF 24 85 80 12 00 10 jmp     ds:jpt_1000115B[eax*4]; switch jump
    */
    $version_sig = { 48 56 83 F8 1E 0F 87 23 01 00 00 FF 24 }
    
    /*
      B1 69            mov     cl, 69h ; 'i'
      90               nop
      30 88 [4]        xor     byte ptr word_10022038[eax], cl
      40               inc     eax
      3D A8 01 00 00   cmp     eax, 1A8h
      7C F2            jl      short loc_10005940
    */    
    $decoder = { B1 ?? 90 30 88 [4] 40 3D A8 01 00 00 7C F2 }
      
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v2_0_49
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Version 2.0.49"
    hash = "ed08c1a21906e313f619adaa0a6e5eb8120cddd17d0084a30ada306f2aca3a4e"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      83 F8 22          cmp     eax, 22h
      0F 87 96 01 00 00 ja      def_1000115D; jumptable 1000115D default case, cases 8,30
      FF 24 ??          jmp     ds:jpt_1000115D[eax*4]; switch jump
    */
    $version_sig = { 83 F8 22 0F 87 96 01 00 00 FF 24 }

    /*
      B1 69            mov     cl, 69h ; 'i'
      EB 03            jmp     short loc_10006930
      8D 49 00         lea     ecx, [ecx+0]
      30 88 [4]        xor     byte ptr word_10023038[eax], cl
      40               inc     eax
      3D 30 05 00 00   cmp     eax, 530h
      72 F2            jb      short loc_10006930
    */
    $decoder = { B1 ?? EB 03 8D 49 00 30 88 [4] 40 3D 30 05 00 00 72 F2  }
  
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v2_1_and_v2_2
{
  // v2.1 and v2.2 use the exact same beacon binary (matching hashes)
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 2.1 and 2.2"
    hash = "ae7a1d12e98b8c9090abe19bcaddbde8db7b119c73f7b40e76cdebb2610afdc2"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      49                dec     ecx; switch 37 cases
      56                push    esi
      57                push    edi
      83 F9 24          cmp     ecx, 24h
      0F 87 8A 01 00 00 ja      def_1000112E; jumptable 1000112E default case, cases 8,30
      FF 24 ??          jmp     ds:jpt_1000112E[ecx*4]; switch jump
    */
    $version_sig = { 49 56 57 83 F9 24 0F 87 8A 01 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v2_3
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 2.3"
    hash = "00dd982cb9b37f6effb1a5a057b6571e533aac5e9e9ee39a399bb3637775ff83"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      49                dec     ecx; switch 39 cases
      56                push    esi
      57                push    edi
      83 F9 26          cmp     ecx, 26h
      0F 87 A9 01 00 00 ja      def_1000112E; jumptable 1000112E default case, cases 8,30
      FF 24 ??          jmp     ds:jpt_1000112E[ecx*4]; switch jump
    */
    $version_sig = { 49 56 57 83 F9 26 0F 87 A9 01 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v2_4
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 2.4"
    hash = "78c6f3f2b80e6140c4038e9c2bcd523a1b205d27187e37dc039ede4cf560beed"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      4A                dec     edx; switch 48 cases
      56                push    esi
      57                push    edi
      83 FA 2F          cmp     edx, 2Fh
      0F 87 F9 01 00 00 ja      def_1000112E; jumptable 1000112E default case, cases 6-8,30
      FF 24 ??          jmp     ds:jpt_1000112E[edx*4]; switch jump
    */
    $version_sig = { 4A 56 57 83 FA 2F 0F 87 F9 01 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v2_5
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 2.5"
    hash = "d99693e3e521f42d19824955bef0cefb79b3a9dbf30f0d832180577674ee2b58"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 59 cases
      57                push    edi
      8B F2             mov     esi, edx
      83 F8 3A          cmp     eax, 3Ah
      0F 87 6E 02 00 00 ja      def_10001130; jumptable 10001130 default case, cases 6-8,30
      FF 24 ??          jmp     ds:jpt_10001130[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F2 83 F8 3A 0F 87 6E 02 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_0
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.0"
    hash = "30251f22df7f1be8bc75390a2f208b7514647835f07593f25e470342fd2e3f52"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 61 cases
      57                push    edi
      8B F2             mov     esi, edx
      83 F8 3C          cmp     eax, 3Ch
      0F 87 89 02 00 00 ja      def_10001130; jumptable 10001130 default case, cases 6-8,30
      FF 24 ??          jmp     ds:jpt_10001130[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F2 83 F8 3C 0F 87 89 02 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_1
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.1"
    hash = "4de723e784ef4e1633bbbd65e7665adcfb03dd75505b2f17d358d5a40b7f35cf"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  // v3.1 and v3.2 share the same C2 handler code. We are using a function that
  // is not included in v3.2 to mark the v3.1 version along with the decoder
  // which allows us to narrow in on only v3.1 samples
  strings:
    /*
      55             push    ebp
      8B EC          mov     ebp, esp
      83 EC 58       sub     esp, 58h
      A1 [4]         mov     eax, ___security_cookie
      33 C5          xor     eax, ebp
      89 45 FC       mov     [ebp+var_4], eax
      E8 DF F5 FF FF call    sub_10002109
      6A 50          push    50h ; 'P'; namelen
      8D 45 A8       lea     eax, [ebp+name]
      50             push    eax; name
      FF 15 [4]      call    ds:gethostname
      8D 45 ??       lea     eax, [ebp+name]
      50             push    eax; name
      FF 15 [4]      call    ds:__imp_gethostbyname
      85 C0          test    eax, eax
      74 14          jz      short loc_10002B58
      8B 40 0C       mov     eax, [eax+0Ch]
      83 38 00       cmp     dword ptr [eax], 0
      74 0C          jz      short loc_10002B58
      8B 00          mov     eax, [eax]
      FF 30          push    dword ptr [eax]; in
      FF 15 [4]      call    ds:inet_ntoa
      EB 05          jmp     short loc_10002B5D
      B8 [4]         mov     eax, offset aUnknown; "unknown"
      8B 4D FC       mov     ecx, [ebp+var_4]
      33 CD          xor     ecx, ebp; StackCookie
      E8 82 B7 00 00 call    @__security_check_cookie@4; __security_check_cookie(x)
      C9             leave
    */
    $version_sig = { 55 8B EC 83 EC 58 A1 [4] 33 C5 89 45 FC E8 DF F5 FF FF 6A 50 8D 45 A8 50 FF 15 [4] 8D 45 ?? 50 FF 15 [4] 85 C0 74 14 8B 40 0C 83 38 00 74 0C 8B 00 FF 30 FF 15 [4] EB 05 B8 [4] 8B 4D FC 33 CD E8 82 B7 00 00 C9 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_2
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.2"
    hash = "b490eeb95d150530b8e155da5d7ef778543836a03cb5c27767f1ae4265449a8d"
    rs2 ="a93647c373f16d61c38ba6382901f468247f12ba8cbe56663abb2a11ff2a5144"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 62 cases
      57                push    edi
      8B F2             mov     esi, edx
      83 F8 3D          cmp     eax, 3Dh
      0F 87 83 02 00 00 ja      def_10001130; jumptable 10001130 default case, cases 6-8,30
      FF 24 ??          jmp     ds:jpt_10001130[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F2 83 F8 3D 0F 87 83 02 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

    // Since v3.1 and v3.2 are so similiar, we use the v3.1 version_sig
    // as a negating condition to diff between 3.1 and 3.2
    /*
      55             push    ebp
      8B EC          mov     ebp, esp
      83 EC 58       sub     esp, 58h
      A1 [4]         mov     eax, ___security_cookie
      33 C5          xor     eax, ebp
      89 45 FC       mov     [ebp+var_4], eax
      E8 DF F5 FF FF call    sub_10002109
      6A 50          push    50h ; 'P'; namelen
      8D 45 A8       lea     eax, [ebp+name]
      50             push    eax; name
      FF 15 [4]      call    ds:gethostname
      8D 45 ??       lea     eax, [ebp+name]
      50             push    eax; name
      FF 15 [4]      call    ds:__imp_gethostbyname
      85 C0          test    eax, eax
      74 14          jz      short loc_10002B58
      8B 40 0C       mov     eax, [eax+0Ch]
      83 38 00       cmp     dword ptr [eax], 0
      74 0C          jz      short loc_10002B58
      8B 00          mov     eax, [eax]
      FF 30          push    dword ptr [eax]; in
      FF 15 [4]      call    ds:inet_ntoa
      EB 05          jmp     short loc_10002B5D
      B8 [4]         mov     eax, offset aUnknown; "unknown"
      8B 4D FC       mov     ecx, [ebp+var_4]
      33 CD          xor     ecx, ebp; StackCookie
      E8 82 B7 00 00 call    @__security_check_cookie@4; __security_check_cookie(x)
      C9             leave
    */
    $version3_1_sig = { 55 8B EC 83 EC 58 A1 [4] 33 C5 89 45 FC E8 DF F5 FF FF 6A 50 8D 45 A8 50 FF 15 [4] 8D 45 ?? 50 FF 15 [4] 85 C0 74 14 8B 40 0C 83 38 00 74 0C 8B 00 FF 30 FF 15 [4] EB 05 B8 [4] 8B 4D FC 33 CD E8 82 B7 00 00 C9 }

  condition:
    $version_sig and $decoder and not $version3_1_sig
}

rule CobaltStrike_Resources_Beacon_Dll_v3_3
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.3"
    hash = "158dba14099f847816e2fc22f254c60e09ac999b6c6e2ba6f90c6dd6d937bc42"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 66 cases
      57                push    edi
      8B F1             mov     esi, ecx
      83 F8 41          cmp     eax, 41h
      0F 87 F0 02 00 00 ja      def_1000112D; jumptable 1000112D default case, cases 6-8,30
      FF 24 ??          jmp     ds:jpt_1000112D[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F1 83 F8 41 0F 87 F0 02 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_4
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.4"
    hash = "5c40bfa04a957d68a095dd33431df883e3a075f5b7dea3e0be9834ce6d92daa3"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 67 cases
      57                push    edi
      8B F1             mov     esi, ecx
      83 F8 42          cmp     eax, 42h
      0F 87 F0 02 00 00 ja      def_1000112D; jumptable 1000112D default case, cases 6-8,26,30
      FF 24 ??          jmp     ds:jpt_1000112D[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F1 83 F8 42 0F 87 F0 02 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_5_hf1_and_3_5_1
{
  // Version 3.5-hf1 and 3.5.1 use the exact same beacon binary (same hash)
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.5-hf1 and 3.5.1 (3.5.x)"
    hash = "c78e70cd74f4acda7d1d0bd85854ccacec79983565425e98c16a9871f1950525"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 68 cases
      57                push    edi
      8B F1             mov     esi, ecx
      83 F8 43          cmp     eax, 43h
      0F 87 07 03 00 00 ja      def_1000112D; jumptable 1000112D default case, cases 6-8,26,30
      FF 24 ??          jmp     ds:jpt_1000112D[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F1 83 F8 43 0F 87 07 03 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_6
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.6"
    hash = "495a744d0a0b5f08479c53739d08bfbd1f3b9818d8a9cbc75e71fcda6c30207d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 72 cases
      57                push    edi
      8B F9             mov     edi, ecx
      83 F8 47          cmp     eax, 47h
      0F 87 2F 03 00 00 ja      def_1000100F; jumptable 1000100F default case, cases 6-8,26,30
      FF 24 ??          jmp     ds:jpt_1000100F[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F9 83 F8 47 0F 87 2F 03 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_7
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.7"
    hash = "f18029e6b12158fb3993f4951dab2dc6e645bb805ae515d205a53a1ef41ca9b2"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 74 cases
      57                push    edi
      8B F9             mov     edi, ecx
      83 F8 49          cmp     eax, 49h
      0F 87 47 03 00 00 ja      def_1000100F; jumptable 1000100F default case, cases 6-8,26,30
      FF 24 ??          jmp     ds:jpt_1000100F[eax*4]; switch jump
    */   
    $version_sig = { 48 57 8B F9 83 F8 49 0F 87 47 03 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_8
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.8"
    hash = "67b6557f614af118a4c409c992c0d9a0cc800025f77861ecf1f3bbc7c293d603"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 76 cases
      57                push    edi
      8B F9             mov     edi, ecx
      83 F8 4B          cmp     eax, 4Bh
      0F 87 5D 03 00 00 ja      def_1000100F; jumptable 1000100F default case, cases 6-8,26,30
      FF 24 ??          jmp     ds:jpt_1000100F[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F9 83 F8 4B 0F 87 5D 03 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

    // XMRig uses a v3.8 sample to trick sandboxes into running their code. 
    // These samples are the same and useless. This string removes many
    // of them from our detection
    $xmrig_srcpath = "C:/Users/SKOL-NOTE/Desktop/Loader/script.go"
    // To remove others, we look for known xmrig C2 domains in the config:
    $c2_1 = "ns7.softline.top" xor
    $c2_2 = "ns8.softline.top" xor
    $c2_3 = "ns9.softline.top" xor
    //$a = /[A-Za-z]{1020}.{4}$/
    
  condition:
    $version_sig and $decoder and not (2 of ($c2_*) or $xmrig_srcpath)
}

/*

  missing specific signatures for 3.9 and 3.10 since we don't have samples

*/

rule CobaltStrike_Resources_Beacon_Dll_v3_11
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.11"
    hash = "2428b93464585229fd234677627431cae09cfaeb1362fe4f648b8bee59d68f29"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  // Original version from April 9, 2018
  strings:
    /*
      48                dec     eax; switch 81 cases
      57                push    edi
      8B FA             mov     edi, edx
      83 F8 50          cmp     eax, 50h
      0F 87 11 03 00 00 ja      def_1000100F; jumptable 1000100F default case, cases 2,6-8,26,30,36
      FF 24 ??          jmp     ds:jpt_1000100F[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B FA 83 F8 50 0F 87 11 03 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_11_bugfix_and_v3_12
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.11-bugfix and 3.12"
    hash = "5912c96fffeabb2c5c5cdd4387cfbfafad5f2e995f310ace76ca3643b866e3aa"
    rs2 ="4476a93abe48b7481c7b13dc912090b9476a2cdf46a1c4287b253098e3523192"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  // Covers both 3.11 (bug fix form May 25, 2018) and v3.12
  strings:
    /*
      48                dec     eax; switch 81 cases
      57                push    edi
      8B FA             mov     edi, edx
      83 F8 50          cmp     eax, 50h
      0F 87 0D 03 00 00 ja      def_1000100F; jumptable 1000100F default case, cases 2,6-8,26,30,36
      FF 24 ??          jmp     ds:jpt_1000100F[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B FA 83 F8 50 0F 87 0D 03 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_13
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.13"
    hash = "362119e3bce42e91cba662ea80f1a7957a5c2b1e92075a28352542f31ac46a0c"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      4A                dec     edx; switch 91 cases
      56                push    esi
      57                push    edi
      83 FA 5A          cmp     edx, 5Ah
      0F 87 2D 03 00 00 ja      def_10008D01; jumptable 10008D01 default case, cases 2,6-8,20,21,26,30,36,63-66
      FF 24 ??          jmp     ds:jpt_10008D01[edx*4]; switch jump
    */
    $version_sig = { 4A 56 57 83 FA 5A 0F 87 2D 03 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_14
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.14"
    hash = "254c68a92a7108e8c411c7b5b87a2f14654cd9f1324b344f036f6d3b6c7accda"
    rs2 ="87b3eb55a346b52fb42b140c03ac93fc82f5a7f80697801d3f05aea1ad236730"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      83 FA 5B  cmp     edx, 5Bh
      77 15     ja      short def_1000939E; jumptable 1000939E default case, cases 2,6-8,20,21,26,30,36,63-66
      FF 24 ??  jmp     ds:jpt_1000939E[edx*4]; switch jump
    */
    $version_sig = { 83 FA 5B 77 15 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Sleeve_Beacon_Dll_v4_0_suspected
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.dll Versions 4.0 (suspected, not confirmed)"
    hash =  "e2b2b72454776531bbc6a4a5dd579404250901557f887a6bccaee287ac71b248"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      51                   push    ecx
      4A                   dec     edx; switch 99 cases
      56                   push    esi
      57                   push    edi
      83 FA 62             cmp     edx, 62h
      0F 87 8F 03 00 00    ja      def_100077C3; jumptable 100077C3 default case, cases 2,6-8,20,21,25,26,30,34-36,63-66
      FF 24 95 56 7B 00 10 jmp     ds:jpt_100077C3[edx*4]; switch jump
    */

    $version_sig = { 51 4A 56 57 83 FA 62 0F 87 8F 03 00 00 FF 24 95 56 7B 00 10 }

    /*
      80 B0 20 00 03 10 ??  xor     byte_10030020[eax], 2Eh
      40                    inc     eax
      3D 00 10 00 00        cmp     eax, 1000h
      7C F1                 jl      short loc_1000912B
    */

    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}

rule CobaltStrike_Sleeve_Beacon_Dll_v4_1_and_v4_2
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.dll Versions 4.1 and 4.2"
    hash = "daa42f4380cccf8729129768f3588bb98e4833b0c40ad0620bb575b5674d5fc3"
    rs2 ="9de55f27224a4ddb6b2643224a5da9478999c7b2dea3a3d6b3e1808148012bcf"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 100 cases
      57                push    edi
      8B F2             mov     esi, edx
      83 F8 63          cmp     eax, 63h
      0F 87 3C 03 00 00 ja      def_10007F28; jumptable 10007F28 default case, cases 2,6-8,20,21,25,26,29,30,34-36,58,63-66,80,81,95-97
      FF 24 ??          jmp     ds:jpt_10007F28[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F2 83 F8 63 0F 87 3C 03 00 00 FF 24 }

    /*
      80 B0 [4] 3E   xor     byte_10031010[eax], 3Eh
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10009791
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Sleeve_Beacon_Dll_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.dll Versions 4.3 and 4.4"
    hash = "51490c01c72c821f476727c26fbbc85bdbc41464f95b28cdc577e5701790845f"
    rs2 ="78a6fbefa677eeee29d1af4a294ee57319221b329a2fe254442f5708858b37dc"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 102 cases
      57                push    edi
      8B F2             mov     esi, edx
      83 F8 65          cmp     eax, 65h
      0F 87 47 03 00 00 ja      def_10007EAD; jumptable 10007EAD default case, cases 2,6-8,20,21,25,26,29,30,34-36,48,58,63-66,80,81,95-97
      FF 24 ??          jmp     ds:jpt_10007EAD[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F2 83 F8 65 0F 87 47 03 00 00 FF 24 }

    /*
      80 B0 [4] 3E   xor     byte_10031010[eax], 3Eh
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10009791
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Sleeve_Beacon_Dll_v4_7_suspected
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.dll Versions 4.7 (suspected, not confirmed)"
    hash =  "da9e91b3d8df3d53425dd298778782be3bdcda40037bd5c92928395153160549"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:

    /*
      53                push    ebx
      56                push    esi
      48                dec     eax; switch 104 cases
      57                push    edi
      8B F2             mov     esi, edx
      83 F8 67          cmp     eax, 67h
      0F 87 5E 03 00 00 ja      def_10008997; jumptable 10008997 default case, cases 2,6-8,20,21,25,26,29,30,34-36,48,58,63-66,80,81,95-97
    */
    $version_sig = { 53 56 48 57 8B F2 83 F8 67 0F 87 5E 03 00 00  }

    /*
      80 B0 [5]      xor     byte_10033020[eax], 2Eh
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_1000ADA1
    */

    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

/*

 64-bit Beacons.
 
 These signatures are a bit different. The decoders are all identical in the 4.x
 series and the command processor doesn't use a switch/case idiom, but rather
 an expanded set of if/then/else branches. This invalidates our method for
 detecting the versions of the beacons by looking at the case count check
 used by the 32-bit versions. As such, we are locking in on "random",
 non-overlapping between version, sections of code in the command processor. 
 While a reasonable method is to look for blocks of Jcc which will have specific
 address offsets per version, this generally is insufficient due to the lack of 
 code changes. As such, the best method appears to be to look for specific
 function call offsets

 NOTE: There are only VERY subtle differences between the following versions:
  * 3.2 and 3.3
  * 3.4 and 3.5-hf1/3.5.1
  * 3.12, 3.13 and 3.14
  * 4.3 and 4.4-4.6 . 
  
 Be very careful if you modify the $version_sig field for either of those rules. 
*/


rule CobaltStrike_Resources_Beacon_x64_v3_2
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.2"
    hash =  "5993a027f301f37f3236551e6ded520e96872723a91042bfc54775dcb34c94a1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      4C 8D 05 9F F8 FF FF lea     r8, sub_18000C4B0
      8B D3                mov     edx, ebx
      48 8B CF             mov     rcx, rdi
      E8 05 1A 00 00       call    sub_18000E620
      EB 0A                jmp     short loc_18000CC27
      8B D3                mov     edx, ebx
      48 8B CF             mov     rcx, rdi
      E8 41 21 00 00       call    sub_18000ED68
      48 8B 5C 24 30       mov     rbx, [rsp+28h+arg_0]
      48 83 C4 20          add     rsp, 20h
    */

    $version_sig = { 4C 8D 05 9F F8 FF FF 8B D3 48 8B CF E8 05 1A 00 00
                     EB 0A 8B D3 48 8B CF E8 41 21 00 00 48 8B 5C 24 30
                     48 83 C4 20 }
    
    /*
      80 31 ??          xor     byte ptr [rcx], 69h
      FF C2             inc     edx
      48 FF C1          inc     rcx
      48 63 C2          movsxd  rax, edx
      48 3D 10 06 00 00 cmp     rax, 610h
    */

    $decoder = { 80 31 ?? FF C2 48 FF C1 48 63 C2 48 3D 10 06 00 00 }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_3
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.3"
    hash =  "7b00721efeff6ed94ab108477d57b03022692e288cc5814feb5e9d83e3788580"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      8B D3                mov     edx, ebx
      48 8B CF             mov     rcx, rdi
      E8 89 66 00 00       call    sub_1800155E8
      E9 23 FB FF FF       jmp     loc_18000EA87
      41 B8 01 00 00 00    mov     r8d, 1
      E9 F3 FD FF FF       jmp     loc_18000ED62
      48 8D 0D 2A F8 FF FF lea     rcx, sub_18000E7A0
      E8 8D 2B 00 00       call    sub_180011B08
      48 8B 5C 24 30       mov     rbx, [rsp+28h+arg_0]
      48 83 C4 20          add     rsp, 20h
    */

    $version_sig = { 8B D3 48 8B CF E8 89 66 00 00 E9 23 FB FF FF 
                     41 B8 01 00 00 00 E9 F3 FD FF FF 48 8D 0D 2A F8 FF FF
                     E8 8D 2B 00 00 48 8B 5C 24 30 48 83 C4 20 }

    /*
      80 31 ??          xor     byte ptr [rcx], 69h
      FF C2             inc     edx
      48 FF C1          inc     rcx
      48 63 C2          movsxd  rax, edx
      48 3D 10 06 00 00 cmp     rax, 610h
    */

    $decoder = { 80 31 ?? FF C2 48 FF C1 48 63 C2 48 3D 10 06 00 00 }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_4
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.4"
    hash =  "5a4d48c2eda8cda79dc130f8306699c8203e026533ce5691bf90363473733bf0"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      8B D3             mov     edx, ebx
      48 8B CF          mov     rcx, rdi
      E8 56 6F 00 00    call    sub_180014458
      E9 17 FB FF FF    jmp     loc_18000D01E
      41 B8 01 00 00 00 mov     r8d, 1
      8B D3             mov     edx, ebx
      48 8B CF          mov     rcx, rdi
      E8 41 4D 00 00    call    sub_180012258
      48 8B 5C 24 30    mov     rbx, [rsp+28h+arg_0]
      48 83 C4 20       add     rsp, 20h
    */
    $version_sig = { 8B D3 48 8B CF E8 56 6F 00 00 E9 17 FB FF FF
                     41 B8 01 00 00 00 8B D3 48 8B CF E8 41 4D 00 00
                     48 8B 5C 24 30 48 83 C4 20 }

    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_18001600E
    */
    
    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_5_hf1_and_v3_5_1
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.5-hf1 and 3.5.1"
    hash =  "934134ab0ee65ec76ae98a9bb9ad0e9571d80f4bf1eb3491d58bacf06d42dc8d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      8B D3             mov     edx, ebx
      48 8B CF          mov     rcx, rdi
      E8 38 70 00 00    call    sub_180014548
      E9 FD FA FF FF    jmp     loc_18000D012
      41 B8 01 00 00 00 mov     r8d, 1
      8B D3             mov     edx, ebx
      48 8B CF          mov     rcx, rdi
      E8 3F 4D 00 00    call    sub_180012264
      48 8B 5C 24 30    mov     rbx, [rsp+28h+arg_0]
      48 83 C4 20       add     rsp, 20h
      5F                pop     rdi
    */

    $version_sig = { 8B D3 48 8B CF E8 38 70 00 00 E9 FD FA FF FF 
                     41 B8 01 00 00 00 8B D3 48 8B CF E8 3F 4D 00 00 
                     48 8B 5C 24 30 48 83 C4 20 5F }

    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_180016B3E
    */

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_6
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.6"
    hash =  "92b0a4aec6a493bcb1b72ce04dd477fd1af5effa0b88a9d8283f26266bb019a1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      48 89 5C 24 08    mov     [rsp+arg_0], rbx
      57                push    rdi
      48 83 EC 20       sub     rsp, 20h
      41 8B D8          mov     ebx, r8d
      48 8B FA          mov     rdi, rdx
      83 F9 27          cmp     ecx, 27h ; '''
      0F 87 47 03 00 00 ja      loc_18000D110
      0F 84 30 03 00 00 jz      loc_18000D0FF
      83 F9 14          cmp     ecx, 14h
      0F 87 A4 01 00 00 ja      loc_18000CF7C
      0F 84 7A 01 00 00 jz      loc_18000CF58
      83 F9 0C          cmp     ecx, 0Ch
      0F 87 C8 00 00 00 ja      loc_18000CEAF
      0F 84 B3 00 00 00 jz      loc_18000CEA0
    */
    $version_sig = { 48 89 5C 24 08 57 48 83 EC 20 41 8B D8 48 8B FA 83 F9 27
                     0F 87 47 03 00 00 0F 84 30 03 00 00 83 F9 14
                     0F 87 A4 01 00 00 0F 84 7A 01 00 00 83 F9 0C
                     0F 87 C8 00 00 00 0F 84 B3 00 00 00 }

    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_180016B3E
    */

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_7
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.7"
    hash =  "81296a65a24c0f6f22208b0d29e7bb803569746ce562e2fa0d623183a8bcca60"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      48 89 5C 24 08    mov     [rsp+arg_0], rbx
      57                push    rdi
      48 83 EC 20       sub     rsp, 20h
      41 8B D8          mov     ebx, r8d
      48 8B FA          mov     rdi, rdx
      83 F9 28          cmp     ecx, 28h ; '('
      0F 87 7F 03 00 00 ja      loc_18000D148
      0F 84 67 03 00 00 jz      loc_18000D136
      83 F9 15          cmp     ecx, 15h
      0F 87 DB 01 00 00 ja      loc_18000CFB3
      0F 84 BF 01 00 00 jz      loc_18000CF9D
    */

    $version_sig = { 48 89 5C 24 08 57 48 83 EC 20 41 8B D8 48 8B FA 83 F9 28
                     0F 87 7F 03 00 00 0F 84 67 03 00 00 83 F9 15
                     0F 87 DB 01 00 00 0F 84 BF 01 00 00 }

    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_180016ECA
    */

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_8
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.8"
    hash =  "547d44669dba97a32cb9e95cfb8d3cd278e00599e6a11080df1a9d09226f33ae"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      8B D3          mov     edx, ebx
      48 8B CF       mov     rcx, rdi
      E8 7A 52 00 00 call    sub_18001269C
      EB 0D          jmp     short loc_18000D431
      45 33 C0       xor     r8d, r8d
      8B D3          mov     edx, ebx
      48 8B CF       mov     rcx, rdi; Src
      E8 8F 55 00 00 call    sub_1800129C0
    */

    $version_sig = { 8B D3 48 8B CF E8 7A 52 00 00 EB 0D 45 33 C0 8B D3 48 8B CF
                     E8 8F 55 00 00 }
    
    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_18001772E
    */
    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_11
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.11 (two subversions)"
    hash =  "64007e104dddb6b5d5153399d850f1e1f1720d222bed19a26d0b1c500a675b1a"
    rs2 = "815f313e0835e7fdf4a6d93f2774cf642012fd21ce870c48ff489555012e0047"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
	
    /*
      48 83 EC 20       sub     rsp, 20h
      41 8B D8          mov     ebx, r8d
      48 8B FA          mov     rdi, rdx
      83 F9 2D          cmp     ecx, 2Dh ; '-'
      0F 87 B2 03 00 00 ja      loc_18000D1EF
      0F 84 90 03 00 00 jz      loc_18000D1D3
      83 F9 17          cmp     ecx, 17h
      0F 87 F8 01 00 00 ja      loc_18000D044
      0F 84 DC 01 00 00 jz      loc_18000D02E
      83 F9 0E          cmp     ecx, 0Eh
      0F 87 F9 00 00 00 ja      loc_18000CF54
      0F 84 DD 00 00 00 jz      loc_18000CF3E
      FF C9             dec     ecx
      0F 84 C0 00 00 00 jz      loc_18000CF29
      83 E9 02          sub     ecx, 2
      0F 84 A6 00 00 00 jz      loc_18000CF18
      FF C9             dec     ecx
    */

    $version_sig = { 48 83 EC 20 41 8B D8 48 8B FA 83 F9 2D 0F 87 B2 03 00 00
                     0F 84 90 03 00 00 83 F9 17 0F 87 F8 01 00 00
                     0F 84 DC 01 00 00 83 F9 0E 0F 87 F9 00 00 00
                     0F 84 DD 00 00 00 FF C9 0F 84 C0 00 00 00 83 E9 02
                     0F 84 A6 00 00 00 FF C9 }
    
    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_180017DCA
    */

    $decoder = {
      80 34 28 ?? 
      48 FF C0
      48 3D 00 10 00 00
      7C F1
    }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_12
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.12"
    hash =  "8a28b7a7e32ace2c52c582d0076939d4f10f41f4e5fa82551e7cc8bdbcd77ebc"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      8B D3          mov     edx, ebx
      48 8B CF       mov     rcx, rdi
      E8 F8 2E 00 00 call    sub_180010384
      EB 16          jmp     short loc_18000D4A4
      8B D3          mov     edx, ebx
      48 8B CF       mov     rcx, rdi
      E8 00 5C 00 00 call    f_OTH__Command_75
      EB 0A          jmp     short loc_18000D4A4
      8B D3          mov     edx, ebx
      48 8B CF       mov     rcx, rdi
      E8 64 4F 00 00 call    f_OTH__Command_74
    */
    $version_sig = { 8B D3 48 8B CF E8 F8 2E 00 00 EB 16 8B D3 48 8B CF
                     E8 00 5C 00 00 EB 0A 8B D3 48 8B CF E8 64 4F 00 00 }
    
    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_180018205
    */
    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}


rule CobaltStrike_Resources_Beacon_x64_v3_13
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.13"
    hash =  "945e10dcd57ba23763481981c6035e0d0427f1d3ba71e75decd94b93f050538e"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      48 8D 0D 01 5B FF FF lea     rcx, f_NET__ExfiltrateData
      48 83 C4 28          add     rsp, 28h
      E9 A8 54 FF FF       jmp     f_OTH__Command_85
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10; lpSrc
      E8 22 55 FF FF       call    f_OTH__Command_84
    */

    $version_sig = { 48 8D 0D 01 5B FF FF 48 83 C4 28 E9 A8 54 FF FF 8B D0
                     49 8B CA E8 22 55 FF FF }
      
    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_180018C01
    */

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_14
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.14"
    hash =  "297a8658aaa4a76599a7b79cb0da5b8aa573dd26c9e2c8f071e591200cf30c93"
    rs2 = "39b9040e3dcd1421a36e02df78fe031cbdd2fb1a9083260b8aedea7c2bc406bf"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:

    /*
      8B D0          mov     edx, eax
      49 8B CA       mov     rcx, r10; Src
      48 83 C4 28    add     rsp, 28h
      E9 B1 1F 00 00 jmp     f_OTH__Command_69
      8B D0          mov     edx, eax
      49 8B CA       mov     rcx, r10; Source
      48 83 C4 28    add     rsp, 28h
    */

    $version_sig = { 8B D0 49 8B CA 48 83 C4 28 E9 B1 1F 00 00 8B D0 49 8B CA
                     48 83 C4 28 }
    
    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_1800196BD
    */
    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}


rule CobaltStrike_Sleeve_Beacon_Dll_x86_v4_0_suspected
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.0 (suspected, not confirmed)"
    hash =  "55aa2b534fcedc92bb3da54827d0daaa23ece0f02a10eb08f5b5247caaa63a73"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      41 B8 01 00 00 00    mov     r8d, 1
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10
      48 83 C4 28          add     rsp, 28h
      E9 D1 B3 FF FF       jmp     sub_180010C5C
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10
      48 83 C4 28          add     rsp, 28h
      E9 AF F5 FF FF       jmp     f_UNK__Command_92__ChangeFlag
      45 33 C0             xor     r8d, r8d
      4C 8D 0D 8D 70 FF FF lea     r9, sub_18000C930
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10
      E8 9B B0 FF FF       call    f_OTH__Command_91__WrapInjection
    */

    $version_sig = { 41 B8 01 00 00 00 8B D0 49 8B CA 48 83 C4 28 E9 D1 B3 FF FF
                     8B D0 49 8B CA 48 83 C4 28 E9 AF F5 FF FF 45 33 C0
                     4C 8D 0D 8D 70 FF FF 8B D0 49 8B CA E8 9B B0 FF FF }

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}

rule CobaltStrike_Sleeve_Beacon_x64_v4_1_and_v_4_2
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.1 and 4.2"
    hash =  "29ec171300e8d2dad2e1ca2b77912caf0d5f9d1b633a81bb6534acb20a1574b2"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      83 F9 34          cmp     ecx, 34h ; '4'
      0F 87 8E 03 00 00 ja      loc_180016259
      0F 84 7A 03 00 00 jz      loc_18001624B
      83 F9 1C          cmp     ecx, 1Ch
      0F 87 E6 01 00 00 ja      loc_1800160C0
      0F 84 D7 01 00 00 jz      loc_1800160B7
      83 F9 0E          cmp     ecx, 0Eh
      0F 87 E9 00 00 00 ja      loc_180015FD2
      0F 84 CE 00 00 00 jz      loc_180015FBD
      FF C9             dec     ecx
      0F 84 B8 00 00 00 jz      loc_180015FAF
      83 E9 02          sub     ecx, 2
      0F 84 9F 00 00 00 jz      loc_180015F9F
      FF C9             dec     ecx
    */

    $version_sig = { 83 F9 34 0F 87 8E 03 00 00 0F 84 7A 03 00 00 83 F9 1C 0F 87 E6 01 00 00
                     0F 84 D7 01 00 00 83 F9 0E 0F 87 E9 00 00 00 0F 84 CE 00 00 00 FF C9
                     0F 84 B8 00 00 00 83 E9 02 0F 84 9F 00 00 00 FF C9 }


    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Sleeve_Beacon_x64_v4_3
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Version 4.3"
    hash =  "3ac9c3525caa29981775bddec43d686c0e855271f23731c376ba48761c27fa3d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
  
    /*
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10; Source
      48 83 C4 28          add     rsp, 28h
      E9 D3 88 FF FF       jmp     f_OTH__CommandAbove_10
      4C 8D 05 84 6E FF FF lea     r8, f_NET__ExfiltrateData
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10
      48 83 C4 28          add     rsp, 28h
    */

    $version_sig = { 8B D0 49 8B CA 48 83 C4 28 E9 D3 88 FF FF
                     4C 8D 05 84 6E FF FF 8B D0 49 8B CA 48 83 C4 28 }
  
    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 2Eh
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_1800186E1
    */
    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}


rule CobaltStrike_Sleeve_Beacon_x64_v4_4_v_4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.4 through at least 4.6"
    hash = "3280fec57b7ca94fd2bdb5a4ea1c7e648f565ac077152c5a81469030ccf6ab44"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10; Source
      48 83 C4 28          add     rsp, 28h
      E9 83 88 FF FF       jmp     f_OTH__CommandAbove_10
      4C 8D 05 A4 6D FF FF lea     r8, f_NET__ExfiltrateData
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10
      48 83 C4 28          add     rsp, 28h
    */

    $version_sig = { 8B D0 49 8B CA 48 83 C4 28 E9 83 88 FF FF
                     4C 8D 05 A4 6D FF FF 8B D0 49 8B CA 48 83 C4 28 }

    /*
      80 34 28 2E       xor     byte ptr [rax+rbp], 2Eh
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_1800184D9
    */

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Sleeve_Beacon_x64_v4_5_variant
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.5 (variant)"
    hash =  "8f0da7a45945b630cd0dfb5661036e365dcdccd085bc6cff2abeec6f4c9f1035"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      41 B8 01 00 00 00 mov     r8d, 1
      8B D0             mov     edx, eax
      49 8B CA          mov     rcx, r10
      48 83 C4 28       add     rsp, 28h
      E9 E8 AB FF FF    jmp     sub_1800115A4
      8B D0             mov     edx, eax
      49 8B CA          mov     rcx, r10
      E8 1A EB FF FF    call    f_UNK__Command_92__ChangeFlag
      48 83 C4 28       add     rsp, 28h
    */
    $version_sig = { 41 B8 01 00 00 00 8B D0 49 8B CA 48 83 C4 28 E9 E8 AB FF FF
                     8B D0 49 8B CA E8 1A EB FF FF 48 83 C4 28 }

    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 2Eh
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_180018E1F
    */

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Bind64_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/bind64.bin signature for versions v2.5 to v4.x"
		hash =  "5dd136f5674f66363ea6463fd315e06690d6cb10e3cc516f2d378df63382955d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		48 31 C0       xor     rax, rax
		AC             lodsb
		41 C1 C9 0D    ror     r9d, 0Dh
		41 01 C1       add     r9d, eax
		38 E0          cmp     al, ah
		75 F1          jnz     short loc_100000000000007D
		4C 03 4C 24 08 add     r9, [rsp+40h+var_38]
		45 39 D1       cmp     r9d, r10d
		75 D8          jnz     short loc_100000000000006E
		58             pop     rax
		44 8B 40 24    mov     r8d, [rax+24h]
		49 01 D0       add     r8, rdx
		66 41 8B 0C 48 mov     cx, [r8+rcx*2]
		44 8B 40 1C    mov     r8d, [rax+1Ch]
		49 01 D0       add     r8, rdx
		41 8B 04 88    mov     eax, [r8+rcx*4]
		48 01 D0       add     rax, rdx
	*/

	$apiLocator = {
			48 [2]
			AC
			41 [2] 0D
			41 [2]
			38 ??
			75 ??
			4C [4]
			45 [2]
			75 ??
			5?
			44 [2] 24
			49 [2]
			66 [4]
			44 [2] 1C
			49 [2]
			41 [3]
			48 
		}


  // the signature for reverse64 and bind really differ slightly, here we are using the inclusion of additional calls
  // found in bind64 to differentate between this and reverse64
  // Note that we can reasonably assume that the constants being passed to the call rbp will be just that, constant,
  // since we are triggering on the API hasher. If that hasher is unchanged, then the hashes we look for should be
  // unchanged. This means we can use these values as anchors in our signature.
	/*
		41 BA C2 DB 37 67 mov     r10d, bind
		FF D5             call    rbp
		48 31 D2          xor     rdx, rdx
		48 89 F9          mov     rcx, rdi
		41 BA B7 E9 38 FF mov     r10d, listen
		FF D5             call    rbp
		4D 31 C0          xor     r8, r8
		48 31 D2          xor     rdx, rdx
		48 89 F9          mov     rcx, rdi
		41 BA 74 EC 3B E1 mov     r10d, accept
		FF D5             call    rbp
		48 89 F9          mov     rcx, rdi
		48 89 C7          mov     rdi, rax
		41 BA 75 6E 4D 61 mov     r10d, closesocket
	*/

	$calls = {
			41 BA C2 DB 37 67
			FF D5
			48 [2]
			48 [2]
			41 BA B7 E9 38 FF
			FF D5
			4D [2]
			48 [2]
			48 [2]
			41 BA 74 EC 3B E1
			FF D5
			48 [2]
			48 [2]
			41 BA 75 6E 4D 61
		}
		
	condition:
		$apiLocator and $calls
}

rule CobaltStrike_Resources_Bind_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/bind.bin signature for versions 2.5 to 4.x"
		hash =  "3727542c0e3c2bf35cacc9e023d1b2d4a1e9e86ee5c62ee5b66184f46ca126d1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		31 ??     xor     eax, eax
		AC        lodsb
		C1 ?? 0D  ror     edi, 0Dh
		01 ??     add     edi, eax
		38 ??     cmp     al, ah
		75 ??     jnz     short loc_10000054
		03 [2]    add     edi, [ebp-8]
		3B [2]    cmp     edi, [ebp+24h]
		75 ??     jnz     short loc_1000004A
		5?        pop     eax
		8B ?? 24  mov     ebx, [eax+24h]
		01 ??     add     ebx, edx
		66 8B [2] mov     cx, [ebx+ecx*2]
		8B ?? 1C  mov     ebx, [eax+1Ch]
		01 ??     add     ebx, edx
		8B ?? 8B  mov     eax, [ebx+ecx*4]
		01 ??     add     eax, edx
		89 [3]    mov     [esp+28h+var_4], eax
		5?        pop     ebx
		5?        pop     ebx
	*/

	$apiLocator = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}

    // the signature for the stagers overlap significantly. Looking for bind.bin specific bytes helps delineate sample types
	/*
		5D             pop     ebp
		68 33 32 00 00 push    '23'
		68 77 73 32 5F push    '_2sw'
	*/

	$ws2_32 = {
			5D
			68 33 32 00 00
			68 77 73 32 5F
		}

  // bind.bin, unlike reverse.bin, listens for incoming connections. Using the API hashes for listen and accept is a solid
  // approach to finding bind.bin specific samples
	/*
		5?             push    ebx
		5?             push    edi
		68 B7 E9 38 FF push    listen
		FF ??          call    ebp
		5?             push    ebx
		5?             push    ebx
		5?             push    edi
		68 74 EC 3B E1 push    accept
	*/
	$listenaccept = {
			5? 
			5? 
			68 B7 E9 38 FF
			FF ?? 
			5? 
			5? 
			5? 
			68 74 EC 3B E1
		}
	
	condition:
		$apiLocator and $ws2_32 and $listenaccept
}

rule  CobaltStrike__Resources_Browserpivot_Bin_v1_48_to_v3_14_and_Sleeve_Browserpivot_Dll_v4_0_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/browserpivot.bin from v1.48 to v3.14 and sleeve/browserpivot.dll from v4.0 to at least v4.4"
		hash =  "12af9f5a7e9bfc49c82a33d38437e2f3f601639afbcdc9be264d3a8d84fd5539"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		FF [1-5]        call    ds:recv               // earlier versions (v1.x to 2.x) this is CALL EBP
		83 ?? FF        cmp     eax, 0FFFFFFFFh
		74 ??           jz      short loc_100020D5
		85 C0           test    eax, eax
		(74  | 76) ??   jz      short loc_100020D5    // earlier versions (v1.x to 2.x) used jbe (76) here
		03 ??           add     esi, eax
		83 ?? 02        cmp     esi, 2
		72 ??           jb      short loc_100020D1
		80 ?? 3E FF 0A  cmp     byte ptr [esi+edi-1], 0Ah
		75 ??           jnz     short loc_100020D1
		80 ?? 3E FE 0D  cmp     byte ptr [esi+edi-2], 0Dh
	*/

	$socket_recv = {
			FF [1-5]
			83 ?? FF 
			74 ?? 
			85 C0
			(74 | 76) ?? 
			03 ?? 
			83 ?? 02 
			72 ?? 
			80 ?? 3E FF 0A 
			75 ?? 
			80 ?? 3E FE 0D 
		}
		
  // distinctive regex (sscanf) format string
  $fmt = "%1024[^ ] %8[^:]://%1016[^/]%7168[^ ] %1024[^ ]"

	condition:
		all of them
}

rule CobaltStrike_Resources_Browserpivot_x64_Bin_v1_48_to_v3_14_and_Sleeve_Browserpivot_x64_Dll_v4_0_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/browserpivot.x64.bin from v1.48 to v3.14 and sleeve/browserpivot.x64.dll from v4.0 to at least v4.4"
		hash =  "0ad32bc4fbf3189e897805cec0acd68326d9c6f714c543bafb9bc40f7ac63f55"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		FF 15 [4]         call    cs:recv
		83 ?? FF          cmp     eax, 0FFFFFFFFh
		74 ??             jz      short loc_1800018FB
		85 ??             test    eax, eax
		74 ??             jz      short loc_1800018FB
		03 ??             add     ebx, eax
		83 ?? 02          cmp     ebx, 2
		72 ??             jb      short loc_1800018F7
		8D ?? FF          lea     eax, [rbx-1]
		80 [2] 0A         cmp     byte ptr [rax+rdi], 0Ah
		75 ??             jnz     short loc_1800018F7
		8D ?? FE          lea     eax, [rbx-2]
		80 [2] 0D         cmp     byte ptr [rax+rdi], 0Dh
	*/

	$socket_recv = {
			FF 15 [4]
			83 ?? FF
			74 ??
			85 ??
			74 ??
			03 ??
			83 ?? 02
			72 ??
			8D ?? FF
			80 [2] 0A
			75 ??
			8D ?? FE
			80 [2] 0D
		}

  // distinctive regex (sscanf) format string
  $fmt = "%1024[^ ] %8[^:]://%1016[^/]%7168[^ ] %1024[^ ]"
		
	condition:
		all of them
}

rule CobaltStrike_Resources_Bypassuac_Dll_v1_49_to_v3_14_and_Sleeve_Bypassuac_Dll_v4_0_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/bypassuac(-x86).dll from v1.49 to v3.14 (32-bit version) and sleeve/bypassuac.dll from v4.0 to at least v4.4"
		hash =  "91d12e1d09a642feedee5da966e1c15a2c5aea90c79ac796e267053e466df365"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		A1 [4]    mov     eax, fileop
		6A 00     push    0
		8B ??     mov     ecx, [eax]
		5?        push    edx
		5?        push    eax
		FF ?? 48  call    dword ptr [ecx+48h]
		85 ??     test    eax, eax
		75 ??     jnz     short loc_10001177
		A1 [4]    mov     eax, fileop
		5?        push    eax
		8B ??     mov     ecx, [eax]
		FF ?? 54  call    dword ptr [ecx+54h]
	*/

	$deleteFileCOM = {
			A1 [4]
			6A 00
			8B ?? 
			5? 
			5? 
			FF ?? 48 
			85 ?? 
			75 ?? 
			A1 [4]
			5? 
			8B ?? 
			FF ?? 54 
		}

	/*
		A1 [4]    mov     eax, fileop
		6A 00     push    0
		FF ?? 08  push    [ebp+copyName]
		8B ??     mov     ecx, [eax]
		FF [5]    push    dstFile
		FF [5]    push    srcFile
		5?        push    eax
		FF ?? 40  call    dword ptr [ecx+40h]
		85 ??     test    eax, eax
		75 ??     jnz     short loc_10001026  // this line can also be 0F 85 <32-bit offset>
		A1 [4]    mov     eax, fileop
		5?        push    eax
		8B ??     mov     ecx, [eax]
		FF ?? 54  call    dword ptr [ecx+54h]
	*/

	$copyFileCOM = {
			A1 [4]
			6A 00
			FF [2]
			8B ?? 
			FF [5]
			FF [5]
			5? 
			FF ?? 40 
			85 ?? 
			[2 - 6]
			A1 [4]
			5? 
			8B ?? 
			FF ?? 54 
		}
		
				
	condition:
		all of them
}


rule CobaltStrike_Resources_Bypassuac_x64_Dll_v3_3_to_v3_14_and_Sleeve_Bypassuac_x64_Dll_v4_0_and_v4_x
{
	meta:
		description = "Cobalt Strike's resources/bypassuac-x64.dll from v3.3 to v3.14 (64-bit version) and sleeve/bypassuac.x64.dll from v4.0 to at least v4.4"
		hash =  "9ecf56e9099811c461d592c325c65c4f9f27d947cbdf3b8ef8a98a43e583aecb"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		48 8B 0D 07 A4 01 00 mov     rcx, cs:fileop
		45 33 C0             xor     r8d, r8d
		48 8B 01             mov     rax, [rcx]
		FF 90 90 00 00 00    call    qword ptr [rax+90h]
		85 C0                test    eax, eax
		75 D9                jnz     short loc_180001022
		48 8B 0D F0 A3 01 00 mov     rcx, cs:fileop
		48 8B 11             mov     rdx, [rcx]
		FF 92 A8 00 00 00    call    qword ptr [rdx+0A8h]
		85 C0                test    eax, eax
	*/

	$deleteFileCOM = {
			48 8B [5]
			45 33 ??
			48 8B ??
			FF 90 90 00 00 00
			85 C0
			75 ??
			48 8B [5]
			48 8B ??
			FF 92 A8 00 00 00
			85 C0
		}	
	
	
	/*
		48 8B 0D 32 A3 01 00 mov     rcx, cs:fileop
		4C 8B 05 3B A3 01 00 mov     r8, cs:dstFile
		48 8B 15 2C A3 01 00 mov     rdx, cs:srcFile
		48 8B 01             mov     rax, [rcx]
		4C 8B CD             mov     r9, rbp
		48 89 5C 24 20       mov     [rsp+38h+var_18], rbx
		FF 90 80 00 00 00    call    qword ptr [rax+80h]
		85 C0                test    eax, eax
		0F 85 7B FF FF FF    jnz     loc_1800010B0
		48 8B 0D 04 A3 01 00 mov     rcx, cs:fileop
		48 8B 11             mov     rdx, [rcx]
		FF 92 A8 00 00 00    call    qword ptr [rdx+0A8h]
	*/

	$copyFileCOM = {
			48 8B [5]
			4C 8B [5]
			48 8B [5]
			48 8B ??
			4C 8B ??
			48 89 [3]
			FF 90 80 00 00 00
			85 C0
			0F 85 [4]
			48 8B [5]
			48 8B 11
			FF 92 A8 00 00 00
		}

	condition:
		all of them
}

rule CobaltStrike_Resources_Bypassuactoken_Dll_v3_11_to_v3_14
{
	meta:
		description = "Cobalt Strike's resources/bypassuactoken.dll from v3.11 to v3.14 (32-bit version)"
		hash =  "df1c7256dfd78506e38c64c54c0645b6a56fc56b2ffad8c553b0f770c5683070"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		5?                 push    eax; ReturnLength
		5?                 push    edi; TokenInformationLength
		5?                 push    edi; TokenInformation
		8B ??              mov     ebx, ecx
		6A 19              push    19h; TokenInformationClass
		5?                 push    ebx; TokenHandle
		FF 15 [4]          call    ds:GetTokenInformation
		85 C0              test    eax, eax
		75 ??              jnz     short loc_10001100
		FF 15 [4]          call    ds:GetLastError
		83 ?? 7A           cmp     eax, 7Ah ; 'z'
		75 ??              jnz     short loc_10001100
		FF [2]             push    [ebp+ReturnLength]; uBytes
		5?                 push    edi; uFlags
		FF 15 [4]          call    ds:LocalAlloc
		8B ??              mov     esi, eax
		8D [2]             lea     eax, [ebp+ReturnLength]
		5?                 push    eax; ReturnLength
		FF [2]             push    [ebp+ReturnLength]; TokenInformationLength
		5?                 push    esi; TokenInformation
		6A 19              push    19h; TokenInformationClass
		5?                 push    ebx; TokenHandle
		FF 15 [4]          call    ds:GetTokenInformation
		85 C0              test    eax, eax
		74 ??              jz      short loc_10001103
		FF ??              push    dword ptr [esi]; pSid
		FF 15 [4]          call    ds:GetSidSubAuthorityCount
		8A ??              mov     al, [eax]
		FE C8              dec     al
		0F B6 C0           movzx   eax, al
		5?                 push    eax; nSubAuthority
		FF ??              push    dword ptr [esi]; pSid
		FF 15 [4]          call    ds:GetSidSubAuthority
		B? 01 00 00 00     mov     ecx, 1
		5?                 push    esi; hMem
		81 ?? 00 30 00 00  cmp     dword ptr [eax], 3000h
	*/

	$isHighIntegrityProcess = {
			5? 
			5? 
			5? 
			8B ?? 
			6A 19
			5? 
			FF 15 [4]
			85 C0
			75 ?? 
			FF 15 [4]
			83 ?? 7A 
			75 ?? 
			FF [2]
			5? 
			FF 15 [4]
			8B ?? 
			8D [2]
			5? 
			FF [2]
			5? 
			6A 19
			5? 
			FF 15 [4]
			85 C0
			74 ?? 
			FF ?? 
			FF 15 [4]
			8A ?? 
			FE C8
			0F B6 C0
			5? 
			FF ?? 
			FF 15 [4]
			B? 01 00 00 00 
			5? 
			81 ?? 00 30 00 00 
		}

	/*
		6A 3C               push    3Ch ; '<'; Size
		8D ?? C4            lea     eax, [ebp+pExecInfo]
		8B ??               mov     edi, edx
		6A 00               push    0; Val
		5?                  push    eax; void *
		8B ??               mov     esi, ecx
		E8 [4]              call    _memset
		83 C4 0C            add     esp, 0Ch
		C7 [2] 3C 00 00 00  mov     [ebp+pExecInfo.cbSize], 3Ch ; '<'
		8D [2]              lea     eax, [ebp+pExecInfo]
		C7 [2] 40 00 00 00  mov     [ebp+pExecInfo.fMask], 40h ; '@'
		C7 [6]              mov     [ebp+pExecInfo.lpFile], offset aTaskmgrExe; "taskmgr.exe"
		C7 [2] 00 00 00 00  mov     [ebp+pExecInfo.lpParameters], 0
		5?                  push    eax; pExecInfo
		C7 [2] 00 00 00 00  mov     [ebp+pExecInfo.lpDirectory], 0
		C7 [6]              mov     [ebp+pExecInfo.lpVerb], offset aRunas; "runas"
		C7 [2] 00 00 00 00  mov     [ebp+pExecInfo.nShow], 0
		FF 15 [4]           call    ds:ShellExecuteExW
		FF 75 FC            push    [ebp+pExecInfo.hProcess]; Process
	*/

	$executeTaskmgr = {
			6A 3C
			8D ?? C4 
			8B ?? 
			6A 00
			5? 
			8B ?? 
			E8 [4]
			83 C4 0C
			C7 [2] 3C 00 00 00 
			8D [2]
			C7 [2] 40 00 00 00 
			C7 [6]
			C7 [2] 00 00 00 00 
			5? 
			C7 [2] 00 00 00 00 
			C7 [6]
			C7 [2] 00 00 00 00 
			FF 15 [4]
			FF 75 FC
		}
		
	condition:
		all of them
}

rule CobaltStrike_Resources_Bypassuactoken_x64_Dll_v3_11_to_v3_14
{
	meta:
		description = "Cobalt Strike's resources/bypassuactoken.x64.dll from v3.11 to v3.14 (64-bit version)"
		hash =  "853068822bbc6b1305b2a9780cf1034f5d9d7127001351a6917f9dbb42f30d67"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		83 F8 7A          cmp     eax, 7Ah ; 'z'
		75 59             jnz     short loc_1800014BC
		8B 54 24 48       mov     edx, dword ptr [rsp+38h+uBytes]; uBytes
		33 C9             xor     ecx, ecx; uFlags
		FF 15 49 9C 00 00 call    cs:LocalAlloc
		44 8B 4C 24 48    mov     r9d, dword ptr [rsp+38h+uBytes]; TokenInformationLength
		8D 53 19          lea     edx, [rbx+19h]; TokenInformationClass
		48 8B F8          mov     rdi, rax
		48 8D 44 24 48    lea     rax, [rsp+38h+uBytes]
		48 8B CE          mov     rcx, rsi; TokenHandle
		4C 8B C7          mov     r8, rdi; TokenInformation
		48 89 44 24 20    mov     [rsp+38h+ReturnLength], rax; ReturnLength
		FF 15 B0 9B 00 00 call    cs:GetTokenInformation
		85 C0             test    eax, eax
		74 2D             jz      short loc_1800014C1
		48 8B 0F          mov     rcx, [rdi]; pSid
		FF 15 AB 9B 00 00 call    cs:GetSidSubAuthorityCount
		8D 73 01          lea     esi, [rbx+1]
		8A 08             mov     cl, [rax]
		40 2A CE          sub     cl, sil
		0F B6 D1          movzx   edx, cl; nSubAuthority
		48 8B 0F          mov     rcx, [rdi]; pSid
		FF 15 9F 9B 00 00 call    cs:GetSidSubAuthority
		81 38 00 30 00 00 cmp     dword ptr [rax], 3000h
	*/

	$isHighIntegrityProcess = {
			83 ?? 7A
			75 ??
			8B [3]
			33 ??
			FF 15 [4]
			44 [4]
			8D [2]
			48 8B ??
			48 8D [3]
			48 8B ??
			4C 8B ??
			48 89 [3]
			FF 15 [4]
			85 C0
			74 ??
			48 8B ??
			FF 15 [4]
			8D [2]
			8A ??
			40 [2]
			0F B6 D1
			48 8B 0F
			FF 15 [4]
			81 ?? 00 30 00 00
		}

	/*
		44 8D 42 70             lea     r8d, [rdx+70h]; Size
		48 8D 4C 24 20          lea     rcx, [rsp+98h+pExecInfo]; void *
		E8 2E 07 00 00          call    memset
		83 64 24 50 00          and     [rsp+98h+pExecInfo.nShow], 0
		48 8D 05 E2 9B 00 00    lea     rax, aTaskmgrExe; "taskmgr.exe"
		0F 57 C0                xorps   xmm0, xmm0
		66 0F 7F 44 24 40       movdqa  xmmword ptr [rsp+98h+pExecInfo.lpParameters], xmm0
		48 89 44 24 38          mov     [rsp+98h+pExecInfo.lpFile], rax
		48 8D 05 E5 9B 00 00    lea     rax, aRunas; "runas"
		48 8D 4C 24 20          lea     rcx, [rsp+98h+pExecInfo]; pExecInfo
		C7 44 24 20 70 00 00 00 mov     [rsp+98h+pExecInfo.cbSize], 70h ; 'p'
		C7 44 24 24 40 00 00 00 mov     [rsp+98h+pExecInfo.fMask], 40h ; '@'
		48 89 44 24 30          mov     [rsp+98h+pExecInfo.lpVerb], rax
		FF 15 05 9B 00 00       call    cs:ShellExecuteExW
	*/

	$executeTaskmgr = {
			44 8D ?? 70
			48 8D [3]
			E8 [4]
			83 [3] 00
			48 8D [5]
			0F 57 ??
			66 0F 7F [3]
			48 89 [3]
			48 8D [5]
			48 8D [3]
			C7 [3] 70 00 00 00
			C7 [3] 40 00 00 00
			48 89 [3]
			FF 15 
		}


	condition:
		all of them
}

rule CobaltStrike_Resources_Command_Ps1_v2_5_to_v3_7_and_Resources_Compress_Ps1_v3_8_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/command.ps1 for versions 2.5 to v3.7 and resources/compress.ps1 from v3.8 to v4.x"
		hash =  "932dec24b3863584b43caf9bb5d0cfbd7ed1969767d3061a7abdc05d3239ed62"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:		
    // the command.ps1 and compress.ps1 are the same file. Between v3.7 and v3.8 the file was renamed from command to compress.
    $ps1 = "$s=New-Object \x49O.MemoryStream(,[Convert]::\x46romBase64String(" nocase
    $ps2 ="));IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();" nocase
  
  condition:
    all of them
}

rule CobaltStrike_Resources_Covertvpn_Dll_v2_1_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/covertvpn.dll signature for version v2.2 to v4.4"
		hash =  "0a452a94d53e54b1df6ba02bc2f02e06d57153aad111171a94ec65c910d22dcf"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		5?                  push    esi
		68 [4]              push    offset ProcName; "IsWow64Process"
		68 [4]              push    offset ModuleName; "kernel32"
		C7 [3-5] 00 00 00 00  mov     [ebp+var_9C], 0                 // the displacement bytes are only 3 in v2.x, 5 in v3.x->v4.x
		FF 15 [4]           call    ds:GetModuleHandleA
		50                  push    eax; hModule
		FF 15 [4]           call    ds:GetProcAddress
		8B ??               mov     esi, eax
		85 ??               test    esi, esi
		74 ??               jz      short loc_1000298B
		8D [3-5]            lea     eax, [ebp+var_9C]                 // the displacement bytes are only 3 in v2.x, 5 in v3.x->v4.x
		5?                  push    eax
		FF 15 [4]           call    ds:GetCurrentProcess
		50                  push    eax
	*/

	$dropComponentsAndActivateDriver_prologue = {
			5? 
			68 [4]
			68 [4]
			C7 [3-5] 00 00 00 00 
			FF 15 [4]
			50
			FF 15 [4]
			8B ?? 
			85 ?? 
			74 ??
			8D [3-5]
			5? 
			FF 15 [4]
			50
		}

	/*
		6A 00          push    0; AccessMode
		5?             push    esi; FileName
		E8 [4]         call    __access
		83 C4 08       add     esp, 8
		83 F8 FF       cmp     eax, 0FFFFFFFFh
		74 ??          jz      short loc_100028A7
		5?             push    esi
		68 [4]         push    offset aWarningSExists; "Warning: %s exists\n"   // this may not exist in v2.x samples
		E8 [4]         call    nullsub_1
		83 C4 08       add     esp, 8             // if the push doesnt exist, then this is 04, not 08
		// v2.x has a PUSH ESI here... so we need to skip that
		6A 00          push    0; hTemplateFile
		68 80 01 00 00 push    180h; dwFlagsAndAttributes
		6A 02          push    2; dwCreationDisposition
		6A 00          push    0; lpSecurityAttributes
		6A 05          push    5; dwShareMode
		68 00 00 00 40 push    40000000h; dwDesiredAccess
		5?             push    esi; lpFileName
		FF 15 [4]      call    ds:CreateFileA
		8B ??          mov     edi, eax
		83 ?? FF       cmp     edi, 0FFFFFFFFh
		75 ??          jnz     short loc_100028E2
		FF 15 [4]      call    ds:GetLastError
		5?             push    eax
	*/

	$dropFile = {
			6A 00
			5? 
			E8 [4]
			83 C4 08
			83 F8 FF
			74 ?? 
			5? 
			[0-5]
			E8 [4]
			83 C4 ??
			[0-2]
			6A 00
			68 80 01 00 00
			6A 02
			6A 00
			6A 05
			68 00 00 00 40
			5? 
			FF 15 [4]
			8B ?? 
			83 ?? FF 
			75 ?? 
			FF 15 [4]
			5? 
		}
	
	$nfp = "npf.sys" nocase
	$wpcap = "wpcap.dll" nocase

	condition:
		all of them
}

rule CobaltStrike_Resources_Covertvpn_injector_Exe_v1_44_to_v2_0_49
{
	meta:
		description = "Cobalt Strike's resources/covertvpn-injector.exe signature for version v1.44 to v2.0.49"
		hash =  "d741751520f46602f5a57d1ed49feaa5789115aeeba7fa4fc7cbb534ee335462"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		C7 04 24 [4]    mov     dword ptr [esp], offset aKernel32; "kernel32"
		E8 [4]          call    GetModuleHandleA
		83 EC 04        sub     esp, 4
		C7 44 24 04 [4] mov     dword ptr [esp+4], offset aIswow64process; "IsWow64Process"
		89 04 24        mov     [esp], eax; hModule
		E8 59 14 00 00  call    GetProcAddress
		83 EC 08        sub     esp, 8
		89 45 ??        mov     [ebp+var_C], eax
		83 7D ?? 00     cmp     [ebp+var_C], 0
		74 ??           jz      short loc_4019BA
		E8 [4]          call    GetCurrentProcess
		8D [2]          lea     edx, [ebp+fIs64bit]
		89 [3]          mov     [esp+4], edx
		89 04 24        mov     [esp], eax
	*/

	$dropComponentsAndActivateDriver_prologue = {
			C7 04 24 [4]
			E8 [4]
			83 EC 04
			C7 44 24 04 [4]
			89 04 24
			E8 59 14 00 00
			83 EC 08
			89 45 ?? 
			83 7D ?? 00 
			74 ?? 
			E8 [4]
			8D [2]
			89 [3]
			89 04 24
		}

	/*
		C7 44 24 04 00 00 00 00 mov     dword ptr [esp+4], 0; AccessMode
		8B [2]                  mov     eax, [ebp+FileName]
		89 ?? 24                mov     [esp], eax; FileName
		E8 [4]                  call    _access
		83 F8 FF                cmp     eax, 0FFFFFFFFh
		74 ??                   jz      short loc_40176D
		8B [2]                  mov     eax, [ebp+FileName]
		89 ?? 24 04             mov     [esp+4], eax
		C7 04 24 [4]            mov     dword ptr [esp], offset aWarningSExists; "Warning: %s exists\n"
		E8 [4]                  call    log
		E9 [4]                  jmp     locret_401871
		C7 44 24 18 00 00 00 00 mov     dword ptr [esp+18h], 0; hTemplateFile
		C7 44 24 14 80 01 00 00 mov     dword ptr [esp+14h], 180h; dwFlagsAndAttributes
		C7 44 24 10 02 00 00 00 mov     dword ptr [esp+10h], 2; dwCreationDisposition
		C7 44 24 0C 00 00 00 00 mov     dword ptr [esp+0Ch], 0; lpSecurityAttributes
		C7 44 24 08 05 00 00 00 mov     dword ptr [esp+8], 5; dwShareMode
		C7 44 24 04 00 00 00 40 mov     dword ptr [esp+4], 40000000h; dwDesiredAccess
		8B [2]                  mov     eax, [ebp+FileName]
		89 04 24                mov     [esp], eax; lpFileName
		E8 [4]                  call    CreateFileA
		83 EC 1C                sub     esp, 1Ch
		89 45 ??                mov     [ebp+hFile], eax
	*/

	$dropFile = {
			C7 44 24 04 00 00 00 00
			8B [2]
			89 ?? 24 
			E8 [4]
			83 F8 FF
			74 ?? 
			8B [2]
			89 ?? 24 04 
			C7 04 24 [4]
			E8 [4]
			E9 [4]
			C7 44 24 18 00 00 00 00
			C7 44 24 14 80 01 00 00
			C7 44 24 10 02 00 00 00
			C7 44 24 0C 00 00 00 00
			C7 44 24 08 05 00 00 00
			C7 44 24 04 00 00 00 40
			8B [2]
			89 04 24
			E8 [4]
			83 EC 1C
			89 45 ?? 
		}

	$nfp = "npf.sys" nocase
	$wpcap = "wpcap.dll" nocase
			
	condition:
		all of them
}

rule CobaltStrike_Resources_Dnsstager_Bin_v1_47_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/dnsstager.bin signature for versions 1.47 to 4.x"
		hash =  "10f946b88486b690305b87c14c244d7bc741015c3fef1c4625fa7f64917897f1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		31 ??     xor     eax, eax
		AC        lodsb
		C1 ?? 0D  ror     edi, 0Dh
		01 ??     add     edi, eax
		38 ??     cmp     al, ah
		75 ??     jnz     short loc_10000054
		03 [2]    add     edi, [ebp-8]
		3B [2]    cmp     edi, [ebp+24h]
		75 ??     jnz     short loc_1000004A
		5?        pop     eax
		8B ?? 24  mov     ebx, [eax+24h]
		01 ??     add     ebx, edx
		66 8B [2] mov     cx, [ebx+ecx*2]
		8B ?? 1C  mov     ebx, [eax+1Ch]
		01 ??     add     ebx, edx
		8B ?? 8B  mov     eax, [ebx+ecx*4]
		01 ??     add     eax, edx
		89 [3]    mov     [esp+28h+var_4], eax
		5?        pop     ebx
		5?        pop     ebx
	*/

	$apiLocator = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}

    // the signature for the stagers overlap significantly. Looking for dnsstager.bin specific bytes helps delineate sample types
	  $dnsapi = { 68 64 6E 73 61 }	
	
	condition:
		$apiLocator and $dnsapi
}

rule CobaltStrike_Resources_Elevate_Dll_v3_0_to_v3_14_and_Sleeve_Elevate_Dll_v4_x
{
	meta:
		description = "Cobalt Strike's resources/elevate.dll signature for v3.0 to v3.14 and sleeve/elevate.dll for v4.x"
		hash =  "6deeb2cafe9eeefe5fc5077e63cc08310f895e9d5d492c88c4e567323077aa2f"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		6A 00               push    0; lParam
		6A 28               push    28h ; '('; wParam
		68 00 01 00 00      push    100h; Msg
		5?                  push    edi; hWnd
		C7 [5] 01 00 00 00  mov     dword_10017E70, 1
		FF ??               call    esi ; PostMessageA
		6A 00               push    0; lParam
		6A 27               push    27h ; '''; wParam
		68 00 01 00 00      push    100h; Msg
		5?                  push    edi; hWnd
		FF ??               call    esi ; PostMessageA
		6A 00               push    0; lParam
		6A 00               push    0; wParam
		68 01 02 00 00      push    201h; Msg
		5?                  push    edi; hWnd
		FF ??               call    esi ; PostMessageA
	*/

	$wnd_proc = {
			6A 00
			6A 28
			68 00 01 00 00
			5? 
			C7 [5] 01 00 00 00 
			FF ?? 
			6A 00
			6A 27
			68 00 01 00 00
			5? 
			FF ?? 
			6A 00
			6A 00
			68 01 02 00 00
			5? 
			FF ?? 
		}

		
	condition:
		$wnd_proc
}

rule CobaltStrike_Resources_Elevate_X64_Dll_v3_0_to_v3_14_and_Sleeve_Elevate_X64_Dll_v4_x
{
	meta:
		description = "Cobalt Strike's resources/elevate.x64.dll signature for v3.0 to v3.14 and sleeve/elevate.x64.dll for v4.x"
		hash =  "c3ee8a9181fed39cec3bd645b32b611ce98d2e84c5a9eff31a8acfd9c26410ec"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		81 FA 21 01 00 00             cmp     edx, 121h
		75 4A                         jnz     short loc_1800017A9
		83 3D 5A 7E 01 00 00          cmp     cs:dword_1800195C0, 0
		75 41                         jnz     short loc_1800017A9
		45 33 C9                      xor     r9d, r9d; lParam
		8D 57 DF                      lea     edx, [rdi-21h]; Msg
		C7 05 48 7E 01 00 01 00 00 00 mov     cs:dword_1800195C0, 1
		45 8D 41 28                   lea     r8d, [r9+28h]; wParam
		FF 15 36 DB 00 00             call    cs:PostMessageA
		45 33 C9                      xor     r9d, r9d; lParam
		8D 57 DF                      lea     edx, [rdi-21h]; Msg
		45 8D 41 27                   lea     r8d, [r9+27h]; wParam
		48 8B CB                      mov     rcx, rbx; hWnd
		FF 15 23 DB 00 00             call    cs:PostMessageA
		45 33 C9                      xor     r9d, r9d; lParam
		45 33 C0                      xor     r8d, r8d; wParam
		BA 01 02 00 00                mov     edx, 201h; Msg
		48 8B CB                      mov     rcx, rbx; hWnd
	*/

	$wnd_proc = {
			81 ?? 21 01 00 00
			75 ??
			83 [5] 00
			75 ??
			45 33 ??
			8D [2]
			C7 [5] 01 00 00 00
			45 [2] 28
			FF 15 [4]
			45 33 ??
			8D [2]
			45 [2] 27
			48 [2]
			FF 15 [4]
			45 33 ??
			45 33 ??
			BA 01 02 00 00
			48 
		}

	condition:
		$wnd_proc
}

rule CobaltStrike_Resources_Httpsstager64_Bin_v3_2_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/httpsstager64.bin signature for versions v3.2 to v4.x"
		hash =  "109b8c55816ddc0defff360c93e8a07019ac812dd1a42209ea7e95ba79b5a573"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		48 31 C0       xor     rax, rax
		AC             lodsb
		41 C1 C9 0D    ror     r9d, 0Dh
		41 01 C1       add     r9d, eax
		38 E0          cmp     al, ah
		75 F1          jnz     short loc_100000000000007D
		4C 03 4C 24 08 add     r9, [rsp+40h+var_38]
		45 39 D1       cmp     r9d, r10d
		75 D8          jnz     short loc_100000000000006E
		58             pop     rax
		44 8B 40 24    mov     r8d, [rax+24h]
		49 01 D0       add     r8, rdx
		66 41 8B 0C 48 mov     cx, [r8+rcx*2]
		44 8B 40 1C    mov     r8d, [rax+1Ch]
		49 01 D0       add     r8, rdx
		41 8B 04 88    mov     eax, [r8+rcx*4]
		48 01 D0       add     rax, rdx
	*/

	$apiLocator = {
			48 [2]
			AC
			41 [2] 0D
			41 [2]
			38 ??
			75 ??
			4C [4]
			45 [2]
			75 ??
			5?
			44 [2] 24
			49 [2]
			66 [4]
			44 [2] 1C
			49 [2]
			41 [3]
			48 
		}


  // the signature for httpstager64 and httpsstager64 really only differ by the flags passed to WinInet API
  // and the inclusion of the InternetSetOptionA call. We will trigger off that API
	/*
		BA 1F 00 00 00    mov     edx, 1Fh
		6A 00             push    0
		68 80 33 00 00    push    3380h
		49 89 E0          mov     r8, rsp
		41 B9 04 00 00 00 mov     r9d, 4
		41 BA 75 46 9E 86 mov     r10d, InternetSetOptionA
	*/

	$InternetSetOptionA = {
			BA 1F 00 00 00
			6A 00
			68 80 33 00 00
			49 [2]
			41 ?? 04 00 00 00
			41 ?? 75 46 9E 86
		}	
	
	condition:
		$apiLocator and $InternetSetOptionA
}

rule CobaltStrike_Resources_Httpsstager_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/httpsstager.bin signature for versions 2.5 to 4.x"
		hash =  "5ebe813a4c899b037ac0ee0962a439833964a7459b7a70f275ac73ea475705b3"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		31 ??     xor     eax, eax
		AC        lodsb
		C1 ?? 0D  ror     edi, 0Dh
		01 ??     add     edi, eax
		38 ??     cmp     al, ah
		75 ??     jnz     short loc_10000054
		03 [2]    add     edi, [ebp-8]
		3B [2]    cmp     edi, [ebp+24h]
		75 ??     jnz     short loc_1000004A
		5?        pop     eax
		8B ?? 24  mov     ebx, [eax+24h]
		01 ??     add     ebx, edx
		66 8B [2] mov     cx, [ebx+ecx*2]
		8B ?? 1C  mov     ebx, [eax+1Ch]
		01 ??     add     ebx, edx
		8B ?? 8B  mov     eax, [ebx+ecx*4]
		01 ??     add     eax, edx
		89 [3]    mov     [esp+28h+var_4], eax
		5?        pop     ebx
		5?        pop     ebx
	*/

	$apiLocator = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}

  // the signature for httpstager and httpsstager really only differ by the flags passed to WinInet API
  // and the inclusion of the InternetSetOptionA call. We will trigger off that API
	/*
		6A 04          push    4
		5?             push    eax
		6A 1F          push    1Fh
		5?             push    esi
		68 75 46 9E 86 push    InternetSetOptionA
		FF ??          call    ebp
	*/

	$InternetSetOptionA = {
			6A 04
			5? 
			6A 1F
			5? 
			68 75 46 9E 86
			FF  
		}
	
	condition:
		$apiLocator and $InternetSetOptionA
}

rule CobaltStrike_Resources_Httpstager64_Bin_v3_2_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/httpstager64.bin signature for versions v3.2 to v4.x"
		hash =  "ad93d1ee561bc25be4a96652942f698eac9b133d8b35ab7e7d3489a25f1d1e76"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		48 31 C0       xor     rax, rax
		AC             lodsb
		41 C1 C9 0D    ror     r9d, 0Dh
		41 01 C1       add     r9d, eax
		38 E0          cmp     al, ah
		75 F1          jnz     short loc_100000000000007D
		4C 03 4C 24 08 add     r9, [rsp+40h+var_38]
		45 39 D1       cmp     r9d, r10d
		75 D8          jnz     short loc_100000000000006E
		58             pop     rax
		44 8B 40 24    mov     r8d, [rax+24h]
		49 01 D0       add     r8, rdx
		66 41 8B 0C 48 mov     cx, [r8+rcx*2]
		44 8B 40 1C    mov     r8d, [rax+1Ch]
		49 01 D0       add     r8, rdx
		41 8B 04 88    mov     eax, [r8+rcx*4]
		48 01 D0       add     rax, rdx
	*/

	$apiLocator = {
			48 [2]
			AC
			41 [2] 0D
			41 [2]
			38 ??
			75 ??
			4C [4]
			45 [2]
			75 ??
			5?
			44 [2] 24
			49 [2]
			66 [4]
			44 [2] 1C
			49 [2]
			41 [3]
			48 
		}


  // the signature for httpstager64 and httpsstager64 really the inclusion or exclusion of InternetSetOptionA. However,
  // there is a subtle difference in the jmp after the InternetOpenA call (short jmp for x86 and long jmp for x64)
	/*
		41 BA 3A 56 79 A7 mov     r10d, InternetOpenA
		FF D5             call    rbp
		EB 61             jmp     short j_get_c2_ip
	*/

	$postInternetOpenJmp = {
			41 ?? 3A 56 79 A7
			FF ??
			EB 
		}

	
	condition:
		$apiLocator and $postInternetOpenJmp
}

rule CobaltStrike_Resources_Httpstager_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/httpstager.bin signature for versions 2.5 to 4.x"
		hash =  "a47569af239af092880751d5e7b68d0d8636d9f678f749056e702c9b063df256"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		31 ??     xor     eax, eax
		AC        lodsb
		C1 ?? 0D  ror     edi, 0Dh
		01 ??     add     edi, eax
		38 ??     cmp     al, ah
		75 ??     jnz     short loc_10000054
		03 [2]    add     edi, [ebp-8]
		3B [2]    cmp     edi, [ebp+24h]
		75 ??     jnz     short loc_1000004A
		5?        pop     eax
		8B ?? 24  mov     ebx, [eax+24h]
		01 ??     add     ebx, edx
		66 8B [2] mov     cx, [ebx+ecx*2]
		8B ?? 1C  mov     ebx, [eax+1Ch]
		01 ??     add     ebx, edx
		8B ?? 8B  mov     eax, [ebx+ecx*4]
		01 ??     add     eax, edx
		89 [3]    mov     [esp+28h+var_4], eax
		5?        pop     ebx
		5?        pop     ebx
	*/

	$apiLocator = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}

  // the signature for httpstager and httpsstager really only differ by the flags passed to WinInet API
  // and the httpstager controls the download loop slightly different than the httpsstager
	/*
		B? 00 2F 00 00  mov     edi, 2F00h
		39 ??           cmp     edi, eax
		74 ??           jz      short loc_100000E9
		31 ??           xor     edi, edi
		E9 [4]          jmp     loc_100002CA      // opcode could also be EB for a short jump (v2.5-v3.10)
	*/

	$downloaderLoop = {
			B? 00 2F 00 00 
			39 ?? 
			74 ?? 
			31 ?? 
			( E9 | EB )
		}

	condition:
		$apiLocator and $downloaderLoop
}

rule CobaltStrike_Resources_Reverse64_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/reverse64.bin signature for versions v2.5 to v4.x"
		hash =  "d2958138c1b7ef681a63865ec4a57b0c75cc76896bf87b21c415b7ec860397e8"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		48 31 C0       xor     rax, rax
		AC             lodsb
		41 C1 C9 0D    ror     r9d, 0Dh
		41 01 C1       add     r9d, eax
		38 E0          cmp     al, ah
		75 F1          jnz     short loc_100000000000007D
		4C 03 4C 24 08 add     r9, [rsp+40h+var_38]
		45 39 D1       cmp     r9d, r10d
		75 D8          jnz     short loc_100000000000006E
		58             pop     rax
		44 8B 40 24    mov     r8d, [rax+24h]
		49 01 D0       add     r8, rdx
		66 41 8B 0C 48 mov     cx, [r8+rcx*2]
		44 8B 40 1C    mov     r8d, [rax+1Ch]
		49 01 D0       add     r8, rdx
		41 8B 04 88    mov     eax, [r8+rcx*4]
		48 01 D0       add     rax, rdx
	*/

	$apiLocator = {
			48 [2]
			AC
			41 [2] 0D
			41 [2]
			38 ??
			75 ??
			4C [4]
			45 [2]
			75 ??
			5?
			44 [2] 24
			49 [2]
			66 [4]
			44 [2] 1C
			49 [2]
			41 [3]
			48 
		}


  // the signature for reverse64 and bind really differ slightly, here we are using the lack of additional calls
  // found in reverse64 to differentate between this and bind64
  // Note that we can reasonably assume that the constants being passed to the call rbp will be just that, constant,
  // since we are triggering on the API hasher. If that hasher is unchanged, then the hashes we look for should be
  // unchanged. This means we can use these values as anchors in our signature.
	/*
		41 BA EA 0F DF E0 mov     r10d, WSASocketA
		FF D5             call    rbp
		48 89 C7          mov     rdi, rax
		6A 10             push    10h
		41 58             pop     r8
		4C 89 E2          mov     rdx, r12
		48 89 F9          mov     rcx, rdi
		41 BA 99 A5 74 61 mov     r10d, connect
		FF D5             call    rbp
	*/

	$calls = {
			48 89 C1
			41 BA EA 0F DF E0
			FF D5
			48 [2]
			6A ??
			41 ??
			4C [2]
			48 [2]
			41 BA 99 A5 74 61
			FF D5
		}
	condition:
		$apiLocator and $calls
}

rule CobaltStrike_Resources_Reverse_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/reverse.bin signature for versions 2.5 to 4.x"
		hash =  "887f666d6473058e1641c3ce1dd96e47189a59c3b0b85c8b8fccdd41b84000c7"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		31 ??     xor     eax, eax
		AC        lodsb
		C1 ?? 0D  ror     edi, 0Dh
		01 ??     add     edi, eax
		38 ??     cmp     al, ah
		75 ??     jnz     short loc_10000054
		03 [2]    add     edi, [ebp-8]
		3B [2]    cmp     edi, [ebp+24h]
		75 ??     jnz     short loc_1000004A
		5?        pop     eax
		8B ?? 24  mov     ebx, [eax+24h]
		01 ??     add     ebx, edx
		66 8B [2] mov     cx, [ebx+ecx*2]
		8B ?? 1C  mov     ebx, [eax+1Ch]
		01 ??     add     ebx, edx
		8B ?? 8B  mov     eax, [ebx+ecx*4]
		01 ??     add     eax, edx
		89 [3]    mov     [esp+28h+var_4], eax
		5?        pop     ebx
		5?        pop     ebx
	*/

	$apiLocator = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}

    // the signature for the stagers overlap significantly. Looking for reverse.bin specific bytes helps delineate sample types
	/*
		5D             pop     ebp
		68 33 32 00 00 push    '23'
		68 77 73 32 5F push    '_2sw'
	*/

	$ws2_32 = {
			5D
			68 33 32 00 00
			68 77 73 32 5F
		}


  // reverse.bin makes outbound connection (using connect) while bind.bin listens for incoming connections (using listen)
  // so the presence of the connect API hash is a solid method for distinguishing between the two.
	/*
		6A 10          push    10h
		[0]5?          push    esi
		5?             push    edi
		68 99 A5 74 61 push    connect
	*/
	$connect = {
			6A 10
			5? 
			5? 
			68 99 A5 74 61
		}
	
	condition:
		$apiLocator and $ws2_32 and $connect
}

rule CobaltStrike_Resources_Smbstager_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/smbstager.bin signature for versions 2.5 to 4.x"
		hash =  "946af5a23e5403ea1caccb2e0988ec1526b375a3e919189f16491eeabc3e7d8c"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		31 ??     xor     eax, eax
		AC        lodsb
		C1 ?? 0D  ror     edi, 0Dh
		01 ??     add     edi, eax
		38 ??     cmp     al, ah
		75 ??     jnz     short loc_10000054
		03 [2]    add     edi, [ebp-8]
		3B [2]    cmp     edi, [ebp+24h]
		75 ??     jnz     short loc_1000004A
		5?        pop     eax
		8B ?? 24  mov     ebx, [eax+24h]
		01 ??     add     ebx, edx
		66 8B [2] mov     cx, [ebx+ecx*2]
		8B ?? 1C  mov     ebx, [eax+1Ch]
		01 ??     add     ebx, edx
		8B ?? 8B  mov     eax, [ebx+ecx*4]
		01 ??     add     eax, edx
		89 [3]    mov     [esp+28h+var_4], eax
		5?        pop     ebx
		5?        pop     ebx
	*/

	$apiLocator = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}

    // the signature for the stagers overlap significantly. Looking for smbstager.bin specific bytes helps delineate sample types
	  $smb = { 68 C6 96 87 52 }	
	  
	  // This code block helps differentiate between smbstager.bin and metasploit's engine which has reasonable level of overlap
	  	/*
		6A 40          push    40h ; '@'
		68 00 10 00 00 push    1000h
		68 FF FF 07 00 push    7FFFFh
		6A 00          push    0
		68 58 A4 53 E5 push    VirtualAlloc
	*/

	$smbstart = {
			6A 40
			68 00 10 00 00
			68 FF FF 07 00
			6A 00
			68 58 A4 53 E5
		}
	
	condition:
		$apiLocator and $smb and $smbstart
}

rule CobaltStrike_Resources_Template_Py_v3_3_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/template.py signature for versions v3.3 to v4.x"
		hash =  "d5cb406bee013f51d876da44378c0a89b7b3b800d018527334ea0c5793ea4006"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:   
    $arch = "platform.architecture()"
    $nope = "WindowsPE"
    $alloc = "ctypes.windll.kernel32.VirtualAlloc"
    $movemem = "ctypes.windll.kernel32.RtlMoveMemory"
    $thread = "ctypes.windll.kernel32.CreateThread"
    $wait = "ctypes.windll.kernel32.WaitForSingleObject"

  condition:
    all of them
}

rule CobaltStrike_Resources_Template_Sct_v3_3_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/template.sct signature for versions v3.3 to v4.x"
		hash =  "fc66cb120e7bc9209882620f5df7fdf45394c44ca71701a8662210cf3a40e142"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
    $scriptletstart = "<scriptlet>" nocase
    $registration = "<registration progid=" nocase
    $classid = "classid=" nocase
		$scriptlang = "<script language=\"vbscript\">" nocase
		$cdata = "<![CDATA["
    $scriptend = "</script>" nocase
	  $antiregistration = "</registration>" nocase
    $scriptletend = "</scriptlet>"

  condition:
    all of them and @scriptletstart[1] < @registration[1] and @registration[1] < @classid[1] and @classid[1] < @scriptlang[1] and @scriptlang[1] < @cdata[1]
}

rule CobaltStrike_Resources__Template_Vbs_v3_3_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/btemplate.vbs signature for versions v3.3 to v4.x"
		hash =  "e0683f953062e63b2aabad7bc6d76a78748504b114329ef8e2ece808b3294135"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	  $ea = "Excel.Application" nocase
    $vis = "Visible = False" nocase
    $wsc = "Wscript.Shell" nocase
    $regkey1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\" nocase
    $regkey2 = "\\Excel\\Security\\AccessVBOM" nocase
    $regwrite = ".RegWrite" nocase
    $dw = "REG_DWORD"
    $code = ".CodeModule.AddFromString"
	 /* Hex encoded Auto_*/ /*Open */
    $ao = { 41 75 74 6f 5f 4f 70 65 6e }
    $da = ".DisplayAlerts"

  condition:
    all of them
}

rule CobaltStrike_Resources_Template__x32_x64_Ps1_v1_45_to_v2_5_and_v3_11_to_v3_14
{
	meta:
		description = "Cobalt Strike's resources/template.x64.ps1, resources/template.x32 from v3.11 to v3.14 and resources/template.ps1 from v1.45 to v2.5 "
		hash =  "ff743027a6bcc0fee02107236c1f5c96362eeb91f3a5a2e520a85294741ded87"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	
		$importVA = "[DllImport(\"kernel32.dll\")] public static extern IntPtr VirtualAlloc" nocase
		$importCT = "[DllImport(\"kernel32.dll\")] public static extern IntPtr CreateThread" nocase
		$importWFSO = "[DllImport(\"kernel32.dll\")] public static extern int WaitForSingleObject" nocase
    $compiler = "New-Object Microsoft.CSharp.CSharpCodeProvider" nocase
    $params = "New-Object System.CodeDom.Compiler.CompilerParameters" nocase
    $paramsSys32 = ".ReferencedAssemblies.AddRange(@(\"System.dll\", [PsObject].Assembly.Location))" nocase
    $paramsGIM = ".GenerateInMemory = $True" nocase
    $result = "$compiler.CompileAssemblyFromSource($params, $assembly)" nocase
    //$data = "[Byte[]]$var_code = [System.Convert]::FromBase64String(" nocase

    //$64bitSpecific = "[IntPtr]::size -eq 8"
    
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Template_x64_Ps1_v3_0_to_v4_x_excluding_3_12_3_13
{
	meta:
		description = "Cobalt Strike's resources/template.x64.ps1, resources/template.hint.x64.ps1 and resources/template.hint.x32.ps1 from v3.0 to v4.x except 3.12 and 3.13"
		hash =  "ff743027a6bcc0fee02107236c1f5c96362eeb91f3a5a2e520a85294741ded87"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
    $dda = "[AppDomain]::CurrentDomain.DefineDynamicAssembly" nocase
    $imm = "InMemoryModule" nocase
    $mdt = "MyDelegateType" nocase
    $rd = "New-Object System.Reflection.AssemblyName('ReflectedDelegate')" nocase
    $data = "[Byte[]]$var_code = [System.Convert]::FromBase64String(" nocase
    $64bitSpecific = "[IntPtr]::size -eq 8"
    $mandatory = "Mandatory = $True"
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Template_x86_Vba_v3_8_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/template.x86.vba signature for versions v3.8 to v4.x"
		hash =  "fc66cb120e7bc9209882620f5df7fdf45394c44ca71701a8662210cf3a40e142"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
    $createstuff = "Function CreateStuff Lib \"kernel32\" Alias \"CreateRemoteThread\"" nocase
    $allocstuff = "Function AllocStuff Lib \"kernel32\" Alias \"VirtualAllocEx\"" nocase
    $writestuff = "Function WriteStuff Lib \"kernel32\" Alias \"WriteProcessMemory\"" nocase
    $runstuff = "Function RunStuff Lib \"kernel32\" Alias \"CreateProcessA\"" nocase
    $vars = "Dim rwxpage As Long" nocase
    $res = "RunStuff(sNull, sProc, ByVal 0&, ByVal 0&, ByVal 1&, ByVal 4&, ByVal 0&, sNull, sInfo, pInfo)"
    $rwxpage = "AllocStuff(pInfo.hProcess, 0, UBound(myArray), &H1000, &H40)"

  condition:
    all of them and @vars[1] < @res[1] and @allocstuff[1] < @rwxpage[1]
}

rule CobaltStrike_Resources_Xor_Bin_v2_x_to_v4_x
{
	meta:
		description = "Cobalt Strike's resource/xor.bin signature for version 2.x through 4.x"
		hash =  "211ccc5d28b480760ec997ed88ab2fbc5c19420a3d34c1df7991e65642638a6f"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	  /* The method for making this signatures consists of extracting each stub from the various resources/xor.bin files
	     in the cobaltstrike.jar files. For each stub found, sort them by byte count (size). Then for all entries in the 
	     same size category, compare them nibble by nibble. Any mismatched nibbles get 0'd. After all stubs have been
	     compared to each other thereby creating a mask, any 0 nibbles are turned to ? wildcards. The results are seen below */
    $stub52 = {fc e8 ?? ?? ?? ?? [1-32] eb 27 5? 8b ??    83 c? ?4 8b ??    31 ?? 83 c? ?4 5? 8b ??    31 ?? 89 ??    31 ?? 83 c? ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb ea 5? ff e? e8 d4 ff ff ff}
    $stub56 = {fc e8 ?? ?? ?? ?? [1-32] eb 2b 5d 8b ?? ?? 83 c5 ?4 8b ?? ?? 31 ?? 83 c5 ?4 55 8b ?? ?? 31 ?? 89 ?? ?? 31 ?? 83 c5 ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb e8 5? ff e? e8 d? ff ff ff}

  condition:
    any of them
}


rule CobaltStrike_Resources_Xor_Bin__64bit_v3_12_to_v4_x
{
	meta:
		description = "Cobalt Strike's resource/xor64.bin signature for version 3.12 through 4.x"
		hash =  "01dba8783768093b9a34a1ea2a20f72f29fd9f43183f3719873df5827a04b744"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	  /* The method for making this signatures consists of extracting each stub from the various resources/xor64.bin files
	     in the cobaltstrike.jar files. For each stub found, sort them by byte count (size). Then for all entries in the 
	     same size category, compare them nibble by nibble. Any mismatched nibbles get 0'd. After all stubs have been
	     compared to each other thereby creating a mask, any 0 nibbles are turned to ? wildcards. The results are seen below */

    $stub58 = {fc e8 ?? ?? ?? ?? [1-32] eb 33 5? 8b ?? 00 4? 83 ?? ?4 8b ?? 00 31 ?? 4? 83 ?? ?4 5? 8b ?? 00 31 ?? 89 ?? 00 31 ?? 4? 83 ?? ?4 83 ?? ?4 31 ?? 39 ?? 74 ?2 eb e7 5? fc 4? 83 ?? f0 ff}
    $stub59 = {fc e8 ?? ?? ?? ?? [1-32] eb 2e 5? 8b ??    48 83 c? ?4 8b ??    31 ?? 48 83 c? ?4 5? 8b ??    31 ?? 89 ??    31 ?? 48 83 c? ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb e9 5?    48 83 ec ?8 ff e? e8 cd ff ff ff}
    $stub63 = {fc e8 ?? ?? ?? ?? [1-32] eb 32 5d 8b ?? ?? 48 83 c5 ?4 8b ?? ?? 31 ?? 48 83 c5 ?4 55 8b ?? ?? 31 ?? 89 ?? ?? 31 ?? 48 83 c5 ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb e7 5?    48 83 ec ?8 ff e? e8 c9 ff ff ff}
  
  condition:
    any of them
}

rule CobaltStrike_Sleeve_BeaconLoader_HA_x86_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.HA.x86.o (HeapAlloc) Versions 4.3 through at least 4.6"
    hash =  "8e4a1862aa3693f0e9011ade23ad3ba036c76ae8ccfb6585dc19ceb101507dcd"
    author = "gssincla@google.com"
    reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
    date = "2022-11-18"
   
  strings:
    /*
      C6 45 F0 48 mov     [ebp+var_10], 48h ; 'H'
      C6 45 F1 65 mov     [ebp+var_F], 65h ; 'e'
      C6 45 F2 61 mov     [ebp+var_E], 61h ; 'a'
      C6 45 F3 70 mov     [ebp+var_D], 70h ; 'p'
      C6 45 F4 41 mov     [ebp+var_C], 41h ; 'A'
      C6 45 F5 6C mov     [ebp+var_B], 6Ch ; 'l'
      C6 45 F6 6C mov     [ebp+var_A], 6Ch ; 'l'
      C6 45 F7 6F mov     [ebp+var_9], 6Fh ; 'o'
      C6 45 F8 63 mov     [ebp+var_8], 63h ; 'c'
      C6 45 F9 00 mov     [ebp+var_7], 0
    */

    $core_sig = {
      C6 45 F0 48
      C6 45 F1 65
      C6 45 F2 61
      C6 45 F3 70
      C6 45 F4 41
      C6 45 F5 6C
      C6 45 F6 6C
      C6 45 F7 6F
      C6 45 F8 63
      C6 45 F9 00
    }

    // These strings can narrow down the specific version
    //$ver_43 = { 9B 2C 3E 60 }         // Version 4.3
    //$ver_44_45_46 = { 55 F8 86 5F }   // Versions 4.4, 4.5, and 4.6
    
  condition:
    all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_MVF_x86_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.MVF.x86.o (MapViewOfFile) Versions 4.3 through at least 4.6"
    hash =  "cded3791caffbb921e2afa2de4c04546067c3148c187780066e8757e67841b44"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      C6 45 EC 4D mov     [ebp+var_14], 4Dh ; 'M'
      C6 45 ED 61 mov     [ebp+var_13], 61h ; 'a'
      C6 45 EE 70 mov     [ebp+var_12], 70h ; 'p'
      C6 45 EF 56 mov     [ebp+var_11], 56h ; 'V'
      C6 45 F0 69 mov     [ebp+var_10], 69h ; 'i'
      C6 45 F1 65 mov     [ebp+var_F], 65h ; 'e'
      C6 45 F2 77 mov     [ebp+var_E], 77h ; 'w'
      C6 45 F3 4F mov     [ebp+var_D], 4Fh ; 'O'
      C6 45 F4 66 mov     [ebp+var_C], 66h ; 'f'
      C6 45 F5 46 mov     [ebp+var_B], 46h ; 'F'
      C6 45 F6 69 mov     [ebp+var_A], 69h ; 'i'
      C6 45 F7 6C mov     [ebp+var_9], 6Ch ; 'l'
      C6 45 F8 65 mov     [ebp+var_8], 65h ; 'e'
      C6 45 F9 00 mov     [ebp+var_7], 0
    */

    $core_sig = {
      C6 45 EC 4D
      C6 45 ED 61
      C6 45 EE 70
      C6 45 EF 56
      C6 45 F0 69
      C6 45 F1 65
      C6 45 F2 77
      C6 45 F3 4F
      C6 45 F4 66
      C6 45 F5 46
      C6 45 F6 69
      C6 45 F7 6C
      C6 45 F8 65
      C6 45 F9 00
    }

    // These strings can narrow down the specific version
    //$ver_43 = { 9C 2C 3E 60 }         // Version 4.3
    //$ver_44_45_46 = { 55 F8 86 5F }   // Versions 4.4, 4.5, and 4.6
    
  condition:
    all of them
}


rule CobaltStrike_Sleeve_BeaconLoader_VA_x86_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.VA.x86.o (VirtualAlloc) Versions 4.3 through at least 4.6"
    hash =  "94d1b993a9d5786e0a9b44ea1c0dc27e225c9eb7960154881715c47f9af78cc1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      C6 45 B0 56 mov     [ebp+var_50], 56h ; 'V'
      C6 45 B1 69 mov     [ebp+var_50+1], 69h ; 'i'
      C6 45 B2 72 mov     [ebp+var_50+2], 72h ; 'r'
      C6 45 B3 74 mov     [ebp+var_50+3], 74h ; 't'
      C6 45 B4 75 mov     [ebp+var_50+4], 75h ; 'u'
      C6 45 B5 61 mov     [ebp+var_50+5], 61h ; 'a'
      C6 45 B6 6C mov     [ebp+var_50+6], 6Ch ; 'l'
      C6 45 B7 41 mov     [ebp+var_50+7], 41h ; 'A'
      C6 45 B8 6C mov     [ebp+var_50+8], 6Ch ; 'l'
      C6 45 B9 6C mov     [ebp+var_50+9], 6Ch ; 'l'
      C6 45 BA 6F mov     [ebp+var_50+0Ah], 6Fh ; 'o'
      C6 45 BB 63 mov     [ebp+var_50+0Bh], 63h ; 'c'
      C6 45 BC 00 mov     [ebp+var_50+0Ch], 0
    */

    $core_sig = {
      C6 45 B0 56
      C6 45 B1 69
      C6 45 B2 72
      C6 45 B3 74
      C6 45 B4 75
      C6 45 B5 61
      C6 45 B6 6C
      C6 45 B7 41
      C6 45 B8 6C
      C6 45 B9 6C
      C6 45 BA 6F
      C6 45 BB 63
      C6 45 BC 00
    }

    /*
      8B 4D FC    mov     ecx, [ebp+var_4]
      83 C1 01    add     ecx, 1
      89 4D FC    mov     [ebp+var_4], ecx
      8B 55 FC    mov     edx, [ebp+var_4]
      3B 55 0C    cmp     edx, [ebp+arg_4]
      73 19       jnb     short loc_231
      0F B6 45 10 movzx   eax, [ebp+arg_8]
      8B 4D 08    mov     ecx, [ebp+arg_0]
      03 4D FC    add     ecx, [ebp+var_4]
      0F BE 11    movsx   edx, byte ptr [ecx]
      33 D0       xor     edx, eax
      8B 45 08    mov     eax, [ebp+arg_0]
      03 45 FC    add     eax, [ebp+var_4]
      88 10       mov     [eax], dl
      EB D6       jmp     short loc_207
    */

    $deobfuscator = {
      8B 4D FC
      83 C1 01
      89 4D FC
      8B 55 FC
      3B 55 0C
      73 19
      0F B6 45 10
      8B 4D 08
      03 4D FC
      0F BE 11
      33 D0
      8B 45 08
      03 45 FC
      88 10
      EB D6
    }
    
  condition:
    all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_x86_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.x86.o Versions 4.3 through at least 4.6"
    hash =  "94d1b993a9d5786e0a9b44ea1c0dc27e225c9eb7960154881715c47f9af78cc1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      C6 45 B0 56 mov     [ebp+var_50], 56h ; 'V'
      C6 45 B1 69 mov     [ebp+var_50+1], 69h ; 'i'
      C6 45 B2 72 mov     [ebp+var_50+2], 72h ; 'r'
      C6 45 B3 74 mov     [ebp+var_50+3], 74h ; 't'
      C6 45 B4 75 mov     [ebp+var_50+4], 75h ; 'u'
      C6 45 B5 61 mov     [ebp+var_50+5], 61h ; 'a'
      C6 45 B6 6C mov     [ebp+var_50+6], 6Ch ; 'l'
      C6 45 B7 41 mov     [ebp+var_50+7], 41h ; 'A'
      C6 45 B8 6C mov     [ebp+var_50+8], 6Ch ; 'l'
      C6 45 B9 6C mov     [ebp+var_50+9], 6Ch ; 'l'
      C6 45 BA 6F mov     [ebp+var_50+0Ah], 6Fh ; 'o'
      C6 45 BB 63 mov     [ebp+var_50+0Bh], 63h ; 'c'
      C6 45 BC 00 mov     [ebp+var_50+0Ch], 0
    */

    $core_sig = {
      C6 45 B0 56
      C6 45 B1 69
      C6 45 B2 72
      C6 45 B3 74
      C6 45 B4 75
      C6 45 B5 61
      C6 45 B6 6C
      C6 45 B7 41
      C6 45 B8 6C
      C6 45 B9 6C
      C6 45 BA 6F
      C6 45 BB 63
      C6 45 BC 00
    }

    /*
      8B 4D FC    mov     ecx, [ebp+var_4]
      83 C1 01    add     ecx, 1
      89 4D FC    mov     [ebp+var_4], ecx
      8B 55 FC    mov     edx, [ebp+var_4]
      3B 55 0C    cmp     edx, [ebp+arg_4]
      73 19       jnb     short loc_231
      0F B6 45 10 movzx   eax, [ebp+arg_8]
      8B 4D 08    mov     ecx, [ebp+arg_0]
      03 4D FC    add     ecx, [ebp+var_4]
      0F BE 11    movsx   edx, byte ptr [ecx]
      33 D0       xor     edx, eax
      8B 45 08    mov     eax, [ebp+arg_0]
      03 45 FC    add     eax, [ebp+var_4]
      88 10       mov     [eax], dl
      EB D6       jmp     short loc_207
    */

    $deobfuscator = {
      8B 4D FC
      83 C1 01
      89 4D FC
      8B 55 FC
      3B 55 0C
      73 19
      0F B6 45 10
      8B 4D 08
      03 4D FC
      0F BE 11
      33 D0
      8B 45 08
      03 45 FC
      88 10
      EB D6
    }
    
  condition:
    $core_sig and not $deobfuscator
}


// 64-bit BeaconLoaders

rule CobaltStrike_Sleeve_BeaconLoader_HA_x64_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.HA.x64.o (HeapAlloc) Versions 4.3 through at least 4.6"
    hash =  "d64f10d5a486f0f2215774e8ab56087f32bef19ac666e96c5627c70d345a354d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      C6 44 24 38 48 mov     [rsp+78h+var_40], 48h ; 'H'
      C6 44 24 39 65 mov     [rsp+78h+var_3F], 65h ; 'e'
      C6 44 24 3A 61 mov     [rsp+78h+var_3E], 61h ; 'a'
      C6 44 24 3B 70 mov     [rsp+78h+var_3D], 70h ; 'p'
      C6 44 24 3C 41 mov     [rsp+78h+var_3C], 41h ; 'A'
      C6 44 24 3D 6C mov     [rsp+78h+var_3B], 6Ch ; 'l'
      C6 44 24 3E 6C mov     [rsp+78h+var_3A], 6Ch ; 'l'
      C6 44 24 3F 6F mov     [rsp+78h+var_39], 6Fh ; 'o'
      C6 44 24 40 63 mov     [rsp+78h+var_38], 63h ; 'c'
      C6 44 24 41 00 mov     [rsp+78h+var_37], 0
    */

    $core_sig = {
      C6 44 24 38 48
      C6 44 24 39 65
      C6 44 24 3A 61
      C6 44 24 3B 70
      C6 44 24 3C 41
      C6 44 24 3D 6C
      C6 44 24 3E 6C
      C6 44 24 3F 6F
      C6 44 24 40 63
      C6 44 24 41 00
    }

    // These strings can narrow down the specific version
    //$ver_43 = { 96 2C 3E 60 }         // Version 4.3
    //$ver_44_45_46 = { D1 56 86 5F }   // Versions 4.4, 4.5, and 4.6
    
  condition:
    all of them
}


rule CobaltStrike_Sleeve_BeaconLoader_MVF_x64_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.MVF.x64.o (MapViewOfFile) Versions 4.3 through at least 4.6"
    hash =  "9d5b6ccd0d468da389657309b2dc325851720390f9a5f3d3187aff7d2cd36594"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      C6 44 24 58 4D mov     [rsp+98h+var_40], 4Dh ; 'M'
      C6 44 24 59 61 mov     [rsp+98h+var_3F], 61h ; 'a'
      C6 44 24 5A 70 mov     [rsp+98h+var_3E], 70h ; 'p'
      C6 44 24 5B 56 mov     [rsp+98h+var_3D], 56h ; 'V'
      C6 44 24 5C 69 mov     [rsp+98h+var_3C], 69h ; 'i'
      C6 44 24 5D 65 mov     [rsp+98h+var_3B], 65h ; 'e'
      C6 44 24 5E 77 mov     [rsp+98h+var_3A], 77h ; 'w'
      C6 44 24 5F 4F mov     [rsp+98h+var_39], 4Fh ; 'O'
      C6 44 24 60 66 mov     [rsp+98h+var_38], 66h ; 'f'
      C6 44 24 61 46 mov     [rsp+98h+var_37], 46h ; 'F'
      C6 44 24 62 69 mov     [rsp+98h+var_36], 69h ; 'i'
      C6 44 24 63 6C mov     [rsp+98h+var_35], 6Ch ; 'l'
      C6 44 24 64 65 mov     [rsp+98h+var_34], 65h ; 'e'
    */

    $core_sig = {
      C6 44 24 58 4D
      C6 44 24 59 61
      C6 44 24 5A 70
      C6 44 24 5B 56
      C6 44 24 5C 69
      C6 44 24 5D 65
      C6 44 24 5E 77
      C6 44 24 5F 4F
      C6 44 24 60 66
      C6 44 24 61 46
      C6 44 24 62 69
      C6 44 24 63 6C
      C6 44 24 64 65
    }

    // These strings can narrow down the specific version
    //$ver_43 = { 96 2C 3E 60 }         // Version 4.3
    //$ver_44_45_46 = { D2 57 86 5F }   // Versions 4.4, 4.5, and 4.6
    
  condition:
    all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_VA_x64_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.VA.x64.o (VirtualAlloc) Versions 4.3 through at least 4.6"
    hash =  "ac090a0707aa5ccd2c645b523bd23a25999990cf6895fce3bfa3b025e3e8a1c9"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      C6 44 24 48 56 mov     [rsp+88h+var_40], 56h ; 'V'
      C6 44 24 49 69 mov     [rsp+88h+var_40+1], 69h ; 'i'
      C6 44 24 4A 72 mov     [rsp+88h+var_40+2], 72h ; 'r'
      C6 44 24 4B 74 mov     [rsp+88h+var_40+3], 74h ; 't'
      C6 44 24 4C 75 mov     [rsp+88h+var_40+4], 75h ; 'u'
      C6 44 24 4D 61 mov     [rsp+88h+var_40+5], 61h ; 'a'
      C6 44 24 4E 6C mov     [rsp+88h+var_40+6], 6Ch ; 'l'
      C6 44 24 4F 41 mov     [rsp+88h+var_40+7], 41h ; 'A'
      C6 44 24 50 6C mov     [rsp+88h+var_40+8], 6Ch ; 'l'
      C6 44 24 51 6C mov     [rsp+88h+var_40+9], 6Ch ; 'l'
      C6 44 24 52 6F mov     [rsp+88h+var_40+0Ah], 6Fh ; 'o'
      C6 44 24 53 63 mov     [rsp+88h+var_40+0Bh], 63h ; 'c'
      C6 44 24 54 00 mov     [rsp+88h+var_40+0Ch], 0
    */

    $core_sig = {
      C6 44 24 48 56
      C6 44 24 49 69
      C6 44 24 4A 72
      C6 44 24 4B 74
      C6 44 24 4C 75
      C6 44 24 4D 61
      C6 44 24 4E 6C
      C6 44 24 4F 41
      C6 44 24 50 6C
      C6 44 24 51 6C
      C6 44 24 52 6F
      C6 44 24 53 63
      C6 44 24 54 00
    }


    /*
      8B 04 24       mov     eax, [rsp+18h+var_18]
      FF C0          inc     eax
      89 04 24       mov     [rsp+18h+var_18], eax
      8B 44 24 28    mov     eax, [rsp+18h+arg_8]
      39 04 24       cmp     [rsp+18h+var_18], eax
      73 20          jnb     short loc_2E7
      8B 04 24       mov     eax, [rsp+18h+var_18]
      0F B6 4C 24 30 movzx   ecx, [rsp+18h+arg_10]
      48 8B 54 24 20 mov     rdx, [rsp+18h+arg_0]
      0F BE 04 02    movsx   eax, byte ptr [rdx+rax]
      33 C1          xor     eax, ecx
      8B 0C 24       mov     ecx, [rsp+18h+var_18]
      48 8B 54 24 20 mov     rdx, [rsp+18h+arg_0]
      88 04 0A       mov     [rdx+rcx], al
    */

    $deobfuscator = {
      8B 04 24
      FF C0
      89 04 24
      8B 44 24 28
      39 04 24
      73 20
      8B 04 24
      0F B6 4C 24 30
      48 8B 54 24 20
      0F BE 04 02
      33 C1
      8B 0C 24
      48 8B 54 24 20
      88 04 0A
    }

    
  condition:
    all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_x64_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.x64.o (Base) Versions 4.3 through at least 4.6"
    hash =  "ac090a0707aa5ccd2c645b523bd23a25999990cf6895fce3bfa3b025e3e8a1c9"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      33 C0                      xor     eax, eax
      83 F8 01                   cmp     eax, 1
      74 63                      jz      short loc_378
      48 8B 44 24 20             mov     rax, [rsp+38h+var_18]
      0F B7 00                   movzx   eax, word ptr [rax]
      3D 4D 5A 00 00             cmp     eax, 5A4Dh
      75 45                      jnz     short loc_369
      48 8B 44 24 20             mov     rax, [rsp+38h+var_18]
      48 63 40 3C                movsxd  rax, dword ptr [rax+3Ch]
      48 89 44 24 28             mov     [rsp+38h+var_10], rax
      48 83 7C 24 28 40          cmp     [rsp+38h+var_10], 40h ; '@'
      72 2F                      jb      short loc_369
      48 81 7C 24 28 00 04 00 00 cmp     [rsp+38h+var_10], 400h
      73 24                      jnb     short loc_369
      48 8B 44 24 20             mov     rax, [rsp+38h+var_18]
      48 8B 4C 24 28             mov     rcx, [rsp+38h+var_10]
      48 03 C8                   add     rcx, rax
      48 8B C1                   mov     rax, rcx
      48 89 44 24 28             mov     [rsp+38h+var_10], rax
      48 8B 44 24 28             mov     rax, [rsp+38h+var_10]
      81 38 50 45 00 00          cmp     dword ptr [rax], 4550h
      75 02                      jnz     short loc_369
    */

    $core_sig = {
      33 C0
      83 F8 01
      74 63
      48 8B 44 24 20
      0F B7 00
      3D 4D 5A 00 00
      75 45
      48 8B 44 24 20
      48 63 40 3C
      48 89 44 24 28
      48 83 7C 24 28 40
      72 2F
      48 81 7C 24 28 00 04 00 00
      73 24
      48 8B 44 24 20
      48 8B 4C 24 28
      48 03 C8
      48 8B C1
      48 89 44 24 28
      48 8B 44 24 28
      81 38 50 45 00 00
      75 02
    }

    /*
      8B 04 24       mov     eax, [rsp+18h+var_18]
      FF C0          inc     eax
      89 04 24       mov     [rsp+18h+var_18], eax
      8B 44 24 28    mov     eax, [rsp+18h+arg_8]
      39 04 24       cmp     [rsp+18h+var_18], eax
      73 20          jnb     short loc_2E7
      8B 04 24       mov     eax, [rsp+18h+var_18]
      0F B6 4C 24 30 movzx   ecx, [rsp+18h+arg_10]
      48 8B 54 24 20 mov     rdx, [rsp+18h+arg_0]
      0F BE 04 02    movsx   eax, byte ptr [rdx+rax]
      33 C1          xor     eax, ecx
      8B 0C 24       mov     ecx, [rsp+18h+var_18]
      48 8B 54 24 20 mov     rdx, [rsp+18h+arg_0]
      88 04 0A       mov     [rdx+rcx], al
    */

    $deobfuscator = {
      8B 04 24
      FF C0
      89 04 24
      8B 44 24 28
      39 04 24
      73 20
      8B 04 24
      0F B6 4C 24 30
      48 8B 54 24 20
      0F BE 04 02
      33 C1
      8B 0C 24
      48 8B 54 24 20
      88 04 0A
    }

    
  condition:
    $core_sig and not $deobfuscator
}

rule malware_CobaltStrike_v3v4 {
          meta:
            description = "detect CobaltStrike Beacon in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "https://blogs.jpcert.or.jp/en/2018/08/volatility-plugin-for-detecting-cobalt-strike-beacon.html"
            hash1 = "154db8746a9d0244146648006cc94f120390587e02677b97f044c25870d512c3"
            hash2 = "f9b93c92ed50743cd004532ab379e3135197b6fb5341322975f4d7a98a0fcde7"

          strings:
            $v1 = { 73 70 72 6E 67 00 }
            $config3 = { 69 69 69 69 69 69 69 69 }
            $config4 = { 2E 2E 2E 2E 2E 2E 2E 2E }

          condition:
            $v1 and 1 of ($config*)
}

rule malware_CobaltStrike_beacon {
     meta:
        description = "CobaltStrike encoding code"
        author = "JPCERT/CC Incident Response Group"
        hash = "1957d8e71c1b14be9b9bde928b47629d8283b8165015647b429f83d11a0d6fb3"
        hash = "4b2b14c79d6476af373f319548ac9e98df3be14319850bec3856ced9a7804237"

     strings:
        $code1 = { 5? 8B ?? 83 C? 04 8B ?? 31 ?? 83 C? 04 5? 8B ?? 31 ?? 89 ?? 31 ?? 83 C? 04 83 E? 04 31 ?? 39 ?? 74 02 EB E? 5? FF E? E8 ?? FF FF FF }
        $code2 = { 5D 8B ?? 00 83 C? 04 8B ?? 00 31 ?? 83 C? 04 5? 8B ?? 00 31 ?? 89 ?? 00 31 ?? 83 C? 04 83 E? 04 31 ?? 39 ?? 74 02 EB E? 5? FF E? E8 ?? FF FF FF }

     condition:
        uint16(0) == 0xE8FC and
        $code1 in (6..200) or $code2 in (6..200)
}

rule Sliver_Implant_32bit
{
  meta:
    description = "Sliver 32-bit implant (with and without --debug flag at compile)"
    hash =  "911f4106350871ddb1396410d36f2d2eadac1166397e28a553b28678543a9357"
    author = "gssincla@google.com"
    reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
    date = "2022-11-18"
    modified = "2022-11-19"

  strings:
    // We look for the specific switch/case statement case values.

    // case "tcppivot":
    /*
      81 ?? 74 63 70 70     cmp     dword ptr [ecx], 70706374h
      .
      .
      .
      81 ?? 04 69 76 6F 74  cmp     dword ptr [ecx+4], 746F7669h
    */
    $s_tcppivot = { 81 ?? 74 63 70 70 [2-20] 81 ?? 04 69 76 6F 74  }

    // case "wg":
    /*
      66 81 ?? 77 67 cmp     word ptr [eax], 6777h      // "gw"
    */
    $s_wg = { 66 81 ?? 77 67 }

    // case "dns":
    /*
      66 81 ?? 64 6E cmp     word ptr [eax], 6E64h    // "nd"
      .
      .
      .
      80 ?? 02 73    cmp     byte ptr [eax+2], 73h ; 's'
    */
    $s_dns = { 66 81 ?? 64 6E [2-20] 80 ?? 02 73 }

    // case "http":
    /*
      81 ?? 68 74 74 70  cmp     dword ptr [eax], 70747468h     // "ptth"
     */
    $s_http = { 81 ?? 68 74 74 70 }

    // case "https":
    /*
      81 ?? 68 74 74 70  cmp     dword ptr [ecx], 70747468h     // "ptth"
      .
      .
      .
      80 ?? 04 73        cmp     byte ptr [ecx+4], 73h ; 's'
    */
    $s_https = { 81 ?? 68 74 74 70 [2-20] 80 ?? 04 73 }

    // case "mtls":       NOTE: this one can be missing due to compilate time config
    /*
      81 ?? 6D 74 6C 73  cmp     dword ptr [eax], 736C746Dh     // "sltm"
    */
    $s_mtls = { 81 ?? 6D 74 6C 73 }

    $fp1 = "cloudfoundry" ascii fullword
  condition:
    4 of ($s*) and not 1 of ($fp*)
}


rule Sliver_Implant_64bit
{
  meta:
    description = "Sliver 64-bit implant (with and without --debug flag at compile)"
    hash =  "2d1c9de42942a16c88a042f307f0ace215cdc67241432e1152080870fe95ea87"
    author = "gssincla@google.com"
    reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
    date = "2022-11-18"
    modified = "2022-11-19"

  strings:
    // We look for the specific switch/case statement case values.

    // case "tcppivot":
    /*
      48 ?? 74 63 70 70 69 76 6F 74 mov     rcx, 746F766970706374h
    */
    $s_tcppivot = { 48 ?? 74 63 70 70 69 76 6F 74 }


    // case "namedpipe":
    /*
      48 ?? 6E 61 6D 65 64 70 69 70 mov     rsi, 70697064656D616Eh      // "pipdeman"
      .
      .
      .
      80 ?? 08 65 cmp     byte ptr [rdx+8], 65h ; 'e'

    */
    $s_namedpipe = { 48 ?? 6E 61 6D 65 64 70 69 70 [2-32] 80 ?? 08 65 }

    // case "https":
    /*
      81 3A 68 74 74 70 cmp     dword ptr [rdx], 70747468h          // "ptth"
      .
      .
      .
      80 7A 04 73       cmp     byte ptr [rdx+4], 73h ; 's'
    */
    $s_https = { 81 ?? 68 74 74 70 [2-32] 80 ?? 04 73 }

    // case "wg":
    /*
      66 81 3A 77 67 cmp     word ptr [rdx], 6777h      // "gw"
    */
    $s_wg = {66 81 ?? 77 67}


    // case "dns":
    /*
      66 81 3A 64 6E cmp     word ptr [rdx], 6E64h     // "nd"
      .
      .
      .
      80 7A 02 73    cmp     byte ptr [rdx+2], 73h ; 's'
    */
    $s_dns = { 66 81 ?? 64 6E [2-20] 80 ?? 02 73 }

    // case "mtls":         // This one may or may not be in the file, depending on the config flags.
    /*
       81 ?? 6D 74 6C 73 cmp   dword ptr [rdx], 736C746Dh          // "mtls"
    */
    $s_mtls = {  81 ?? 6D 74 6C 73  }

    $fp1 = "cloudfoundry" ascii fullword
  condition:
    5 of ($s*) and not 1 of ($fp*)
}

rule Quasar_RAT_1 {
   meta:
      description = "Detects Quasar RAT"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
      date = "2017-04-07"
      hash1 = "0774d25e33ca2b1e2ee2fafe3fdbebecefbf1d4dd99e6460f0bc8713dd0fd740"
      hash2 = "1ce40a89ef9d56fd32c00db729beecc17d54f4f7c27ff22f708a957cd3f9a4ec"
      hash3 = "515c1a68995557035af11d818192f7866ef6a2018aa13112fefbe08395732e89"
      hash4 = "f08db220df716de3d4f63f3007a03f902601b9b32099d6a882da87312f263f34"
      id = "36220de3-aa1a-5c34-adae-432d939c811e"
   strings:
      $s1 = "DoUploadAndExecute" fullword ascii
      $s2 = "DoDownloadAndExecute" fullword ascii
      $s3 = "DoShellExecute" fullword ascii
      $s4 = "set_Processname" fullword ascii

      $op1 = { 04 1e fe 02 04 16 fe 01 60 }
      $op2 = { 00 17 03 1f 20 17 19 15 28 }
      $op3 = { 00 04 03 69 91 1b 40 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and all of ($s*) or all of ($op*) )
}

rule Quasar_RAT_2 {
   meta:
      description = "Detects Quasar RAT"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
      date = "2017-04-07"
      super_rule = 1
      hash1 = "0774d25e33ca2b1e2ee2fafe3fdbebecefbf1d4dd99e6460f0bc8713dd0fd740"
      hash2 = "515c1a68995557035af11d818192f7866ef6a2018aa13112fefbe08395732e89"
      hash3 = "f08db220df716de3d4f63f3007a03f902601b9b32099d6a882da87312f263f34"
      id = "0ca795c5-3631-5a99-8675-37558485f478"
   strings:
      $x1 = "GetKeyloggerLogsResponse" fullword ascii
      $x2 = "get_Keylogger" fullword ascii
      $x3 = "HandleGetKeyloggerLogsResponse" fullword ascii

      $s1 = "DoShellExecuteResponse" fullword ascii
      $s2 = "GetPasswordsResponse" fullword ascii
      $s3 = "GetStartupItemsResponse" fullword ascii
      $s4 = "<GetGenReader>b__7" fullword ascii
      $s5 = "RunHidden" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and $x1 ) or ( all of them )
}

rule MAL_QuasarRAT_May19_1 {
   meta:
      description = "Detects QuasarRAT malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blog.ensilo.com/uncovering-new-activity-by-apt10"
      date = "2019-05-27"
      modified = "2023-01-06"
      hash1 = "0644e561225ab696a97ba9a77583dcaab4c26ef0379078c65f9ade684406eded"
      id = "a4e82b6a-31f8-59fc-acfa-805c4594680a"
   strings:
      $x1 = "Quasar.Common.Messages" ascii fullword
      $x2 = "Client.MimikatzTools" ascii fullword
      $x3 = "Resources.powerkatz_x86.dll" ascii fullword
      $x4 = "Uninstalling... good bye :-(" wide

      $xc1 = { 41 00 64 00 6D 00 69 00 6E 00 00 11 73 00 63 00
               68 00 74 00 61 00 73 00 6B 00 73 00 00 1B 2F 00
               63 00 72 00 65 00 61 00 74 00 65 00 20 00 2F 00
               74 00 6E 00 20 00 22 00 00 27 22 00 20 00 2F 00
               73 }
      $xc2 = { 00 70 00 69 00 6E 00 67 00 20 00 2D 00 6E 00 20
               00 31 00 30 00 20 00 6C 00 6F 00 63 00 61 00 6C
               00 68 00 6F 00 73 00 74 00 20 00 3E 00 20 00 6E
               00 75 00 6C 00 0D 00 0A 00 64 00 65 00 6C 00 20
               00 2F 00 61 00 20 00 2F 00 71 00 20 00 2F 00 66
               00 20 00 }
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and 1 of them
}

rule malware_Quasar_strings {
          meta:
            description = "detect QuasarRAT in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            hash1 = "390c1530ff62d8f4eddff0ac13bc264cbf4183e7e3d6accf8f721ffc5250e724"

          strings:
            $quasarstr1 = "Client.exe" wide
            $quasarstr2 = "({0}:{1}:{2})" wide
            $sql1 = "SELECT * FROM Win32_DisplayConfiguration" wide
            $sql2 = "{0}d : {1}h : {2}m : {3}s" wide
            $sql3 = "SELECT * FROM FirewallProduct" wide
            $net1 = "echo DONT CLOSE THIS WINDOW!" wide
            $net2 = "freegeoip.net/xml/" wide
            $net3 = "http://api.ipify.org/" wide
            $resource = { 52 00 65 00 73 00 6F 00 75 00 72 00 63 00 65 00 73 00 00 17 69 00 6E 00 66 00 6F 00 72 00 6D 00 61 00 74 00 69 00 6F 00 6E 00 00 }

          condition:
            ((all of ($quasarstr*) or all of ($sql*)) and $resource) or all of ($net*)
}

rule meterpreter_reverse_tcp_shellcode {
    meta:
        author = "FDD @ Cuckoo sandbox"
        description = "Rule for metasploit's  meterpreter reverse tcp raw shellcode"

    strings:
        $s1 = { fce8 8?00 0000 60 }     // shellcode prologe in metasploit
        $s2 = { 648b ??30 }             // mov edx, fs:[???+0x30]
        $s3 = { 4c77 2607 }             // kernel32 checksum
        $s4 = "ws2_"                    // ws2_32.dll
        $s5 = { 2980 6b00 }             // WSAStartUp checksum
        $s6 = { ea0f dfe0 }             // WSASocket checksum
        $s7 = { 99a5 7461 }             // connect checksum

    condition:
        all of them and filesize < 5KB
}

rule meterpreter_reverse_tcp_shellcode_rev1 {
    meta:
        author = "FDD @ Cuckoo sandbox"
        description = "Meterpreter reverse TCP shell rev1"
        LHOST = 0xae
        LPORT = 0xb5

    strings:
        $s1 = { 6a00 53ff d5 }

    condition:
        meterpreter_reverse_tcp_shellcode and $s1 in (270..filesize)
}

rule meterpreter_reverse_tcp_shellcode_rev2 {
    meta:
        author = "FDD @ Cuckoo sandbox"
        description = "Meterpreter reverse TCP shell rev2"
        LHOST = 194
        LPORT = 201

    strings:
        $s1 = { 75ec c3 }

    condition:
        meterpreter_reverse_tcp_shellcode and $s1 in (270..filesize)
}

rule meterpreter_reverse_tcp_shellcode_domain {
    meta:
        author = "FDD @ Cuckoo sandbox"
        description = "Variant used if the user specifies a domain instead of a hard-coded IP"

    strings:
        $s1 = { a928 3480 }             // Checksum for gethostbyname
        $domain = /(\w+\.)+\w{2,6}/

    condition:
        meterpreter_reverse_tcp_shellcode and all of them
}

rule metasploit_download_exec_shellcode_rev1 {
    meta:
        author = "FDD @ Cuckoo Sandbox"
        description = "Rule for metasploit's download and exec shellcode"
        name = "Metasploit download & exec payload"
        URL = 185

    strings:
        $s1 = { fce8 8?00 0000 60 }     // shellcode prologe in metasploit
        $s2 = { 648b ??30 }             // mov edx, fs:[???+0x30]
        $s4 = { 4c77 2607 }             // checksum for LoadLibraryA
        $s5 = { 3a56 79a7 }             // checksum for InternetOpenA
        $s6 = { 5789 9fc6 }             // checksum for InternetConnectA
        $s7 = { eb55 2e3b }             // checksum for HTTPOpenRequestA
        $s8 = { 7546 9e86 }             // checksum for InternetSetOptionA
        $s9 = { 2d06 187b }             // checksum for HTTPSendRequestA
        $url = /\/[\w_\-\.]+/

    condition:
        all of them and filesize < 5KB
}

rule metasploit_download_exec_shellcode_rev2 {
    meta:
        author = "FDD @ Cuckoo Sandbox"
        description = "Rule for metasploit's download and exec shellcode"
        name = "Metasploit download & exec payload"
        URL = 185

    strings:
        $s1 = { fce8 8?00 0000 60 }     // shellcode prologe in metasploit
        $s2 = { 648b ??30 }             // mov edx, fs:[???+0x30]
        $s4 = { 4c77 2607 }             // checksum for LoadLibraryA
        $s5 = { 3a56 79a7 }             // checksum for InternetOpenA
        $s6 = { 5789 9fc6 }             // checksum for InternetConnectA
        $s7 = { eb55 2e3b }             // checksum for HTTPOpenRequestA
        $s9 = { 2d06 187b }             // checksum for HTTPSendRequestA
        $url = /\/[\w_\-\.]+/

    condition:
        all of them and filesize < 5KB
}

rule metasploit_bind_shell {
    meta:
        author = "FDD @ Cuckoo Sandbox"
        description = "Rule for metasploit's bind shell shellcode"
        name = "Metasploit bind shell payload"

    strings:
        $s1 = { fce8 8?00 0000 60 }     // shellcode prologe in metasploit
        $s2 = { 648b ??30 }             // mov edx, fs:[???+0x30]
        $s3 = { 4c77 2607 }             // checksum for LoadLibraryA
        $s4 = { 2980 6b00 }             // checksum for WSAStartup
        $s5 = { ea0f dfe0 }             // checksum for WSASocketA
        $s6 = { c2db 3767 }             // checksum for bind
        $s7 = { b7e9 38ff }             // checksum for listen
        $s8 = { 74ec 3be1 }             // checksum for accept

    condition:
        all of them and filesize < 5KB
}

rule Msfpayloads_msf {
   meta:
      description = "Metasploit Payloads - file msf.sh"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      modified = "2022-08-18"
      hash1 = "320a01ec4e023fb5fbbaef963a2b57229e4f918847e5a49c7a3f631cb556e96c"
      id = "c56dbb8e-1e03-5112-b2ef-a0adfd14dffa"
   strings:
      $s1 = "export buf=\\" ascii
   condition:
      filesize < 5MB and $s1
}

rule Msfpayloads_msf_2 {
   meta:
      description = "Metasploit Payloads - file msf.asp"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "e52f98466b92ee9629d564453af6f27bd3645e00a9e2da518f5a64a33ccf8eb5"
      id = "ec1ae1b6-18a3-5590-ae15-1e2b362c545a"
   strings:
      $s1 = "& \"\\\" & \"svchost.exe\"" fullword ascii
      $s2 = "CreateObject(\"Wscript.Shell\")" fullword ascii
      $s3 = "<% @language=\"VBScript\" %>" fullword ascii
   condition:
      all of them
}

rule Msfpayloads_msf_psh {
   meta:
      description = "Metasploit Payloads - file msf-psh.vba"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "5cc6c7f1aa75df8979be4a16e36cece40340c6e192ce527771bdd6463253e46f"
      id = "5b760f03-b0f8-5871-bd34-e7e44443530c"
   strings:
      $s1 = "powershell.exe -nop -w hidden -e" ascii
      $s2 = "Call Shell(" ascii
      $s3 = "Sub Workbook_Open()" fullword ascii
   condition:
      all of them
}

rule Msfpayloads_msf_exe {
   meta:
      description = "Metasploit Payloads - file msf-exe.vba"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "321537007ea5052a43ffa46a6976075cee6a4902af0c98b9fd711b9f572c20fd"
      id = "fd07240e-0ee0-5318-a436-d97054e92414"
   strings:
      $s1 = "'* PAYLOAD DATA" fullword ascii
      $s2 = " = Shell(" ascii
      $s3 = "= Environ(\"USERPROFILE\")" fullword ascii
      $s4 = "'**************************************************************" fullword ascii
      $s5 = "ChDir (" ascii
      $s6 = "'* MACRO CODE" fullword ascii
   condition:
      4 of them
}

rule Msfpayloads_msf_3 {
   meta:
      description = "Metasploit Payloads - file msf.psh"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "335cfb85e11e7fb20cddc87e743b9e777dc4ab4e18a39c2a2da1aa61efdbd054"
      id = "ad09167f-a12a-5f07-940b-df679fa8e6c0"
   strings:
      $s1 = "[DllImport(\"kernel32.dll\")] public static extern int WaitForSingleObject(" ascii
      $s2 = "public enum MemoryProtection { ExecuteReadWrite = 0x40 }" fullword ascii
      $s3 = ".func]::VirtualAlloc(0,"
      $s4 = ".func+AllocationType]::Reserve -bOr [" ascii
      $s5 = "New-Object System.CodeDom.Compiler.CompilerParameters" fullword ascii
      $s6 = "ReferencedAssemblies.AddRange(@(\"System.dll\", [PsObject].Assembly.Location))" fullword ascii
      $s7 = "public enum AllocationType { Commit = 0x1000, Reserve = 0x2000 }" fullword ascii
      $s8 = ".func]::CreateThread(0,0,$" fullword ascii
      $s9 = "public enum Time : uint { Infinite = 0xFFFFFFFF }" fullword ascii
      $s10 = "= [System.Convert]::FromBase64String(\"/" ascii
      $s11 = "{ $global:result = 3; return }" fullword ascii
   condition:
      4 of them
}

rule Msfpayloads_msf_4 {
   meta:
      description = "Metasploit Payloads - file msf.aspx"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "26b3e572ba1574164b76c6d5213ab02e4170168ae2bcd2f477f246d37dbe84ef"
      id = "00d7681b-6041-5fe1-adbb-8b7c40df0193"
   strings:
      $s1 = "= VirtualAlloc(IntPtr.Zero,(UIntPtr)" ascii
      $s2 = ".Length,MEM_COMMIT, PAGE_EXECUTE_READWRITE);" ascii
      $s3 = "[System.Runtime.InteropServices.DllImport(\"kernel32\")]" fullword ascii
      $s4 = "private static IntPtr PAGE_EXECUTE_READWRITE=(IntPtr)0x40;" fullword ascii
      $s5 = "private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr,UIntPtr size,Int32 flAllocationType,IntPtr flProtect);" fullword ascii
   condition:
      4 of them
}

rule Msfpayloads_msf_exe_2 {
   meta:
      description = "Metasploit Payloads - file msf-exe.aspx"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "3a2f7a654c1100e64d8d3b4cd39165fba3b101bbcce6dd0f70dae863da338401"
      id = "a55a33e1-8f04-5417-af0c-b7e2da36fb46"
   strings:
      $x1 = "= new System.Diagnostics.Process();" fullword ascii
      $x2 = ".StartInfo.UseShellExecute = true;" fullword ascii
      $x3 = ", \"svchost.exe\");" ascii
      $s4 = " = Path.GetTempPath();" ascii
   condition:
      all of them
}

rule Msfpayloads_msf_5 {
   meta:
      description = "Metasploit Payloads - file msf.msi"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "7a6c66dfc998bf5838993e40026e1f400acd018bde8d4c01ef2e2e8fba507065"
      id = "030d1982-c9a8-539d-a995-7901ae425857"
   strings:
      $s1 = "required to install Foobar 1.0." fullword ascii
      $s2 = "Copyright 2009 The Apache Software Foundation." fullword wide
      $s3 = "{50F36D89-59A8-4A40-9689-8792029113AC}" fullword ascii
   condition:
      all of them
}

rule Msfpayloads_msf_6 {
   meta:
      description = "Metasploit Payloads - file msf.vbs"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "8d6f55c6715c4a2023087c3d0d7abfa21e31a629393e4dc179d31bb25b166b3f"
      id = "5485102b-e709-5111-814a-e6878b4bd889"
   strings:
      $s1 = "= CreateObject(\"Wscript.Shell\")" fullword ascii
      $s2 = "= CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
      $s3 = ".GetSpecialFolder(2)" ascii
      $s4 = ".Write Chr(CLng(\"" ascii
      $s5 = "= \"4d5a90000300000004000000ffff00" ascii
      $s6 = "For i = 1 to Len(" ascii
      $s7  = ") Step 2" ascii
   condition:
      5 of them
}

rule Msfpayloads_msf_7 {
   meta:
      description = "Metasploit Payloads - file msf.vba"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "425beff61a01e2f60773be3fcb74bdfc7c66099fe40b9209745029b3c19b5f2f"
      id = "8d1b742e-510a-5807-ad3f-f10cc325d292"
   strings:
      $s1 = "Private Declare PtrSafe Function CreateThread Lib \"kernel32\" (ByVal" ascii
      $s2 = "= VirtualAlloc(0, UBound(Tsw), &H1000, &H40)" fullword ascii
      $s3 = "= RtlMoveMemory(" ascii
   condition:
      all of them
}

rule Msfpayloads_msf_8 {
   meta:
      description = "Metasploit Payloads - file msf.ps1"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "519717e01f0cb3f460ef88cd70c3de8c7f00fb7c564260bd2908e97d11fde87f"
      id = "54466663-12ef-5fa4-a13c-e80ddbc0f4f8"
   strings:
      $s1 = "[DllImport(\"kernel32.dll\")]" fullword ascii
      $s2 = "[DllImport(\"msvcrt.dll\")]" fullword ascii
      $s3 = "-Name \"Win32\" -namespace Win32Functions -passthru" fullword ascii
      $s4 = "::VirtualAlloc(0,[Math]::Max($" ascii
      $s5 = ".Length,0x1000),0x3000,0x40)" ascii
      $s6 = "public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);" fullword ascii
      $s7 = "::memset([IntPtr]($" ascii
   condition:
      6 of them
}

rule Msfpayloads_msf_cmd {
   meta:
      description = "Metasploit Payloads - file msf-cmd.ps1"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "9f41932afc9b6b4938ee7a2559067f4df34a5c8eae73558a3959dd677cb5867f"
      id = "71d42c34-a0b0-5173-8f2f-f48a7af0e4ff"
   strings:
      $x1 = "%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -e" ascii
   condition:
      all of them
}

rule Msfpayloads_msf_9 {
   meta:
      description = "Metasploit Payloads - file msf.war - contents"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "e408678042642a5d341e8042f476ee7cef253871ef1c9e289acf0ee9591d1e81"
      id = "488a2e97-ebc2-5ccf-ab5d-dfed4b534b52"
   strings:
      $s1 = "if (System.getProperty(\"os.name\").toLowerCase().indexOf(\"windows\") != -1)" fullword ascii
      $s2 = ".concat(\".exe\");" fullword ascii
      $s3 = "[0] = \"chmod\";" ascii
      $s4 = "= Runtime.getRuntime().exec(" ascii
      $s5 = ", 16) & 0xff;" ascii

      $x1 = "4d5a9000030000000" ascii
   condition:
      4 of ($s*) or (
         uint32(0) == 0x61356434 and $x1 at 0
      )
}

rule Msfpayloads_msf_10 {
   meta:
      description = "Metasploit Payloads - file msf.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "3cd74fa28323c0d64f45507675ac08fb09bae4dd6b7e11f2832a4fbc70bb7082"
      id = "3bc3b66a-9f8a-55c2-ae2a-00faa778cef7"
   strings:
      $s1 = { 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff ac 3c 61 }
      $s2 = { 01 c7 38 e0 75 f6 03 7d f8 3b 7d 24 75 e4 58 8b }
      $s3 = { 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 5f 5f }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule Msfpayloads_msf_svc {
   meta:
      description = "Metasploit Payloads - file msf-svc.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "2b02c9c10577ee0c7590d3dadc525c494122747a628a7bf714879b8e94ae5ea1"
      id = "45d1c527-1f90-50f3-8e64-e77d69386b0a"
   strings:
      $s1 = "PAYLOAD:" fullword ascii
      $s2 = ".exehll" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 50KB and all of them )
}

rule Msfpayloads_msf_11 {
   meta:
      description = "Metasploit Payloads - file msf.hta"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "d1daf7bc41580322333a893133d103f7d67f5cd8a3e0f919471061d41cf710b6"
      id = "59b0cced-ffdc-5f2f-878c-856883ee275f"
   strings:
      $s1 = ".ExpandEnvironmentStrings(\"%PSModulePath%\") + \"..\\powershell.exe\") Then" fullword ascii
      $s2 = "= CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
      $s3 = "= CreateObject(\"Wscript.Shell\") " fullword ascii
   condition:
      all of them
}

rule Msfpayloads_msf_ref {
   meta:
      description = "Metasploit Payloads - file msf-ref.ps1"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "4ec95724b4c2b6cb57d2c63332a1dd6d4a0101707f42e3d693c9aab19f6c9f87"
      id = "517ed365-03c6-5563-984b-dae10464671a"
   strings:
      $s1 = "kernel32.dll WaitForSingleObject)," ascii
      $s2 = "= ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\\\')" ascii
      $s3 = "GetMethod('GetProcAddress').Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object" ascii
      $s4 = ".DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual'," ascii
      $s5 = "= [System.Convert]::FromBase64String(" ascii
      $s6 = "[Parameter(Position = 0, Mandatory = $True)] [Type[]]" fullword ascii
      $s7 = "DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard," ascii
   condition:
      5 of them
}

rule MAL_Metasploit_Framework_UA {
   meta:
      description = "Detects User Agent used in Metasploit Framework"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/rapid7/metasploit-framework/commit/12a6d67be48527f5d3987e40cac2a0cbb4ab6ce7"
      date = "2018-08-16"
      score = 65
      hash1 = "1743e1bd4176ffb62a1a0503a0d76033752f8bd34f6f09db85c2979c04bbdd29"
      id = "e5a18456-3a07-5b58-ad95-086152298a1f"
   strings:
      $s3 = "Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and 1 of them
}

rule HKTL_Meterpreter_inMemory {
   meta:
      description = "Detects Meterpreter in-memory"
      author = "netbiosX, Florian Roth"
      reference = "https://www.reddit.com/r/purpleteamsec/comments/hjux11/meterpreter_memory_indicators_detection_tooling/"
      date = "2020-06-29"
      modified = "2023-04-21"
      score = 85
      id = "29c3bb7e-4da8-5924-ada7-2f28d9352009"
   strings: 
      $sxc1 = { 6D 65 74 73 72 76 2E 64 6C 6C 00 00 52 65 66 6C 
               65 63 74 69 76 65 4C 6F 61 64 65 72 }
      $sxs1 = "metsrv.x64.dll" ascii fullword
      $ss1 = "WS2_32.dll" ascii fullword
      $ss2 = "ReflectiveLoader" ascii fullword

      $fp1 = "SentinelOne" ascii wide
      $fp2 = "fortiESNAC" ascii wide
      $fp3 = "PSNMVHookMS" ascii wide
   condition: 
      ( 1 of ($sx*) or 2 of ($s*) )
      and not 1 of ($fp*)
}
