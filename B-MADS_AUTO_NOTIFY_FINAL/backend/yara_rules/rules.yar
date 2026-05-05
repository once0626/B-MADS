import "math"

/////////////////////////////////////////////////
// 1️⃣ WINDOWS EXECUTABLES (.exe, .dll)
/////////////////////////////////////////////////
rule EXE_Advanced_Malware
{
    meta:
        category = "exe"
        severity = "high"

    strings:
        $ps = "powershell"
        $enc = "-enc"
        $iex = "IEX"
        $va = "VirtualAlloc"
        $wpm = "WriteProcessMemory"
        $crt = "CreateRemoteThread"

    condition:
        uint16(0) == 0x5A4D and
        (
            ($ps and 2 of ($enc,$iex)) or
            all of ($va,$wpm,$crt)
        )
}

/////////////////////////////////////////////////
// 2️⃣ PACKED / ENCRYPTED PAYLOAD (ANY FILE)
/////////////////////////////////////////////////
rule High_Entropy_Packed_File
{
    strings:
        $js = "/JavaScript"
        $open = "/OpenAction"
        $launch = "/Launch"
        $embed = "/EmbeddedFile"

    condition:
        filesize > 100KB and
        math.entropy(0, filesize) > 7.5 and
        any of ($js, $open, $launch, $embed)
}



/////////////////////////////////////////////////
// 3️⃣ FILELESS POWERSHELL ATTACK
/////////////////////////////////////////////////
rule PowerShell_Fileless_Attack
{
    meta:
        category = "fileless"
        severity = "critical"

    strings:
        $ps = "powershell"
        $enc = "-enc"
        $iex = "IEX"
        $b64 = "FromBase64String"
        $dl = "DownloadString"

    condition:
        $ps and 2 of ($enc,$iex,$b64,$dl)
}

/////////////////////////////////////////////////
// 4️⃣ MALICIOUS PDF
/////////////////////////////////////////////////
rule PDF_Weaponized
{
    meta:
        category = "pdf"
        severity = "medium"

    strings:
        $pdf = "%PDF"
        $js = "/JavaScript"
        $open = "/OpenAction"
        $eval = "eval("
        $launch = "/Launch"

    condition:
        $pdf at 0 and 2 of ($js,$open,$eval,$launch)
}

/////////////////////////////////////////////////
// 5️⃣ MS OFFICE MACRO MALWARE
/////////////////////////////////////////////////
rule Office_Macro_Malware
{
    meta:
        category = "office"
        severity = "critical"

    strings:
        $vba = "VBA"
        $auto = "AutoOpen"
        $shell = "Shell("
        $create = "CreateObject"
        $ps = "powershell"

    condition:
        2 of ($vba,$auto,$shell,$create,$ps)
}

/////////////////////////////////////////////////
// 6️⃣ POWERPOINT (.pptx)
/////////////////////////////////////////////////
rule PPTX_Malicious_Content
{
    meta:
        category = "pptx"
        severity = "medium"

    strings:
        $zip = { 50 4B 03 04 }
        $ole = "oleObject"
        $embed = "embeddedPackage"
        $cmd = "cmd.exe"
        $ps = "powershell"

    condition:
        $zip at 0 and 2 of ($ole,$embed,$cmd,$ps)
}

/////////////////////////////////////////////////
// 7️⃣ HTML / JAVASCRIPT MALWARE
/////////////////////////////////////////////////
rule HTML_JS_Malware
{
    meta:
        category = "html"
        severity = "high"

    strings:
        $script = "<script"
        $eval = "eval("
        $atob = "atob("
        $iframe = "<iframe"
        $redir = "window.location"

    condition:
        2 of ($script,$eval,$atob,$iframe,$redir)
}

/////////////////////////////////////////////////
// 8️⃣ MALICIOUS ZIP / ARCHIVES
/////////////////////////////////////////////////
rule ZIP_Malicious_Archive
{
    meta:
        category = "archive"
        severity = "medium"

    strings:
        $zip = { 50 4B 03 04 }
        $exe = ".exe"
        $js = ".js"
        $ps1 = ".ps1"

    condition:
        $zip at 0 and 1 of ($exe,$js,$ps1)
}

/////////////////////////////////////////////////
// 9️⃣ COMMAND & CONTROL INDICATORS
/////////////////////////////////////////////////
rule C2_Network_Indicators
{
    meta:
        category = "network"
        severity = "critical"

    strings:
        $http = "http://"
        $ua = "User-Agent"
        $post = "POST /"
        $ip = /[0-9]{1,3}(\.[0-9]{1,3}){3}/

    condition:
        all of ($http,$ua) and any of ($post,$ip)
}

/////////////////////////////////////////////////
// 🔟 SANDBOX / VM EVASION
/////////////////////////////////////////////////
rule Sandbox_Evasion
{
    meta:
        category = "evasion"
        severity = "medium"

    strings:
        $vm1 = "VIRTUALBOX"
        $vm2 = "VMware"
        $vm3 = "VBoxService"
        $sleep = "Sleep"
        $tick = "GetTickCount"

    condition:
        2 of ($vm*) and any of ($sleep,$tick)
}
