import yara

RULES = yara.compile(source="""
rule PowerShell_Malware {
    strings:
        $a = "Invoke-Expression"
        $b = "DownloadString"
        $c = "FromBase64String"
    condition:
        any of them
}

rule USB_Worm {
    strings:
        $a = "autorun.inf"
        $b = ".vbs"
        $c = ".cmd"
    condition:
        2 of them
}
""")
