rule PHPWebshell : webshell php
{
    meta:
        description = "PHP webshell patterns"
        severity = "critical"
        author = "GhostForensics"
        mitre_attack = "T1505.003"

    strings:
        $php1 = "eval($_" nocase
        $php2 = "eval(base64_decode" nocase
        $php3 = "system($_GET" nocase
        $php4 = "passthru(" nocase
        $php5 = "shell_exec(" nocase
        $php6 = "exec($_" nocase
        $php7 = "assert($_" nocase
        $php8 = "preg_replace" nocase
        $php9 = "<?php @eval" nocase

    condition:
        2 of them
}

rule ASPXWebshell : webshell aspx
{
    meta:
        description = "ASPX webshell patterns"
        severity = "critical"
        author = "GhostForensics"
        mitre_attack = "T1505.003"

    strings:
        $asp1 = "Request.QueryString" nocase
        $asp2 = "Process.Start" nocase
        $asp3 = "cmd.exe" nocase
        $asp4 = "Response.Write" nocase
        $asp5 = "Server.Execute" nocase

    condition:
        ($asp1 and $asp2 and $asp3) or ($asp2 and $asp4 and $asp5)
}

rule JSPWebshell : webshell jsp
{
    meta:
        description = "JSP webshell patterns"
        severity = "critical"
        author = "GhostForensics"
        mitre_attack = "T1505.003"

    strings:
        $jsp1 = "Runtime.getRuntime().exec" nocase
        $jsp2 = "request.getParameter" nocase
        $jsp3 = "ProcessBuilder" nocase

    condition:
        $jsp1 and ($jsp2 or $jsp3)
}
