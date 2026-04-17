rule CredentialHarvesting : credentials
{
    meta:
        description = "Credential harvesting tool indicators"
        severity = "critical"
        author = "GhostForensics"
        mitre_attack = "T1003"

    strings:
        $mimi1 = "mimikatz" nocase
        $mimi2 = "sekurlsa" nocase
        $mimi3 = "logonpasswords" nocase
        $mimi4 = "wdigest" nocase
        $mimi5 = "kerberos::list" nocase
        $mimi6 = "lsadump" nocase

        $lazagne1 = "lazagne" nocase
        $lazagne2 = "laZagne" nocase

        $dump1 = "procdump" nocase
        $dump2 = "comsvcs.dll" nocase
        $dump3 = "MiniDump" nocase
        $dump4 = "sekurlsa::logonPasswords" nocase

    condition:
        any of them
}

rule PasswordStrings : credentials
{
    meta:
        description = "Plaintext password patterns in memory"
        severity = "high"
        author = "GhostForensics"
        mitre_attack = "T1552.001"

    strings:
        $pw1 = "password=" nocase
        $pw2 = "passwd=" nocase
        $pw3 = "pwd=" nocase
        $pw4 = "credentials=" nocase
        $pw5 = "Authorization: Basic" nocase
        $pw6 = "Authorization: Bearer" nocase

    condition:
        2 of them
}

rule SSHKeys : credentials
{
    meta:
        description = "SSH private key material in memory"
        severity = "high"
        author = "GhostForensics"
        mitre_attack = "T1552.004"

    strings:
        $rsa = "-----BEGIN RSA PRIVATE KEY-----" ascii
        $openssh = "-----BEGIN OPENSSH PRIVATE KEY-----" ascii
        $ec = "-----BEGIN EC PRIVATE KEY-----" ascii
        $dsa = "-----BEGIN DSA PRIVATE KEY-----" ascii

    condition:
        any of them
}
