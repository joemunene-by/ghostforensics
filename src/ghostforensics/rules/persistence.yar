rule RegistryPersistence : persistence
{
    meta:
        description = "Registry-based persistence mechanisms"
        severity = "high"
        author = "GhostForensics"
        mitre_attack = "T1547.001"

    strings:
        $run1 = "CurrentVersion\\Run" nocase
        $run2 = "CurrentVersion\\RunOnce" nocase
        $run3 = "CurrentVersion\\RunServices" nocase
        $run4 = "CurrentVersion\\Policies\\Explorer\\Run" nocase
        $winlogon1 = "Winlogon\\Shell" nocase
        $winlogon2 = "Winlogon\\Userinit" nocase

    condition:
        any of them
}

rule ScheduledTaskPersistence : persistence
{
    meta:
        description = "Scheduled task persistence indicators"
        severity = "high"
        author = "GhostForensics"
        mitre_attack = "T1053.005"

    strings:
        $schtasks1 = "schtasks /create" nocase
        $schtasks2 = "schtasks.exe /create" nocase
        $schtasks3 = "Register-ScheduledTask" nocase
        $schtasks4 = "New-ScheduledTaskAction" nocase
        $at1 = "at.exe" nocase

    condition:
        any of them
}

rule ServicePersistence : persistence
{
    meta:
        description = "Windows service persistence indicators"
        severity = "high"
        author = "GhostForensics"
        mitre_attack = "T1543.003"

    strings:
        $svc1 = "sc create" nocase
        $svc2 = "sc.exe create" nocase
        $svc3 = "New-Service" nocase
        $svc4 = "InstallUtil" nocase
        $svc5 = "ServiceBase" nocase

    condition:
        any of them
}

rule WMIPersistence : persistence
{
    meta:
        description = "WMI event subscription persistence"
        severity = "high"
        author = "GhostForensics"
        mitre_attack = "T1546.003"

    strings:
        $wmi1 = "__EventFilter" nocase
        $wmi2 = "CommandLineEventConsumer" nocase
        $wmi3 = "ActiveScriptEventConsumer" nocase
        $wmi4 = "__FilterToConsumerBinding" nocase
        $wmi5 = "Set-WmiInstance" nocase
        $wmi6 = "Register-WmiEvent" nocase

    condition:
        2 of them
}
