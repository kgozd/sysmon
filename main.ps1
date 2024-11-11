function get_logs {
    param (
        [int]$event_id
    )

    try {
        $logs = Get-WinEvent -FilterHashtable @{LogName = 'Microsoft-Windows-Sysmon/Operational'; ID = $event_id }
    }
    catch {
        Write-Host "Wystapil blad podczas wykonywania polecenia."
        exit
    }

    if ($logs.Count -eq 0) {
        Write-Host "Nie znaleziono zdarzen dla podanego Event ID."
        return
    }

    foreach ($log in $logs) {
        Write-Host $log.Message
        Write-Host "***************************************************"
    }  
    Write-Host " "
    Write-Host  "Znaleziono $($logs.count) zdarzen"
    Write-Host "---------------------------------------------------------"

}

function show_event_id_help {
    $events = @(
        @{ID = 1; Tag = "ProcessCreate"; Event = "Process Create" },
        @{ID = 2; Tag = "FileCreateTime"; Event = "File creation time" },
        @{ID = 3; Tag = "NetworkConnect"; Event = "Network connection detected" },
        @{ID = 4; Tag = "n/a"; Event = "Sysmon service state change (cannot be filtered)" },
        @{ID = 5; Tag = "ProcessTerminate"; Event = "Process terminated" },
        @{ID = 6; Tag = "DriverLoad"; Event = "Driver Loaded" },
        @{ID = 7; Tag = "ImageLoad"; Event = "Image loaded" },
        @{ID = 8; Tag = "CreateRemoteThread"; Event = "CreateRemoteThread detected" },
        @{ID = 9; Tag = "RawAccessRead"; Event = "RawAccessRead detected" },
        @{ID = 10; Tag = "ProcessAccess"; Event = "Process accessed" },
        @{ID = 11; Tag = "FileCreate"; Event = "File created" },
        @{ID = 12; Tag = "RegistryEvent"; Event = "Registry object added or deleted" },
        @{ID = 13; Tag = "RegistryEvent"; Event = "Registry value set" },
        @{ID = 14; Tag = "RegistryEvent"; Event = "Registry object renamed" },
        @{ID = 15; Tag = "FileCreateStreamHash"; Event = "File stream created" },
        @{ID = 16; Tag = "n/a"; Event = "Sysmon configuration change (cannot be filtered)" },
        @{ID = 17; Tag = "PipeEvent"; Event = "Named pipe created" },
        @{ID = 18; Tag = "PipeEvent"; Event = "Named pipe connected" },
        @{ID = 19; Tag = "WmiEvent"; Event = "WMI filter" },
        @{ID = 20; Tag = "WmiEvent"; Event = "WMI consumer" },
        @{ID = 21; Tag = "WmiEvent"; Event = "WMI consumer filter" },
        @{ID = 22; Tag = "DNSQuery"; Event = "DNS query" },
        @{ID = 23; Tag = "FileDelete"; Event = "File Delete archived" },
        @{ID = 24; Tag = "ClipboardChange"; Event = "New content in the clipboard" },
        @{ID = 25; Tag = "ProcessTampering"; Event = "Process image change" },
        @{ID = 26; Tag = "FileDeleteDetected"; Event = "File Delete logged" },
        @{ID = 27; Tag = "FileBlockExecutable"; Event = "File Block Executable" },
        @{ID = 28; Tag = "FileBlockShredding"; Event = "File Block Shredding" },
        @{ID = 29; Tag = "FileExecutableDetected"; Event = "File Executable Detected" }
    )

    Write-Host "ID    |   Tag                 | Event"
    Write-Host "------------------------------------------"

    foreach ($event in $events) {
        Write-Host "$($event.ID) | $($event.Tag) | $($event.Event)`n"
    }
}

function get_event_id_or_help {
    while ($true) {
        Write-Host "Wpisz Event ID aby wyswietlic zdarzenia, lub 'h' aby otrzymac pomoc" 
        $chosen_sign = Read-Host " "

        if ($chosen_sign -eq 'h') {
            show_event_id_help
            Write-Host "Wpisz Event ID aby wyswietlic zdarzenia, lub 'h' aby otrzymac pomoc" 
        }
        elseif ($chosen_sign -match '^\d+$') {
            $chosen_sign_int = [int]$chosen_sign
            if ($chosen_sign_int -ge 1 -and $chosen_sign_int -le 29) {
                return $chosen_sign_int
            } else {
                Write-Host "Nieprawidlowy znak lub ID poza zakresem (1-29)!"
            }
        }
        else {
            Write-Host "Nieprawidlowy znak! Musisz wpisac liczbe lub 'h' dla pomocy."
        }
    }
}
function main {
    while ($true) {
    $event_id = get_event_id_or_help
    Write-Host "Receiving Logs for Event ID: $event_id"
    get_logs -event_id $event_id

    }
}

main
