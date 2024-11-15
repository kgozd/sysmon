


function get_logs {
    param (
        [int]$event_id
        
    )

    try {
        $logs = Get-WinEvent -FilterHashtable @{LogName = 'Microsoft-Windows-Sysmon/Operational'; ID = $event_id }
    }
    catch {
        Write-Host "Wystąpił błąd podczas wykonywania polecenia. Upewnij się, że masz odpowiednie uprawnienia." -ForegroundColor Red 
        return
    }

    if ($logs.Count -eq 0) {
        Write-Host "Nie znaleziono logów dla tego zdarzenia!"
        return
    }

    $results = @()
    foreach ($log in $logs) {
        $message = $log.Message -split "`n" | ForEach-Object { $_.Trim() } 
        $data = @{}

        foreach ($line in $message) {
            if ($line -match "^(.*?):\s*(.+)$") {
                $key = $matches[1]
                $value = $matches[2]
                $data[$key] = $value
            }
        }

       # $data["TimeCreated"] = $log.TimeCreated
       # $data["EventID"] = $log.Id
       # $data["ProviderName"] = $log.ProviderName

        $results += [PSCustomObject]$data
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputPath = "EventLogs_EventID_${event_id}_$timestamp.csv"

    if ($logs.Count -gt 100) {
        $results | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8
        Write-Host "`nZnaleziono $($logs.Count) zdarzeń.`nDane zapisano w pliku: $outputPath" -ForegroundColor Green 
    } else {
        $results | Format-Table -AutoSize -Wrap

        $results | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8
        Write-Host "`nZnaleziono $($logs.Count) zdarzeń.`nDane zapisano w pliku: $outputPath" -ForegroundColor Green 
    }

    Write-Host "---------------------------------------------------------`n"  
}





function show_event_id_help {
    param (
        $events
        
    )
   
    Write-Host "`nID | Tag | Event" -ForegroundColor Blue
    Write-Host "------------------------------------------" -ForegroundColor Blue

    foreach ($event in $events) {
        Write-Host "$($event.ID) | $($event.Tag) | $($event.Event)`n" -ForegroundColor Blue
        Write-Host "------------------------------------------------------------" -ForegroundColor Blue

    }
   
}

function get_event_id_or_help {
    param (
        $events
        
    )
    while ($true) {
        Write-Host "`nWpisz Event ID aby wyswietlic zdarzenia, lub 'h' aby otrzymac pomoc`n" 
        $chosen_sign = Read-Host " "

        if ($chosen_sign -eq 'h') {
            show_event_id_help -events  $events
        }
        elseif ($chosen_sign -match '^\d+$') {
            $chosen_sign_int = [int]$chosen_sign
            $event_ID_description = ($events | Where-object {$_.ID -eq $chosen_sign_int}).Event

            if ($chosen_sign_int -ge 1 -and $chosen_sign_int -le 29) {
                return $chosen_sign_int,  $event_ID_description
            } else {
                Write-Host "Nieprawidlowy znak lub ID poza zakresem (1-29)!"
            }
        }
        else {
            Write-Host "Nieprawidlowy znak! Musisz wpisac event ID lub 'h' dla pomocy.`n"   -ForegroundColor DarkRed
        }
    }
}
function main {
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



    while ($true) {
    $event_id ,  $event_ID_description = get_event_id_or_help -events $events
    Write-Host "Receiving Logs for Event ID: $event_id, Event Description: $event_ID_description" -ForegroundColor Yellow
    get_logs -event_id $event_id

    }
}

main
