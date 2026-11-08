#requires -Version 5.1
<#
.SYNOPSIS
    dwrean.net Debloat - Ελληνικός βοηθός καθαρισμού Windows 11.
.DESCRIPTION
    Προαιρετικές ρυθμίσεις ιδιωτικότητας και επιλεκτική αφαίρεση εφαρμογών.
    Προεπισκόπηση, επιβεβαίωση, αντίγραφα ρυθμίσεων και αναφορά ενεργειών.
    Δεν αφαιρεί drivers, υπηρεσίες συστήματος ή προσωπικά αρχεία.
.NOTES
    Έκδοση 1.0.0 | https://dwrean.net | Windows PowerShell 5.1
    Οι λειτουργίες δεν έχουν δοκιμαστεί σε κάθε έκδοση των Windows 11.
#>

param([switch]$PreviewOnly)

$ErrorActionPreference = 'Stop'
$script:AppVersion = '1.0.0'
$script:BaseDir = Join-Path $env:LOCALAPPDATA 'dwrean-debloat'
$script:BackupDir = Join-Path $script:BaseDir 'backups'
$script:LogDir = Join-Path $script:BaseDir 'logs'
$script:RestorePointAttempted = $false

foreach ($directory in @($script:BaseDir, $script:BackupDir, $script:LogDir)) {
    if (-not (Test-Path -LiteralPath $directory)) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }
}
$script:LogFile = Join-Path $script:LogDir ("session-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))

function Write-Status {
    param([string]$Message, [string]$Color = 'Gray')
    Write-Host $Message -ForegroundColor $Color
    Add-Content -LiteralPath $script:LogFile -Value ("[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message) -Encoding UTF8
}

function Read-Confirmation {
    param([string]$Word, [string]$Message)
    Write-Status $Message 'Yellow'
    $response = Read-Host "Για επιβεβαίωση, πληκτρολόγησε $Word"
    return ($response.Trim() -ceq $Word)
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-Rule {
    param([string]$Label, [string]$Path, [string]$Name, [int]$Value)
    [pscustomobject]@{ Label = $Label; Path = $Path; Name = $Name; Value = $Value; Kind = 'DWord' }
}

# Οι ρυθμίσεις HKCU αφορούν μόνο τον τρέχοντα χρήστη.
# Οι πολιτικές HKLM μπορεί να μην υποστηρίζονται από όλες τις εκδόσεις Windows.
$script:RegistryGroups = @{
    'basic' = @(
        (New-Rule 'Απενεργοποίηση διαφημιστικού αναγνωριστικού' 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' 'Enabled' 0),
        (New-Rule 'Απενεργοποίηση εξατομικευμένων διαγνωστικών προτάσεων' 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy' 'TailoredExperiencesWithDiagnosticDataEnabled' 0),
        (New-Rule 'Περιορισμός προτεινόμενου περιεχομένου' 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SoftLandingEnabled' 0),
        (New-Rule 'Όχι αυτόματες προτεινόμενες εφαρμογές' 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SilentInstalledAppsEnabled' 0),
        (New-Rule 'Λιγότερες προτάσεις στο μενού Έναρξη' 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-338388Enabled' 0),
        (New-Rule 'Απενεργοποίηση προτεινόμενων συμβουλών' 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-338389Enabled' 0),
        (New-Rule 'Απενεργοποίηση προτάσεων στις Ρυθμίσεις' 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-353694Enabled' 0),
        (New-Rule 'Απόκρυψη Widgets από τη γραμμή εργασιών' 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'TaskbarDa' 0),
        (New-Rule 'Απενεργοποίηση δυναμικών highlights αναζήτησης' 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings' 'IsDynamicSearchBoxPresent' 0),
        (New-Rule 'Απόκρυψη ειδοποιήσεων με προτάσεις Windows' 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.Suggested' 'Enabled' 0)
    )
    'diagnostics' = @(
        (New-Rule 'Περιορισμός συλλογής διαγνωστικών στα απαραίτητα*' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry' 1),
        (New-Rule 'Απόκρυψη προτροπών για σχόλια' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'DoNotShowFeedbackNotifications' 1)
    )
    'ai' = @(
        (New-Rule 'Απαγόρευση αποθήκευσης στιγμιότυπων Recall*' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' 'DisableAIDataAnalysis' 1)
    )
    'edge' = @(
        (New-Rule 'Απόκρυψη πλευρικής γραμμής Edge*' 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'HubsSidebarEnabled' 0),
        (New-Rule 'Απενεργοποίηση λειτουργίας Edge στο παρασκήνιο*' 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'BackgroundModeEnabled' 0),
        (New-Rule 'Απενεργοποίηση επιτάχυνσης εκκίνησης Edge*' 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'StartupBoostEnabled' 0),
        (New-Rule 'Απόκρυψη Microsoft Rewards στον Edge*' 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'ShowMicrosoftRewards' 0)
    )
}

function Get-RegistrySnapshot {
    param($Rule)
    $exists = $false
    $oldValue = $null
    $oldKind = $null
    if (Test-Path -LiteralPath $Rule.Path) {
        $key = Get-Item -LiteralPath $Rule.Path -ErrorAction Stop
        if (@($key.GetValueNames()) -contains $Rule.Name) {
            $exists = $true
            $oldKind = $key.GetValueKind($Rule.Name).ToString()
            $oldValue = $key.GetValue($Rule.Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        }
    }
    [pscustomobject]@{
        Path = $Rule.Path; Name = $Rule.Name; Existed = $exists
        PreviousKind = $oldKind; PreviousValue = $oldValue
    }
}

function Write-RegistryRule {
    param($Rule)
    if (-not (Test-Path -LiteralPath $Rule.Path)) {
        New-Item -Path $Rule.Path -Force -ErrorAction Stop | Out-Null
    }
    New-ItemProperty -LiteralPath $Rule.Path -Name $Rule.Name -PropertyType DWord -Value $Rule.Value -Force -ErrorAction Stop | Out-Null
}

function Save-RegistryBackup {
    param([string]$GroupKey, [object[]]$Rules)
    $records = @()
    foreach ($rule in $Rules) { $records += Get-RegistrySnapshot $rule }
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $file = Join-Path $script:BackupDir ("registry-{0}-{1}.json" -f $GroupKey, (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
    $backup = [pscustomobject]@{
        FormatVersion = 1; Application = 'dwrean.net Debloat'
        Created = (Get-Date -Format 'o'); UserSid = $sid
        Group = $GroupKey; Values = $records
    }
    $backup | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $file -Encoding UTF8 -ErrorAction Stop
    Write-Status "Αντίγραφο προηγούμενων ρυθμίσεων: $file" 'Cyan'
    return $file
}

function Invoke-RestorePoint {
    if ($script:RestorePointAttempted) { return }
    $script:RestorePointAttempted = $true
    try {
        $null = Checkpoint-Computer -Description 'dwrean.net Debloat - πριν από αλλαγές' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        Write-Status 'Δημιουργήθηκε σημείο επαναφοράς συστήματος.' 'Green'
    } catch {
        Write-Status 'Δεν δημιουργήθηκε σημείο επαναφοράς (ενδέχεται να είναι απενεργοποιημένη η Προστασία Συστήματος).' 'Yellow'
        Write-Status 'Το ξεχωριστό αντίγραφο ρυθμίσεων θα διατηρηθεί κανονικά.' 'Yellow'
    }
}

function Show-RulesAndApply {
    param([string]$Group, [string]$Title, [string]$Warning = '')
    $rules = @($script:RegistryGroups[$Group])
    Write-Host ''
    Write-Status "--- $Title ---" 'Cyan'
    if ($Warning) { Write-Status $Warning 'Yellow' }
    foreach ($rule in $rules) {
        try {
            $before = Get-RegistrySnapshot $rule
            $display = if ($before.Existed) { [string]$before.PreviousValue } else { 'δεν υπάρχει' }
            Write-Status ("• {0}: {1} -> {2}" -f $rule.Label, $display, $rule.Value)
        } catch { Write-Status ("• {0}: αδυναμία ανάγνωσης παλιάς τιμής" -f $rule.Label) 'Yellow' }
    }
    if ($PreviewOnly) { Write-Status 'Λειτουργία προεπισκόπησης: καμία αλλαγή.' 'Cyan'; return }
    if (-not (Read-Confirmation 'ΕΦΑΡΜΟΓΗ' 'Οι παραπάνω αλλαγές θα εφαρμοστούν. Συνέχεια;')) {
        Write-Status 'Η ενέργεια ακυρώθηκε.' 'Yellow'; return
    }
    if (-not (Test-IsAdministrator)) {
        Write-Status 'Απαιτείται εκτέλεση ως διαχειριστής.' 'Red'; return
    }
    try { $backupFile = Save-RegistryBackup $Group $rules }
    catch { Write-Status "Αδυναμία δημιουργίας αντιγράφου. Καμία αλλαγή: $($_.Exception.Message)" 'Red'; return }
    Invoke-RestorePoint
    $ok = 0; $fail = 0
    foreach ($rule in $rules) {
        try {
            Write-RegistryRule $rule
            Write-Status "[OK] $($rule.Label)" 'Green'; $ok++
        } catch {
            Write-Status "[ΣΦΑΛΜΑ] $($rule.Label): $($_.Exception.Message)" 'Red'; $fail++
        }
    }
    Write-Status "Ολοκλήρωση: $ok επιτυχίες, $fail αποτυχίες. Επανεκκίνηση μπορεί να χρειαστεί." 'Cyan'
    Write-Status "Επαναφορά των τιμών: επιλογή 7 (αρχείο $backupFile)." 'Cyan'
}

function Restore-RegistryBackup {
    $backups = @(Get-ChildItem -LiteralPath $script:BackupDir -Filter 'registry-*.json' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    if ($backups.Count -eq 0) { Write-Status 'Δεν βρέθηκαν αντίγραφα ρυθμίσεων.' 'Yellow'; return }
    Write-Status 'Διαθέσιμα αντίγραφα ρυθμίσεων:' 'Cyan'
    for ($i = 0; $i -lt $backups.Count; $i++) {
        Write-Status ("{0}. {1}" -f ($i + 1), $backups[$i].Name)
    }
    $choice = Read-Host 'Αριθμός αντιγράφου (0 για ακύρωση)'
    $number = 0
    if (-not [int]::TryParse($choice, [ref]$number) -or $number -le 0 -or $number -gt $backups.Count) { return }
    try {
        $backup = Get-Content -LiteralPath $backups[$number - 1].FullName -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
        if ($backup.FormatVersion -ne 1 -or $backup.Application -ne 'dwrean.net Debloat' -or -not $backup.Values) {
            throw 'Μη έγκυρο ή μη συμβατό αντίγραφο.'
        }
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        if ($backup.UserSid -ne $sid) { throw 'Το αντίγραφο ανήκει σε διαφορετικό λογαριασμό Windows.' }
        # Δεν δεχόμαστε αυθαίρετες διαδρομές από τροποποιημένο JSON.
        $allowed = @{}
        foreach ($groupRules in $script:RegistryGroups.Values) {
            foreach ($r in $groupRules) { $allowed[($r.Path + '|' + $r.Name)] = $true }
        }
        foreach ($record in @($backup.Values)) {
            if (-not $allowed.ContainsKey(([string]$record.Path + '|' + [string]$record.Name))) {
                throw 'Το αντίγραφο περιέχει μη αναγνωρισμένη ρύθμιση.'
            }
        }
    } catch { Write-Status "Αποτυχία ανάγνωσης: $($_.Exception.Message)" 'Red'; return }
    Write-Status 'Επαναφέρονται μόνο οι τιμές μητρώου, ΟΧΙ διαγραμμένες εφαρμογές.' 'Yellow'
    if ($PreviewOnly -or -not (Read-Confirmation 'ΕΠΑΝΑΦΟΡΑ' 'Επαναφορά των προηγούμενων τιμών;')) { return }
    if (-not (Test-IsAdministrator)) { Write-Status 'Απαιτούνται δικαιώματα διαχειριστή.' 'Red'; return }
    # Πριν από την επαναφορά αποθηκεύουμε και τη σημερινή κατάσταση.
    $reverseRules = @()
    foreach ($record in @($backup.Values)) {
        $reverseRules += [pscustomobject]@{ Path = $record.Path; Name = $record.Name; Value = 0 }
    }
    try { $null = Save-RegistryBackup 'before-restore' $reverseRules }
    catch { Write-Status 'Αδυναμία δημιουργίας αντιγράφου πριν την επαναφορά. Ακύρωση.' 'Red'; return }
    foreach ($record in @($backup.Values)) {
        try {
            if ($record.Path -notmatch '^HK(CU|LM):\\' -or $record.Name -notmatch '^[\w.-]+$') { throw 'Μη επιτρεπτή τιμή/διαδρομή.' }
            if ($record.Existed) {
                if (-not (Test-Path -LiteralPath $record.Path)) { New-Item -Path $record.Path -Force | Out-Null }
                $kind = [Enum]::Parse([Microsoft.Win32.RegistryValueKind], [string]$record.PreviousKind)
                $old = $record.PreviousValue
                switch ([string]$record.PreviousKind) {
                    'DWord'      { $old = [int]$old }
                    'QWord'      { $old = [long]$old }
                    'Binary'     { $old = [byte[]]@($old) }
                    'MultiString'{ $old = [string[]]@($old) }
                    default      { $old = [string]$old }
                }
                $item = Get-Item -LiteralPath $record.Path
                $item.SetValue([string]$record.Name, $old, [Microsoft.Win32.RegistryValueKind]$kind)
            } elseif (Test-Path -LiteralPath $record.Path) {
                Remove-ItemProperty -LiteralPath $record.Path -Name $record.Name -ErrorAction SilentlyContinue
            }
            Write-Status "[OK] $($record.Name)" 'Green'
        } catch { Write-Status "[ΣΦΑΛΜΑ] $($record.Name): $($_.Exception.Message)" 'Red' }
    }
    Write-Status 'Η επαναφορά ολοκληρώθηκε. Ίσως απαιτείται επανεκκίνηση.' 'Cyan'
}

# Κατάλογος προαιρετικών εφαρμογών· επιτρέπεται μόνο χειροκίνητη επιλογή.
$script:AppCatalog = @(
    [pscustomobject]@{Label='Clipchamp'; Pattern='Clipchamp.Clipchamp'; Vendor='All'},
    [pscustomobject]@{Label='Microsoft Solitaire Collection'; Pattern='Microsoft.MicrosoftSolitaireCollection'; Vendor='All'},
    [pscustomobject]@{Label='Microsoft News'; Pattern='Microsoft.BingNews'; Vendor='All'},
    [pscustomobject]@{Label='Κέντρο σχολίων (Feedback Hub)'; Pattern='Microsoft.WindowsFeedbackHub'; Vendor='All'},
    [pscustomobject]@{Label='Συμβουλές πρώτης χρήσης'; Pattern='Microsoft.Getstarted'; Vendor='All'},
    [pscustomobject]@{Label='Spotify (προαιρετικό, εφόσον δεν το χρησιμοποιείς)'; Pattern='SpotifyAB.SpotifyMusic'; Vendor='All'},
    [pscustomobject]@{Label='Netflix (προαιρετικό)'; Pattern='4DF9E0F8.Netflix'; Vendor='All'},
    [pscustomobject]@{Label='Facebook (προαιρετικό)'; Pattern='Facebook.Facebook'; Vendor='All'},
    [pscustomobject]@{Label='Roblox (προαιρετικό)'; Pattern='ROBLOXCORPORATION.ROBLOX'; Vendor='All'},
    [pscustomobject]@{Label='HP JumpStarts'; Pattern='*HPJumpStarts*'; Vendor='HP'},
    [pscustomobject]@{Label='HP QuickDrop'; Pattern='*HPQuickDrop*'; Vendor='HP'},
    [pscustomobject]@{Label='Dell Digital Delivery'; Pattern='*DellDigitalDelivery*'; Vendor='Dell'},
    [pscustomobject]@{Label='Dell Registration'; Pattern='*DellRegistration*'; Vendor='Dell'},
    [pscustomobject]@{Label='ASUS GlideX'; Pattern='*ASUSGlideX*'; Vendor='ASUS'},
    [pscustomobject]@{Label='Acer Product Registration'; Pattern='*AcerProductRegistration*'; Vendor='Acer'},
    [pscustomobject]@{Label='Acer User Experience'; Pattern='*AcerUserExperience*'; Vendor='Acer'},
    [pscustomobject]@{Label='Lenovo Now'; Pattern='*LenovoNow*'; Vendor='Lenovo'}
)

function Select-AndRemoveApps {
    param([bool]$OnlyOEM)
    Write-Host ''
    try {
        $installed = @(Get-AppxPackage -ErrorAction Stop)
    } catch { Write-Status "Αδυναμία ανάγνωσης εφαρμογών: $($_.Exception.Message)" 'Red'; return }
    $manufacturer = ''
    if ($OnlyOEM) {
        try { $manufacturer = [string](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).Manufacturer }
        catch { Write-Status 'Δεν ήταν δυνατή η αναγνώριση κατασκευαστή.' 'Yellow'; return }
        Write-Status "Κατασκευαστής υπολογιστή: $manufacturer" 'Cyan'
    }
    $candidates = @()
    foreach ($entry in $script:AppCatalog) {
        if ($OnlyOEM) {
            if ($entry.Vendor -eq 'All' -or $manufacturer -notmatch [regex]::Escape($entry.Vendor)) { continue }
        } else {
            if ($entry.Vendor -ne 'All') { continue }
        }
        foreach ($app in $installed) {
            if ($app.Name -like $entry.Pattern) {
                $candidates += [pscustomobject]@{ Label = $entry.Label; Name = $app.Name; FullName = $app.PackageFullName }
            }
        }
    }
    $candidates = @($candidates | Sort-Object FullName -Unique)
    if ($candidates.Count -eq 0) {
        Write-Status 'Δεν βρέθηκαν αντίστοιχες προαιρετικές εφαρμογές στον τρέχοντα χρήστη.' 'Yellow'; return
    }
    Write-Status 'Βρέθηκαν οι παρακάτω εφαρμογές (δεν έχει αφαιρεθεί τίποτα):' 'Cyan'
    for ($i = 0; $i -lt $candidates.Count; $i++) {
        Write-Status ("{0}. {1} ({2})" -f ($i + 1), $candidates[$i].Label, $candidates[$i].Name)
    }
    if ($PreviewOnly) { Write-Status 'Λειτουργία προεπισκόπησης: καμία αλλαγή.' 'Cyan'; return }
    $raw = Read-Host 'Γράψε τους αριθμούς προς αφαίρεση (π.χ. 1,3) ή 0 για ακύρωση'
    if ($raw.Trim() -eq '0' -or [string]::IsNullOrWhiteSpace($raw)) { return }
    $indexes = @()
    foreach ($part in ($raw -split '[,\s]+')) {
        $n = 0
        if (-not [int]::TryParse($part, [ref]$n) -or $n -lt 1 -or $n -gt $candidates.Count) {
            Write-Status "Μη έγκυρη επιλογή: $part. Η διαδικασία ακυρώθηκε." 'Red'; return
        }
        $indexes += ($n - 1)
    }
    $indexes = @($indexes | Sort-Object -Unique)
    $selection = @($indexes | ForEach-Object { $candidates[$_] })
    Write-Status 'ΠΡΟΣΟΧΗ: Η απεγκατάσταση εφαρμογών ΔΕΝ αναιρείται από τα αντίγραφα μητρώου.' 'Yellow'
    foreach ($app in $selection) { Write-Status "Για αφαίρεση: $($app.Label)" 'Yellow' }
    if (-not (Read-Confirmation 'ΔΙΑΓΡΑΦΗ' 'Θέλεις να απεγκατασταθούν ΜΟΝΟ οι επιλεγμένες εφαρμογές;')) { return }
    if (-not (Test-IsAdministrator)) { Write-Status 'Απαιτούνται δικαιώματα διαχειριστή.' 'Red'; return }
    Invoke-RestorePoint
    foreach ($app in $selection) {
        try {
            Remove-AppxPackage -Package $app.FullName -ErrorAction Stop
            Write-Status "[OK] Αφαιρέθηκε: $($app.Label)" 'Green'
        } catch { Write-Status "[ΣΦΑΛΜΑ] $($app.Label): $($_.Exception.Message)" 'Red' }
    }
    Write-Status 'Αφαιρέθηκαν μόνο εφαρμογές του τρέχοντος χρήστη, όχι drivers ή υπηρεσίες.' 'Cyan'
}

function Show-MainMenu {
    while ($true) {
        Write-Host ''
        Write-Host '========================================================' -ForegroundColor DarkCyan
        Write-Host ("  dwrean.net DEBLOAT  v{0}" -f $script:AppVersion) -ForegroundColor Cyan
        Write-Host '  Ελληνικός βοηθός καθαρισμού Windows 11' -ForegroundColor White
        Write-Host '========================================================' -ForegroundColor DarkCyan
        if ($PreviewOnly) { Write-Host '  ΜΟΝΟ ΠΡΟΕΠΙΣΚΟΠΗΣΗ - καμία αλλαγή' -ForegroundColor Yellow }
        Write-Host '  1. Ιδιωτικότητα και προτάσεις Windows'
        Write-Host '  2. Περιορισμός διαγνωστικών δεδομένων'
        Write-Host '  3. Απενεργοποίηση αποθήκευσης Recall'
        Write-Host '  4. Προαιρετικές ρυθμίσεις Microsoft Edge'
        Write-Host '  5. Επιλογή εφαρμογών Windows για αφαίρεση'
        Write-Host '  6. Προαιρετικές εφαρμογές κατασκευαστή (OEM)'
        Write-Host '  7. Επαναφορά προηγούμενων ρυθμίσεων'
        Write-Host '  8. Προβολή φακέλου logs / αντιγράφων'
        Write-Host '  0. Έξοδος'
        $answer = Read-Host 'Επιλογή'
        switch ($answer.Trim()) {
            '1' { Show-RulesAndApply 'basic' 'Ιδιωτικότητα και περιβάλλον Windows' }
            '2' { Show-RulesAndApply 'diagnostics' 'Διαγνωστικά Windows' '* Απαιτούμενα δεδομένα, όχι πλήρης απενεργοποίηση· η πολιτική εξαρτάται από την έκδοση Windows.' }
            '3' { Show-RulesAndApply 'ai' 'Προστασία Recall' '* Αν υπάρχουν στιγμιότυπα Recall, η ενεργοποίηση αυτής της πολιτικής ενδέχεται να τα διαγράψει οριστικά.' }
            '4' { Show-RulesAndApply 'edge' 'Προαιρετικές πολιτικές Edge' '* Ο Edge μπορεί να εμφανίσει «Διαχειρίζεται από τον οργανισμό σας». Μπορεί να χρειαστεί επανεκκίνηση του browser.' }
            '5' { Select-AndRemoveApps $false }
            '6' { Select-AndRemoveApps $true }
            '7' { Restore-RegistryBackup }
            '8' { Write-Status "Logs: $script:LogDir" 'Cyan'; Write-Status "Αντίγραφα: $script:BackupDir" 'Cyan' }
            '0' { Write-Status 'Έξοδος. Ευχαριστούμε που χρησιμοποιείς το dwrean.net Debloat!' 'Cyan'; return }
            default { Write-Status 'Διάλεξε έναν από τους διαθέσιμους αριθμούς.' 'Yellow' }
        }
    }
}

if ($env:OS -ne 'Windows_NT') { Write-Status 'Αυτή η εφαρμογή λειτουργεί μόνο σε Windows.' 'Red'; exit 1 }
Write-Status 'dwrean.net Debloat | https://dwrean.net' 'Cyan'
Write-Status "Αναφορά συνεδρίας: $script:LogFile" 'Cyan'
if (-not (Test-IsAdministrator)) {
    Write-Status 'Για εφαρμογή αλλαγών απαιτείται PowerShell ως διαχειριστής. Η προεπισκόπηση είναι διαθέσιμη.' 'Yellow'
}
Show-MainMenu