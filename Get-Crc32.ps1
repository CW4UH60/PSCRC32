using namespace System.Globalization
using namespace System.Text

param(
    [string]$Path,
    [bool]$IncludeRoot = $true,
    [switch]$OutputJson,
    [switch]$Gui
)

function New-UInt32FromHex {
    param([Parameter(Mandatory)][string]$HexNoPrefix)
    [uint32]::Parse($HexNoPrefix, [NumberStyles]::HexNumber, [CultureInfo]::InvariantCulture)
}

Write-Host "Chris is so cool...."


Write-Host "This is some junk data..."
function Update-Crc32Bytes {
    param(
        [Parameter(Mandatory)][uint32]$Crc,
        [Parameter(Mandatory)][uint32[]]$Table,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes,
        [int]$Offset = 0,
        [int]$Count = -1
    )
    if ($Count -lt 0) { $Count = $Bytes.Length - $Offset }
    $end = $Offset + $Count
    for ($i = $Offset; $i -lt $end; $i++) {
        $idx = [int](($Crc -bxor $Bytes[$i]) -band 0xFF)
        $Crc = ($Crc -shr 8) -bxor $Table[$idx]
    }
    $Crc
}

function Update-Crc32FileStream {
    param(
        [Parameter(Mandatory)][uint32]$Crc,
        [Parameter(Mandatory)][uint32[]]$Table,
        [Parameter(Mandatory)][string]$Path
    )

    $bufferSize = 1024 * 1024
    $buffer = New-Object byte[] $bufferSize

    $stream = [System.IO.File]::Open(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read
    )

    try {
        while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $Crc = Update-Crc32Bytes -Crc $Crc -Table $Table -Bytes $buffer -Offset 0 -Count $read
        }
    }
    finally {
        $stream.Dispose()
    }

    $Crc
}

function Get-Crc32OfFileUInt32 {
    param([Parameter(Mandatory)][string]$Path)

    $table = Get-Crc32Table
    $crc = New-UInt32FromHex "FFFFFFFF"
    $crc = Update-Crc32FileStream -Crc $crc -Table $table -Path $Path
    $crc = $crc -bxor (New-UInt32FromHex "FFFFFFFF")
    $crc
}

function Get-Crc32OfBytesUInt32 {
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)

    $table = Get-Crc32Table
    $crc = New-UInt32FromHex "FFFFFFFF"
    $crc = Update-Crc32Bytes -Crc $crc -Table $table -Bytes $Bytes
    $crc = $crc -bxor (New-UInt32FromHex "FFFFFFFF")
    $crc
}

function UInt32ToLittleEndianBytes {
    param([Parameter(Mandatory)][uint32]$Value)
    [byte[]]@(
        [byte]($Value -band 0xFF),
        [byte](($Value -shr 8) -band 0xFF),
        [byte](($Value -shr 16) -band 0xFF),
        [byte](($Value -shr 24) -band 0xFF)
    )
}

function Format-7zSum32PlusHigh {
    param([Parameter(Mandatory)][uint64]$Sum)

    $low  = [uint32]($Sum % 4294967296)
    $high = [uint32]([math]::Floor($Sum / 4294967296))

    ('{0:X8}-{1:X8}' -f $low, $high)
}

function Get-7ZipFolderCrc32Aggregates {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FolderPath,
        [bool]$IncludeRoot = $true,
        [switch]$DebugPaths
    )

    if (-not (Test-Path -LiteralPath $FolderPath -PathType Container)) {
        throw "Folder not found: $FolderPath"
    }

    $root    = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $FolderPath).Path).TrimEnd('\')
    $topName = [System.IO.Path]::GetFileName($root)

    # UTF-16LE, no BOM
    $utf16le = [System.Text.UnicodeEncoding]::new($false, $false)

    function Get-RelPathForwardSlash_PS51 {
        param(
            [Parameter(Mandatory)][string]$Root,
            [Parameter(Mandatory)][string]$Item
        )

        $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
        $itemFull = [System.IO.Path]::GetFullPath($Item)

        $rootUri = [Uri]("file:///" + ($rootFull.Replace('\\','/')) + "/")
        $itemUri = [Uri]("file:///" + ($itemFull.Replace('\\','/')))

        $relUri = $rootUri.MakeRelativeUri($itemUri)
        $rel = [Uri]::UnescapeDataString($relUri.OriginalString)

        $rel = $rel.TrimEnd('/')

        if ($rel.StartsWith("../")) {
            throw "Computed relative path escapes root. Root='$rootFull' Item='$itemFull' Rel='$rel'"
        }

        return $rel
    }

    function Get-7zHashedPath {
        param(
            [Parameter(Mandatory)][string]$FullPath,
            [Parameter(Mandatory)][bool]$IsDir
        )

        $full = [System.IO.Path]::GetFullPath($FullPath).TrimEnd('\')

        # Root entry (folder mode only): "TopFolder" (NO trailing '/')
        if ($IncludeRoot -and ($full -ieq $root)) {
            return $topName
        }

        $inner = Get-RelPathForwardSlash_PS51 -Root $root -Item $full

        if (-not $IncludeRoot) {
            if ([string]::IsNullOrEmpty($inner)) {
                throw "IncludeRoot is false but inner path was empty for '$full' (should never happen)."
            }
            return $inner
        }

        if ([string]::IsNullOrEmpty($inner)) { return $topName }
        return "$topName/$inner"
    }

    function Get-ItemCrc_DataAndNames {
        param(
            [Parameter(Mandatory)][bool]$IsDir,
            [Parameter(Mandatory)][uint32]$DataDigestCrc,
            [Parameter(Mandatory)][string]$PathUtf16LeString
        )

        # pre[16]=0; pre[0]=1 for dirs; then 4 bytes digest; then UTF-16LE path bytes.
        $pre = New-Object byte[] 16
        if ($IsDir) { $pre[0] = 1 }

        $digestBytes = if ($IsDir) {
            New-Object byte[] 4  # 00 00 00 00
        } else {
            UInt32ToLittleEndianBytes -Value $DataDigestCrc
        }

        $pathBytes = $utf16le.GetBytes($PathUtf16LeString)

        $itemBytes = New-Object byte[] ($pre.Length + $digestBytes.Length + $pathBytes.Length)
        [Array]::Copy($pre, 0, $itemBytes, 0, $pre.Length)
        [Array]::Copy($digestBytes, 0, $itemBytes, $pre.Length, $digestBytes.Length)
        [Array]::Copy($pathBytes, 0, $itemBytes, $pre.Length + $digestBytes.Length, $pathBytes.Length)

        Get-Crc32OfBytesUInt32 -Bytes $itemBytes
    }

    $dirItems  = @(Get-ChildItem -LiteralPath $root -Directory -Recurse -Force -ErrorAction SilentlyContinue)
    $fileItems = @(Get-ChildItem -LiteralPath $root -File      -Recurse -Force -ErrorAction SilentlyContinue)

    # ---- Aggregate 1: data ----
    [uint64]$sumData = 0
    $fileCrcMap = @{}

    foreach ($f in $fileItems) {
        $crc = Get-Crc32OfFileUInt32 -Path $f.FullName
        $fileCrcMap[$f.FullName] = $crc
        $sumData += [uint64]$crc
    }

    # ---- Aggregate 2: data + names ----
    [uint64]$sumDataNames = 0

    $dirsForHash = @()
    if ($IncludeRoot) { $dirsForHash += $root }
    $dirsForHash += $dirItems | ForEach-Object { $_.FullName }

    foreach ($d in $dirsForHash) {
        $path = Get-7zHashedPath -FullPath $d -IsDir $true
        $itemCrc = Get-ItemCrc_DataAndNames -IsDir $true -DataDigestCrc 0 -PathUtf16LeString $path
        if ($DebugPaths) { Write-Host ("DIR : {0}`nCRC : {1:X8}" -f $path, $itemCrc) }
        $sumDataNames += [uint64]$itemCrc
    }

    foreach ($f in $fileItems) {
        $path = Get-7zHashedPath -FullPath $f.FullName -IsDir $false
        $dataCrc = $fileCrcMap[$f.FullName]
        $itemCrc = Get-ItemCrc_DataAndNames -IsDir $false -DataDigestCrc $dataCrc -PathUtf16LeString $path
        if ($DebugPaths) { Write-Host ("FIL : {0}`nCRC : {1:X8}" -f $path, $itemCrc) }
        $sumDataNames += [uint64]$itemCrc
    }

    [pscustomobject]@{
        Path = $root
        Type = "Folder"
        IncludeRoot = $IncludeRoot
        "CRC32 checksum for data"           = (Format-7zSum32PlusHigh -Sum $sumData)
        "CRC32 checksum for data and names" = (Format-7zSum32PlusHigh -Sum $sumDataNames)
    }
}

function Get-7ZipFileCrc32 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$FilePath)

    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
        throw "File not found: $FilePath"
    }

    $full = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $FilePath).Path)

    $crc = Get-Crc32OfFileUInt32 -Path $full

    [pscustomobject]@{
        Path = $full
        Type = "File"
        "CRC32 checksum for data" = ('{0:X8}' -f $crc)
    }
}

function Get-7ZipCrc32 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [bool]$IncludeRoot = $true
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Path not found: $Path"
    }

    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        return Get-7ZipFileCrc32 -FilePath $Path
    }

    return Get-7ZipFolderCrc32Aggregates -FolderPath $Path -IncludeRoot $IncludeRoot
}

function Test-IsWindowsPlatform {
    [CmdletBinding()]
    param()

    $isWindowsVariable = Get-Variable -Name IsWindows -ErrorAction SilentlyContinue
    if ($null -ne $isWindowsVariable) {
        return [bool]$isWindowsVariable.Value
    }

    return [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)
}

function Start-7ZipCrc32Gui {
    [CmdletBinding()]
    param(
        [Nullable[bool]]$IsWindowsOverride
    )

    $isWindows = if ($PSBoundParameters.ContainsKey('IsWindowsOverride')) {
        [bool]$IsWindowsOverride
    } else {
        Test-IsWindowsPlatform
    }

    if (-not $isWindows) {
        throw "GUI mode requires Windows. Use -Path in CLI mode for CI and GitHub Actions."
    }

    Add-Type -AssemblyName System.Windows.Forms

    # ---- Picker: choose file OR folder ----
    $choice = [System.Windows.Forms.MessageBox]::Show(
        "Click YES to pick a FILE, NO to pick a FOLDER.",
        "7-Zip-style CRC32",
        [System.Windows.Forms.MessageBoxButtons]::YesNoCancel,
        [System.Windows.Forms.MessageBoxIcon]::Question
    )

    if ($choice -eq [System.Windows.Forms.DialogResult]::Cancel) {
        Write-Host "Canceled."
        return
    }

    if ($choice -eq [System.Windows.Forms.DialogResult]::Yes) {
        $ofd = New-Object System.Windows.Forms.OpenFileDialog
        $ofd.Title = "Select a file to compute CRC32"
        $ofd.CheckFileExists = $true
        if ($ofd.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
            Write-Host "No file selected."
            return
        }

        Get-7ZipCrc32 -Path $ofd.FileName | Format-List *
        return
    }

    $fbd = New-Object System.Windows.Forms.FolderBrowserDialog
    $fbd.Description = "Select a folder to compute 7-Zip-style CRC32 aggregates"
    $fbd.ShowNewFolderButton = $false

    if ($fbd.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        Write-Host "No folder selected."
        return
    }

    # Default matches: 7z h "<folder>"  (IncludeRoot = $true)
    Get-7ZipCrc32 -Path $fbd.SelectedPath -IncludeRoot $true | Format-List *
}

function Invoke-GetCrc32EntryPoint {
    [CmdletBinding()]
    param(
        [string]$Path,
        [bool]$IncludeRoot = $true,
        [switch]$OutputJson,
        [switch]$Gui,
        [Nullable[bool]]$IsWindowsOverride,
        [scriptblock]$StartGuiAction = {
            param($ResolvedIsWindows)
            Start-7ZipCrc32Gui -IsWindowsOverride:$ResolvedIsWindows
        }
    )

    $isWindows = if ($PSBoundParameters.ContainsKey('IsWindowsOverride')) {
        [bool]$IsWindowsOverride
    } else {
        Test-IsWindowsPlatform
    }

    if ($Path) {
        $result = Get-7ZipCrc32 -Path $Path -IncludeRoot $IncludeRoot
        if ($OutputJson) {
            $result | ConvertTo-Json -Depth 4 -Compress
        } else {
            $result | Format-List *
        }
        return
    }

    if ($Gui -or ($isWindows -and -not $env:CI -and -not $env:GITHUB_ACTIONS)) {
        & $StartGuiAction $isWindows
        return
    }

    throw "No -Path provided. In non-interactive mode (CI/GitHub Actions), pass -Path '<file-or-folder>'."
}

if ($PSCommandPath -and ($MyInvocation.InvocationName -ne '.')) {
    Invoke-GetCrc32EntryPoint -Path $Path -IncludeRoot:$IncludeRoot -OutputJson:$OutputJson -Gui:$Gui
}
