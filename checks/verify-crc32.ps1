$ErrorActionPreference = 'Stop'

. "$PSScriptRoot/../Get-Crc32.ps1"

function Assert-Equal {
    param(
        [Parameter(Mandatory)]$Actual,
        [Parameter(Mandatory)]$Expected,
        [Parameter(Mandatory)][string]$Message
    )

    if ($Actual -ne $Expected) {
        throw "Assertion failed: $Message. Expected '$Expected', got '$Actual'."
    }
}

Write-Host 'Running CRC32 known-vector checks...'

$ascii = [System.Text.Encoding]::ASCII
$utf8 = [System.Text.Encoding]::UTF8

$vectors = @(
    @{ Name = 'empty'; Bytes = [byte[]]@(); Expected = '00000000' },
    @{ Name = '123456789'; Bytes = $ascii.GetBytes('123456789'); Expected = 'CBF43926' },
    @{ Name = 'The quick brown fox jumps over the lazy dog'; Bytes = $utf8.GetBytes('The quick brown fox jumps over the lazy dog'); Expected = '414FA339' }
)

foreach ($vector in $vectors) {
    $actual = '{0:X8}' -f (Get-Crc32OfBytesUInt32 -Bytes $vector.Bytes)
    Assert-Equal -Actual $actual -Expected $vector.Expected -Message "known vector [$($vector.Name)]"
}

Write-Host 'Running file-vs-bytes consistency check...'
$tempFile = Join-Path ([System.IO.Path]::GetTempPath()) ("crc32-test-{0}.bin" -f [guid]::NewGuid().ToString('N'))
try {
    $data = [byte[]](0..255)
    [System.IO.File]::WriteAllBytes($tempFile, $data)

    $crcBytes = '{0:X8}' -f (Get-Crc32OfBytesUInt32 -Bytes $data)
    $crcFile = '{0:X8}' -f (Get-Crc32OfFileUInt32 -Path $tempFile)
    Assert-Equal -Actual $crcFile -Expected $crcBytes -Message 'file CRC should match bytes CRC'
}
finally {
    if (Test-Path -LiteralPath $tempFile) {
        Remove-Item -LiteralPath $tempFile -Force
    }
}

Write-Host 'Running folder aggregate mutation check...'
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("crc32-folder-{0}" -f [guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $tempRoot | Out-Null
    $filePath = Join-Path $tempRoot 'sample.txt'

    Set-Content -LiteralPath $filePath -Value 'before change' -NoNewline -Encoding UTF8
    $before = Get-7ZipCrc32 -Path $tempRoot

    Set-Content -LiteralPath $filePath -Value 'after change' -NoNewline -Encoding UTF8
    $after = Get-7ZipCrc32 -Path $tempRoot

    if ($before.'CRC32 checksum for data' -eq $after.'CRC32 checksum for data') {
        throw 'Folder aggregate data CRC did not change after file content update.'
    }

    if ($before.'CRC32 checksum for data and names' -eq $after.'CRC32 checksum for data and names') {
        throw 'Folder aggregate data-and-names CRC did not change after file content update.'
    }
}
finally {
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}

Write-Host 'All CRC32 checks passed.'
