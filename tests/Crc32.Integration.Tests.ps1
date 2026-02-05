$ErrorActionPreference = 'Stop'

Describe '7-Zip CRC32 integration parity' {
    BeforeAll {
        $repoRoot = Split-Path -Parent $PSScriptRoot
        $scriptPath = Join-Path $repoRoot 'Get-Crc32.ps1'
        $artifactDir = Join-Path $repoRoot 'test-artifacts'
        New-Item -ItemType Directory -Path $artifactDir -Force | Out-Null

        function Get-7ZipExe {
            if ($env:SEVEN_ZIP_EXE -and (Test-Path -LiteralPath $env:SEVEN_ZIP_EXE)) {
                return $env:SEVEN_ZIP_EXE
            }

            $cmd = Get-Command 7z -ErrorAction SilentlyContinue
            if ($cmd) {
                return $cmd.Source
            }

            $default = 'C:\Program Files\7-Zip\7z.exe'
            if (Test-Path -LiteralPath $default) {
                return $default
            }

            throw '7z executable not found. Set SEVEN_ZIP_EXE or install 7-Zip.'
        }


        function Invoke-7Zip {
            param(
                [Parameter(Mandatory)][string]$SevenZipExe,
                [Parameter(Mandatory)][string[]]$Arguments
            )

            $output = & $SevenZipExe @Arguments 2>&1
            $exitCode = $LASTEXITCODE

            $lines = @($output | ForEach-Object { [string]$_ })
            if ($lines.Count -eq 1 -and [string]::IsNullOrWhiteSpace($lines[0])) {
                $lines = @()
            }

            return [pscustomobject]@{
                ExitCode = $exitCode
                Lines = $lines
                Text = ($lines -join "`n")
                Command = "$SevenZipExe $($Arguments -join ' ')"
            }
        }

        function Parse-7ZipCrcOutput {
            param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$OutputLines)

            $dataLine = $OutputLines | Where-Object { $_ -match '^CRC32\s+for data:\s+' } | Select-Object -First 1
            $dataNamesLine = $OutputLines | Where-Object { $_ -match '^CRC32\s+for data and names:\s+' } | Select-Object -First 1

            if (-not $dataLine -or -not $dataNamesLine) {
                throw "Unable to parse CRC lines from 7z output.`n$($OutputLines -join "`n")"
            }

            $data = [regex]::Match($dataLine, '^CRC32\s+for data:\s+([0-9A-F\-]+)$')
            $dataNames = [regex]::Match($dataNamesLine, '^CRC32\s+for data and names:\s+([0-9A-F\-]+)$')

            if (-not $data.Success -or -not $dataNames.Success) {
                throw "CRC line format mismatch in 7z output.`n$($OutputLines -join "`n")"
            }

            [pscustomobject]@{
                Data = $data.Groups[1].Value.ToUpperInvariant()
                DataAndNames = $dataNames.Groups[1].Value.ToUpperInvariant()
            }
        }


        function Write-ArtifactJson {
            param(
                [Parameter(Mandatory)][string]$Name,
                [Parameter(Mandatory)]$Data
            )

            $path = Join-Path $global:Fixture.ArtifactDir $Name
            $Data | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path -Encoding UTF8
            return $path
        }

        function Invoke-RepoScript {
            param(
                [Parameter(Mandatory)][string]$TargetPath,
                [bool]$IncludeRoot = $true
            )

            $json = & $scriptPath -Path $TargetPath -IncludeRoot:$IncludeRoot -OutputJson 2>&1
            if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
                throw "Get-Crc32.ps1 failed for path '$TargetPath'. Output:`n$($json -join "`n")"
            }

            $jsonText = ($json | Out-String).Trim()
            return ($jsonText | ConvertFrom-Json)
        }

        $sevenZip = Get-7ZipExe
        $fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("crc32-integration-{0}" -f [guid]::NewGuid().ToString('N'))
        $topFolder = Join-Path $fixtureRoot 'TopFolder'
        $nestedDir = Join-Path $topFolder 'A\B'
        $emptyDir = Join-Path $topFolder 'emptyDir'
        $file1 = Join-Path $nestedDir 'file.bin'
        $file2 = Join-Path $topFolder 'file2.txt'

        New-Item -ItemType Directory -Path $nestedDir -Force | Out-Null
        New-Item -ItemType Directory -Path $emptyDir -Force | Out-Null
        New-Item -ItemType File -Path $file1 -Force | Out-Null
        New-Item -ItemType File -Path $file2 -Force | Out-Null

        $global:Fixture = [pscustomobject]@{
            SevenZip = $sevenZip
            Root = $fixtureRoot
            TopFolder = $topFolder
            File1 = $file1
            File2 = $file2
            ScriptPath = $scriptPath
            ArtifactDir = $artifactDir
        }
    }

    AfterAll {
        if ($global:Fixture -and (Test-Path -LiteralPath $global:Fixture.Root)) {
            Remove-Item -LiteralPath $global:Fixture.Root -Recurse -Force
        }
    }

    It 'matches 7z for folder include-root and contents-only modes' {
        $includeRootResult = $null
        $contentsResult = $null
        $includeRootParsed = $null
        $contentsParsed = $null
        $scriptIncludeRoot = $null
        $scriptContentsOnly = $null

        try {
            $includeRootResult = Invoke-7Zip -SevenZipExe $global:Fixture.SevenZip -Arguments @('h', '-scrcCRC32', $global:Fixture.TopFolder)
            $contentsResult = Invoke-7Zip -SevenZipExe $global:Fixture.SevenZip -Arguments @('h', '-scrcCRC32', (Join-Path $global:Fixture.TopFolder '*'), '-r')

            if ($includeRootResult.ExitCode -ne 0) {
                throw "7z include-root command failed (exit $($includeRootResult.ExitCode)). Command: $($includeRootResult.Command)`n$($includeRootResult.Text)"
            }

            if ($contentsResult.ExitCode -ne 0) {
                throw "7z contents-only command failed (exit $($contentsResult.ExitCode)). Command: $($contentsResult.Command)`n$($contentsResult.Text)"
            }

            if (-not $includeRootResult.Lines -or $includeRootResult.Lines.Count -eq 0) {
                throw "7z include-root command produced no output. Command: $($includeRootResult.Command)"
            }

            if (-not $contentsResult.Lines -or $contentsResult.Lines.Count -eq 0) {
                throw "7z contents-only command produced no output. Command: $($contentsResult.Command)"
            }

            $includeRootParsed = Parse-7ZipCrcOutput -OutputLines $includeRootResult.Lines
            $contentsParsed = Parse-7ZipCrcOutput -OutputLines $contentsResult.Lines

            $scriptIncludeRoot = Invoke-RepoScript -TargetPath $global:Fixture.TopFolder -IncludeRoot:$true
            $scriptContentsOnly = Invoke-RepoScript -TargetPath $global:Fixture.TopFolder -IncludeRoot:$false

            $scriptIncludeRoot.'CRC32 checksum for data' | Should -Be $includeRootParsed.Data
            $scriptIncludeRoot.'CRC32 checksum for data and names' | Should -Be $includeRootParsed.DataAndNames
            $scriptContentsOnly.'CRC32 checksum for data' | Should -Be $contentsParsed.Data
            $scriptContentsOnly.'CRC32 checksum for data and names' | Should -Be $contentsParsed.DataAndNames

            # Guard against 7-Zip behavior/version drift.
            $includeRootParsed.Data | Should -Be '00000000-00000000'
            $includeRootParsed.DataAndNames | Should -Be '3ED73E74-00000003'
            $contentsParsed.Data | Should -Be '00000000-00000000'
            $contentsParsed.DataAndNames | Should -Be '06F61F71-00000002'
        }
        catch {
            Write-Host '--- 7z include-root output ---'
            Write-Host $includeRootResult.Text
            Write-Host '--- 7z contents-only output ---'
            Write-Host $contentsResult.Text
            Write-Host '--- parsed include-root ---'
            $includeRootParsed | Format-List * | Out-String | Write-Host
            Write-Host '--- parsed contents-only ---'
            $contentsParsed | Format-List * | Out-String | Write-Host
            Write-Host '--- script include-root object ---'
            $scriptIncludeRoot | Format-List * | Out-String | Write-Host
            Write-Host '--- script contents-only object ---'
            $scriptContentsOnly | Format-List * | Out-String | Write-Host
            throw
        }
        finally {
            if ($includeRootResult) {
                Set-Content -LiteralPath (Join-Path $global:Fixture.ArtifactDir '7z-include-root.txt') -Value $includeRootResult.Text -Encoding UTF8
            }
            if ($contentsResult) {
                Set-Content -LiteralPath (Join-Path $global:Fixture.ArtifactDir '7z-contents-only.txt') -Value $contentsResult.Text -Encoding UTF8
            }

            $report = [pscustomobject]@{
                Fixture = [pscustomobject]@{
                    TopFolder = $global:Fixture.TopFolder
                    File1 = $global:Fixture.File1
                    File2 = $global:Fixture.File2
                }
                IncludeRoot = [pscustomobject]@{
                    SevenZip = $includeRootResult
                    Parsed = $includeRootParsed
                    Script = $scriptIncludeRoot
                }
                ContentsOnly = [pscustomobject]@{
                    SevenZip = $contentsResult
                    Parsed = $contentsParsed
                    Script = $scriptContentsOnly
                }
                ExpectedConstants = [pscustomobject]@{
                    IncludeRootData = '00000000-00000000'
                    IncludeRootDataAndNames = '3ED73E74-00000003'
                    ContentsOnlyData = '00000000-00000000'
                    ContentsOnlyDataAndNames = '06F61F71-00000002'
                }
                GeneratedAtUtc = [DateTime]::UtcNow.ToString('o')
            }

            Write-ArtifactJson -Name 'crc32-folder-parity-report.json' -Data $report | Out-Null
        }
    }

    It 'returns 00000000 for zero-byte files in file mode' {
        $file1Result = $null
        $file2Result = $null

        try {
            $file1Result = Invoke-RepoScript -TargetPath $global:Fixture.File1
            $file2Result = Invoke-RepoScript -TargetPath $global:Fixture.File2

            $file1Result.'CRC32 checksum for data' | Should -Be '00000000'
            $file2Result.'CRC32 checksum for data' | Should -Be '00000000'
        }
        catch {
            Write-Host '--- script file1 object ---'
            $file1Result | Format-List * | Out-String | Write-Host
            Write-Host '--- script file2 object ---'
            $file2Result | Format-List * | Out-String | Write-Host
            throw
        }
        finally {
            $report = [pscustomobject]@{
                File1Path = $global:Fixture.File1
                File2Path = $global:Fixture.File2
                File1Result = $file1Result
                File2Result = $file2Result
                ExpectedDataCrc = '00000000'
                GeneratedAtUtc = [DateTime]::UtcNow.ToString('o')
            }
            Write-ArtifactJson -Name 'crc32-file-mode-report.json' -Data $report | Out-Null
        }
    }
}
