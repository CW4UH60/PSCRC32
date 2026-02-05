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
            param(
                [Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$OutputLines,
                [bool]$RequireDataAndNames = $true
            )

            $dataLine = $OutputLines | Where-Object { $_ -match '^CRC32\s+for data:\s+' } | Select-Object -First 1
            $dataNamesLine = $OutputLines | Where-Object { $_ -match '^CRC32\s+for data and names:\s+' } | Select-Object -First 1

            if (-not $dataLine) {
                throw "Unable to parse CRC data line from 7z output.`n$($OutputLines -join "`n")"
            }

            if ($RequireDataAndNames -and -not $dataNamesLine) {
                throw "Unable to parse CRC data-and-names line from 7z output.`n$($OutputLines -join "`n")"
            }

            $data = [regex]::Match($dataLine, '^CRC32\s+for data:\s+([0-9A-F\-]+)$')
            if (-not $data.Success) {
                throw "CRC data line format mismatch in 7z output.`n$($OutputLines -join "`n")"
            }

            $dataAndNamesValue = $null
            if ($dataNamesLine) {
                $dataNames = [regex]::Match($dataNamesLine, '^CRC32\s+for data and names:\s+([0-9A-F\-]+)$')
                if (-not $dataNames.Success) {
                    throw "CRC data-and-names line format mismatch in 7z output.`n$($OutputLines -join "`n")"
                }

                $dataAndNamesValue = $dataNames.Groups[1].Value.ToUpperInvariant()
            }

            [pscustomobject]@{
                Data = $data.Groups[1].Value.ToUpperInvariant()
                DataAndNames = $dataAndNamesValue
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

        function Export-FixtureArtifacts {
            param(
                [Parameter(Mandatory)][string]$FixtureRoot,
                [Parameter(Mandatory)][string]$ArtifactDir
            )

            if (-not (Test-Path -LiteralPath $FixtureRoot)) {
                return $null
            }

            $topFolderPath = Join-Path $FixtureRoot 'TopFolder'
            if (-not (Test-Path -LiteralPath $topFolderPath)) {
                throw "Expected fixture folder '$topFolderPath' was not found."
            }

            $artifactTopFolder = Join-Path $ArtifactDir 'TopFolder'
            if (Test-Path -LiteralPath $artifactTopFolder) {
                Remove-Item -LiteralPath $artifactTopFolder -Recurse -Force
            }

            Copy-Item -LiteralPath $topFolderPath -Destination $ArtifactDir -Recurse -Force

            # Ensure empty directories are preserved in zipped CI artifacts (hidden files can be excluded by upload-artifact defaults).
            $artifactEmptyDir = Join-Path $artifactTopFolder 'emptyDir'
            if ((Test-Path -LiteralPath $artifactEmptyDir) -and -not (Get-ChildItem -LiteralPath $artifactEmptyDir -Force | Select-Object -First 1)) {
                Set-Content -LiteralPath (Join-Path $artifactEmptyDir 'emptyDir.deleteMe') -Value '' -NoNewline -Encoding ASCII
            }

            $inventory = Get-ChildItem -LiteralPath $topFolderPath -Recurse -Force | ForEach-Object {
                [pscustomobject]@{
                    RelativePath = $_.FullName.Substring($FixtureRoot.TrimEnd('\', '/').Length).TrimStart('\', '/')
                    Type = if ($_.PSIsContainer) { 'Directory' } else { 'File' }
                    Length = if ($_.PSIsContainer) { $null } else { $_.Length }
                }
            }

            $snapshotReport = [pscustomobject]@{
                FixtureRoot = $FixtureRoot
                ExportedRoot = $artifactTopFolder
                Items = $inventory
                GeneratedAtUtc = [DateTime]::UtcNow.ToString('o')
            }

            Write-ArtifactJson -Name 'fixture-snapshot-report.json' -Data $snapshotReport | Out-Null
            return $artifactTopFolder
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
        $file3 = Join-Path $topFolder 'non-empty-text.txt'
        $file4 = Join-Path $nestedDir 'non-empty-bytes.bin'

        New-Item -ItemType Directory -Path $nestedDir -Force | Out-Null
        New-Item -ItemType Directory -Path $emptyDir -Force | Out-Null
        New-Item -ItemType File -Path $file1 -Force | Out-Null
        New-Item -ItemType File -Path $file2 -Force | Out-Null
        Set-Content -LiteralPath $file3 -Value 'abc' -NoNewline -Encoding ASCII
        [System.IO.File]::WriteAllBytes($file4, [byte[]](0..255))

        $global:Fixture = [pscustomobject]@{
            SevenZip = $sevenZip
            Root = $fixtureRoot
            TopFolder = $topFolder
            File1 = $file1
            File2 = $file2
            File3 = $file3
            File4 = $file4
            ScriptPath = $scriptPath
            ArtifactDir = $artifactDir
        }
    }

    AfterAll {
        if ($global:Fixture) {
            Export-FixtureArtifacts -FixtureRoot $global:Fixture.Root -ArtifactDir $global:Fixture.ArtifactDir | Out-Null
        }

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
            $includeRootParsed.Data | Should -Be '5E29CE35-00000000'
            $includeRootParsed.DataAndNames | Should -Be '5E0C7D03-00000004'
            $contentsParsed.Data | Should -Be '5E29CE35-00000000'
            $contentsParsed.DataAndNames | Should -Be 'FE057358-00000002'
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
                    IncludeRootData = '5E29CE35-00000000'
                    IncludeRootDataAndNames = '5E0C7D03-00000004'
                    ContentsOnlyData = '5E29CE35-00000000'
                    ContentsOnlyDataAndNames = 'FE057358-00000002'
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

    It 'matches expected CRC32 values for non-empty files in file mode' {
        $file3Result = $null
        $file4Result = $null
        $file3SevenZip = $null
        $file4SevenZip = $null
        $file3SevenZipParsed = $null
        $file4SevenZipParsed = $null

        try {
            $file3Result = Invoke-RepoScript -TargetPath $global:Fixture.File3
            $file4Result = Invoke-RepoScript -TargetPath $global:Fixture.File4

            $file3Result.'CRC32 checksum for data' | Should -Be '352441C2'
            $file4Result.'CRC32 checksum for data' | Should -Be '29058C73'

            $file3SevenZip = Invoke-7Zip -SevenZipExe $global:Fixture.SevenZip -Arguments @('h', '-scrcCRC32', $global:Fixture.File3)
            $file4SevenZip = Invoke-7Zip -SevenZipExe $global:Fixture.SevenZip -Arguments @('h', '-scrcCRC32', $global:Fixture.File4)

            if ($file3SevenZip.ExitCode -ne 0) {
                throw "7z file3 command failed (exit $($file3SevenZip.ExitCode)). Command: $($file3SevenZip.Command)`n$($file3SevenZip.Text)"
            }

            if ($file4SevenZip.ExitCode -ne 0) {
                throw "7z file4 command failed (exit $($file4SevenZip.ExitCode)). Command: $($file4SevenZip.Command)`n$($file4SevenZip.Text)"
            }

            $file3SevenZipParsed = Parse-7ZipCrcOutput -OutputLines $file3SevenZip.Lines -RequireDataAndNames:$false
            $file4SevenZipParsed = Parse-7ZipCrcOutput -OutputLines $file4SevenZip.Lines -RequireDataAndNames:$false

            $file3Result.'CRC32 checksum for data' | Should -Be $file3SevenZipParsed.Data
            $file4Result.'CRC32 checksum for data' | Should -Be $file4SevenZipParsed.Data
        }
        catch {
            Write-Host '--- script file3 object ---'
            $file3Result | Format-List * | Out-String | Write-Host
            Write-Host '--- script file4 object ---'
            $file4Result | Format-List * | Out-String | Write-Host
            Write-Host '--- 7z file3 output ---'
            Write-Host $file3SevenZip.Text
            Write-Host '--- 7z file4 output ---'
            Write-Host $file4SevenZip.Text
            throw
        }
        finally {
            $report = [pscustomobject]@{
                File3Path = $global:Fixture.File3
                File4Path = $global:Fixture.File4
                File3Result = $file3Result
                File4Result = $file4Result
                File37Zip = $file3SevenZipParsed
                File47Zip = $file4SevenZipParsed
                Expected = [pscustomobject]@{
                    File3DataCrc = '352441C2'
                    File4DataCrc = '29058C73'
                }
                GeneratedAtUtc = [DateTime]::UtcNow.ToString('o')
            }
            Write-ArtifactJson -Name 'crc32-non-empty-file-mode-report.json' -Data $report | Out-Null
        }
    }

    It 'honors -Gui explicit mode with Windows detection and guardrails' {
        . $global:Fixture.ScriptPath

        $guiInvocation = [pscustomobject]@{
            Called = $false
            IsWindows = $null
        }

        $guiAction = {
            param($ResolvedIsWindows)
            $guiInvocation.Called = $true
            $guiInvocation.IsWindows = $ResolvedIsWindows
        }

        { Invoke-GetCrc32EntryPoint -Gui -IsWindowsOverride:$false -StartGuiAction $guiAction } |
            Should -Not -Throw

        $guiInvocation.Called | Should -BeTrue
        $guiInvocation.IsWindows | Should -BeFalse

        { Start-7ZipCrc32Gui -IsWindowsOverride:$false } |
            Should -Throw 'GUI mode requires Windows*'
    }
}
