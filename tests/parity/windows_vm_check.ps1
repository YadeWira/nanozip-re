# windows_vm_check.ps1 -- the Windows half of tests/windows_original.sh, to run ON
# a Windows machine (the attribute restore does not survive wine).
#
# Put nz_orig32.exe / nz_orig64.exe (the original 0.09a Windows binaries) and
# nz_recon_i686.exe / nz_recon_x86_64.exe (this port, cross-built) in one
# directory and run:  pwsh -NoProfile -File windows_vm_check.ps1 -Dir <that dir>
#
# It archives a tree whose files carry every attribute combination with the
# Windows original under all eight codecs, extracts each with the original and
# with both of our builds, and compares contents, sizes and ATTRIBUTES plus the
# `l` and `t` console output.
param([string]$Dir = "C:\Users\ia\nzre_wo")
Set-Location $Dir
$ErrorActionPreference = "Continue"
$orig = ".\nz_orig32.exe"; $ours32 = ".\nz_recon_i686.exe"; $ours64 = ".\nz_recon_x86_64.exe"
# fixtures, with attributes set natively on Windows
if (Test-Path src) { Remove-Item -Recurse -Force src }
New-Item -ItemType Directory -Force -Path src\sub | Out-Null
-join ((1..40000) | ForEach-Object { [char](65 + ($_ % 26)) }) | Out-File -Encoding ascii src\t.txt
$rand = New-Object byte[] 100000; (New-Object Random 7).NextBytes($rand)
[IO.File]::WriteAllBytes("$Dir\src\b.bin", $rand)
"tiny"        | Out-File -Encoding ascii src\s.txt
"in a subdir" | Out-File -Encoding ascii src\sub\c.txt
1..5 | ForEach-Object { "a$_" | Out-File -Encoding ascii "src\a$_.txt" }
(Get-Item src\a2.txt).Attributes = 'ReadOnly, Archive'
(Get-Item src\a3.txt).Attributes = 'Hidden, Archive'
(Get-Item src\a4.txt).Attributes = 'System, Archive'
(Get-Item src\a5.txt).Attributes = 'ReadOnly, Hidden, System, Archive'
"attributes set: " + ((Get-ChildItem src\a*.txt -Force | ForEach-Object { "$($_.Name)=$($_.Attributes)" }) -join " ")

function State($d) {
  if (-not (Test-Path $d)) { return "" }
  (Get-ChildItem $d -Recurse -File -Force | Sort-Object FullName | ForEach-Object {
     $rel = $_.FullName.Substring((Resolve-Path $d).Path.Length).TrimStart('\')
     "$rel $($_.Length) $($_.Attributes) $((Get-FileHash $_.FullName -Algorithm SHA256).Hash.Substring(0,16))"
  }) -join "`n"
}
$pass = 0; $fail = 0
foreach ($spec in @("n:-cn","c:-cc","d:-cd","Du:-cD","f:-cf","Fu:-cF","o:-co","Ou:-cO")) {
  $tag, $opt = $spec.Split(":")
  Push-Location src
  & "..\nz_orig32.exe" a $opt -r "..\w_$tag.nz" t.txt b.bin s.txt sub a1.txt a2.txt a3.txt a4.txt a5.txt *> $null
  Pop-Location
  if (-not (Test-Path "w_$tag.nz")) { "FAIL ${tag}: archive not built"; $fail++; continue }
  foreach ($who in @("orig","o32","o64")) {
    $bin = $orig; if ($who -eq "o32") { $bin = $ours32 }; if ($who -eq "o64") { $bin = $ours64 }
    $d = "x_${tag}_$who"; if (Test-Path $d) { Remove-Item -Recurse -Force $d }
    New-Item -ItemType Directory -Force -Path $d | Out-Null
    Push-Location $d; & "..\$(Split-Path -Leaf $bin)" x -y "..\w_$tag.nz" *> $null; Pop-Location
  }
  $ref = State "x_${tag}_orig"
  foreach ($who in @("o32","o64")) {
    if ((State "x_${tag}_$who") -eq $ref) { $pass++ } else {
      "FAIL ${tag} extraction ($who):"; $fail++
      Compare-Object ($ref -split "`n") ((State "x_${tag}_$who") -split "`n") |
        Select-Object -First 4 | ForEach-Object { "    $($_.SideIndicator) $($_.InputObject)" }
    }
  }
  # console: l and t
  function Clean($s) { ($s -split "`r?`n" | Where-Object { $_ -notmatch "MHz|Win32|Win64|IO-|in [0-9]" }) -join "`n" }
  foreach ($cmd in @("l","t")) {
    $a = Clean ((& $orig $cmd "w_$tag.nz" 2>&1) | Out-String)
    foreach ($who in @($ours32, $ours64)) {
      $b = Clean ((& $who $cmd "w_$tag.nz" 2>&1) | Out-String)
      if ($a -eq $b) { $pass++ } else {
        "FAIL ${tag} console $cmd ($(Split-Path -Leaf $who)):"; $fail++
        Compare-Object ($a -split "`n") ($b -split "`n") | Select-Object -First 4 |
          ForEach-Object { "    $($_.SideIndicator) $($_.InputObject)" }
      }
    }
  }
}
"vmcheck: $pass checks passed, $fail failed"
