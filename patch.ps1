# FFBE Memorial KO patch - overlay on your own APK. Needs only Windows PowerShell 5.1 + .NET 4.7.2+ (built into Windows 10/11).
param([string]$Apk, [string]$Out, [switch]$Force)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$payload = Join-Path $here 'payload'
$keyDir = Join-Path $env:LOCALAPPDATA 'FFBE-KO-Patch\key'
# reuse a key made inside the Claude desktop app sandbox, so updates keep installing over the same app
if (-not (Test-Path (Join-Path $keyDir 'signing_key.txt'))) {
  $k = Get-ChildItem (Join-Path $env:LOCALAPPDATA 'Packages\Claude_*\LocalCache\Local\FFBE-KO-Patch\key\signing_key.txt') -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($k) { $keyDir = $k.DirectoryName }
}

if (-not $Apk) {
  Add-Type -AssemblyName System.Windows.Forms
  $dlg = New-Object System.Windows.Forms.OpenFileDialog
  $dlg.Title = 'FFBE Memorial 원본 APK 선택'; $dlg.Filter = 'APK (*.apk)|*.apk'
  if ($dlg.ShowDialog() -ne 'OK') { Write-Host '취소됨'; exit 1 }
  $Apk = $dlg.FileName
}
$Apk = (Resolve-Path -LiteralPath $Apk).Path
if (-not $Out) { $Out = Join-Path (Split-Path -Parent $Apk) ([IO.Path]::GetFileNameWithoutExtension($Apk) + '-KO.apk') }
if ((Resolve-Path -LiteralPath (Split-Path -Parent $Out)).Path -and ($Out -eq $Apk)) { throw '출력 파일이 원본과 같습니다.' }

Add-Type -Language CSharp -ReferencedAssemblies 'System.Core','System.IO.Compression' -TypeDefinition (Get-Content -Raw -Encoding UTF8 (Join-Path $here 'ApkPatcher.cs'))

Write-Host "원본: $Apk"
$expected = (Get-Content -Raw (Join-Path $payload 'expected_sha256.txt')).Trim().ToLower()
$actual = [ApkPatcher]::Sha256File($Apk)
if ($actual -ne $expected) {
  Write-Host "경고: 이 APK는 패치가 만들어진 버전(FFBE-Memorial-EN-Global-Events-v208, 145206221 bytes)과 다릅니다." -ForegroundColor Yellow
  Write-Host "  기대 SHA-256: $expected"; Write-Host "  실제 SHA-256: $actual"
  if (-not $Force) {
    $a = Read-Host '그래도 계속하시겠습니까? (y/N)'
    if ($a -notmatch '^[yY]') { exit 1 }
  }
}
Write-Host '패치 적용 중... (1~2분)'
[ApkPatcher]::Run($Apk, $Out, $payload, $keyDir)

# 사후 점검: ZIP이 열리고 사전/글꼴이 payload와 같은지
Add-Type -AssemblyName System.IO.Compression.FileSystem
$z = [IO.Compression.ZipFile]::OpenRead($Out)
try {
  $names = $z.Entries | ForEach-Object FullName
  foreach ($n in 'assets/ko_dict.json','assets/frida_script.js','assets/font/FOT-SkipStd-E.otf','assets/font/TT_RodinCattleya-B.ttf','classes.dex','lib/arm64-v8a/libgame.so') {
    if ($names -notcontains $n) { throw "결과물에 $n 이(가) 없습니다." }
  }
  if (@($names | Where-Object { $_ -match '^META-INF/.*\.(SF|RSA)$' }).Count -ne 0) { throw '이전 서명 파일이 남아 있습니다.' }
  Write-Host ("검증 통과: 엔트리 {0}개" -f $names.Count)
} finally { $z.Dispose() }
Write-Host "완료: $Out" -ForegroundColor Green
Write-Host ("크기 {0:N0} bytes / SHA-256 {1}" -f (Get-Item $Out).Length, [ApkPatcher]::Sha256File($Out))
