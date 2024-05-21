nim c --genscript .\dll_main.nim

cd .\cache\dll_main

set inputFile="@mdll_main.nim.c"
set tempFile=%inputFile%.tmp

powershell -Command ^
    "$inputFile = '%inputFile%';" ^
    "$tempFile = '%tempFile%';" ^
    "$pattern = 'N_LIB_PRIVATE void PreMainInner(void) {';" ^
    "$found = $false;" ^
    "Get-Content -Path $inputFile | ForEach-Object { if (-not $found) { if ($_ -match [regex]::Escape($pattern)) { $found = $true } else { $_ } } } | Set-Content -Path $tempFile;" ^
    "Remove-Item -Path $inputFile;" ^
    "Rename-Item -Path $tempFile -NewName $inputFile;"

REM Check if the process was successful
if exist "%inputFile%" (
    echo File has been processed successfully.
) else (
    echo There was an error processing the file.
)

call compile_dll_main.bat
cd ..\..

move .\cache\dll_main\dll_main.dll .\dll_main.dll
