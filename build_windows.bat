@echo off
setlocal enabledelayedexpansion

echo ==============================================================
echo       Packet Analyzer & DPI Engine - Windows Builder
echo ==============================================================
echo.

cd /d "%~dp0"

:: 1. Check if cl (MSVC) is already in PATH
where cl >nul 2>nul
if %ERRORLEVEL% equ 0 (
    echo [INFO] Found Microsoft Visual C++ Compiler (cl.exe) in PATH.
    goto BUILD_MSVC
)

:: 2. Check for Visual Studio 2022 / 2019 installation paths
set "VS_PATH_1=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
set "VS_PATH_2=C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
set "VS_PATH_3=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
set "VS_PATH_4=C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
set "VS_PATH_5=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"

for %%p in ("%VS_PATH_1%" "%VS_PATH_2%" "%VS_PATH_3%" "%VS_PATH_4%" "%VS_PATH_5%") do (
    if exist %%p (
        echo [INFO] Found Visual Studio vcvars64.bat at %%p
        echo [INFO] Initializing MSVC environment...
        call %%p >nul 2>nul
        goto BUILD_MSVC
    )
)

:: 3. Check if g++ (MinGW) is in PATH
where g++ >nul 2>nul
if %ERRORLEVEL% equ 0 (
    echo [INFO] Found MinGW-w64 Compiler (g++.exe) in PATH.
    goto BUILD_MINGW
)

:: 4. Check for common MinGW installation directories
if exist "C:\msys64\mingw64\bin\g++.exe" (
    set "PATH=C:\msys64\mingw64\bin;%PATH%"
    echo [INFO] Found MinGW-w64 at C:\msys64\mingw64\bin
    goto BUILD_MINGW
)
if exist "C:\mingw64\bin\g++.exe" (
    set "PATH=C:\mingw64\bin;%PATH%"
    echo [INFO] Found MinGW-w64 at C:\mingw64\bin
    goto BUILD_MINGW
)

:: 5. No C++ compiler found
echo [NOTE] No C++ compiler (MSVC 'cl' or MinGW 'g++') was detected in your PATH.
echo.
echo ==============================================================
echo  YOU DO NOT NEED TO COMPILE! THE PYTHON ENGINE RUNS INSTANTLY
echo ==============================================================
echo The native Windows DPI Engine (dpi_engine.py / dpi.bat) has
echo zero dependencies and works directly with Python 3 right now:
echo.
echo    dpi.bat test_dpi.pcap output.pcap
echo    python dpi_engine.py test_dpi.pcap output.pcap --block-app YouTube
echo.
echo If you would like to compile the C++17 Multi-Threaded engine:
echo   Option A: Install MinGW via winget:
echo             winget install MSYS2.MSYS2
echo   Option B: Install Visual Studio Community with 'Desktop C++':
echo             https://visualstudio.microsoft.com/downloads/
echo.
exit /b 0

:BUILD_MSVC
echo [BUILD] Compiling C++17 DPI Engine with MSVC...
cl /EHsc /std:c++17 /O2 /I include /Fe:dpi_engine.exe src\dpi_mt.cpp src\pcap_reader.cpp src\packet_parser.cpp src\sni_extractor.cpp src\types.cpp
if %ERRORLEVEL% equ 0 (
    echo.
    echo [SUCCESS] Successfully compiled: dpi_engine.exe
    echo You can now run: dpi_engine.exe test_dpi.pcap output.pcap
    exit /b 0
) else (
    echo [ERROR] MSVC compilation failed.
    exit /b 1
)

:BUILD_MINGW
echo [BUILD] Compiling C++17 DPI Engine with MinGW g++...
g++ -std=c++17 -O2 -I include -o dpi_engine.exe src/dpi_mt.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp
if %ERRORLEVEL% equ 0 (
    echo.
    echo [SUCCESS] Successfully compiled: dpi_engine.exe
    echo You can now run: dpi_engine.exe test_dpi.pcap output.pcap
    exit /b 0
) else (
    echo [ERROR] MinGW compilation failed.
    exit /b 1
)
