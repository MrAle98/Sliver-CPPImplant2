call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" x86_amd64 
"C:\vcpkg\vcpkg\downloads\tools\cmake-3.25.0-windows\cmake-3.25.0-windows-i386\bin\cmake.exe" --preset %1
"C:\vcpkg\vcpkg\downloads\tools\cmake-3.25.0-windows\cmake-3.25.0-windows-i386\bin\cmake.exe" --build --preset %2