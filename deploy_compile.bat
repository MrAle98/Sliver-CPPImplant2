call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x86_amd64 
echo %PATH%
cmake.exe --preset %1
cmake.exe --build --preset %2