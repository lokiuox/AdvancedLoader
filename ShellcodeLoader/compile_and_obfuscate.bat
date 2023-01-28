@echo off
echo Step 1: compile with signature
del step1.exe
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /target:exe /out:step1.exe /keyfile:key.snk /unsafe Program.cs DInvoke.cs Unhooker.cs
echo Step 2: dotfuscator
"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\Extensions\PreEmptiveSolutions\DotfuscatorCE\dotfuscator.exe" /q Dotfuscator.xml
echo Step 3: sign again
cd Dotfuscated

"C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools\ildasm.exe" step1.exe /out=disass.il
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ilasm.exe /exe /resource=disass.res /X64 /PE64 /key=..\key.snk /output=..\ShellcodeLoader_Obf.exe /MDV=v4.0.30319 /MSV=2.0 disass.il
pause
cd ..
rmdir /S /Q Dotfuscated
del step1.exe