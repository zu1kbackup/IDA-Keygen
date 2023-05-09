# IDA-Keygen
从网上收集的IDA keygen 、IDA patch、IDA Key checker 。

每个目录中都有对应的使用方法。其中 ida_key_checker 来自：https://github.com/pr701/ida_key_checker


下面两个项目针对 IDA 7.2 之前的安装包密码进行暴力破解。

find_drand48_innosetup_pw 项目来自：https://github.com/seritools/find_drand48_innosetup_pw 

ida_setup_password_cracker 项目来自：https://github.com/namazso/ida_setup_password_cracker 

IDA-patcher
来自: https://github.com/modz2014/IDA-patcher

# IDA 绿化设置

首先安装 python 并将 python 移动到 IDA 的目录，然后运行下列脚本。其中脚本中 PYTHON_BASE 根据自己的 python 目录进行更改即可。
```
rem 获取 python 环境
set PATH=%~dp0
set PYTHON_BASE=%PATH%Python39
set PYTHON_PATH=%PYTHON_BASE%\python.exe
set PYTHONW_PATH=%PYTHON_BASE%\pythonw.exe
set PYTHON_LIB=%PYTHON_BASE%\Lib
set PYTHON_DLL=%PYTHON_BASE%\DLLs

rem  设置 python 环境
@reg add HKEY_CURRENT_USER\SOFTWARE\Python\PythonCore\3.9\InstallPath /t REG_SZ /d %PYTHON_BASE% /f
@reg add HKEY_CURRENT_USER\SOFTWARE\Python\PythonCore\3.9\InstallPath /v "ExecutablePath" /t REG_SZ /d %PYTHON_PATH% /f
@reg add HKEY_CURRENT_USER\SOFTWARE\Python\PythonCore\3.9\InstallPath /v "WindowedExecutablePath" /t REG_SZ /d %PYTHONW_PATH% /f
@reg add HKEY_CURRENT_USER\SOFTWARE\Python\PythonCore\3.9\PythonPath /d %PYTHON_LIB%;%PYTHON_DLL% /f

rem  设置 Python3TargetDLL 环境
set PYTHON39_DLL=%PYTHON_BASE%\python39.dll
reg.exe add "HKCU\SOFTWARE\Hex-Rays\IDA" /v "Python3TargetDLL" /t REG_SZ /d %PYTHON39_DLL% /f

rem  禁止自动更新
reg.exe add "HKCU\SOFTWARE\Hex-Rays\IDA" /v "AutoCheckUpdates" /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Hex-Rays\IDA" /v "AutoRequestUpdates" /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Hex-Rays\IDA" /v "AutoUseLumina" /t REG_DWORD /d 0 /f

echo "Greening is completed, please press any key to exit"
pause
```

参考：http://scz.617.cn:8/python/202011182246.txt

之前的一个仓库 https://github.com/CKCat/IDA_sdk_tools.git 因为违反 DMCA 被删了，所以如果这个仓库的东西对你有用，最好还是下载到本地吧。
```
Hello,

We received a DMCA takedown notice regarding your repository CKCat/IDA_sdk_tools.
As such, we have disabled public access to the repository.

The notice has been publicly posted at:

https://github.com/github/dmca/blob/master/2023/04/2023-04-19-hex-rays.md

If you believe that your repository was disabled as a result of mistake or misidentification, you have the right to file a counter notice and have the repository reinstated. Our help articles provide more details about how the DMCA notice-and-takedown process works at GitHub and how to file a counter notice with us if you choose:

https://docs.github.com/articles/dmca-takedown-policy
https://docs.github.com/articles/guide-to-submitting-a-dmca-counter-notice

If you have any questions about the process or the risks in filing a counter notice, we suggest that you consult with a lawyer.

Thanks,
The GitHub Team
```