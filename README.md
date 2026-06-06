# KernelBase

> A lightweight Windows kernel driver that exports helper functions for kernel image analysis, module export resolution, module information queries, safe memory access, and access to un‑exported kernel internals.  
> 轻量 Windows 内核驱动，导出内核映像分析、模块导出解析、模块信息查询、安全内存访问及未导出内核内部函数访问等辅助函数。

---

## Why KernelBase? / 为什么需要 KernelBase？

Many kernel security tools, rootkit detection, or calling of non‑exported kernel functions require the base address of `ntoskrnl.exe`, the ability to convert relative offsets into absolute addresses, resolve functions from other kernel modules, obtain module information, safely read and write kernel memory, and even access previously un‑exported internal routines. This driver isolates those steps into a standalone module, so other drivers only need to dynamically obtain the exported helpers – no need to reinvent the wheel.

很多内核安全工具、Rootkit 检测，或是调用未导出的内核函数，都需要先拿到 `ntoskrnl.exe` 的基址，将相对偏移转换为绝对地址，从其他内核模块解析函数，获取模块信息，安全地读写内核内存，甚至访问此前未公开的内部例程。这个驱动把这些步骤抽离成一个独立模块，其他驱动只需动态获取这些辅助函数就行了，不用重复造轮子。

---

## Features / 功能

Functions are categorized by risk level. For full per‑function documentation, see the [Wiki API Reference](https://github.com/YunLv-L/KernelBase/wiki/API-Reference).  
函数按风险等级分类。每个函数的完整文档请见 [Wiki API 参考](https://github.com/YunLv-L/KernelBase/wiki/API-Reference)。

| Risk Level / 风险等级 | Count / 数量 | Description / 说明 |
|-----------------------|--------------|-------------------|
| ✅ **Safe / 安全** | 13 | Read‑only operations, safe to call anytime. / 只读操作，可随时调用。 |
| ⚠️ **Moderate / 中危** | 7 | Returns sensitive pointers or requires IRQL caution. / 返回敏感指针或需注意 IRQL。 |
| 🔴 **High / 高危** | 6 | **Must** attach a kernel debugger (PatchGuard disabled). / **必须**连接内核调试器（PatchGuard 禁用）。 |

> For detailed risk level definitions and usage preconditions, see [Risk Levels Explained](https://github.com/YunLv-L/KernelBase/wiki/Risk-Levels-Explained).  
> 详细风险等级定义和使用前提请见 [风险等级说明](https://github.com/YunLv-L/KernelBase/wiki/Risk-Levels-Explained)。

---

## Build Requirements / 编译要求

- **Visual Studio Build Tools** (2019 or later, with MSVC toolchain)  
  **Visual Studio Build Tools**（2019 或更高，包含 MSVC 工具链）
- **Windows Driver Kit (WDK)** – e.g., version `10.0.26100.0`  
  **Windows Driver Kit (WDK)** – 例如版本 `10.0.26100.0`
- Typical WDK installation path / 典型 WDK 安装路径: `D:\WindowsKit` (adjust as needed / 根据实际情况修改)

---

## How to Build / 如何编译

1. Open **x64 Native Tools Command Prompt for VS**  
   打开 **x64 Native Tools Command Prompt for VS**
2. Set the WDK root environment variable (modify if your WDK is elsewhere)  
   设置 WDK 根目录环境变量（如果 WDK 装在其他位置请自行修改）:
   ```cmd
   set WDKBuildRoot=D:\WindowsKit
   ```
3. Navigate to the project root and run / 进入项目根目录运行:
   ```cmd
   build.bat
   ```
4. The compiled driver will be located at `bin\x64\Debug\KernelBase.sys`  
   编译好的驱动会放在 `bin\x64\Debug\KernelBase.sys`。

For a complete walkthrough, see the [Quick Start Wiki](https://github.com/YunLv-L/KernelBase/wiki/Quick-Start).  
完整操作指南请见 [快速开始 Wiki](https://github.com/YunLv-L/KernelBase/wiki/Quick-Start)。

---

## Signing / 签名

> 💡 **为了让你更快上手：** KernelBase 在 `certs/` 目录下提供了一个公共测试证书，方便你直接签名加载，省去生成证书的步骤。  
> **To help you get started quickly:** KernelBase includes a public test certificate in the `certs/` folder, so you can sign and load the driver right away without extra setup.

### Using the provided test certificate / 使用提供的测试证书

A public test certificate is included in the `certs/` folder for development purposes only.  
`certs/` 文件夹中包含一个公共测试证书，仅用于开发目的。

**DO NOT use this certificate for production. It is publicly shared and its password is `none` (the literal string).**  
**请勿将此证书用于生产环境。它是公开共享的，密码为 `none`（即字符串 none）。**

To sign with it, simply run:
使用它签名只需运行：

```cmd
sign.bat
```

The script will automatically use `certs\TestCert.pfx` (password: `none`) to sign `KernelBase.sys`.  
脚本将自动使用 `certs\TestCert.pfx`（密码为 `none`）对 `KernelBase.sys` 进行签名。

### Using your own certificate / 使用你自己的证书

If you prefer to use your own certificate, either:
如果你想使用自己的证书，可以：

1. Replace `certs\TestCert.pfx` with your own `.pfx` file, or  
   将 `certs\TestCert.pfx` 替换为你自己的 `.pfx` 文件，或
2. Edit `sign.bat` and update the `PFX` and `PASSWORD` variables.  
   编辑 `sign.bat`，更新 `PFX` 和 `PASSWORD` 变量。

Before loading the driver, enable test signing mode / 加载驱动前，先开启测试签名模式:
```cmd
bcdedit /set testsigning on
```
Then restart the system / 然后重启系统。

### Fix DebugView No Output / 解决 DebugView 无输出

If DebugView shows no kernel output after loading KernelBase, enable DbgPrint via registry:  
如果加载 KernelBase 后 DebugView 没有内核输出，可通过注册表启用 DbgPrint：

```cmd
regedit /s DbgPrint\Enable_DbgPrint.reg
shutdown /r /t 0
```

To restore the default setting:  
要恢复默认设置：

```cmd
regedit /s DbgPrint\Disable_DbgPrint.reg
```

---

## Loading the Driver / 加载驱动

```cmd
sc create KernelBase type= kernel binPath= "full\path\to\KernelBase.sys"
sc start KernelBase
```

To make it start automatically at boot / 设置为系统启动时自动加载:
```cmd
sc config KernelBase start= system
```

---

## Usage in Other Drivers / 在其他驱动中使用

### ❌ Wrong approach (will always fail) / 错误用法（永远失败）

`MmGetSystemRoutineAddress` **only** searches the export tables of `ntoskrnl.exe` and `hal.dll`. It **cannot** find exports from any third‑party driver (including `KernelBase.sys`). The call below will **always** return `NULL`.

`MmGetSystemRoutineAddress` **仅**查找 `ntoskrnl.exe` 和 `hal.dll` 的导出表，**无法**解析任何第三方驱动（包括 `KernelBase.sys`）的导出。下面的调用**永远**返回 `NULL`。

```c
// DO NOT DO THIS - it will never work / 不要这样做，永远无效
PVOID (*GetKernelBase)(void) = (PVOID (*)(void))MmGetSystemRoutineAddress(L"GetKernelBase");
```

### ✅ Correct approach / 正确用法

You need to manually locate `KernelBase.sys` in the system module list and parse its PE export table. The generic helper function below can retrieve **any** exported function from a loaded driver by name.  
你需要手动在系统模块列表中定位 `KernelBase.sys` 并解析它的 PE 导出表。下面的通用辅助函数可以通过名称获取任意已加载驱动导出的**任何**函数。

```c
// Universal helper: get exported function address from a loaded driver
// 通用辅助函数：从已加载驱动中获取导出函数地址
PVOID GetExportFromDriver(PCWSTR DriverFileName, PCSTR ExportName)
{
    NTSTATUS status;
    ULONG size = 0;
    PRTL_PROCESS_MODULES modules = NULL;
    PVOID funcAddr = NULL;

    status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &size);
    if (status != STATUS_INFO_LENGTH_MISMATCH) return NULL;

    modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, size, 'gKwK');
    if (!modules) return NULL;

    status = ZwQuerySystemInformation(SystemModuleInformation, modules, size, NULL);
    if (!NT_SUCCESS(status)) { ExFreePoolWithTag(modules, 'gKwK'); return NULL; }

    PVOID targetBase = NULL;
    for (ULONG i = 0; i < modules->NumberOfModules; ++i) {
        PCWSTR fullPath = modules->Modules[i].FullPathName;
        PCWSTR fileName = wcsrchr(fullPath, L'\\');
        fileName = fileName ? (fileName + 1) : fullPath;
        if (_wcsicmp(fileName, DriverFileName) == 0) {
            targetBase = modules->Modules[i].ImageBase;
            break;
        }
    }
    ExFreePoolWithTag(modules, 'gKwK');
    if (!targetBase) return NULL;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)targetBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PUCHAR)targetBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    ULONG exportRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportRva) return NULL;

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)targetBase + exportRva);
    DWORD* names = (DWORD*)((PUCHAR)targetBase + exports->AddressOfNames);
    WORD* ordinals = (WORD*)((PUCHAR)targetBase + exports->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)((PUCHAR)targetBase + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
        PCSTR name = (PCSTR)((PUCHAR)targetBase + names[i]);
        if (strcmp(name, ExportName) == 0) {
            funcAddr = (PVOID)((PUCHAR)targetBase + functions[ordinals[i]]);
            break;
        }
    }
    return funcAddr;
}
```

**Then in your `DriverEntry` / 然后在你的 `DriverEntry` 里:**

```c
// 获取需要的导出函数
PVOID (*GetKernelBase)(void) = (PVOID (*)(void))
    GetExportFromDriver(L"KernelBase.sys", "GetKernelBase");
// ... add others as needed

if (GetKernelBase) {
    PVOID base = GetKernelBase();
    // Now you can use it...
}
```

For more examples and a detailed explanation, see the [Wiki page on calling from your driver](https://github.com/YunLv-L/KernelBase/wiki/Calling-KernelBase-from-Your-Driver).  
更多示例和详细解释，请见 [Wiki 调用页面](https://github.com/YunLv-L/KernelBase/wiki/Calling-KernelBase-from-Your-Driver)。

---

## Loading Order / 加载顺序

Calling drivers **must** be loaded after `KernelBase.sys`. You can enforce this via service dependency:  
调用方驱动**必须**在 `KernelBase.sys` 之后加载，可通过服务依赖保证加载顺序：

```cmd
sc create YourDriver type= kernel binPath= "..." depend= KernelBase
```

---

## 📚 Wiki / 文档

For detailed guides, API reference, FAQ, and more:  
更详细的指南、API 参考、常见问题等：

- [Home / 首页](https://github.com/YunLv-L/KernelBase/wiki)
- [Quick Start / 快速开始](https://github.com/YunLv-L/KernelBase/wiki/Quick-Start)
- [API Reference / API 参考](https://github.com/YunLv-L/KernelBase/wiki/API-Reference)
- [Calling from Your Driver / 从你的驱动调用](https://github.com/YunLv-L/KernelBase/wiki/Calling-KernelBase-from-Your-Driver)
- [Risk Levels Explained / 风险等级说明](https://github.com/YunLv-L/KernelBase/wiki/Risk-Levels-Explained)
- [FAQ / 常见问题](https://github.com/YunLv-L/KernelBase/wiki/FAQ)
- [Version History / 版本历史](https://github.com/YunLv-L/KernelBase/wiki/Version-History)
- [Demo Drivers / 演示驱动](https://github.com/YunLv-L/KernelBase/wiki/Demo-Drivers)
- [Contributing / 贡献指南](https://github.com/YunLv-L/KernelBase/wiki/Contributing)
- [Roadmap / 未来计划](https://github.com/YunLv-L/KernelBase/wiki/Roadmap)

---

## License / 许可证

This project is licensed under the **Apache License 2.0**.  
本项目采用 **Apache License 2.0** 授权。  
See the [LICENSE](LICENSE) file for the full license text.  
完整许可证文本请查看 [LICENSE](LICENSE) 文件。

---

## Disclaimer / 免责声明

This driver is intended for **educational and research purposes** only.  
本驱动仅用于**教育和研究**目的。  
Use in production environments requires proper Microsoft signing and compliance with applicable laws.  
在生产环境中使用需要正确的微软签名，并遵守相关法律法规。
