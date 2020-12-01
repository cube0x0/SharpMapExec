Dynamic Language Runtime
========================
The Dynamic Language Runtime enables language developers to more easily create dynamic languages for the .NET platform. In addition to being a pluggable back-end for dynamic language compilers, the DLR provides language interop for dynamic operations on objects. The DLR has common hosting APIs for using dynamic languages as libraries or for scripting in your .NET applications.

| **What?** | **Where?** |
| --------: | :------------: |
| **Windows/Linux/macOS Builds** | [![Build status](https://dotnet.visualstudio.com/IronLanguages/_apis/build/status/DLR)](https://dotnet.visualstudio.com/IronLanguages/_build/latest?definitionId=41) [![Github build status](https://github.com/IronLanguages/dlr/workflows/CI/badge.svg)](https://github.com/IronLanguages/dlr/actions?workflow=CI) |
| **Downloads** | [![NuGet](https://img.shields.io/nuget/v/DynamicLanguageRuntime.svg)](https://www.nuget.org/packages/DynamicLanguageRuntime/) [![Release](https://img.shields.io/github/release/IronLanguages/dlr.svg)](https://github.com/IronLanguages/dlr/releases/latest)|
| **Help** | [![Gitter chat](https://badges.gitter.im/IronLanguages/ironpython.svg)](https://gitter.im/IronLanguages/ironpython) [![StackExchange](https://img.shields.io/stackexchange/stackoverflow/t/dynamic-language-runtime.svg)](http://stackoverflow.com/questions/tagged/dynamic-language-runtime) |

Code of Conduct
---------------
This project has adopted the code of conduct defined by the Contributor Covenant to clarify expected behavior in our community.
For more information see the [.NET Foundation Code of Conduct](https://dotnetfoundation.org/code-of-conduct). 

Installation
------------
The best way to install the DLR is through the NuGet DynamicLanguageRuntime package.

Documentation
-------------
The best current documentation is in the Docs/ directory, in Word and PDF format (it *was* a Microsoft project, after all).

Help
----
If you have any questions, [open an issue](https://github.com/IronLanguages/dlr/issues/new), even if it's not an actual bug. The issues are an acceptable discussion forum as well.

History
-------
The original DLR site is at [CodePlex](http://dlr.codeplex.com). The DLR was part of a much larger repository containing IronPython and IronRuby as well; you can find it at the [main](https://github.com/IronLanguages/main) repository. This is a smaller repository containing just the DLR, which makes it easier to package and should make it easier to do more regular releases.

Build
-----
You will need to have Visual Studio 2019 16.4.0 or later installed on your machine.

On Windows machines, start a Visual Studio command prompt and type:

    > make
    
On Unix machines, make sure Mono is installed and in the PATH, and type:

    $ make

Since the main development is on Windows, Mono bugs may inadvertantly be introduced
- please report them!
