# Microsoft.Diagnostics.Tracing.TraceEvent 3.2.5

The ETW assemblies the in-guest API-call and injection monitors load. Without them
those monitors exit within a second of starting and the report shows a single error
row where the trace should be, which is S17-D50.

## Where these came from

Downloaded 2026-08-07 from the official NuGet flat container:

    https://api.nuget.org/v3-flatcontainer/microsoft.diagnostics.tracing.traceevent/3.2.5/microsoft.diagnostics.tracing.traceevent.3.2.5.nupkg

- Package size: 5,483,776 bytes
- Package SHA-256: `1568E53A47089D399238AB6C98594A6404414435EE46500A2F6DA36BF140A333`

## What was taken

From `lib/netstandard2.0/`:

| File | Bytes | Why |
|---|---|---|
| `Microsoft.Diagnostics.Tracing.TraceEvent.dll` | 3,315,512 | the library the monitors load by name |
| `Microsoft.Diagnostics.FastSerialization.dll` | 76,088 | required at load time by the above |
| `Dia2Lib.dll` | 59,024 | required at load time by the above |
| `TraceReloggerLib.dll` | 23,216 | required at load time by the above |

From `build/native/amd64/`:

| File | Bytes | Why |
|---|---|---|
| `amd64/KernelTraceControl.dll` | 266,696 | needed to open a kernel ETW session; the guest is amd64 |

`msdia140.dll` was deliberately not taken: it serves symbol resolution, which these
monitors do not perform. The `x86` and `arm64` native variants were not taken because
the provisioned guest is amd64; add the matching directory here if a guest of another
architecture is ever provisioned.

## The dependency closure beside them

TraceEvent 3.2.5 ships **only** a `netstandard2.0` build — the package has no
`net4x` folder at all. A stock Windows guest runs Windows PowerShell 5.1 on the
Desktop CLR, which does not carry the .NET Standard 2.0 support-pack assemblies,
so staging the five files above alone gets `Add-Type` far enough to find the
library and no further: it throws `ReflectionTypeLoadException` naming
`System.Text.Json`, `System.Reflection.Metadata` and `System.Memory`.

The rest of the assemblies here are that closure. They were not hand-picked:
a throwaway `net472` project with a single `PackageReference` to
`Microsoft.Diagnostics.Tracing.TraceEvent` 3.2.5 was restored and published on
2026-08-08, and NuGet resolved which build of each dependency a Desktop-CLR
consumer needs. The published output is what sits in this directory.

| Assembly | Assembly version | Bytes |
|---|---|---|
| `Microsoft.Bcl.AsyncInterfaces.dll` | 9.0.0.8 | 26,384 |
| `Microsoft.Diagnostics.NETCore.Client.dll` | 0.2.10.10501 | 147,392 |
| `Microsoft.Extensions.DependencyInjection.dll` | 6.0.0.0 | 84,608 |
| `Microsoft.Extensions.DependencyInjection.Abstractions.dll` | 6.0.0.0 | 47,216 |
| `Microsoft.Extensions.Logging.dll` | 6.0.0.0 | 44,656 |
| `Microsoft.Extensions.Logging.Abstractions.dll` | 6.0.0.0 | 64,112 |
| `Microsoft.Extensions.Options.dll` | 6.0.0.0 | 58,480 |
| `Microsoft.Extensions.Primitives.dll` | 6.0.0.0 | 43,120 |
| `Microsoft.Win32.Registry.dll` | 5.0.0.0 | 26,496 |
| `System.Buffers.dll` | 4.0.3.0 | 20,856 |
| `System.Collections.Immutable.dll` | 9.0.0.8 | 259,384 |
| `System.Diagnostics.DiagnosticSource.dll` | 6.0.0.0 | 166,512 |
| `System.IO.Pipelines.dll` | 9.0.0.8 | 84,752 |
| `System.Memory.dll` | 4.0.1.2 | 142,240 |
| `System.Numerics.Vectors.dll` | 4.1.4.0 | 115,856 |
| `System.Reflection.Metadata.dll` | 9.0.0.8 | 511,264 |
| `System.Reflection.TypeExtensions.dll` | 4.1.5.0 | 21,576 |
| `System.Runtime.CompilerServices.Unsafe.dll` | 6.0.3.0 | 19,256 |
| `System.Security.AccessControl.dll` | 5.0.0.0 | 33,672 |
| `System.Security.Principal.Windows.dll` | 5.0.0.0 | 18,312 |
| `System.Text.Encodings.Web.dll` | 9.0.0.8 | 79,656 |
| `System.Text.Json.dll` | 9.0.0.8 | 726,840 |
| `System.Threading.Tasks.Extensions.dll` | 4.2.0.1 | 25,984 |
| `System.ValueTuple.dll` | 4.0.3.0 | 25,232 |

Source packages, all from `https://api.nuget.org/v3-flatcontainer/<id>/<version>/`:

| Package | Version | Bytes | SHA-256 |
|---|---|---|---|
| `Microsoft.Bcl.AsyncInterfaces` | 9.0.8 | 98,143 | `6972C4C31E1E799EA6127DE8EE90A5E66568B6821DE790621B80B592E38B7E7C` |
| `Microsoft.Diagnostics.NETCore.Client` | 0.2.510501 | 163,679 | `BDA612812A323C7D1727E09566AF97952C8BD6D2606799045CA330631FB523DC` |
| `Microsoft.Extensions.DependencyInjection` | 6.0.0 | 208,004 | `819B8C6AE9CC255CAFBDEA6ECCDA1D18F45CE9EA8A1FFFDB92CDFDE7B75890F2` |
| `Microsoft.Extensions.DependencyInjection.Abstractions` | 6.0.0 | 149,541 | `49991ED2334A22A26FBEE91DB5AF8C808946B2B3F611D3E4912F257CB83B26EE` |
| `Microsoft.Extensions.Logging` | 6.0.0 | 111,767 | `F16B1929119F5D6E4CB1790C98D55FEAC96B930F9C474D3973390E3F6294A939` |
| `Microsoft.Extensions.Logging.Abstractions` | 6.0.0 | 458,701 | `40DA9C437C7E30E2BB9576D6902CD23966BFD90C9835B74CFCE1046D6375E52C` |
| `Microsoft.Extensions.Options` | 6.0.0 | 140,038 | `0F19C48068825E992BC459315ED397AB06A202DA088C0F1549258272C5B41701` |
| `Microsoft.Extensions.Primitives` | 6.0.0 | 144,250 | `020BF2B2CCE9435D40893049164BD2CBC267C085938F5E4F7DE93B4FB4E151CE` |
| `Microsoft.Win32.Registry` | 5.0.0 | 354,731 | `F64CA53C67CA65CE7CC85A8D29AEFBB2DA2672836731E1115E8CD62730DC5080` |
| `System.Buffers` | 4.5.1 | 93,737 | `C30B3DD2C7E2F4CEE4B823D692FD42118309B42AB1F5007F923D329A5B0D6B12` |
| `System.Collections.Immutable` | 9.0.8 | 651,173 | `FF9EF9ED82CB95B9032F6F7E652A13889E13A45CBA1D048AC1D30F953ECA610C` |
| `System.Diagnostics.DiagnosticSource` | 6.0.0 | 374,970 | `458F6E5923DD2B67E04B0963D4E1C1181568DD9BC642004937302C4B93863167` |
| `System.IO.Pipelines` | 9.0.8 | 223,692 | `74EF38AD47290E08FA93CAD366ADCA9B2FF2FBA73F70FD456B576C095F492250` |
| `System.Memory` | 4.5.5 | 208,978 | `10F43DA352A29FB2B3188E4EDD4DCF5100194C8B526E4F61FE2E2B5623775A22` |
| `System.Numerics.Vectors` | 4.5.0 | 382,792 | `A9D49320581FDA1B4F4BE6212C68C01A22CDF228026099C20A8EABEFCF90F9CF` |
| `System.Reflection.Metadata` | 9.0.8 | 1,114,748 | `E0D83E08C096BC0A1BE9575010B8C609FD525327D9E5CDDF3E29AF5E77A13BC4` |
| `System.Reflection.TypeExtensions` | 4.7.0 | 249,287 | `184B42197C2D3A79187A3495F937E5F83AB21AAE634D4695C8BF5E32EA4C1C13` |
| `System.Runtime.CompilerServices.Unsafe` | 6.1.2 | 75,106 | `5F6A7F53AF3465F92BEB6DA873EBE0E496206C313313B98BADEE4355A6B25937` |
| `System.Security.AccessControl` | 5.0.0 | 621,573 | `B9E486F989FCD9EBF1C86067138F4DE03FA780E0C35E0A2B9E506D4373A6C39E` |
| `System.Security.Principal.Windows` | 5.0.0 | 535,022 | `081390C25F6F78592B28ADA853C24514488A221FE9F9A24EFAAF5373643FF3D6` |
| `System.Text.Encodings.Web` | 9.0.8 | 293,522 | `D85CB9FD502A047BB07311CC55EBF2CD00D12119724D9953FB9A70AFA3ADBAE5` |
| `System.Text.Json` | 9.0.8 | 1,877,396 | `084A0B3A3D0A7AE72D2B68D777AC99FBFE72C786A9B0487BFB1B091FDE61FF57` |
| `System.Threading.Tasks.Extensions` | 4.5.4 | 89,582 | `A304A963CC0796C5179F9C6B7D8022BBCE3B2FA7C029EB6196F631F7B462D678` |
| `System.ValueTuple` | 4.5.0 | 204,904 | `9E21FA9767D4E76BC0CEE065C1D40CC34384A114BFEC4D70E6C981168A926802` |

### Why staging these files is not sufficient on its own

Having the assemblies in the same directory does not make the Desktop CLR load
them. Two things get in the way, and both were measured against a real Windows
PowerShell 5.1 on 2026-08-08:

1. **The CLR probes the host's application base, not the loaded assembly's own
   directory.** `powershell.exe` is the application, so its base is
   `%SystemRoot%\System32\WindowsPowerShell\v1.0` — nothing here is found from
   there, and `Add-Type` fails with all these files sitting beside the library.
2. **Strong-named references bind to an exact version.** TraceEvent references
   `System.Text.Json, Version=9.0.0.0`, and the assembly NuGet resolves is
   `9.0.0.8`. A normal .NET Framework application gets binding redirects
   generated into its `app.config`; PowerShell has none for these, so even a
   successfully located assembly is rejected on version.

The monitors therefore pre-load every assembly in this directory and install an
`AssemblyResolve` handler that matches on **simple name**, which satisfies both
points at once. That handler must not call `LoadFrom` — doing so re-enters
resolution for the loaded assembly's own references and recurses until the
process dies with a `StackOverflowException`, which is what a first attempt did.
It resolves only from assemblies already loaded into the AppDomain.

## Licence

TraceEvent is published by Microsoft under the MIT licence. The package carries its
licence declaration in `Microsoft.Diagnostics.Tracing.TraceEvent.nuspec` rather than as
a bundled licence file, which is why no `LICENSE.TXT` sits beside these binaries. Every
dependency listed above is likewise published by Microsoft under the MIT licence and is
redistributable on those terms.
