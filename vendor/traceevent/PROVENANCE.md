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

## Licence

TraceEvent is published by Microsoft under the MIT licence. The package carries its
licence declaration in `Microsoft.Diagnostics.Tracing.TraceEvent.nuspec` rather than as
a bundled licence file, which is why no `LICENSE.TXT` sits beside these binaries.
