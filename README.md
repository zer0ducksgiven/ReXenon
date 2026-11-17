# ReXenon

ReXenon converts Xbox 360 executables into C++ code that can be compiled for any platform. It is a fork of
hedge-dev's [XenonRecomp](https://github.com/hedge-dev/XenonRecomp) (MIT) and builds the game code of the
[Forza Motorsport 2 PC port](https://github.com/zer0ducksgiven/Forza-Motorsport-2-ReGPU).

**DISCLAIMER:** like XenonRecomp, ReXenon does not provide a runtime. It only converts the game code to C++,
which won't work without a runtime behind it. **Making the game work is your responsibility.**

## Why use it instead of XenonRecomp

XenonRecomp is a great base, and ReXenon keeps its design, command line and config format. What it changes
is what happens when the recompiler meets code it can't handle, how close the instructions are to the
console, how much a new game needs set up by hand, and how much CPU time the guest memory accesses cost.

### It fails loudly instead of writing wrong code

When XenonRecomp meets an instruction it can't recompile, it prints a message, leaves only a disassembly
comment where the code should be, and keeps going. A call or branch to an address it doesn't know is quieter
still: it becomes a `// ERROR` comment in the output, usually followed by a `return`, with no message at all.
Either way the output still compiles, the run still succeeds, and the game misbehaves later, far from the
cause.

ReXenon writes `PPC_UNIMPLEMENTED(address, what)` or `PPC_UNRESOLVED_BRANCH(from, to)` there, which trap by
default. It lists every problem at the end of the run and exits with an error unless you set
`allow_unresolved = true`. A clean run means every instruction was recompiled.

### The instructions are closer to the console

ReXenon builds and runs Xenia's PowerPC instruction tests (`ReXenonTests`, 170,448 cases); 142,286 pass. Most
of the 28,161 that still fail involve NaN inputs or differ only in the CR bits; a smaller number are in the
estimate instructions (`vrefp`, `vrsqrtefp`, `fres`) and in `vmaddfp`/`vnmsubfp`/`vsl`/`vsr` with ordinary
values. Fixes over XenonRecomp include:

- Every scalar instruction the tests use, and 47 vector instructions XenonRecomp didn't have (compares,
  integer max/min, saturating adds and packs, averages, rotates and shifts, VMX128 forms). `vmaxfp`/`vminfp`
  handle NaN and signed zero as VMX does, and vector record forms set cr6.
- `vpkd3d128` for types 0-5 with packs 1-3, matching Xenia (type 6 and pack 0 still trap as unimplemented).
  XenonRecomp's FLOAT16_4 pack read its source after overwriting it when source and destination were the
  same register; FM2's shipped code had 4 such packs writing garbage.
- `vsldoi128` encodings that the disassembler took for PPC405 multiply-accumulate instructions (`mullhwu.`,
  `macchw`...) are decoded as `vsldoi128`. Forza Motorsport 3 has one.
- `dcbz` clears the whole 128-byte cache line (XenonRecomp cleared 32 bytes).
- `fctid`/`fctidz` saturate at exactly 2^63. `mfocrf` and `mtfsf` use their field masks.
- Divides by zero and overflowing divides give 0 instead of crashing the host. PowerPC leaves the result
  undefined, and Xenia also uses 0.
- Jump tables switch on the low 32 bits of the register, as 32-bit guest code expects.
- Conditional calls (`bcl`, `beql`, `bnectrl` and friends) are recompiled, setting LR on both paths, and
  `blrl` calls through LR. XenonRecomp reported the first as unrecognized instructions and emitted a debug
  trap for the second.
- A function that runs off its end into the next one becomes a tail call. XenonRecomp's version cut PGR4's
  `memset` short, so it lost the last 1 to 3 bytes.
- The XEX loader allocates the full image for basic-compressed executables (XenonRecomp's buffer could end
  short of the size it reports).

### Less to set up for a new game

XenonRecomp finds most functions from `.pdata` and `bl` targets, but it gets some wrong: functions with jump
tables, C++ functions whose exception-handler code it takes for the end of the function, and exception data
in front of functions, which it decodes as code. Ports fix these by hand with a `functions` list and
`invalid_instructions` entries (Forza Motorsport 2 had 28, Project Gotham Racing 4 had 262). ReXenon finds
most of them itself:

- Exception data in front of functions (`.pdata` entries with the exception flag) is skipped automatically.
- A branch into the middle of another function, right after code that never falls through, starts a new
  function there.
- `auto_switch_tables = true` finds and checks jump tables at load time, so the switch table file only has to
  list the ones the patterns miss.
- `data_function_starts = true` also starts a function at code addresses stored in `.rdata` or `.data` that
  sit where a function would start (after `blr`, padding or an unconditional `b`). It's a safety net so a
  function reached only through a vtable or callback can't be merged into its neighbour.
- `emit_analysis_path` writes the functions and switch tables the analysis found as config files, so a port
  can freeze them. The round trip gives identical output.

Skipping exception data alone took PGR4 from 161 problems to 3 with no config change; splitting at stranded
branch targets fixed the last 3. With their hand-written function lists removed, FM2 and PGR4 both generate
with no analysis problems (FM2 had 328 before, PGR4 3,215). Neither game has been played that way yet, so the
FM2 port still ships with its list.

### More hooks for the port

The output calls macros a port can define before including `ppc_context.h`. Most defaults produce the same
code XenonRecomp did. The exceptions: the barriers are now compiler barriers where XenonRecomp emitted
nothing, and the two failure hooks trap where XenonRecomp printed a message and kept going.

Macro|Default|Use
-|-|-
`PPC_MFTB()`|`__rdtsc()`|The timebase. FM2 maps it to the console's 49.875 MHz clock.
`PPC_SYNC()`, `PPC_LWSYNC()`, `PPC_EIEIO()`, `PPC_ISYNC()`|compiler barriers|Memory barriers. With `hardware_fences = true`, `sync` becomes a full fence and `lwsync`/`eieio` acquire-release fences; `isync` stays a compiler barrier.
`PPC_TRAP(address)`|nothing|Trap instructions (`tw`, `td` and the immediate forms).
`PPC_UNIMPLEMENTED(address, what)`, `PPC_UNRESOLVED_BRANCH(from, to)`|`__builtin_trap()`|See above.
`PPC_SWITCH_MISS(address, index)`|`__builtin_unreachable()`|A jump-table index past the table.
`PPC_INDIRECT_MISS(address)`|`__builtin_trap()`|An indirect call to an unknown address (with `PPC_CHECK_INDIRECT_CALLS`).
`PPC_FUNC_TABLE_BASE`|end of the image|Where the indirect-call table lives (see `function_table_address`).
`PPC_GUEST_LOAD(T, p)`, `PPC_GUEST_STORE(T, p, v)`|relaxed atomics|Scalar guest memory accesses (see above). `PPC_VOLATILE_GUEST_ACCESS` makes them `volatile`.
`PPC_GUEST_VLOAD(p)`, `PPC_GUEST_VSTORE(p, v)`|`volatile` 16-byte access|Vector guest memory accesses.

### Guest memory accesses that don't slow down the code around them

XenonRecomp makes every guest load and store `volatile`. clang-cl compiles `volatile` with MSVC semantics, as
an acquire load or a release store, so the compiler can't keep a register value in a host register across any
guest access: it stores and reloads the PPC context around each one. ReXenon makes guest accesses relaxed
atomics instead (`PPC_GUEST_LOAD`/`PPC_GUEST_STORE`). Each access is still made exactly once, at its width and in
program order, but the context stays in host registers between them. Vector accesses (`lvx`, `stvx`, ...) are
`volatile` 16-byte accesses, so they can't be merged or skipped either. Guest ordering comes from
`sync`/`lwsync`/`eieio`, as on the console.

In FM2 on a Ryzen 7 5800X this cuts the main thread's CPU time per frame by about 17% and raises the frame rate
by 10 to 30%. On an FX-8350, where the main thread is limited by something else, the gain is 1 to 2%. Define
`PPC_VOLATILE_GUEST_ACCESS` to get XenonRecomp's `volatile` accesses back. On targets where `volatile` gave
hardware ordering (MSVC-style volatile on ARM64), turn on `hardware_fences`.

The other options that remove work (empty-function calls, return-address stores, register save/restore calls)
measured within about 2% of XenonRecomp on the FX when every exe ran at a fixed load address. Without a fixed
address, where the hot code landed in memory (each boot under ASLR, or after a relink) moved the frame rate by
3 to 10%, more than those changes. They stay in, off by default.

## Using it

ReXenon uses the same executables (`XenonAnalyse`, `XenonRecomp`), command line and config as XenonRecomp.
With no new options set, its output differs from XenonRecomp's only in the fixes above, in fewer FP-mode
switches (it skips them for instructions the mode can't affect), in the guest accesses above, and in the new
macros. When switching a port over:

- If the port patched the timebase in the output, define `PPC_MFTB()` instead.
- Hook any function the analysis now splits off. FM2 gained one, a second SwitchToFiber copy.
- The run exits with an error if anything is left unresolved, and it deletes `ppc_recomp.<n>.cpp` files in
  the output folder that it didn't write. It creates the output folder if it's missing (XenonRecomp crashed).
- Guest accesses are relaxed atomics. If the port's own code relied on the old `volatile` ordering, define
  `PPC_VOLATILE_GUEST_ACCESS` until it's fixed.

All new options go in `[main]` and are off by default:

Option|What it does
-|-
`allow_unresolved`|Finish with exit code 0 even when unimplemented instructions or unresolved branches are left.
`auto_switch_tables`|Find jump tables at load time. Entries in `switch_table_file_path` take priority.
`data_function_starts`|Start functions at code addresses stored in data sections (see above).
`emit_analysis_path`|Folder (relative to the config) to write the found functions and switch tables to.
`elide_empty_functions`|Leave out calls to functions whose whole body is `blr`. List the ones the port hooks in `keep_functions`.
`elide_return_lr`|Don't store LR for an `mtlr` directly before a `blr`. With `inline_register_thunks`, also skip the LR store on a `bl` to an inlined save/restore helper, unless the function reads LR later. Makes LR in crash logs stale.
`inline_register_thunks`|Recompile the `__savegprlr`/`__restgprlr`/fpr/vmx helpers inline at each call.
`function_table_address`|Put the indirect-call table at this guest address (the port must commit that memory). If the table is too far away for a 32-bit displacement, the run prints the range of addresses that would fit.
`chunk_by_address`|Split output files by guest address (e.g. `0x8000`), so a change rebuilds about 10 files, not all 200.
`exact_estimates`|`frsqrte`/`vrsqrtefp` use the console's lookup tables instead of `1/sqrt`.
`fused_madd`|`vmaddfp`/`vnmsubfp` use fused multiply-add (only truly fused when the port builds with `-mfma`).
`hardware_fences`|Real fences for `sync`, `lwsync` and `eieio` (see the macro table).

XenonRecomp's own `non_volatile_as_local` (keep r14-r31, f14-f31, v14-v31 and v64-v127 in locals) is made safe:
ReXenon finds the functions that read them before writing them and keeps those on the context. The
configured setjmp/longjmp addresses count as host functions; list more in `context_functions`, and functions
the port implements in `host_functions`.

Paths in the config are relative to the config file. Absolute paths aren't supported.

### Instruction tests

On Windows, with CMake, Ninja and clang-cl: set `TESTS` at the top of `ReXenonTests/run.py` to your Xenia
checkout's `src/xenia/cpu/ppc/testing`, and `VCENV` to a script that sets up the Visual C++ environment. Then
run `py -I ReXenonTests/run.py`. It configures and builds the test driver itself (`-DREXENON_TESTS=ON`, in
`build-tests`), assembles the tests, recompiles and runs them, and writes `ReXenonTests/results.txt` (summary
and failures) and `ReXenonTests/results_all.tsv` (one line per test). `--filter` limits the run to some suites,
and `--options` runs with recompiler options.

`docs/overnight/LOG.md` and `docs/night2/LOG.md` (the guest accesses) have the full record of each change, how
it was checked and every measurement.

---

The rest of this file is XenonRecomp's own documentation. It still applies to ReXenon.

## XenonRecomp: Implementation Details

### Instructions

The instructions are directly converted without any effort to make them resemble decompiled code, meaning the output is not very human-readable. The CPU state is passed as an argument to every PPC function, which includes definitions for every PPC register and their current values at the time of execution. The second argument is the base address pointer, as the Xbox 360 CPU uses 32-bit pointers.

A good amount of PPC instructions are implemented, with missing ones primarily being variants of already implemented instructions. Some instructions, like the D3D unpack/pack instructions, do not support all operand types. When a missing case is encountered, a warning is generated, or a debug break is inserted into the converted C++ code.

The instruction implementations operate on little-endian values. However, since the Xbox 360 is a big-endian machine, the memory load instructions swap endianness when reading values, and memory store instructions reverse it to big-endian before writing. All the memory loads and stores are marked volatile to prevent Clang from doing unsafe code reordering. (In ReXenon they are relaxed atomics instead; see "Guest memory accesses" above.)

Vector registers' endianness handling is more complicated. Instead of swapping individual 32-bit elements, the recompiler chooses to reverse the entire 16-byte vector. Instructions must account for this reversed order, such as using the WZY components instead of XYZ in dot products or requiring reversed arguments for vector pack instructions.

The FPU expects denormalized numbers to remain unmodified, while VMX instructions always flush them. This is managed by storing the current floating-point state in the CPU state struct and enabling or disabling denormal flushing as necessary before executing each instruction.

Most VMX instructions are implemented using x86 intrinsics. Support for ARM64 is implemented using [SIMD Everywhere](https://github.com/simd-everywhere/simde).

### MMIO

MMIO, which is typically used for hardware operations such as XMA decoding, is currently unimplemented. There is an unfinished attempt to implement MMIO, but supporting it may be non-trivial and could require advanced analysis of instructions.

### Indirect Functions

Virtual function calls are resolved by creating a "perfect hash table" at runtime, where dereferencing a 64-bit pointer (using the original instruction address multiplied by 2) gives the address of the recompiled function. This was previously implemented by creating an 8 GB virtual allocation, but it had too much memory pressure. Now it relies on function addresses being placed after the valid XEX memory region in the base memory pointer. These regions are exported as macros in the output `ppc_config.h` file.

### Jump Tables

Jump tables, at least in older Xbox 360 binaries, often have predictable assembly patterns, making them easy to detect statically without needing a virtual machine. XenonAnalyse has logic for detecting jump tables in Sonic Unleashed, though variations in other games (likely due to updates in the Xbox 360 compiler) may require modifications to the detection logic. Currently, there is no fully generic solution for handling jump tables, so updates to the detection logic may be needed for other games.

The typical way to find jump tables is by searching for the `mtctr r0` instruction. It will almost always be followed with a `bctr`, with the previous instructions computing the jump address.

XenonAnalyse generates a TOML file containing detected jump tables, which can be referenced in the main TOML config file. This allows the recompiler to generate real switch cases for these jump tables.

### Function Boundary Analysis

XenonAnalyse includes a function boundary analyzer that works well in most cases. Functions with stack space have their boundaries defined in the `.pdata` segment of the XEX. For functions not found in this segment, the analyzer detects the start of functions by searching for branch link instructions, and determines their length via static analysis.

However, the analyzer struggles with functions containing jump tables, since they look like tail calls without enough information. While there is currently no solution for this, it might be relatively simple to extend the function analyzer to account for jump tables defined in the TOML file. As a workaround, the recompiler TOML file allows users to manually define function boundaries.

### Exceptions

The recompiler currently does not support exceptions. This is challenging due to the use of the link register and the fact that exception handlers can jump to arbitrary code locations.

### setjmp

`setjmp` and `longjmp` are implemented by redirecting them to native implementations. Thanks to the Xbox 360's large number of vector registers, the guest CPU state struct is large enough to hold the x86 CPU state and potentially states from other architectures.

### Optimizations

Since Xbox 360 binaries typically follow a stable ABI, we can make certain assumptions about code structure, allowing the Clang compiler to generate better code. Several optimization options are available in the recompiler, but it's recommended to test them only after having a successfully functioning recompilation.

The link register can be skipped assuming the game does not utilize exceptions, as the whole process of recompilation already takes care of function return behavior.

The following registers, assuming the game doesn't violate the ABI, can be safely converted into local variables, as they never leave the function scope:
* Count register
* XER
* Reserved register
* Condition registers
* Non argument registers
* Non volatile registers

The local variable optimization particularly introduces the most improvements, as the calls to the register restore/save functions can be completely removed, and the redundant stores to the PPC context struct can be eliminated. In [Unleashed Recompiled](https://github.com/hedge-dev/UnleashedRecomp), the executable size decreases by around 20 MB with these optimizations, and frame times are reduced by several milliseconds.

### Patch Mechanisms

XenonRecomp defines PPC functions in a way that makes them easy to hook, using techniques in the Clang compiler. By aliasing a PPC function to an "implementation function" and marking the original function as weakly linked, users can override it with a custom implementation while retaining access to the original function:

```cpp
PPC_FUNC_IMPL(__imp__sub_XXXXXXXX);
PPC_FUNC(sub_XXXXXXXX)
{
    __imp__sub_XXXXXXXX(ctx, base);
}
```

Additionally, mid-asm hooks can be inserted directly into the translated C++ code at specific instruction addresses. The recompiler inserts these function calls, and users are responsible for implementing them in their recompilation project. The linker resolves them during compilation.

## Usage

### XenonAnalyse

XenonAnalyse, when used as a command-line application, allows an XEX file to be passed as an input argument to output a TOML file containing all the detected jump tables in the executable:

```
XenonAnalyse [input XEX file path] [output jump table TOML file path]
```

However, as explained in the earlier sections, due to variations between games, additional support may be needed to handle different patterns.

[An example jump table TOML file can be viewed in the Unleashed Recompiled repository.](https://github.com/hedge-dev/UnleashedRecomp/blob/main/UnleashedRecompLib/config/SWA_switch_tables.toml)

### XenonRecomp

XenonRecomp accepts a TOML file with recompiler configurations and the path to the `ppc_context.h` file located in the XenonUtils directory:

```
XenonRecomp [input TOML file path] [input PPC context header file path]
```

[An example recompiler TOML file can be viewed in the Unleashed Recompiled repository.](https://github.com/hedge-dev/UnleashedRecomp/blob/main/UnleashedRecompLib/config/SWA.toml)

#### Main

```toml
[main]
file_path = "../private/default.xex"
patch_file_path = "../private/default.xexp"
patched_file_path = "../private/default_patched.xex"
out_directory_path = "../ppc"
switch_table_file_path = "SWA_switch_tables.toml"
```

All the paths are relative to the directory where the TOML file is stored.

Property|Description
-|-
file_path|Path to the XEX file.
patch_file_path|Path to the XEXP file. This is not required if the game has no title updates.
patched_file_path|Path to the patched XEX file. XenonRecomp will create this file automatically if it is missing and reuse it in subsequent recompilations. It does nothing if no XEXP file is specified. You can pass this output file to XenonAnalyse.
out_directory_path|Path to the directory that will contain the output C++ code. XenonRecomp needs it to exist; ReXenon creates it.
switch_table_file_path|Path to the TOML file containing the jump table definitions. The recompiler uses this file to convert jump tables to real switch cases.

#### Optimizations

```toml
skip_lr = false
skip_msr = false
ctr_as_local = false
xer_as_local = false
reserved_as_local = false
cr_as_local = false
non_argument_as_local = false
non_volatile_as_local = false
```

Enables or disables various optimizations explained earlier in the documentation. It is recommended not to enable these optimizations until you have a successfully running recompilation. 

#### Register Restore & Save Functions

```toml
restgprlr_14_address = 0x831B0B40
savegprlr_14_address = 0x831B0AF0
restfpr_14_address = 0x831B144C
savefpr_14_address = 0x831B1400
restvmx_14_address = 0x831B36E8
savevmx_14_address = 0x831B3450
restvmx_64_address = 0x831B377C
savevmx_64_address = 0x831B34E4
```

Xbox 360 binaries feature specialized register restore & save functions that act similarly to switch case fallthroughs. Every function that utilizes non-volatile registers either has an inlined version of these functions or explicitly calls them. The recompiler requires the starting address of each restore/save function in the TOML file to recompile them correctly. These functions could likely be auto-detected, but there is currently no mechanism for it.

Property|Description|Byte Pattern
-|-|-
restgprlr_14_address|Start address of the `__restgprlr_14` function. It starts with `ld r14, -0x98(r1)`, repeating the same operation for the rest of the non-volatile registers and restoring the link register at the end.|`e9 c1 ff 68`
savegprlr_14_address|Start address of the `__savegprlr_14` function. It starts with `std r14, -0x98(r1)`, repeating the same operation for the rest of the non-volatile registers and saving the link register at the end.|`f9 c1 ff 68`
restfpr_14_address|Start address of the `__restfpr_14` function. It starts with `lfd f14, -0x90(r12)`, repeating the same operation for the rest of the non-volatile FPU registers.|`c9 cc ff 70`
savefpr_14_address|Start address of the `__savefpr_14` function. It starts with `stfd r14, -0x90(r12)`, repeating the same operation for the rest of the non-volatile FPU registers.|`d9 cc ff 70`
restvmx_14_address|Start address of the `__restvmx_14` function. It starts with `li r11, -0x120` and `lvx v14, r11, r12`, repeating the same operation for the rest of the non-volatile VMX registers until `v31`.|`39 60 fe e0 7d cb 60 ce`
savevmx_14_address|Start address of the `__savevmx_14` function. It starts with `li r11, -0x120` and `stvx v14, r11, r12`, repeating the same operation for the rest of the non-volatile VMX registers until `v31`.|`39 60 fe e0 7d cb 61 ce`
restvmx_64_address|Start address of the `__restvmx_64` function. It starts with `li r11, -0x400` and `lvx128 v64, r11, r12`, repeating the same operation for the rest of the non-volatile VMX registers.|`39 60 fc 00 10 0b 60 cb`
savevmx_64_address|Start address of the `__savevmx_64` function. It starts with `li r11, -0x400` and `stvx128 v64, r11, r12`, repeating the same operation for the rest of the non-volatile VMX registers.|`39 60 fc 00 10 0b 61 cb`

#### longjmp & setjmp

```toml
longjmp_address = 0x831B6790
setjmp_address = 0x831B6AB0
```

These are addresses for the `longjmp` and `setjmp` functions in the executable. The recompiler directly redirects these functions to native versions. The implementation of these functions might vary between games. In some cases, you might find `longjmp` by looking for calls to `RtlUnwind`, and `setjmp` typically appears just after it.

If the game does not use these functions, you can remove the properties from the TOML file.

#### Explicit Function Boundaries

```toml
functions = [
    { address = 0x824E7EF0, size = 0x98 },
    { address = 0x824E7F28, size = 0x60 },
]
```

You can define function boundaries explicitly using the `functions` property if XenonAnalyse fails to analyze them correctly, for example, with functions containing jump tables.

#### Invalid Instruction Skips

```toml
invalid_instructions = [
    { data = 0x00000000, size = 4 }, # Padding
    { data = 0x831B1C90, size = 8 }, # C++ Frame Handler
    { data = 0x8324B3BC, size = 8 }, # C Specific Frame Handler
    { data = 0x831C8B50, size = 8 },
    { data = 0x00485645, size = 44 } # End of .text
]
```

In the `invalid_instructions` property, you can define 32-bit integer values that instruct the recompiler to skip over certain bytes when it encounters them. For example, in Unleashed Recompiled, these are used to skip over exception handling data, which is placed between functions but is not valid code.

#### Mid-asm Hooks

```toml
[[midasm_hook]]
name = "IndexBufferLengthMidAsmHook"
address = 0x82E26244
registers = ["r3"]
```

```cpp
void IndexBufferLengthMidAsmHook(PPCRegister& r3)
{
    // ...
}
```

You can define multiple mid-asm hooks in the TOML file, allowing the recompiler to insert function calls at specified addresses. When implementing them in your recompilation project, the linker will resolve the calls automatically.

Property|Description
-|-
name|Function name of the mid-asm hook. You can reuse function names to place the same implementation at multiple addresses. Otherwise, unique implementations must have unique names.
address|Address of the instruction where the function call will be placed. This does not overwrite the instruction at the specified address.
registers|Registers to pass as arguments to the mid-asm hook. This is a list of registers because the local variable optimization does not keep optimized registers within the PPC context struct.
return|Set to `true` to indicate that the function where the hook was inserted should immediately return after calling the mid-asm hook.
return_on_true|Set to `true` to indicate that the function should return if the mid-asm hook call returns `true`.
return_on_false|Set to `true` to indicate that the function should return if the mid-asm hook call returns `false`.
jump_address|The address to jump to immediately after calling the mid-asm hook. The address must be within the same function where the hook was placed.
jump_address_on_true|The address to jump to if the mid-asm hook returns `true`. The address must be within the same function where the hook was placed.
jump_address_on_false|The address to jump to if the mid-asm hook returns `false`. The address must be within the same function where the hook was placed.
after_instruction|Set to `true` to place the mid-asm hook immediately after the instruction, instead of before.

Certain properties are mutually exclusive. For example, you cannot use both `return` and `jump_address`, and direct or conditional returns/jumps cannot be mixed. The recompiler is going to show warnings if this is not followed.

### Tests

XenonRecomp can recompile Xenia's PPC tests and execute them through the XenonTests project in the repository. After building the tests using Xenia's build system, XenonRecomp can process the `src/xenia/cpu/ppc/testing/bin` directory as input, generating C++ files in the specified output directory:

```
XenonRecomp [input testing directory path] [input PPC context header file path] [output directory path]
```

Once the files are generated, refresh XenonTests' CMake cache to make them appear in the project. The tests can then be executed to compare the results of instructions against the expected values.

## Building

The project requires CMake 3.20 or later and Clang 18 or later to build. Since the repository includes submodules, ensure you clone it recursively.

Compilers other than Clang have not been tested and are not recommended, including for recompilation output. The project relies on compiler-specific intrinsics and techniques that may not function correctly on other compilers, and many optimization methods depend on Clang's code generation.

On Windows, you can use the clang-cl toolset and open the project in Visual Studio's CMake integration.

## Special Thanks

This project could not have been possible without the [Xenia](https://github.com/xenia-project/xenia) emulator, as many parts of the CPU code conversion process has been implemented by heavily referencing its PPC code translator. The project also uses code from [Xenia Canary](https://github.com/xenia-canary/xenia-canary) to patch XEX binaries.
