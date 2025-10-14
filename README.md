# VolkDMA
A direct memory access library for memory analysis & manipulation, reverse engineering, and debugging.

### Currently supports:
- **DMA session management**
  - RAII DMA handle
  - Optional memory map bootstrapping and dumping
  - FPGA prepping routine for stable initialization
  - PID lookup (single and list by name)
  - Signature scanning in a given VA range with wildcard support

- **Process memory & modules**
  - Module metadata (base, size, path), enumeration, and in-memory PE image dumping
  - Typed reads/writes and pointer-chain reads
  - Creating/executing/closing scatter handles
  - Preparing scatter reads/writes
  - Virtual-to-physical address translation
  - CR3 fix

- **Input state (kernel-derived)**
  - Cursor position
  - Detecting pressed keys and mouse buttons
  - Built-in VK code to name table

## Included Binaries

To simplify both compilation and usage, all required binaries are included in this repository.

VolkDMA requires the included custom **`vmm.lib`** and **`vmm.dll`**, which have been patched for compatibility with the **virtual-to-physical address translation** and **CR3 fix**.
Do **not** replace these files with stock versions unless you fully understand the patch and its implications.

When using this library, place `FTD3XX.dll`, `leechcore.dll`, and `vmm.dll` in the same directory as your executable.
All required DLLs are available in the [`dlls`](dlls) folder.

## Contributors
- **Creator:** [lyk64](https://github.com/lyk64)
- [Stipulations](https://github.com/Stipulations)

## Credits
This project builds upon and utilizes components from [LeechCore](https://github.com/ufrisk/LeechCore) and [MemProcFS](https://github.com/ufrisk/MemProcFS), both created by [Ulf Frisk](https://github.com/ufrisk).

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
