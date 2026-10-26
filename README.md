# Seclab — Security Research Automation Toolkit

Minimal, dependency-free toolkit for authorized security research: file hashing, string
extraction, PE header/section inspection, entropy analysis, and markdown report generation.

Built for repeatable first-pass triage of samples in **authorized** assessments: hash,
inspect, extract, summarize — with the exact commands recorded so any finding can be
reproduced.

## Requirements

- Python 3.8+
- No third-party dependencies
- Windows / macOS / Linux

## Commands

```text
python seclab.py hash    <file...>                     # MD5 / SHA256 / size
python seclab.py strings <file> [--min 6] [--unicode]  # printable strings
python seclab.py pe      <file>                        # PE headers + sections
python seclab.py entropy <file>                        # shannon entropy
python seclab.py report  <file> [-o report.md]         # markdown analysis report
```

## Sample output

```text
$ python seclab.py pe C:\Windows\System32\notepad.exe
file        C:\Windows\System32\notepad.exe
size        200704 bytes
sha256      da5807bb0997cc6b5132950ec87eda2b33b1ac4533cf1f7a22a6f3b576ed7c5b
machine     x64
pe_type     PE32+
entrypoint  0x23bd0  image_base 0x140000000
sections    7
file_entropy 6.309

name            vaddr      vsize        raw  entropy
.text      0x00001000     148623     148992    6.275
.rdata     0x00026000      37512      37888    5.930
.data      0x00030000      10008       3584    1.807
.pdata     0x00033000       4332       4608    4.944
.rsrc      0x00036000       3032       3072    4.612
.reloc     0x00037000        728       1024    4.129
```

```text
$ python seclab.py strings seclab.py --min 8
-- 179 strings (min 8)
#!/usr/bin/env python3
"""Seclab - minimal security research automation toolkit.
...
```

`report` produces a markdown file with hashes, PE observations, a five-stage workflow
(recon → enumerate → analyze → verify → evidence) and the exact reproduction commands.

## Roadmap

- [ ] PE imports/exports table parsing
- [ ] Section-level entropy histogram
- [ ] Batch mode over a directory
- [ ] JSON output for pipeline integration
- [ ] CI checks (typecheck, smoke tests)

## Disclaimer

For **authorized security testing only**. Only analyze files you own or have explicit
permission to assess. The authors accept no responsibility for misuse.

## License

MIT — see [LICENSE](LICENSE).
