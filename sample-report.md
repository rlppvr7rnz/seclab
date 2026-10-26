# Analysis report: notepad.exe

## Sample

- Path: `C:\Windows\System32\notepad.exe`
- Size: 200704 bytes
- MD5: `6f51bcabf1b2b34ad7e670aee6da451f`
- SHA256: `da5807bb0997cc6b5132950ec87eda2b33b1ac4533cf1f7a22a6f3b576ed7c5b`
- Entropy: 6.309 bits/byte

## Static observations

- Machine: x64
- Sections: 7
- Entry point: 0x23bd0 (image base 0x140000000)
- Section entropy (max): 6.275

## Workflow

1. Recon: hashes and file type recorded above.
2. Enumerate: sections and strings reviewed.
3. Analyze: suspicious regions noted with offsets.
4. Verify: findings reproduced with the exact commands below.

## Reproduction

```
python seclab.py hash C:\Windows\System32\notepad.exe
python seclab.py pe C:\Windows\System32\notepad.exe
python seclab.py strings C:\Windows\System32\notepad.exe --min 8
```

## Notes

Only analyze samples you own or are authorized to assess.
