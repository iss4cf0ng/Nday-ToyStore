# WinDbg Cheatsheet

## View Structure

```bash
dt nt!_EPROCESS
dt nt!_EPROCESS ffffd8000 0x12345678
dt nt!_EPROCESS ImageFileName UniqueProcessId

dt _TEB
```

## Execution Flow

- `g`: Go
- `p`: Step Over
- `t`: Trace / Step Into
- `bp`: Breakpoint
- `bl`: Breakpoint List
- `bc`: Breakpoint Clear

## Unassemble

```bash
u nt!NtSetInformationProcess
```

```bash
uf ntdll!LdrpSetInformationProcess
```

## Dump Memory (d\*)

- `dq [address]`: QWORD
- `dd [address]`: DWORD
- `da [address]`: ASCII
- `du [address]`: Unicode

```bash
dq ffffd8000 12345678
```

## Examine Symbols

```bash
x ntdll!*SetInformationProcess
```

## List Nearest Symbols

```bash
ln fffff801 12345678
```

## Process / Thread

```bash
!process [address] [flag] 
!process 0 0
!process ffffd800 12345678
```

```bash
!thread [address]
~
~0s
```


