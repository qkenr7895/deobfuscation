## How To Use
#### 1. Compile PinTool
First, we need to compile a PinTool to extract the execution trace and VM context switches from the target binary
```
$ cd deobfuscator
$ make
```
#### 2. Prepare Virtualized Binary
Next, we need to prepare virtualized binary to apply the PinTool
```
$ cd test
$ make
$ (Apply virtualization to the "test_native" binary generated in the previous "make" command using VMProtect)
```
If done correctly, the following results should be produced
```
$ ls
extract_trace.sh
find_regions.sh
Makefile
test.c
test_native
test_native_vmp (or the name of the virtualized binary you specified)
```
#### 3. Find VM Context Switches
Finally, we need to apply the PinTool to the virtualized binary to identify VM context switches
```
$ (In the Makefile, set "TARGET_BINARY" to the virtualized binary)
$ make trace
```
This process will generate the following files

- trace_vmp 
  - execution trace of target binary
  - each row represents [sequence number] [executed instruction][16 general registers][rflags][address to write][address to read]

- vm_enter_vmp
  - dd
vm_enter_vmp 
vm_enter_call_vmp 
vm_exit_vmp 
vm_exit_ret_vmp
