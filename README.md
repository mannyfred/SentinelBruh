# SentinelBruh
#### Dirty PoC on how to abuse S1's VEH for Vectored Syscalls and Local Execution (win10)


The following PoC abuses 2 things:
- Static offset of LdrpVectorHandlerList from the base of Ntdll
- S1's goofy detection methods

### LdrpVectorHandlerList

LdrpVectorHandlerList sits at a static offset from the base address of Ntdll (different on w10 and w11). This list will be very valuable when there are VEHs already registered, as this will grant us the possibility of "registering" a VEH manually.

![LdrpVectorHandlerList](https://github.com/mannyfred/SentinelBruh/assets/113118336/8647a263-af70-4e76-82f2-635896b22594)

| VEH_LIST   (NTDLL + 0x1813f0)       |       
| ----------------------------------- |
| stuff                               | 
| PVECTORED_HANDLER_ENTRY    first    | 
| stuff                               | 
| stuff                               | 

When registering a VEH, RtlpAddVectoredExceptionHandler allocates and initializes a struct related to a VEH handler on the heap, adding a pointer to said struct into the VEH_LIST.

Each VEH_HANDLER_ENTRY instance contains a bit of info, but they main thing we are after is the encoded pointer:

| VEH_HANDLER_ENTRY                   |       
| ----------------------------------- |
| stuff                               | 
| stuff                               | 
| stuff                               | 
| Encoded VEH pointer                 | 

Hard to tell info about each member as there isn't much info about VEHs.
Just go read this (it's good) -> [Dumping VEHs](https://dimitrifourny.github.io/2020/06/11/dumping-veh-win10.html)

The only thing to note is that this specific PoC (SentinelBruh) uses [EncodePointer](https://learn.microsoft.com/en-us/previous-versions/bb432254(v=vs.85)) instead of doing a syscall to retrieve the process cookie. This decision was made because we are already doing vectored syscalls, and there's literally no point in doing that. But if interested, [here](https://github.com/mannyfred/MShadowVEH/blob/main/MShadowVEH/MShadowVEH/main.c#L180).

### Abusing an already present VEH

Since we all know that S1 registers a VEH that it uses for PAGE_GUARD hooking, why don't we just do some trolling and pull an Uno reverse on them?
Well, it's super easy, since we have:
- VEH list location in Ntdll
- A structure related to a registered VEH handler already initialized somewhere
- EncodePointer, or a process cookie when going the syscall route

With these things, we are able to overwrite the encoded VEH function pointer located in the VEH_HANDLER_ENTRY struct. 

This just means that we can register our own VEH handler by overwriting a single pointer, with no calls to AddVectoredExceptionHandler.
With our own VEH now in play, multiple actions can be performed with it. 

In this PoC, [Vectored Syscalls](https://redops.at/en/blog/syscalls-via-vectored-exception-handling) and local execution is demonstrated. 


Catching all sorts of exceptions with our new VEH demo:

![image](https://github.com/mannyfred/SentinelBruh/assets/113118336/0c5e4276-8ae8-4849-bade-b589b06d574b)


Adding 5pidersMom as a user:
- Overwriting S1's registered VEH pointer
- Doing local mapping via vectored syscalls
- Copying the shellcode from .rsrc and decoding it
- Overwriting VEH pointer once again, making it point to mapped memory
- Causing an exception, triggering the execution of our shellcode

https://github.com/mannyfred/SentinelBruh/assets/113118336/a99106ae-647d-497d-a285-42baed633dc7







### Acknowledgements
- @DimitriFourny [Dumping VEH on Win10](https://dimitrifourny.github.io/2020/06/11/dumping-veh-win10.html)
- @VirtualAllocEx [Vectored Syscalls](https://redops.at/en/blog/syscalls-via-vectored-exception-handling)
- @Ollie.Whitehouse [Detecting Anomalous VEH Handlers](https://research.nccgroup.com/2022/03/01/detecting-anomalous-vectored-exception-handlers-on-windows/)
- @Maldev-Academy (@mrd0x, @NUL0x4C, @Cracked5pider) [Maldev Academy](https://maldevacademy.com/)
- @l1inear, @0xtriboulet, @kyle41111
