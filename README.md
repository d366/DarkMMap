DarkMMap
========

Manual PE image mapper

Supported features:

- x86 and x64 image support
- Mapping into any arbitrary unprotected process
- Section mapping with proper memory protection flags
- Image relocations (only 2 types supported. I haven't seen a single PE image with some other relocation types)
- Imports are resolved***
- Delayed imports can be resolved***
- Bound import is resolved as a side effect, I think
- Module exports
- Loading of forwarded export images
- Api schema name redirection
- SxS redirection and isolation
- Activation context support
- Dll path resolving similar to native load order
- TLS callbacks*
- Static TLS data, sort of**
- Exception handling support (SEH and C++), needs more testing though, but seems reliable
- Adding module to some native loader structures(for basic module api support: GetModuleHandle, GetProcAdress, etc.)
- Security cookie initialization
- C++/CLI images can be mapped (this needs adding module to native structures)
- Image unloading 
- Increase reference counter for import libraries in case of manual import mapping***
- Unlink image VAD entry****

Things it can't do yet:

- Trace module dependencies during unload
- Remove module from native loader structures upon unload
- Lots of other things I don't know about or forgot

* TLS callback are only executed for one thread with DLL_PROCESS_ATTACH and DLL_PROCESS_DETACH reasons during image loading and unloading respectively.

** Implemented using native LdrpHandleTlsData call. Official documentation also says that you shouldn't load images with static TLS dynamically (LoadLibrary). 

*** Imports and all dependencies can be mapped either manually or by native loader. In case of manual mapping circular dependencies are handled properly.

**** Ring 0, for fun only, supported Win7 and Win8. Win8 has floating BSOD bug upon target process exit(MmDeleteProcessAddressSpace); haven't figured it out yet.