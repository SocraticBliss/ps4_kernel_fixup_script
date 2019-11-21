# PS4 Kernel Cleanup
SocraticBliss(R)

Still a WIP

1) Offset Fixup
2) Structs Creation
   - cdevsw
   - sys_init
   - sys_uninit
   - kobj_class
   - brand_info
   - brandnote
   - malloc_type
   - mod_depend
   - mod_metadata
   - mod_version
   - moduledata_t
   - driver_module_data
   - sysctl_oid
   - sysentvec
   - sysent

Major Thanks to...
* ChendoChap
* Pablo (kozarovv)
* Specter

# Usage
1) Load an early PS4 Kernel (with symbols) as an ELF64.
2) Run the **ps4_kernel_cleanup.py** script
