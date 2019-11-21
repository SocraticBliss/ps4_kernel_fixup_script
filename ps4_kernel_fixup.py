#!/usr/bin/env python
from idaapi import *
from idautils import *
from idc import *

import idaapi
import idautils
import idc

'''

PS4 Kernel Fixup by SocraticBliss (R)

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

'''

text        = idaapi.get_segm_by_name('.text')
rodata      = idaapi.get_segm_by_name('.rodata')
sysinit     = idaapi.get_segm_by_name('set_sysinit_set')
sysuninit   = idaapi.get_segm_by_name('set_sysuninit_set')
sysctl      = idaapi.get_segm_by_name('set_sysctl_set')
modmetadata = idaapi.get_segm_by_name('set_modmetadata_set')
cons        = idaapi.get_segm_by_name('set_cons_set')
got         = idaapi.get_segm_by_name('.got')
data        = idaapi.get_segm_by_name('.data')
abs         = idaapi.get_segm_by_name('abs')

SEGMENTS = [rodata, sysinit, sysuninit, sysctl, modmetadata, cons, got, data]

# ##name_cdevsw
CDEVSW = [(0x4, 'Version'),
          (0x4, 'Flags'),
          (0x8, 'Name'),
          (0x8, 'Open'),
          (0x8, 'File Descriptor Open'),
          (0x8, 'Close'),
          (0x8, 'Read'),
          (0x8, 'Write'),
          (0x8, 'Input/Ouput Control'),
          (0x8, 'Poll'),
          (0x8, 'Memory Map'),
          (0x8, 'Strategy'),
          (0x8, 'Dump'),
          (0x8, 'KQFilter'),
          (0x8, 'Purge'),
          (0x8, 'Memory Map Single'),
          (0x4, 'Spare0'),
          (0x4, 'Spare0'),
          (0x4, 'Spare0'),
          (0x4, ''),
          (0x8, 'Spare1'),
          (0x8, 'Spare1'),
          (0x8, 'Spare1'),
          (0x8, 'Devs lh First'),
          (0x4, 'Spare2'),
          (0x4, ''),
          (0x8, 'Giant Trick')]

'''
# Un/Initialization Order

  SI_ORDER_FIRST  = 0x0
  SI_ORDER_SECOND = 0x1
  SI_ORDER_THIRD  = 0x2
  SI_ORDER_FOURTH = 0x3
  SI_ORDER_MIDDLE = 0x1000000
  SI_ORDER_ANY    = 0xFFFFFFF

'''
# ##name_sys_init
SYSINIT = [(0x4, 'Subsystem Identifier'),
           (0x4, 'Initialization Order'),
           (0x8, 'Initialization'),
           (0x8, 'Arguments')]

# ##name_sys_uninit
SYSUNINIT = [(0x4, 'Subsystem Identifier'),
             (0x4, 'Un-Initialization Order'),
             (0x8, 'Un-Initialization'),
             (0x8, 'Arguments')]

# ##name_class
KOBJCLASS = [(0x8, 'Name'),
             (0x8, 'Methods'),
             (0x8, 'Size'),
             (0x8, 'Base Classes'),
             (0x4, 'Reference Count'),
             (0x4, ''),
             (0x8, 'Operations Table')]

# ##name_brand_info
BRANDINFO = [(0x4, 'Brand'),
             (0x4, 'Machine Type'),
             (0x8, 'Compatibility 3 Brand'),
             (0x8, 'Emulation Path'),
             (0x8, 'Interpreter Path'),
             (0x8, 'System Entry Vector'),
             (0x8, 'Interpreter New Path'),
             (0x4, 'Flags'),
             (0x4, ''),
             (0x8, 'Brand Note')]

# ##name_brandnote
BRANDNOTE = [(0x4, 'Name Size'),
             (0x4, 'Description Size'),
             (0x4, 'Type'),
             (0x4, ''),
             (0x8, 'Vendor'),
             (0x4, 'Flags'),
             (0x4, ''),
             (0x8, 'Translate OSRel')]

# M_##name
MALLOC = [(0x8, 'Next'),
          (0x8, 'Magic'),
          (0x8, 'Short Description'),
          (0x8, 'Handler')]

'''
# Module Types

  MDT_DEPEND   = 0x1
  MDT_MODULE   = 0x2
  MDT_VERSION  = 0x3
  MDT_PNP_INFO = 0x4

'''
# _mod_metadata_##module_version
# _mod_metadata_md_##module
# _mod_metadata_md_##module_on_##mdepend
METADATA = [(0x4, 'Version'),
            (0x4, 'Type'),
            (0x8, 'Data'),
            (0x8, 'Name')]

# _##module_depend_on_##mdepend 
DEPEND = [(0x4, 'Minimum Version'),
          (0x4, 'Preferred Version'),
          (0x4, 'Maximum Version')]

# ##name_moduledata
MODULEDATA = [(0x8, 'Name'),
              (0x8, 'Event Handler'),
              (0x8, 'Extra Data')]

# ##busname_driver_mod
DRIVERMOD = [(0x8, 'Event Handler'),
             (0x8, 'Arguments'),
             (0x8, 'Bus Name'),
             (0x8, 'Driver'),
             (0x8, 'Class'),
             (0x4, 'Pass'),
             (0x4, '')]

# ##module_version
VERSION = [(0x4, 'Version')]

# sysctl__##name
SYSCTLOID = [(0x8, 'Parent'),
             (0x8, 'Link'),
             (0x4, 'Number'),
             (0x4, 'Kind'),
             (0x8, 'Argument 1'),
             (0x8, 'Argument 2'),
             (0x8, 'Name'),
             (0x8, 'Handler'),
             (0x8, 'Format'),
             (0x4, 'Reference Count'),
             (0x4, 'Running'),
             (0x8, 'Description')]

# ##name_sysentvec
SYSENTVEC = [(0x4, 'Number of Syscall Entries'),
             (0x4, ''),
             (0x8, 'Syscall Entry Table'),
             (0x4, 'Mask'), 
             (0x4, 'Signal Size'),
             (0x8, 'Signal Entry Table'),
             (0x4, 'Error Size'),
             (0x4, ''),
             (0x8, 'Error Entry Table'),
             (0x8, 'Translate Trampoline'),
             (0x8, 'Stack Fixup'),
             (0x8, 'Send Signal'),
             (0x8, 'Signal Code'),
             (0x8, 'Signal Code Size'),
             (0x8, 'Prepare Syscall'),
             (0x8, 'Name'),
             (0x8, 'Core Dump'),
             (0x8, 'Img Act Try'),
             (0x4, 'Minimum Signal Stack Size'),
             (0x4, 'Page Size'),
             (0x8, 'Minimum User Address'),
             (0x8, 'Maximum User Address'),
             (0x8, 'User Stack'),
             (0x8, 'PS Strings'),
             (0x4, 'Stack Protect'),
             (0x4, ''),
             (0x8, 'Copy Out Strings'),
             (0x8, 'Set Registers'),
             (0x8, 'Fix Limit'),
             (0x8, 'Maximum Size'),
             (0x4, 'Flags'),
             (0x4, ''),
             (0x8, 'Set Syscall Return Value'),
             (0x8, 'Fetch Syscall Arguments'),
             (0x8, 'Syscall Names Table'),
             (0x8, 'Shared Page Base'),
             (0x8, 'Share Page Length'),
             (0x8, 'Signal Code Base'),
             (0x8, 'Time Keep Base'),
             (0x4, 'Time Keep Off'),
             (0x4, 'Time Keep Current'),
             (0x4, 'Time Keep Gen')]

# ##name_sysent
SYSENT = [(0x4, 'Arguments'),
          (0x4, ''),
          (0x8, 'System Call'),
          (0x2, 'Audit Event'),
          (0x6, ''),
          (0x8, 'Trace Argument Conversion'),
          (0x4, 'Trace Entry'),
          (0x4, 'Trace Return'),
          (0x4, 'Flags'),
          (0x4, 'Thread Count')]

def Chendo(address, members):

    for (size, name) in members:
        flags = idaapi.get_flags_by_size(size)
        idaapi.do_unknown_range(address, size, 0)
        
        if name == '':
            idc.make_array(address, size)
        else:
            idaapi.create_data(address, flags, size, BADNODE) 
        
        idc.set_cmt(address, name, False)
        address += size

def Pablo(address, end):

    while address < end:
        offset = idaapi.find_binary(address, end, '?? FF FF FF FF', 0x10, SEARCH_DOWN)
        offset -= 0x3
        
        if idaapi.is_unknown(idaapi.get_flags(offset)):
            if text.start_ea <= idaapi.get_qword(offset) <= abs.end_ea:
                idaapi.create_data(offset, FF_QWORD, 0x8, BADNODE)
            
        address = offset + 0x4

print('# PS4 Kernel Fixup')

print('# [1] Offset Fixup')
# --------------------------------------------------------------------------------------------------------
# Fixup Offsets
for segment in SEGMENTS:
    print('Fixing %s...' % idaapi.get_segm_name(segment))
    Pablo(segment.start_ea, segment.end_ea)

print('# [2] Struct Creation')
# --------------------------------------------------------------------------------------------------------
# Struct Creation
# https://github.com/freebsd/freebsd/blob/master/sys/sys/
for (address, name) in idautils.Names():

    if data.start_ea < address < data.end_ea:
    
        # conf.h
        if name.endswith('_cdevsw'):
            struct = CDEVSW
        
        # kernel.h
        elif '_sys_init' in name:
            struct = SYSINIT
            
        elif '_sys_uninit' in name:
            struct = SYSUNINIT
        
        # kobj.h
        elif name.endswith('_class') and 'g_class' not in name:
            struct = KOBJCLASS
        
        # imgact_elf.h
        elif name.endswith('_brand_info') or name.endswith('_brand_oinfo'):
            struct = BRANDINFO
        
        elif name.endswith('_brandnote'):
            struct = BRANDNOTE
        
        # malloc.h
        elif name.startswith('M_'):
            struct = MALLOC
        
        # module.h
        elif name.endswith('_moduledata') or name.endswith('_conf'):
            struct = MODULEDATA
        
        elif name.startswith('_mod_metadata_'):
            struct = METADATA
        
        elif '_depend_on_' in name:
            struct = DEPEND
        
        elif name.endswith('_driver_mod') and 'sbl' not in name:
            struct = DRIVERMOD
            
        elif name.endswith('_version'):
            struct = VERSION
        
        # sysctl.h
        elif name.startswith('sysctl__'):
            struct = SYSCTLOID
        
        # sysent.h
        elif name.endswith('_sysvec'):
            struct = SYSENTVEC
            
        elif name == 'sysent':
            struct = SYSENT
        
        else:
            continue
        
        Chendo(address, struct)

print('# Done!')
