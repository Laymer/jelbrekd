//
//  KernUtils.c
//  test
//
//  Created by Tanay Findley on 5/19/19.
//  Copyright © 2019 Tanay Findley. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/sysctl.h>
#include "KernUtils.h"
#include "mach_vm.h"
#include "tfp0_holder.h"
#include "bypass.h"
#include "common.h"
#include "PFOffs.h"
#include "OffsetHolder.h"
#include "tfp0_holder.h"
#include "find_port.h"
#include "offsets.h"
#include "kernel_slide.h"
#include "PFOffs.h"
#include "vnode_utils.h"
#include "proc_info.h"
#include "libproc.h"
#include "OSObj.h"
#include "sandbox.h"

#define LOG(str, args...) fprintf(stderr, "[*] " str "\n", ##args)


uint64_t get_proc_struct_for_pid(pid_t pid)
{
    
    uint64_t proc = ReadKernel64(ReadKernel64(GETOFFSET(kernel_task)) + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
    while (proc) {
        if (ReadKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_PID)) == pid)
            return proc;
        proc = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_P_LIST));
    }
    return 0;
}

uint64_t kmem_alloc(uint64_t size)
{
    if (get_tfp_port() == MACH_PORT_NULL) {
        LOG("attempt to allocate kernel memory before any kernel memory write primitives available");
        return 0;
    }
    
    kern_return_t err;
    mach_vm_address_t addr = 0;
    mach_vm_size_t ksize = round_page_kernel(size);
    err = mach_vm_allocate(get_tfp_port(), &addr, ksize, VM_FLAGS_ANYWHERE);
    if (err != KERN_SUCCESS) {
        LOG("unable to allocate kernel memory via tfp0: %s %x", mach_error_string(err), err);
        return 0;
    }
    return addr;
}

int kstrcmp(uint64_t kstr, const char* str) {
    size_t len = strlen(str) + 1;
    char *local = malloc(len + 1);
    local[len] = '\0';
    
    int ret = 1;
    
    if (kreadOwO(kstr, local, len) == len) {
        ret = strcmp(local, str);
    }
    
    free(local);
    
    return ret;
}

bool kmem_free(uint64_t kaddr, uint64_t size)
{
    if (get_tfp_port() == MACH_PORT_NULL) {
        LOG("attempt to deallocate kernel memory before any kernel memory write primitives available");
        return false;
    }
    
    kern_return_t err;
    mach_vm_size_t ksize = round_page_kernel(size);
    err = mach_vm_deallocate(get_tfp_port(), kaddr, ksize);
    if (err != KERN_SUCCESS) {
        LOG("unable to deallocate kernel memory via tfp0: %s %x", mach_error_string(err), err);
        return false;
    }
    return true;
}

void getOffsets()
{
    LOG("Getting offsets from file...");
    #define getCachedOff(val, name) do { \
    NSMutableDictionary *offsets = [NSMutableDictionary dictionaryWithContentsOfFile:@"/slice/offsets.plist"]; \
    uint64_t offsetName = (uint64_t)strtoull([offsets[@name] UTF8String], NULL, 16); \
    SETOFFSET(val, offsetName); \
    LOG("OFFSET " name ": 0x%016llx", GETOFFSET(val)); \
    } while (false)
    
    getCachedOff(kernel_task, "KernelTask");
    getCachedOff(pmap_load_trust_cache, "pmap_load_trust_cache");
    getCachedOff(smalloc, "smalloc");
    getCachedOff(add_x0_x0_0x40_ret, "add_x0_x0_0x40_ret");
    getCachedOff(zone_map_ref, "zone_map_ref");
    getCachedOff(osunserializexml, "osunserializexml");
    getCachedOff(vfs_context_current, "vfs_context_current");
    getCachedOff(vnode_lookup, "vnode_lookup");
    getCachedOff(vnode_put, "vnode_put");
    getCachedOff(kalloc_canblock, "kalloc_canblock");
    getCachedOff(ubc_cs_blob_allocate_site, "ubc_cs_blob_allocate_site");
    getCachedOff(cs_validate_csblob, "cs_validate_csblob");
    getCachedOff(cs_find_md, "cs_find_md");
    getCachedOff(cs_blob_generation_count, "cs_blob_generation_count");
    getCachedOff(kfree, "kfree");
    getCachedOff(OSBoolean_True, "OSBoolean_True");
    
    #undef getCachedOff
    
}


typedef struct {
    uint64_t prev;
    uint64_t next;
    uint64_t start;
    uint64_t end;
} kmap_hdr_t;

uint64_t zm_fix_addr(uint64_t addr) {
    static kmap_hdr_t zm_hdr = {0, 0, 0, 0};
    if (zm_hdr.start == 0) {
        // xxx ReadKernel64(0) ?!
        // uint64_t zone_map_ref = find_zone_map_ref();
        LOG("zone_map_ref: %llx ", GETOFFSET(zone_map_ref));
        uint64_t zone_map = ReadKernel64(GETOFFSET(zone_map_ref));
        LOG("zone_map: %llx ", zone_map);
        // hdr is at offset 0x10, mutexes at start
        size_t r = kreadOwO(zone_map + 0x10, &zm_hdr, sizeof(zm_hdr));
        LOG("zm_range: 0x%llx - 0x%llx (read 0x%zx, exp 0x%zx)", zm_hdr.start, zm_hdr.end, r, sizeof(zm_hdr));
        
        if (r != sizeof(zm_hdr) || zm_hdr.start == 0 || zm_hdr.end == 0) {
            LOG("kread of zone_map failed!");
            exit(EXIT_FAILURE);
        }
        
        if (zm_hdr.end - zm_hdr.start > 0x100000000) {
            LOG("zone_map is too big, sorry.");
            exit(EXIT_FAILURE);
        }
    }
    
    uint64_t zm_tmp = (zm_hdr.start & 0xffffffff00000000) | ((addr) & 0xffffffff);
    
    return zm_tmp < zm_hdr.start ? zm_tmp + 0x100000000 : zm_tmp;
}


uint64_t get_address_of_port(pid_t pid, mach_port_t port)
{
    uint64_t proc_struct_addr = get_proc_struct_for_pid(pid);
    uint64_t task_addr = ReadKernel64(proc_struct_addr + koffset(KSTRUCT_OFFSET_PROC_TASK));
    uint64_t itk_space = ReadKernel64(task_addr + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
    uint64_t is_table = ReadKernel64(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));
    uint32_t port_index = port >> 8;
    const int sizeof_ipc_entry_t = 0x18;
    uint64_t port_addr = ReadKernel64(is_table + (port_index * sizeof_ipc_entry_t));
    return port_addr;
}

bool have_kmem_read()
{
    return (get_tfp_port() != MACH_PORT_NULL);
}

uint64_t cached_task_self_addr = 0;
bool found_offs = false;
uint64_t task_self_addr()
{
    if (cached_task_self_addr == 0) {
        cached_task_self_addr = have_kmem_read() && found_offs ? get_address_of_port(getpid(), mach_task_self()) : find_port_address(mach_task_self(), MACH_MSG_TYPE_COPY_SEND);
        LOG("task self: 0x%llx", cached_task_self_addr);
    }
    return cached_task_self_addr;
}


size_t kreadOwO(uint64_t where, void* p, size_t size)
{
    int rv;
    size_t offset = 0;
    while (offset < size) {
        mach_vm_size_t sz, chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_read_overwrite(get_tfp_port(),
                                    where + offset,
                                    chunk,
                                    (mach_vm_address_t)p + offset,
                                    &sz);
        if (rv || sz == 0) {
            LOG("error reading kernel @%p", (void*)(offset + where));
            break;
        }
        offset += sz;
    }
    return offset;
}

size_t kwriteOwO(uint64_t where, const void* p, size_t size)
{
    int rv;
    size_t offset = 0;
    while (offset < size) {
        size_t chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_write(get_tfp_port(),
                           where + offset,
                           (mach_vm_offset_t)p + offset,
                           (mach_msg_type_number_t)chunk);
        if (rv) {
            LOG("error writing kernel @%p", (void*)(offset + where));
            break;
        }
        offset += chunk;
    }
    return offset;
}

bool wkbuffer(uint64_t kaddr, void* buffer, size_t length)
{
    if (get_tfp_port() == MACH_PORT_NULL) {
        LOG("attempt to write to kernel memory before any kernel memory write primitives available");
        return false;
    }
    
    return (kwriteOwO(kaddr, buffer, length) == length);
}


bool rkbuffer(uint64_t kaddr, void* buffer, size_t length)
{
    return (kreadOwO(kaddr, buffer, length) == length);
}



uint64_t rk64_via_tfp0(uint64_t kaddr)
{
    uint64_t val = 0;
    rkbuffer(kaddr, &val, sizeof(val));
    return val;
}

uint32_t rk32_via_tfp0(uint64_t kaddr)
{
    uint32_t val = 0;
    rkbuffer(kaddr, &val, sizeof(val));
    return val;
}

uint16_t ReadKernel16(uint64_t kaddr) {
    uint16_t val = 0;
    rkbuffer(kaddr, &val, sizeof(val));
    return val;
}


uint64_t ReadKernel64(uint64_t kaddr)
{
    if (get_tfp_port() != MACH_PORT_NULL) {
        return rk64_via_tfp0(kaddr);
    }
    
    LOG("attempt to read kernel memory but no kernel memory read primitives available");
    
    return 0;
}

uint32_t ReadKernel32(uint64_t kaddr)
{
    if (get_tfp_port() != MACH_PORT_NULL) {
        return rk32_via_tfp0(kaddr);
    }
    
    LOG("attempt to read kernel memory but no kernel memory read primitives available");
    
    return 0;
}

void WriteKernel64(uint64_t kaddr, uint64_t val)
{
    if (get_tfp_port() == MACH_PORT_NULL) {
        LOG("attempt to write to kernel memory before any kernel memory write primitives available");
        return;
    }
    wkbuffer(kaddr, &val, sizeof(val));
}

void WriteKernel32(uint64_t kaddr, uint32_t val)
{
    if (get_tfp_port() == MACH_PORT_NULL) {
        LOG("attempt to write to kernel memory before any kernel memory write primitives available");
        return;
    }
    wkbuffer(kaddr, &val, sizeof(val));
}


void unsandbox(uint64_t proc) {
    fprintf(stderr, "[jelbrekd] Unsandboxed proc 0x%llx\n", proc);
    uint64_t ucred = ReadKernel64(proc + off_p_ucred);
    uint64_t cr_label = ReadKernel64(ucred + off_ucred_cr_label);
    WriteKernel64(cr_label + off_sandbox_slot, 0);
}

bool canRead(const char *file) {
    NSString *path = @(file);
    NSFileManager *fileManager = [NSFileManager defaultManager];
    return ([fileManager attributesOfItemAtPath:path error:nil]);
}

int fixupexec(char *file) {
    return bypassCodeSign(file);
}


int fixupdylib(char *dylib) {
    #define VSHARED_DYLD    0x000200
    LOG("Fixing up dylib %s", dylib);
    LOG("Getting vnode");
    uint64_t vnode = vnodeForPath(dylib);
    if (!vnode) {
        LOG("Failed to get vnode!");
        return -1;
    }
    LOG("vnode of %s: 0x%llx", dylib, vnode);
    uint32_t v_flags = ReadKernel32(vnode + off_v_flags);
    
    if (v_flags & VSHARED_DYLD) {
        _vnode_put(vnode);
        return 0;
    }
    
    LOG("old v_flags: 0x%x", v_flags);
    uint32_t new_vflags = v_flags | VSHARED_DYLD;
    LOG("new v_flags: 0x%x", new_vflags);
    
    if (v_flags != new_vflags)
    {
        WriteKernel32(vnode + off_v_flags, v_flags | VSHARED_DYLD);
        v_flags = ReadKernel32(vnode + off_v_flags);
        _vnode_put(vnode);
    } else {
        return 0;
    }
    
    
    return !(v_flags & VSHARED_DYLD);
}


void setUID (uid_t uid, uint64_t proc) {
    uint64_t ucred = ReadKernel64(proc + off_p_ucred);
    WriteKernel32(proc + off_p_uid, uid);
    WriteKernel32(proc + off_p_ruid, uid);
    WriteKernel32(ucred + off_ucred_cr_uid, uid);
    WriteKernel32(ucred + off_ucred_cr_ruid, uid);
    WriteKernel32(ucred + off_ucred_cr_svuid, uid);
    fprintf(stderr, "Overwritten UID to %i for proc 0x%llx\n", uid, proc);
}

void setGID(gid_t gid, uint64_t proc) {
    uint64_t ucred = ReadKernel64(proc + off_p_ucred);
    WriteKernel32(proc + off_p_gid, gid);
    WriteKernel32(proc + off_p_rgid, gid);
    WriteKernel32(ucred + off_ucred_cr_rgid, gid);
    WriteKernel32(ucred + off_ucred_cr_svgid, gid);
    fprintf(stderr, "Overwritten GID to %i for proc 0x%llx\n", gid, proc);
}

void fixupsetuid(int pid){
    
    uint64_t procForPid = get_proc_struct_for_pid(pid);
    if (procForPid == 0)
    {
        fprintf(stderr, "Error Getting Proc!\n");
        return;
    } else {
        fprintf(stderr, "Got Proc: %llx for pid %d\n", procForPid, pid);
        setUID(0, procForPid);
        setGID(0, procForPid);
    }
}

const char* abs_path_exceptions[] = {
    "/Library",
    "/private/var/mobile/Library",
    "/private/var/mnt",
    "/System/Library/Caches",
    NULL
};

static const char *exc_key = "com.apple.security.exception.files.absolute-path.read-only";

//About the only shit we EVER use.

void set_csflags(uint64_t proc) {
    uint32_t csflags = ReadKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_P_CSFLAGS));
    csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW | CS_DEBUGGED) & ~(CS_RESTRICT | CS_HARD | CS_KILL);
    WriteKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_P_CSFLAGS), csflags);
}


void set_tfplatform(uint64_t proc) {
    uint64_t task_struct_addr = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_TASK));
    uint32_t task_t_flags = ReadKernel32(task_struct_addr + koffset(KSTRUCT_OFFSET_TASK_TFLAGS));
    task_t_flags |= TF_PLATFORM;
    WriteKernel32(task_struct_addr + koffset(KSTRUCT_OFFSET_TASK_TFLAGS), task_t_flags);
}

uint64_t exception_osarray_cache = 0;
uint64_t get_exception_osarray(void) {
    if (exception_osarray_cache == 0) {
        exception_osarray_cache = OSUnserializeXML(
                                                   "<array>"
                                                   "<string>/Library/</string>"
                                                   "<string>/private/var/mobile/Library/</string>"
                                                   "<string>/private/var/mnt/</string>"
                                                   "<string>/System/Library/Caches/</string>"
                                                   "</array>"
                                                   );
    }
    
    return exception_osarray_cache;
}

void set_amfi_entitlements(uint64_t proc) {
    uint64_t proc_ucred = ReadKernel64(proc + off_p_ucred);
    uint64_t amfi_entitlements = ReadKernel64(ReadKernel64(proc_ucred + 0x78) + 0x8);
    
    int rv = 0;
    
    rv = OSDictionary_SetItem(amfi_entitlements, "get-task-allow", GETOFFSET(OSBoolean_True));
    if (rv != 1) {
        fprintf(stderr, "failed to set get-task-allow within amfi_entitlements!");;
    }
    
    rv = OSDictionary_SetItem(amfi_entitlements, "com.apple.private.skip-library-validation", GETOFFSET(OSBoolean_True));
    if (rv != 1) {
        fprintf(stderr, "failed to set com.apple.private.skip-library-validation within amfi_entitlements!");
    }
    
    uint64_t present = OSDictionary_GetItem(amfi_entitlements, exc_key);
    
    if (present == 0) {
        rv = OSDictionary_SetItem(amfi_entitlements, exc_key, get_exception_osarray());
    } else if (present != get_exception_osarray()) {
        unsigned int itemCount = OSArray_ItemCount(present);
        fprintf(stderr, "got item count: %d", itemCount);
        
        BOOL foundEntitlements = NO;
        
        uint64_t itemBuffer = OSArray_ItemBuffer(present);
        
        for (int i = 0; i < itemCount; i++) {
            uint64_t item = ReadKernel64(itemBuffer + (i * sizeof(void *)));
            char *entitlementString = OSString_CopyString(item);
            fprintf(stderr, "found ent string: %s", entitlementString);
            if (strcmp(entitlementString, "/Library/") == 0) {
                foundEntitlements = YES;
                free(entitlementString);
                break;
            }
            free(entitlementString);
        }
        
        if (!foundEntitlements){
            rv = OSArray_Merge(present, get_exception_osarray());
        } else {
            rv = 1;
        }
    } else {
        rv = 1;
    }
    
    if (rv != 1) {
        fprintf(stderr, "Setting exc FAILED! amfi_entitlements: 0x%llx present: 0x%llx", amfi_entitlements, present);
    }
}




void set_sandbox_extensions(uint64_t proc) {
    uint64_t proc_ucred = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_UCRED));
    uint64_t sandbox = ReadKernel64(ReadKernel64(proc_ucred + 0x78) + 0x10);
    
    char name[40] = {0};
    kreadOwO(proc + 0x250, name, 20);
    
    fprintf(stderr, "proc = 0x%llx & proc_ucred = 0x%llx & sandbox = 0x%llx\n", proc, proc_ucred, sandbox);
    
    if (sandbox == 0) {
        fprintf(stderr, "no sandbox, skipping\n");
        return;
    }
    
    if (has_file_extension(sandbox, abs_path_exceptions[0])) {
        fprintf(stderr, "already has '%s', skipping\n", abs_path_exceptions[0]);
        return;
    }
    
    uint64_t ext = 0;
    const char** path = abs_path_exceptions;
    while (*path != NULL) {
        ext = extension_create_file(*path, ext);
        if (ext == 0) {
            fprintf(stderr, "extension_create_file(%s) failed, panic!\n", *path);
        }
        ++path;
    }
    
    fprintf(stderr, "last extension_create_file ext: 0x%llx\n", ext);
    
    if (ext != 0) {
        extension_add(ext, sandbox, exc_key);
    }
}


void set_csblob(uint64_t proc) {
    uint64_t textvp = ReadKernel64(proc + off_p_textvp); // vnode of executable
    if (textvp == 0) return;
    
    uint16_t vnode_type = ReadKernel16(textvp + off_v_type);
    if (vnode_type != 1) return; // 1 = VREG
    
    uint64_t ubcinfo = ReadKernel64(textvp + off_v_ubcinfo);
    
    // Loop through all csblob entries (linked list) and update
    // all (they must match by design)
    uint64_t csblob = ReadKernel64(ubcinfo + off_ubcinfo_csblobs);
    while (csblob != 0) {
        WriteKernel32(csblob + off_csb_platform_binary, 1);
        
        csblob = ReadKernel64(csblob);
    }
}



int setcsflagsandplatformize(int pid) {
    uint64_t proc = get_proc_struct_for_pid(pid);
    if (proc == 0)
    {
        LOG("Error getting proc for PID: %i", pid);
        return -1;
    } else {
        set_csflags(proc);
        set_tfplatform(proc);
        set_amfi_entitlements(proc);
        set_sandbox_extensions(proc);
        set_csblob(proc);
    }
    
    return 0;
}
