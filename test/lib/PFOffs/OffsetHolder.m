#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>

#import "OffsetHolder.h"

#define SYSTEM_VERSION_EQUAL_TO(v)                  ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedSame)
#define SYSTEM_VERSION_GREATER_THAN(v)              ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedDescending)
#define SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(v)  ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] != NSOrderedAscending)
#define SYSTEM_VERSION_LESS_THAN(v)                 ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedAscending)
#define SYSTEM_VERSION_LESS_THAN_OR_EQUAL_TO(v)     ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] != NSOrderedDescending)

uint32_t* offsets = NULL;

uint32_t _kstruct_offsets_12_0[] = {
    0xb, // KSTRUCT_OFFSET_TASK_LCK_MTX_TYPE
    0x10, // KSTRUCT_OFFSET_TASK_REF_COUNT
    0x14, // KSTRUCT_OFFSET_TASK_ACTIVE
    0x20, // KSTRUCT_OFFSET_TASK_VM_MAP
    0x28, // KSTRUCT_OFFSET_TASK_NEXT
    0x30, // KSTRUCT_OFFSET_TASK_PREV
    0x300, // KSTRUCT_OFFSET_TASK_ITK_SPACE
#if __arm64e__
    0x368, // KSTRUCT_OFFSET_TASK_BSD_INFO
#else
    0x358, // KSTRUCT_OFFSET_TASK_BSD_INFO
#endif
#if __arm64e__
    0x3a8, // KSTRUCT_OFFSET_TASK_ALL_IMAGE_INFO_ADDR
#else
    0x398, // KSTRUCT_OFFSET_TASK_ALL_IMAGE_INFO_ADDR
#endif
#if __arm64e__
    0x3b0, // KSTRUCT_OFFSET_TASK_ALL_IMAGE_INFO_SIZE
#else
    0x3a0, // KSTRUCT_OFFSET_TASK_ALL_IMAGE_INFO_SIZE
#endif
#if __arm64e__
    0x400, // KSTRUCT_OFFSET_TASK_TFLAGS
#else
    0x390, // KSTRUCT_OFFSET_TASK_TFLAGS
#endif
    
    0x0, // KSTRUCT_OFFSET_IPC_PORT_IO_BITS
    0x4, // KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES
    0x40, // KSTRUCT_OFFSET_IPC_PORT_IKMQ_BASE
    0x50, // KSTRUCT_OFFSET_IPC_PORT_MSG_COUNT
    0x60, // KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER
    0x68, // KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT
    0x88, // KSTRUCT_OFFSET_IPC_PORT_IP_PREMSG
    0x90, // KSTRUCT_OFFSET_IPC_PORT_IP_CONTEXT
    0xa0, // KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS
    
    0x60, // KSTRUCT_OFFSET_PROC_PID
    0x108, // KSTRUCT_OFFSET_PROC_P_FD
    0x10, // KSTRUCT_OFFSET_PROC_TASK
    0xf8, // KSTRUCT_OFFSET_PROC_UCRED
    0x8, // KSTRUCT_OFFSET_PROC_P_LIST
    0x290, // KSTRUCT_OFFSET_PROC_P_CSFLAGS
    
    0x0, // KSTRUCT_OFFSET_FILEDESC_FD_OFILES
    
    0x8, // KSTRUCT_OFFSET_FILEPROC_F_FGLOB
    
    0x38, // KSTRUCT_OFFSET_FILEGLOB_FG_DATA
    
    0x10, // KSTRUCT_OFFSET_SOCKET_SO_PCB
    
    0x10, // KSTRUCT_OFFSET_PIPE_BUFFER
    
    0x14, // KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE_SIZE
    0x20, // KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE
    
    0xd8, // KSTRUCT_OFFSET_VNODE_V_MOUNT
    0x78, // KSTRUCT_OFFSET_VNODE_VU_SPECINFO
    0x0, // KSTRUCT_OFFSET_VNODE_V_LOCK
    0xe0, // KSTRUCT_OFFSET_VNODE_V_DATA
    
    0x10, // KSTRUCT_OFFSET_SPECINFO_SI_FLAGS
    
    0x70, // KSTRUCT_OFFSET_MOUNT_MNT_FLAG
    0x8f8, // KSTRUCT_OFFSET_MOUNT_MNT_DATA
    
    0x10, // KSTRUCT_OFFSET_HOST_SPECIAL
    
    0x18, // KSTRUCT_OFFSET_UCRED_CR_UID
    0x78, // KSTRUCT_OFFSET_UCRED_CR_LABEL
    
    0x18, // KSTRUCT_SIZE_IPC_ENTRY
    
    0x6c, // KFREE_ADDR_OFFSET
};

uint32_t koffset(enum kstruct_offset offset)
{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSLog(@"offsets selected for iOS 12.0 or above");
        offsets = _kstruct_offsets_12_0;
    });
    return offsets[offset];
}
