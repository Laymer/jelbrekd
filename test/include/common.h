#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>             // uint*_t
#include <stdbool.h>
#include <mach-o/loader.h>
#ifdef __OBJC__
#include <Foundation/Foundation.h>
#define RAWLOG(str, args...) do { NSLog(@str, ##args); } while(false)
#else
#include <CoreFoundation/CoreFoundation.h>
extern void NSLog(CFStringRef, ...);
#define RAWLOG(str, args...) do { NSLog(CFSTR(str), ##args); } while(false)
#endif

#define LOG(str, args...) RAWLOG("[*] " str, ##args)

#define SafeFree(x) do { if (x) free(x); } while(false)
#define SafeFreeNULL(x) do { SafeFree(x); (x) = NULL; } while(false)

extern uint64_t offset_options;
#define OPT(x) (offset_options?((rk64(offset_options) & OPT_ ##x)?true:false):false)
#define SETOPT(x) (offset_options?wk64(offset_options, rk64(offset_options) | OPT_ ##x):0)
#define UNSETOPT(x) (offset_options?wk64(offset_options, rk64(offset_options) & ~OPT_ ##x):0)
#define OPT_GET_TASK_ALLOW (1<<0)
#define OPT_CS_DEBUGGED (1<<1)

#define ADDR                 "0x%016llx"
#define MACH_HEADER_MAGIC    MH_MAGIC_64
#define MACH_LC_SEGMENT      LC_SEGMENT_64
typedef struct mach_header_64 mach_hdr_t;
typedef struct segment_command_64 mach_seg_t;
typedef uint64_t kptr_t;
typedef struct load_command mach_lc_t;

#define KPTR_NULL ((kptr_t) 0)
#endif
