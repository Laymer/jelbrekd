//
//  KernUtils.h
//  test
//
//  Created by Tanay Findley on 5/19/19.
//  Copyright © 2019 Tanay Findley. All rights reserved.
//

#ifndef KernUtils_h
#define KernUtils_h

#include <stdbool.h>
#include <stdio.h>
#define __FILENAME__ (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)
#define _assert(test, message, fatal) do \
if (!(test)) { \
int saved_errno = errno; \
LOG("__assert(%d:%s)@%s:%u[%s]", saved_errno, #test, __FILENAME__, __LINE__, __FUNCTION__); \
} \
while (false)

bool wkbuffer(uint64_t kaddr, void* buffer, size_t length);
bool rkbuffer(uint64_t kaddr, void* buffer, size_t length);
uint64_t zm_fix_addr(uint64_t addr);
size_t kreadOwO(uint64_t where, void* p, size_t size);
size_t kwriteOwO(uint64_t where, const void* p, size_t size);
uint64_t task_self_addr(void);
int setcsflagsandplatformize(int pid);
void WriteKernel32(uint64_t kaddr, uint32_t val);
void WriteKernel64(uint64_t kaddr, uint64_t val);
uint32_t ReadKernel32(uint64_t kaddr);
uint64_t ReadKernel64(uint64_t kaddr);
bool have_kmem_read(void);
uint64_t kmem_alloc(uint64_t size);
bool kmem_free(uint64_t kaddr, uint64_t size);
int kstrcmp(uint64_t kstr, const char* str);
uint64_t get_address_of_port(pid_t pid, mach_port_t port);
void getOffsets(void);


int setcsflagsandplatformize(int pid);
void unsandbox(uint64_t proc);
void fixupsetuid(int pid);
int fixupdylib(char *dylib);
int fixupexec(char *file);

bool canRead(const char *file);
uint32_t find_macho_header(FILE *file);

#endif /* KernUtils_h */
