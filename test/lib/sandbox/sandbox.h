//
//  sandbox.h
//  test
//
//  Created by Tanay Findley on 5/12/19.
//  Copyright © 2019 Tanay Findley. All rights reserved.
//

#ifndef sandbox_h
#define sandbox_h

#include <stdio.h>


// see https://stek29.rocks/2018/01/26/sandbox.html

void extension_add(uint64_t ext, uint64_t sb, const char* desc);
uint64_t extension_create_file(const char* path, uint64_t nextptr);
int has_file_extension(uint64_t sb, const char* path);

#endif /* sandbox_h */
