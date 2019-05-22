//
//  tfp0_holder.c
//  test
//
//  Created by Tanay Findley on 4/21/19.
//  Copyright © 2019 Tanay Findley. All rights reserved.
//

#include "tfp0_holder.h"
#include <mach/mach.h>

mach_port_t tfp_port = MACH_PORT_NULL;

void set_tfp_port(mach_port_t tfpZ)
{
    tfp_port = tfpZ;
}

mach_port_t get_tfp_port()
{
    return tfp_port;
}
