/*
 * CLRBootstrap
 * Copyright (c) 2013-2014 LexManos.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser Public License v2.1
 * which accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 *
 */

// CLRBootstrap.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "CLRBootstrap.h"


// This is an example of an exported variable
CLRBOOTSTRAP_API int nCLRBootstrap=0;

// This is an example of an exported function.
CLRBOOTSTRAP_API int fnCLRBootstrap(void)
{
	return 42;
}

// This is the constructor of a class that has been exported.
// see CLRBootstrap.h for the class definition
CCLRBootstrap::CCLRBootstrap()
{
	return;
}
