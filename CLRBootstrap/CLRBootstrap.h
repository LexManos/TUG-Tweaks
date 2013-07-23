/*
 * CLRBootstrap
 * Copyright (c) 2013-2014 LexManos.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser Public License v2.1
 * which accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 *
 */

// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the CLRBOOTSTRAP_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// CLRBOOTSTRAP_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef CLRBOOTSTRAP_EXPORTS
#define CLRBOOTSTRAP_API __declspec(dllexport)
#else
#define CLRBOOTSTRAP_API __declspec(dllimport)
#endif

// This class is exported from the CLRBootstrap.dll
class CLRBOOTSTRAP_API CCLRBootstrap {
public:
	CCLRBootstrap(void);
	// TODO: add your methods here.
};

extern CLRBOOTSTRAP_API int nCLRBootstrap;

CLRBOOTSTRAP_API int fnCLRBootstrap(void);
