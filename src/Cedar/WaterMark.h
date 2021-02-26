// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// WaterMark.h
// Header of WaterMark.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>

#ifndef	WATERMARK_H
#define	WATERMARK_H

// Digital watermark
extern BYTE WaterMark[];
extern BYTE Saitama[];

UINT SizeOfWaterMark();
UINT SizeOfSaitama();

#define	MAX_WATERMARK_SIZE		(SizeOfWaterMark() + HTTP_PACK_RAND_SIZE_MAX * 2)

#endif	// WATERMARK_H

