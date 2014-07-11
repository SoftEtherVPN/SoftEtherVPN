// SoftEther VPN Source Code
// Cedar Communication Module
// 
// SoftEther VPN Server, Client and Bridge are free software under GPLv2.
// 
// Copyright (c) 2012-2014 Daiyuu Nobori.
// Copyright (c) 2012-2014 SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) 2012-2014 SoftEther Corporation.
// 
// All Rights Reserved.
// 
// http://www.softether.org/
// 
// Author: Daiyuu Nobori
// Comments: Tetsuo Sugiyama, Ph.D.
// 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// version 2 as published by the Free Software Foundation.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License version 2
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// 
// THE LICENSE AGREEMENT IS ATTACHED ON THE SOURCE-CODE PACKAGE
// AS "LICENSE.TXT" FILE. READ THE TEXT FILE IN ADVANCE TO USE THE SOFTWARE.
// 
// 
// THIS SOFTWARE IS DEVELOPED IN JAPAN, AND DISTRIBUTED FROM JAPAN,
// UNDER JAPANESE LAWS. YOU MUST AGREE IN ADVANCE TO USE, COPY, MODIFY,
// MERGE, PUBLISH, DISTRIBUTE, SUBLICENSE, AND/OR SELL COPIES OF THIS
// SOFTWARE, THAT ANY JURIDICAL DISPUTES WHICH ARE CONCERNED TO THIS
// SOFTWARE OR ITS CONTENTS, AGAINST US (SOFTETHER PROJECT, SOFTETHER
// CORPORATION, DAIYUU NOBORI OR OTHER SUPPLIERS), OR ANY JURIDICAL
// DISPUTES AGAINST US WHICH ARE CAUSED BY ANY KIND OF USING, COPYING,
// MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING, AND/OR
// SELLING COPIES OF THIS SOFTWARE SHALL BE REGARDED AS BE CONSTRUED AND
// CONTROLLED BY JAPANESE LAWS, AND YOU MUST FURTHER CONSENT TO
// EXCLUSIVE JURISDICTION AND VENUE IN THE COURTS SITTING IN TOKYO,
// JAPAN. YOU MUST WAIVE ALL DEFENSES OF LACK OF PERSONAL JURISDICTION
// AND FORUM NON CONVENIENS. PROCESS MAY BE SERVED ON EITHER PARTY IN
// THE MANNER AUTHORIZED BY APPLICABLE LAW OR COURT RULE.
// 
// USE ONLY IN JAPAN. DO NOT USE THIS SOFTWARE IN ANOTHER COUNTRY UNLESS
// YOU HAVE A CONFIRMATION THAT THIS SOFTWARE DOES NOT VIOLATE ANY
// CRIMINAL LAWS OR CIVIL RIGHTS IN THAT PARTICULAR COUNTRY. USING THIS
// SOFTWARE IN OTHER COUNTRIES IS COMPLETELY AT YOUR OWN RISK. THE
// SOFTETHER VPN PROJECT HAS DEVELOPED AND DISTRIBUTED THIS SOFTWARE TO
// COMPLY ONLY WITH THE JAPANESE LAWS AND EXISTING CIVIL RIGHTS INCLUDING
// PATENTS WHICH ARE SUBJECTS APPLY IN JAPAN. OTHER COUNTRIES' LAWS OR
// CIVIL RIGHTS ARE NONE OF OUR CONCERNS NOR RESPONSIBILITIES. WE HAVE
// NEVER INVESTIGATED ANY CRIMINAL REGULATIONS, CIVIL LAWS OR
// INTELLECTUAL PROPERTY RIGHTS INCLUDING PATENTS IN ANY OF OTHER 200+
// COUNTRIES AND TERRITORIES. BY NATURE, THERE ARE 200+ REGIONS IN THE
// WORLD, WITH DIFFERENT LAWS. IT IS IMPOSSIBLE TO VERIFY EVERY
// COUNTRIES' LAWS, REGULATIONS AND CIVIL RIGHTS TO MAKE THE SOFTWARE
// COMPLY WITH ALL COUNTRIES' LAWS BY THE PROJECT. EVEN IF YOU WILL BE
// SUED BY A PRIVATE ENTITY OR BE DAMAGED BY A PUBLIC SERVANT IN YOUR
// COUNTRY, THE DEVELOPERS OF THIS SOFTWARE WILL NEVER BE LIABLE TO
// RECOVER OR COMPENSATE SUCH DAMAGES, CRIMINAL OR CIVIL
// RESPONSIBILITIES. NOTE THAT THIS LINE IS NOT LICENSE RESTRICTION BUT
// JUST A STATEMENT FOR WARNING AND DISCLAIMER.
// 
// 
// SOURCE CODE CONTRIBUTION
// ------------------------
// 
// Your contribution to SoftEther VPN Project is much appreciated.
// Please send patches to us through GitHub.
// Read the SoftEther VPN Patch Acceptance Policy in advance:
// http://www.softether.org/5-download/src/9.patch
// 
// 
// DEAR SECURITY EXPERTS
// ---------------------
// 
// If you find a bug or a security vulnerability please kindly inform us
// about the problem immediately so that we can fix the security problem
// to protect a lot of users around the world as soon as possible.
// 
// Our e-mail address for security reports is:
// softether-vpn-security [at] softether.org
// 
// Please note that the above e-mail address is not a technical support
// inquiry address. If you need technical assistance, please visit
// http://www.softether.org/ and ask your question on the users forum.
// 
// Thank you for your cooperation.
// 
// 
// NO MEMORY OR RESOURCE LEAKS
// ---------------------------
// 
// The memory-leaks and resource-leaks verification under the stress
// test has been passed before release this source code.


// WinJumpList.cpp
// HTML display module source code for Win32

#include <GlobalConst.h>

#ifdef	WIN32

//#define NTDDI_WIN7                          0x06010000
//#define	_WIN32_WINNT	_WIN32_WINNT_VISTA
//#define NTDDI_VERSION NTDDI_VISTA  // Specifies that the minimum required platform is Windows 7.
#define WIN32_LEAN_AND_MEAN       // Exclude rarely-used stuff from Windows headers
#define STRICT_TYPED_ITEMIDS      // Utilize strictly typed IDLists

//#include <objectarray.h>
#include <shobjidl.h>
#include <propkey.h>
#include <propvarutil.h>
//#include <knownfolders.h>
//#include <shlobj.h>


#ifdef StrCpy
#undef StrCpy
#endif

#ifdef StrCat
#undef StrCat
#endif

#ifdef StrCmp
#undef StrCmp
#endif


#define	WIN32COM_CPP

//#define	_WIN32_WINNT		0x0502
//#define	WINVER				0x0502
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include <comdef.h>
#include <Mshtmhst.h>
//#include <shlobj.h>
#include <commctrl.h>
#include <Dbghelp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>

extern "C"
{
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>
}
#include "../PenCore/resource.h"

extern "C"
{

	//////////////////////////////////////////////////////////////////////////
	//JumpList
	//#define NTDDI_WIN7                          0x06010000
	//#define NTDDI_VERSION NTDDI_WIN7  // Specifies that the minimum required platform is Windows 7.
	//#define WIN32_LEAN_AND_MEAN       // Exclude rarely-used stuff from Windows headers
	//#define STRICT_TYPED_ITEMIDS      // Utilize strictly typed IDLists
	//
	//
	//#include <shobjidl.h>
	//#include <propkey.h>
	//#include <propvarutil.h>
	//#include <knownfolders.h>
	//#include <shlobj.h>
	//
	//#pragma comment(lib, "propsys.lib")
	//#pragma comment(lib, "shlwapi.lib")

	#define CREATE_PROPERTYKEY(l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8, pid) { { l, w1, w2, { b1, b2,  b3,  b4,  b5,  b6,  b7,  b8 } }, pid }


	// Determines if the provided IShellItem is listed in the array of items that the user has removed
	bool _IsItemInArray(IShellItem *psi, IObjectArray *poaRemoved)
	{
		bool fRet = false;
		UINT cItems;
		if (SUCCEEDED(poaRemoved->GetCount(&cItems)))
		{
			IShellItem *psiCompare;
			for (UINT i = 0; !fRet && i < cItems; i++)
			{
				if (SUCCEEDED(poaRemoved->GetAt(i, IID_PPV_ARGS(&psiCompare))))
				{
					int iOrder;
					fRet = SUCCEEDED(psiCompare->Compare(psi, SICHINT_CANONICAL, &iOrder)) && (0 == iOrder);
					psiCompare->Release();
				}
			}
		}
		return fRet;
	}


	JL_HRESULT JL_CreateCustomDestinationList(JL_PCustomDestinationList* poc, wchar_t* appID)
	{
		ICustomDestinationList *pcdl;

		//CLSID_DestinationList = 6332DEBF-87B5-4670-90C0-5E57-B408-A49E

		GUID destList;

		destList.Data1 = 2012286192;
		destList.Data2 = 15797;
		destList.Data3 = 18790;

		destList.Data4[0] = 181;
		destList.Data4[1] = 32;
		destList.Data4[2] = 183;
		destList.Data4[3] = 197;
		destList.Data4[4] = 79;
		destList.Data4[5] = 211;
		destList.Data4[6] = 94;
		destList.Data4[7] = 214;

		//destList = CLSID_DestinationList;

		//HRESULT hr = CoCreateInstance(CLSID_DestinationList, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pcdl));
		HRESULT hr = CoCreateInstance(destList, 
			NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pcdl));

		if (SUCCEEDED(hr))
		{
			pcdl->SetAppID(appID);
			(*poc) = (void*)pcdl;
		}
		else
		{
			(*poc) = NULL;
		}

		return hr;
	}

	JL_HRESULT JL_ReleaseCustomDestinationList(JL_PCustomDestinationList poc)
	{
		ICustomDestinationList *pcdl = (ICustomDestinationList*)poc;
		if(pcdl != NULL)
		{
			pcdl->Release();
		}

		return 0;
	}

	JL_HRESULT JL_BeginList(JL_PCustomDestinationList poc, JL_PObjectArray* oaRemoved)
	{
		UINT cMinSlots;
		IObjectArray *poaRemoved;

		ICustomDestinationList *pcdl = (ICustomDestinationList*)poc;

		HRESULT hr = pcdl->BeginList(&cMinSlots, IID_PPV_ARGS(&poaRemoved));

		(*oaRemoved) = poaRemoved;

		return hr;
	}

	JL_HRESULT JL_CommitList(JL_PCustomDestinationList cdl)
	{
		ICustomDestinationList *pcdl = (ICustomDestinationList*)cdl;

		return pcdl->CommitList();
	}


	//JL_HRESULT JL_AddTasksToList(JL_PCustomDestinationList pcdl, JL_PObjectCollection poc)
	//{
	//	return 0;
	//}

	JL_HRESULT JL_CreateObjectCollection(JL_PObjectCollection* jpoc)
	{

		//CLSID_EnumerableObjectCollection = 2D3468C1-36A7-43B6-AC24-D3F0-2FD9-607A


		GUID enumObjCol;

		enumObjCol.Data1 = 758409409;
		enumObjCol.Data2 = 13991;
		enumObjCol.Data3 = 17334;

		enumObjCol.Data4[0] = 172;
		enumObjCol.Data4[1] = 36;
		enumObjCol.Data4[2] = 211;
		enumObjCol.Data4[3] = 240;
		enumObjCol.Data4[4] = 47;
		enumObjCol.Data4[5] = 217;
		enumObjCol.Data4[6] = 96;
		enumObjCol.Data4[7] = 122;

		//enumObjCol = CLSID_EnumerableObjectCollection;

		IObjectCollection *poc;
		//HRESULT hr = CoCreateInstance(CLSID_EnumerableObjectCollection, NULL, CLSCTX_INPROC, IID_PPV_ARGS(&poc));
		HRESULT hr = CoCreateInstance(enumObjCol,
			NULL, CLSCTX_INPROC, IID_PPV_ARGS(&poc));

		if (SUCCEEDED(hr))
		{
			(*jpoc) = poc;
		}
		else{
			(*jpoc) = NULL;
		}
		return hr;
	}

	JL_HRESULT JL_ReleaseObjectCollection(JL_PObjectCollection jpoc)
	{
		IObjectCollection *poc = (IObjectCollection *)jpoc;
		if(poc != NULL)
		{
			return poc->Release();
		}

		return 0;
	}

	JL_HRESULT JL_ObjectCollectionAddShellLink(JL_PObjectCollection jpoc, JL_PShellLink jpsl)
	{
		IObjectCollection *poc = (IObjectCollection *)jpoc;
		IShellLink *psl = (IShellLink *) jpsl;

		return poc->AddObject(psl);

	}


	JL_HRESULT JL_AddCategoryToList(JL_PCustomDestinationList jpcdl, 
		JL_PObjectCollection jpoc, 
		wchar_t* categoryName,
		JL_PObjectArray jpoaRemoved)
	{
		ICustomDestinationList *pcdl = (ICustomDestinationList*)jpcdl;
		IObjectCollection *poc = (IObjectCollection *)jpoc;
		 IObjectArray *poaRemoved = (IObjectArray*)jpoaRemoved;

		//for (UINT i = 0; i < ARRAYSIZE(c_rgpszFiles); i++)
		//{
		//	IShellItem *psi;
		//	if (SUCCEEDED(SHCreateItemInKnownFolder(FOLDERID_Documents, KF_FLAG_DEFAULT, c_rgpszFiles[i], IID_PPV_ARGS(&psi))))
		//	{
		//		// Items listed in the removed list may not be re-added to the Jump List during this
		//		// list-building transaction.  They should not be re-added to the Jump List until
		//		// the user has used the item again.  The AppendCategory call below will fail if
		//		// an attempt to add an item in the removed list is made.
		//		if (!_IsItemInArray(psi, poaRemoved))
		//		{
		//			poc->AddObject(psi);
		//		}
		//		psi->Release();
		//	}
		//}

		IObjectArray *poa;
		HRESULT hr = poc->QueryInterface(IID_PPV_ARGS(&poa));
		if (SUCCEEDED(hr))
		{
		
			// Add the category to the Jump List.  If there were more categories, they would appear
			// from top to bottom in the order they were appended.
			hr = pcdl->AppendCategory(categoryName, poa);
			//hr = pcdl->AddUserTasks(poa);
			poa->Release();

			if (SUCCEEDED(hr))
			{
			}
			else
			{
				Print("Failed AppendCategory\n");
			}
		}
		else
		{
			Print("Failed QueryInterface\n");
		}
		

		return hr;
	}



	JL_HRESULT JL_CreateShellLink(
		wchar_t* pszPath, 
		wchar_t* pszArguments, 
		wchar_t* pszTitle, 
		wchar_t* iconLocation,
		int iconIndex, 
		wchar_t* description, JL_PShellLink *ppsl)
	{
		IShellLinkW *psl;
		HRESULT hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&psl));
		if (SUCCEEDED(hr))
		{
			// Determine our executable's file path so the task will execute this application
			//WCHAR szAppPath[MAX_PATH];
			//if (GetModuleFileName(NULL, szAppPath, ARRAYSIZE(szAppPath)))
			//{
				//hr = psl->SetPath(L"C:\\Program Files\\PacketiX VPN Client\\vpncmgr.exe");
				//hr = psl->SetArguments(L"50792311B00B9E01E7534AAA881087AB2BB83A1F");


			psl->SetPath(pszPath);
			psl->SetArguments(pszArguments);
			if(iconLocation != NULL)
			{
				psl->SetIconLocation(iconLocation,iconIndex);
			}

			if(description != NULL)
			{
				psl->SetDescription(description);
			}
				if (SUCCEEDED(hr))
				{
					// The title property is required on Jump List items provided as an IShellLink
					// instance.  This value is used as the display name in the Jump List.
					IPropertyStore *pps;
					hr = psl->QueryInterface(IID_PPV_ARGS(&pps));
					if (SUCCEEDED(hr))
					{
						PROPVARIANT propvar;
						hr = InitPropVariantFromString(pszTitle, &propvar);
						if (SUCCEEDED(hr))
						{

							////PKEY_Title
							//#define DEFINE_PROPERTYKEY(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8, pid) 
							//EXTERN_C const PROPERTYKEY DECLSPEC_SELECTANY name 
							//	= { { l, w1, w2, { b1, b2,  b3,  b4,  b5,  b6,  b7,  b8 } }, pid }
							//DEFINE_PROPERTYKEY(PKEY_Title, 0xF29F85E0, 0x4FF9, 0x1068, 0xAB, 0x91, 0x08, 0x00, 0x2B, 0x27, 0xB3, 0xD9, 2);

							PROPERTYKEY pkey_title = 
								CREATE_PROPERTYKEY(0xF29F85E0, 0x4FF9, 0x1068, 0xAB, 0x91, 0x08, 0x00, 0x2B, 0x27, 0xB3, 0xD9, 2);

							
							//hr = pps->SetValue(PKEY_Title, propvar);
							hr = pps->SetValue(pkey_title, propvar);


							if (SUCCEEDED(hr))
							{
								hr = pps->Commit();
								if (SUCCEEDED(hr))
								{
									IShellLink *tpsl;
									hr = psl->QueryInterface(IID_PPV_ARGS(&tpsl));
									(*ppsl) = tpsl;
								}
							}
							PropVariantClear(&propvar);
						}
						pps->Release();
					}
				}

				/*
				hr = psl->SetPath(szAppPath);
				if (SUCCEEDED(hr))
				{
				hr = psl->SetArguments(pszArguments);
				if (SUCCEEDED(hr))
				{
				// The title property is required on Jump List items provided as an IShellLink
				// instance.  This value is used as the display name in the Jump List.
				IPropertyStore *pps;
				hr = psl->QueryInterface(IID_PPV_ARGS(&pps));
				if (SUCCEEDED(hr))
				{
				PROPVARIANT propvar;
				hr = InitPropVariantFromString(pszTitle, &propvar);
				if (SUCCEEDED(hr))
				{
				hr = pps->SetValue(PKEY_Title, propvar);
				if (SUCCEEDED(hr))
				{
				hr = pps->Commit();
				if (SUCCEEDED(hr))
				{
				hr = psl->QueryInterface(IID_PPV_ARGS(ppsl));
				}
				}
				PropVariantClear(&propvar);
				}
				pps->Release();
				}
				}
				}
				*/
			//}
			//else
			//{
			//	hr = HRESULT_FROM_WIN32(GetLastError());
			//}
			psl->Release();
		}
		return hr;
	}

	JL_HRESULT JL_ReleaseShellLink(JL_PShellLink jpsl)
	{
		IShellLink *psl = (IShellLink *) jpsl;

		if(psl != NULL)
		{
			return psl->Release();
		}

		return 0;
	}

	// Removes that existing custom Jump List for this application.
	JL_HRESULT JL_DeleteJumpList(JL_PCustomDestinationList jpcdl,wchar_t* appID)
	{
		ICustomDestinationList *pcdl = (ICustomDestinationList *)jpcdl;
		//HRESULT hr = CoCreateInstance(CLSID_DestinationList, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pcdl));

		HRESULT	hr = pcdl->DeleteList(appID);


		return hr;
	}



	//////////////////////////////////////////////////////////////////////////
	//SetApplicationID for Windows 7
	JL_HRESULT JL_SetCurrentProcessExplicitAppUserModelID(wchar_t* appID)
	{
#ifdef UNICODE
		HMODULE hModule = LoadLibraryW( L"shell32.dll");
#else
		HMODULE hModule = LoadLibraryA( "shell32.dll");
#endif
		HRESULT (__stdcall *SetAppID) (PCWSTR);

		if( hModule == NULL )
		{
			//// Load failure (there is no DLL)
			// MessageBoxW( NULL, L"shell32.dll not found", L"Error", MB_OK );
			Print("Not Found shell32.dll");
		}
		else
		{
			// Get the address of the function in the DLL
			SetAppID = (HRESULT (__stdcall *)(PCWSTR))
				GetProcAddress( hModule, "SetCurrentProcessExplicitAppUserModelID" );
			if( SetAppID != NULL )
			{
				FreeLibrary( hModule );
				return SetAppID(appID);
			}
			else
			{
				//MessageBoxW( NULL, L"There may not be a function", L"Error", MB_OK );
				Print("Not Found SetCurrentProcessExplicitAppUserModelID");

			}

			// Release the loaded DLL
			FreeLibrary( hModule );
		}
		return 0;


	}



}

#endif

//////////////////////////////////////////////////////////////////////////
// Size Rect
// 

CT_Rect GetBoundingRect(CT_RectF_c* rect)
{
	CT_Rect r = CT_Rect((int)rect->X,(int)rect->Y,(int)rect->Width,(int)rect->Height);
	if(r.Right() < (rect->X + rect->Width)) 
		r.Width+=1;
	if(r.Bottom() < (rect->Y + rect->Height)) 
		r.Height+=1;

	return r;
}


CT_ARGB32 CT_GetAAPix32(UCHAR* srcPtr, int width, int height, int xFix, int yFix);

//////////////////////////////////////////////////////////////////////////
// DrawImage method
void CT_DrawImage(UCHAR* dest, CT_RectF_c destRect, int destWidth, int destHeight,
				  UCHAR* src, CT_RectF_c srcRect, int srcWidth, int srcHeight)
{

	double scaleW = destRect.Width / srcRect.Width;
	double scaleH = destRect.Height / srcRect.Height;


	CT_ARGB32* dest32 = (CT_ARGB32*)(dest);
	CT_ARGB32* src32 =  (CT_ARGB32*)(src);

	float dfx = (float)(1 / scaleW);
	float dfy = (float)(1 / scaleH);

	float srcSX = srcRect.X;
	float srcSY = srcRect.Y;

	int srcSXFix = (int)(srcSX*65536);
	int srcSYFix = (int)(srcSY*65536);
	int dfxFix = (int)(dfx*65536);
	int dfyFix = (int)(dfy*65536);

	//CT_Rect dRect = destRect.GetBoundingRect();

	CT_Rect dRect = GetBoundingRect(&destRect);

	// Clipping not supported: ToDo
	dRect.X = ct_max(0,dRect.X);
	dRect.Y = ct_max(0,dRect.Y);
	dRect.Right((int)ct_min(destRect.X + destRect.Width,dRect.Right()));
	dRect.Bottom((int)ct_min(destRect.Y + destRect.Height,dRect.Bottom()));

	//CT_ARGB32* dPix = dest32->GetPixelAddressNC(dRect.X, dRect.Y);
	CT_ARGB32* dPix = &(dest32[destWidth*dRect.Y + dRect.X]);

	//int dpW = dest32->GetWidth() - dRect.Width;
	int dpW = destWidth - dRect.Width;
	for (int dy = dRect.Y; dy < dRect.Bottom(); dy++)
	{

		int syFix = srcSYFix;
		int sxFix = srcSXFix;

		// Anti-aliasing
		for (int dx = dRect.X; dx < dRect.Right(); dx++)
		{
			int rPixX = ( ((sxFix >> 15) & 0x00000001) == 1) ? (sxFix >> 16)+1 : (sxFix >> 16);
			int rPixY = ( ((syFix >> 15) & 0x00000001) == 1) ? (syFix >> 16)+1 : (syFix >> 16);

			//CT_ARGB32* sPix = &(src32[rPixY * srcWidth + rPixX]);

			//*dPix = *sPix;
			//if(sPix != NULL)
			{					
				//*dPix = src32->GetAAPix32(sxFix,syFix);
				*dPix = CT_GetAAPix32((UCHAR*)src32, srcWidth, srcHeight,sxFix, syFix);
			}

			sxFix += dfxFix;
			dPix++;
		}
	

		srcSYFix += dfyFix;
		dPix += dpW;
	}

}

bool isWhiteColor(CT_ARGB32 col)
{
	return 
		(col.R == 255 &&
		 col.G == 255 &&
		 col.B == 255);
}


CT_ARGB32 CT_GetAAPix32(UCHAR* srcPtr, int width, int height, int xFix, int yFix)
{

	//return CT_ARGB32(255,255,255,255);

	//CT_Bitmap32* src = this;
	CT_ARGB32* src = (CT_ARGB32*)(srcPtr);

	int fixx = xFix;
	int fixy = yFix;

	int fx = (fixx >> 8) & 0xFF;
	int fy = (fixy >> 8) & 0xFF;

	int f[4];
	f[0] = ((255 - fx) * (255 - fy)) >> 8;
	f[1] = (fx * (255 - fy)) >> 8;
	f[2] = ((255 - fx) * fy) >> 8;
	f[3] = (fx * fy) >> 8;

	int px = fixx >> 16;
	int py = fixy >> 16;

	int a, r, g, b;
	a = r = g = b = 0;
	CT_Size size = CT_Size(width, height);
	CT_ARGB32 col = CT_ARGB32(0,255,255,255);
	
	CT_ARGB32 pixs[4];
	for(int j = 0; j < 2; j++)
	{
		for (int i = 0; i < 2; i++)
		{
			int sx = px + i;
			int sy = py + j;

			CT_ARGB32* c;

			if(sx < 0 || sx >= width || sy < 0 || sy >= height)
			{
				c = &col;
			}
			else
			{
				//c = src->GetPixelAddressNC(sx, sy);
				c = &(src[sy * width + sx]);
			}
			pixs[j*2+i] = *c;

			a += c->A * f[j*2 + i];
			r += c->R * f[j*2 + i];
			g += c->G * f[j*2 + i];
			b += c->B * f[j*2 + i];

		}
	}

	bool isAllWhite = true;
	for(int k = 0; k < 4; k++)
	{
		if(!isWhiteColor(pixs[k]))
		{
			isAllWhite = false;
			break;
		}
	}

	if(isAllWhite)
	{
		//
		return CT_ARGB32(0, 255, 255, 255);
	}
	else
	{
		a = a >> 8;
		r = r >> 8;
		g = g >> 8;
		b = b >> 8;

		return CT_ARGB32(a, r, g, b);
	}

}

// 


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
