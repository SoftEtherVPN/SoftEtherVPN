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


// Win32Com.h
// Header of Win32Com.c

#ifndef	WIN32COM_H
#define	WIN32COM_H

#ifdef	WIN32COM_CPP

// Internal function

#endif	// WIN32COM_CPP

// For external function

#pragma comment(lib,"htmlhelp.lib")
#pragma comment(lib,"Urlmon.lib")

#if	defined(__cplusplus)
extern "C"
{
#endif

	void ShowHtml(HWND hWnd, char *url, wchar_t *option);
	bool CreateLink(wchar_t *filename, wchar_t *target, wchar_t *workdir, wchar_t *args,
		wchar_t *comment, wchar_t *icon, UINT icon_index);
	wchar_t *FolderDlgW(HWND hWnd, wchar_t *title, wchar_t *default_dir);
	char *FolderDlgA(HWND hWnd, wchar_t *title, char *default_dir);

	bool InstallNdisProtocolDriver(wchar_t *inf_path, wchar_t *id, UINT lock_timeout);
	bool Win32UPnPAddPort(UINT outside_port, UINT inside_port, bool udp, char *local_ip, wchar_t *description, bool remove_before_add);

	//////////////////////////////////////////////////////////////////////////
	//JumpList

	//Application ID for VPN Client Manager
	#define APPID_CM GC_UI_APPID_CM

	typedef void* JL_PCustomDestinationList;
	typedef void* JL_PObjectArray;
	typedef void* JL_PShellLink;
	typedef void* JL_PObjectCollection;
	typedef long JL_HRESULT;

	JL_HRESULT JL_CreateCustomDestinationList(JL_PCustomDestinationList* poc, wchar_t* appID);
	JL_HRESULT JL_ReleaseCustomDestinationList(JL_PCustomDestinationList poc);

	JL_HRESULT JL_BeginList(JL_PCustomDestinationList poc, JL_PObjectArray* oaRemoved);
	JL_HRESULT JL_CommitList(JL_PCustomDestinationList cdl);


	JL_HRESULT JL_CreateObjectCollection(JL_PObjectCollection* poc);
	JL_HRESULT JL_ReleaseObjectCollection(JL_PObjectCollection poc);
	JL_HRESULT JL_ObjectCollectionAddShellLink(JL_PObjectCollection poc, JL_PShellLink ppsl);

	JL_HRESULT JL_AddCategoryToList(JL_PCustomDestinationList pcdl, 
		JL_PObjectCollection poc, 
		wchar_t* categoryName,
		JL_PObjectArray poaRemoved);
	JL_HRESULT JL_DeleteJumpList(JL_PCustomDestinationList jpcdl,wchar_t* appID);


	JL_HRESULT JL_CreateShellLink(
		wchar_t* pszPath, 
		wchar_t* pszArguments, 
		wchar_t* pszTitle, 
		wchar_t* iconLocation,
		int iconIndex,
		wchar_t* description, JL_PShellLink *ppsl);
	JL_HRESULT JL_ReleaseShellLink(JL_PShellLink ppsl);


	//SetApplicationID for Windows 7
	JL_HRESULT JL_SetCurrentProcessExplicitAppUserModelID(wchar_t* appID);


	//JL_HRESULT JL_AddTasksToList(JL_PCustomDestinationList pcdl, JL_PObjectCollection poc);

	//////////////////////////////////////////////////////////////////////////
	//DrawImage
	// 

	#if	defined(__cplusplus)
	
typedef UCHAR ct_uchar;
typedef char ct_char;

#define ct_max(a,b) (((a) > (b)) ? (a): (b))
#define ct_min(a,b) (((a) < (b)) ? (a): (b))
#define ct_clamp(n,mi,ma) (ct_max(ct_min((n),(ma)),(mi)))
#define ct_clamp01(n) ct_clamp(n,0,1)

/**
* Union representing 32-bit color with alpha channel.
* CT_Color32, CT_AHSV32, CT_AYCbCr32 are also the same.
*
*/
typedef union CT_ARGB32
{
public:

	/** 32-bit integer intensity */
	UINT ARGB;

	/** RGB Color System */
	struct  
	{
		ct_uchar B;
		ct_uchar G;
		ct_uchar R;
		ct_uchar A;
	};

	/** HSV Color System */
	struct HSVA
	{
		ct_uchar V;
		ct_uchar S;
		ct_uchar H;
		ct_uchar A;
	}HSVA;

	/** YCbCr Color System */
	struct  YCbCrA
	{
		ct_uchar Y;
		ct_char Cb;
		ct_char Cr;
		ct_uchar A;
	}YCbCrA;


	/** Default constructor */
	CT_ARGB32(){}

	/** Constructor to initialize by specified color.
	* @param a Alpha channel
	* @param r Red, Hue, Cr
	* @param g Green, Saturation, Cb
	* @param b Blue, Value, Y
	*/
	CT_ARGB32(ct_uchar a,ct_uchar r,ct_uchar g,ct_uchar b)
	{
		A = a;
		R = r;
		G = g;
		B = b;
	}



}CT_ARGB32;


class CT_Size
{
public:
	int Width;
	int Height;

	CT_Size(int w, int h)
	{
		Width = w;
		Height = h;
	}
};

class CT_Rect
{
public:
	int X;
	int Y;
	int Width;
	int Height;

	CT_Rect()
	{	
		X = 0;
		Y = 0;
		Width = 0;
		Height = 0;
	}

	CT_Rect(int x, int y,int w, int h)
	{	
		X = x;
		Y = y;
		Width = w;
		Height = h;
	}

	int Right(){return X + Width;}
	int Bottom(){return Y + Height;}

	void Right(int r){ Width = r - X;}
	void Bottom(int b){ Height = b - Y;}

};



#endif //__cplusplus

typedef struct CT_RectF_c
{
	float X;
	float Y;
	float Width;
	float Height;
} CT_RectF_c;

void CT_DrawImage(UCHAR* dest, CT_RectF_c destRect, int destWidth, int destHeight,
				  UCHAR* src, CT_RectF_c srcRect, int srcWidth, int srcHeight);



#if	defined(__cplusplus)
}
#endif


//EXTERN_C const IID IID_IObjectCollection;
//EXTERN_C const IID IID_ICustomDestinationList;

#if defined(__cplusplus)


#ifndef	__IObjectArray_INTERFACE_DEFINED__
#define	__IObjectArray_INTERFACE_DEFINED__

MIDL_INTERFACE("92CA9DCD-5622-4bba-A805-5E9F541BD8C9")
IObjectArray : public IUnknown
{
public:
	virtual HRESULT STDMETHODCALLTYPE GetCount( 
		/* [out] */ __RPC__out UINT *pcObjects) = 0;

	virtual HRESULT STDMETHODCALLTYPE GetAt( 
		/* [in] */ UINT uiIndex,
		/* [in] */ __RPC__in REFIID riid,
		/* [iid_is][out] */ __RPC__deref_out_opt void **ppv) = 0;

};

MIDL_INTERFACE("5632b1a4-e38a-400a-928a-d4cd63230295")
IObjectCollection : public IObjectArray
{
public:
	virtual HRESULT STDMETHODCALLTYPE AddObject( 
		/* [in] */ __RPC__in_opt IUnknown *punk) = 0;

	virtual HRESULT STDMETHODCALLTYPE AddFromArray( 
		/* [in] */ __RPC__in_opt IObjectArray *poaSource) = 0;

	virtual HRESULT STDMETHODCALLTYPE RemoveObjectAt( 
		/* [in] */ UINT uiIndex) = 0;

	virtual HRESULT STDMETHODCALLTYPE Clear( void) = 0;

};

#endif	// __IObjectArray_INTERFACE_DEFINED__

#ifndef	__ICustomDestinationList_INTERFACE_DEFINED__
#define	__ICustomDestinationList_INTERFACE_DEFINED__

typedef /* [v1_enum] */ 
enum KNOWNDESTCATEGORY
{	
	KDC_FREQUENT	= 1,
	KDC_RECENT	= ( KDC_FREQUENT + 1 ) 
} 	KNOWNDESTCATEGORY;

MIDL_INTERFACE("6332debf-87b5-4670-90c0-5e57b408a49e")
ICustomDestinationList : public IUnknown
{
public:
	virtual HRESULT STDMETHODCALLTYPE SetAppID( 
		/* [string][in] */ __RPC__in_string LPCWSTR pszAppID) = 0;

	virtual HRESULT STDMETHODCALLTYPE BeginList( 
		/* [out] */ __RPC__out UINT *pcMinSlots,
		/* [in] */ __RPC__in REFIID riid,
		/* [iid_is][out] */ __RPC__deref_out_opt void **ppv) = 0;

	virtual HRESULT STDMETHODCALLTYPE AppendCategory( 
		/* [string][in] */ __RPC__in_string LPCWSTR pszCategory,
		/* [in] */ __RPC__in_opt IObjectArray *poa) = 0;

	virtual HRESULT STDMETHODCALLTYPE AppendKnownCategory( 
		/* [in] */ KNOWNDESTCATEGORY category) = 0;

	virtual HRESULT STDMETHODCALLTYPE AddUserTasks( 
		/* [in] */ __RPC__in_opt IObjectArray *poa) = 0;

	virtual HRESULT STDMETHODCALLTYPE CommitList( void) = 0;

	virtual HRESULT STDMETHODCALLTYPE GetRemovedDestinations( 
		/* [in] */ __RPC__in REFIID riid,
		/* [iid_is][out] */ __RPC__deref_out_opt void **ppv) = 0;

	virtual HRESULT STDMETHODCALLTYPE DeleteList( 
		/* [string][unique][in] */ __RPC__in_opt_string LPCWSTR pszAppID) = 0;

	virtual HRESULT STDMETHODCALLTYPE AbortList( void) = 0;

};


#endif	// __ICustomDestinationList_INTERFACE_DEFINED__


#endif //defined(__cplusplus)



#endif	// WIN32COM_H

// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
