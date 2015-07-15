

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 7.00.0500 */
/* at Sat May 30 17:41:51 2015
 */
/* Compiler settings for .\vpnweb.idl:
    Oicf, W1, Zp8, env=Win32 (32b run)
    protocol : dce , ms_ext, c_ext
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
//@@MIDL_FILE_HEADING(  )

#pragma warning( disable: 4049 )  /* more than 64k source lines */


/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 440
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif // __RPCNDR_H_VERSION__

#ifndef COM_NO_WINDOWS_H
#include "windows.h"
#include "ole2.h"
#endif /*COM_NO_WINDOWS_H*/

#ifndef __vpnweb_h__
#define __vpnweb_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

/* Forward Declarations */ 

#ifndef __IVpnWebControl_FWD_DEFINED__
#define __IVpnWebControl_FWD_DEFINED__
typedef interface IVpnWebControl IVpnWebControl;
#endif 	/* __IVpnWebControl_FWD_DEFINED__ */


#ifndef __VpnWebControl_FWD_DEFINED__
#define __VpnWebControl_FWD_DEFINED__

#ifdef __cplusplus
typedef class VpnWebControl VpnWebControl;
#else
typedef struct VpnWebControl VpnWebControl;
#endif /* __cplusplus */

#endif 	/* __VpnWebControl_FWD_DEFINED__ */


/* header files for imported files */
#include "oaidl.h"
#include "ocidl.h"

#ifdef __cplusplus
extern "C"{
#endif 


#ifndef __IVpnWebControl_INTERFACE_DEFINED__
#define __IVpnWebControl_INTERFACE_DEFINED__

/* interface IVpnWebControl */
/* [unique][helpstring][nonextensible][dual][uuid][object] */ 


EXTERN_C const IID IID_IVpnWebControl;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("BEAC96A9-05ED-46B3-975C-4462E83878F5")
    IVpnWebControl : public IDispatch
    {
    public:
        virtual /* [helpstring][id][propget] */ HRESULT STDMETHODCALLTYPE get_InstallerExeUrl( 
            /* [retval][out] */ BSTR *pVal) = 0;
        
        virtual /* [helpstring][id][propput] */ HRESULT STDMETHODCALLTYPE put_InstallerExeUrl( 
            /* [in] */ BSTR newVal) = 0;
        
        virtual /* [helpstring][id][propget] */ HRESULT STDMETHODCALLTYPE get_InstallerInfUrl( 
            /* [retval][out] */ BSTR *pVal) = 0;
        
        virtual /* [helpstring][id][propput] */ HRESULT STDMETHODCALLTYPE put_InstallerInfUrl( 
            /* [in] */ BSTR newVal) = 0;
        
        virtual /* [helpstring][id][propget] */ HRESULT STDMETHODCALLTYPE get_SettingUrl( 
            /* [retval][out] */ BSTR *pVal) = 0;
        
        virtual /* [helpstring][id][propput] */ HRESULT STDMETHODCALLTYPE put_SettingUrl( 
            /* [in] */ BSTR newVal) = 0;
        
        virtual /* [helpstring][id][propget] */ HRESULT STDMETHODCALLTYPE get_VpnServerManagerMode( 
            /* [retval][out] */ BSTR *pVal) = 0;
        
        virtual /* [helpstring][id][propput] */ HRESULT STDMETHODCALLTYPE put_VpnServerManagerMode( 
            /* [in] */ BSTR newVal) = 0;
        
        virtual /* [helpstring][id][propget] */ HRESULT STDMETHODCALLTYPE get_VpnServerHostname( 
            /* [retval][out] */ BSTR *pVal) = 0;
        
        virtual /* [helpstring][id][propput] */ HRESULT STDMETHODCALLTYPE put_VpnServerHostname( 
            /* [in] */ BSTR newVal) = 0;
        
        virtual /* [helpstring][id][propget] */ HRESULT STDMETHODCALLTYPE get_VpnServerHubName( 
            /* [retval][out] */ BSTR *pVal) = 0;
        
        virtual /* [helpstring][id][propput] */ HRESULT STDMETHODCALLTYPE put_VpnServerHubName( 
            /* [in] */ BSTR newVal) = 0;
        
        virtual /* [helpstring][id][propget] */ HRESULT STDMETHODCALLTYPE get_VpnServerPassword( 
            /* [retval][out] */ BSTR *pVal) = 0;
        
        virtual /* [helpstring][id][propput] */ HRESULT STDMETHODCALLTYPE put_VpnServerPassword( 
            /* [in] */ BSTR newVal) = 0;
        
        virtual /* [helpstring][id][propget] */ HRESULT STDMETHODCALLTYPE get_LanguageID( 
            /* [retval][out] */ BSTR *pVal) = 0;
        
        virtual /* [helpstring][id][propput] */ HRESULT STDMETHODCALLTYPE put_LanguageID( 
            /* [in] */ BSTR newVal) = 0;
        
    };
    
#else 	/* C style interface */

    typedef struct IVpnWebControlVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IVpnWebControl * This,
            /* [in] */ REFIID riid,
            /* [iid_is][out] */ 
            __RPC__deref_out  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IVpnWebControl * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IVpnWebControl * This);
        
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            IVpnWebControl * This,
            /* [out] */ UINT *pctinfo);
        
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            IVpnWebControl * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);
        
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            IVpnWebControl * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [range][in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);
        
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            IVpnWebControl * This,
            /* [in] */ DISPID dispIdMember,
            /* [in] */ REFIID riid,
            /* [in] */ LCID lcid,
            /* [in] */ WORD wFlags,
            /* [out][in] */ DISPPARAMS *pDispParams,
            /* [out] */ VARIANT *pVarResult,
            /* [out] */ EXCEPINFO *pExcepInfo,
            /* [out] */ UINT *puArgErr);
        
        /* [helpstring][id][propget] */ HRESULT ( STDMETHODCALLTYPE *get_InstallerExeUrl )( 
            IVpnWebControl * This,
            /* [retval][out] */ BSTR *pVal);
        
        /* [helpstring][id][propput] */ HRESULT ( STDMETHODCALLTYPE *put_InstallerExeUrl )( 
            IVpnWebControl * This,
            /* [in] */ BSTR newVal);
        
        /* [helpstring][id][propget] */ HRESULT ( STDMETHODCALLTYPE *get_InstallerInfUrl )( 
            IVpnWebControl * This,
            /* [retval][out] */ BSTR *pVal);
        
        /* [helpstring][id][propput] */ HRESULT ( STDMETHODCALLTYPE *put_InstallerInfUrl )( 
            IVpnWebControl * This,
            /* [in] */ BSTR newVal);
        
        /* [helpstring][id][propget] */ HRESULT ( STDMETHODCALLTYPE *get_SettingUrl )( 
            IVpnWebControl * This,
            /* [retval][out] */ BSTR *pVal);
        
        /* [helpstring][id][propput] */ HRESULT ( STDMETHODCALLTYPE *put_SettingUrl )( 
            IVpnWebControl * This,
            /* [in] */ BSTR newVal);
        
        /* [helpstring][id][propget] */ HRESULT ( STDMETHODCALLTYPE *get_VpnServerManagerMode )( 
            IVpnWebControl * This,
            /* [retval][out] */ BSTR *pVal);
        
        /* [helpstring][id][propput] */ HRESULT ( STDMETHODCALLTYPE *put_VpnServerManagerMode )( 
            IVpnWebControl * This,
            /* [in] */ BSTR newVal);
        
        /* [helpstring][id][propget] */ HRESULT ( STDMETHODCALLTYPE *get_VpnServerHostname )( 
            IVpnWebControl * This,
            /* [retval][out] */ BSTR *pVal);
        
        /* [helpstring][id][propput] */ HRESULT ( STDMETHODCALLTYPE *put_VpnServerHostname )( 
            IVpnWebControl * This,
            /* [in] */ BSTR newVal);
        
        /* [helpstring][id][propget] */ HRESULT ( STDMETHODCALLTYPE *get_VpnServerHubName )( 
            IVpnWebControl * This,
            /* [retval][out] */ BSTR *pVal);
        
        /* [helpstring][id][propput] */ HRESULT ( STDMETHODCALLTYPE *put_VpnServerHubName )( 
            IVpnWebControl * This,
            /* [in] */ BSTR newVal);
        
        /* [helpstring][id][propget] */ HRESULT ( STDMETHODCALLTYPE *get_VpnServerPassword )( 
            IVpnWebControl * This,
            /* [retval][out] */ BSTR *pVal);
        
        /* [helpstring][id][propput] */ HRESULT ( STDMETHODCALLTYPE *put_VpnServerPassword )( 
            IVpnWebControl * This,
            /* [in] */ BSTR newVal);
        
        /* [helpstring][id][propget] */ HRESULT ( STDMETHODCALLTYPE *get_LanguageID )( 
            IVpnWebControl * This,
            /* [retval][out] */ BSTR *pVal);
        
        /* [helpstring][id][propput] */ HRESULT ( STDMETHODCALLTYPE *put_LanguageID )( 
            IVpnWebControl * This,
            /* [in] */ BSTR newVal);
        
        END_INTERFACE
    } IVpnWebControlVtbl;

    interface IVpnWebControl
    {
        CONST_VTBL struct IVpnWebControlVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IVpnWebControl_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IVpnWebControl_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IVpnWebControl_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IVpnWebControl_GetTypeInfoCount(This,pctinfo)	\
    ( (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo) ) 

#define IVpnWebControl_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    ( (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo) ) 

#define IVpnWebControl_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    ( (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId) ) 

#define IVpnWebControl_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    ( (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr) ) 


#define IVpnWebControl_get_InstallerExeUrl(This,pVal)	\
    ( (This)->lpVtbl -> get_InstallerExeUrl(This,pVal) ) 

#define IVpnWebControl_put_InstallerExeUrl(This,newVal)	\
    ( (This)->lpVtbl -> put_InstallerExeUrl(This,newVal) ) 

#define IVpnWebControl_get_InstallerInfUrl(This,pVal)	\
    ( (This)->lpVtbl -> get_InstallerInfUrl(This,pVal) ) 

#define IVpnWebControl_put_InstallerInfUrl(This,newVal)	\
    ( (This)->lpVtbl -> put_InstallerInfUrl(This,newVal) ) 

#define IVpnWebControl_get_SettingUrl(This,pVal)	\
    ( (This)->lpVtbl -> get_SettingUrl(This,pVal) ) 

#define IVpnWebControl_put_SettingUrl(This,newVal)	\
    ( (This)->lpVtbl -> put_SettingUrl(This,newVal) ) 

#define IVpnWebControl_get_VpnServerManagerMode(This,pVal)	\
    ( (This)->lpVtbl -> get_VpnServerManagerMode(This,pVal) ) 

#define IVpnWebControl_put_VpnServerManagerMode(This,newVal)	\
    ( (This)->lpVtbl -> put_VpnServerManagerMode(This,newVal) ) 

#define IVpnWebControl_get_VpnServerHostname(This,pVal)	\
    ( (This)->lpVtbl -> get_VpnServerHostname(This,pVal) ) 

#define IVpnWebControl_put_VpnServerHostname(This,newVal)	\
    ( (This)->lpVtbl -> put_VpnServerHostname(This,newVal) ) 

#define IVpnWebControl_get_VpnServerHubName(This,pVal)	\
    ( (This)->lpVtbl -> get_VpnServerHubName(This,pVal) ) 

#define IVpnWebControl_put_VpnServerHubName(This,newVal)	\
    ( (This)->lpVtbl -> put_VpnServerHubName(This,newVal) ) 

#define IVpnWebControl_get_VpnServerPassword(This,pVal)	\
    ( (This)->lpVtbl -> get_VpnServerPassword(This,pVal) ) 

#define IVpnWebControl_put_VpnServerPassword(This,newVal)	\
    ( (This)->lpVtbl -> put_VpnServerPassword(This,newVal) ) 

#define IVpnWebControl_get_LanguageID(This,pVal)	\
    ( (This)->lpVtbl -> get_LanguageID(This,pVal) ) 

#define IVpnWebControl_put_LanguageID(This,newVal)	\
    ( (This)->lpVtbl -> put_LanguageID(This,newVal) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IVpnWebControl_INTERFACE_DEFINED__ */



#ifndef __vpnwebLib_LIBRARY_DEFINED__
#define __vpnwebLib_LIBRARY_DEFINED__

/* library vpnwebLib */
/* [helpstring][version][uuid] */ 


EXTERN_C const IID LIBID_vpnwebLib;

EXTERN_C const CLSID CLSID_VpnWebControl;

#ifdef __cplusplus

class DECLSPEC_UUID("64F1A16B-C3EE-484C-B551-35338A9BB6D2")
VpnWebControl;
#endif
#endif /* __vpnwebLib_LIBRARY_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

unsigned long             __RPC_USER  BSTR_UserSize(     unsigned long *, unsigned long            , BSTR * ); 
unsigned char * __RPC_USER  BSTR_UserMarshal(  unsigned long *, unsigned char *, BSTR * ); 
unsigned char * __RPC_USER  BSTR_UserUnmarshal(unsigned long *, unsigned char *, BSTR * ); 
void                      __RPC_USER  BSTR_UserFree(     unsigned long *, BSTR * ); 

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


