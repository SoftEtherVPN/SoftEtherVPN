// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// SW.h
// Header of SW.c

#ifndef	SW_H
#define	SW_H

#define	SW_REG_KEY					"Software\\" GC_REG_COMPANY_NAME "\\Setup Wizard Settings"


UINT SWExec();
UINT SWExecMain();
LIST *SwNewSfxFileList();
void SwFreeSfxFileList(LIST *o);
bool SwAddBasicFilesToList(LIST *o, char *component_name);
bool SwCompileSfx(LIST *o, wchar_t *dst_filename);
bool SwGenSfxModeMain(char *mode, wchar_t *dst);
bool SwWaitForVpnClientPortReady(UINT timeout);

#endif	// SW_H


