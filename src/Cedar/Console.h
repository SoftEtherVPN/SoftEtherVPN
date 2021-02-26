// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Console.h
// Header of Console.c

#ifndef	CONSOLE_H
#define	CONSOLE_H

// Constant
#define	MAX_PROMPT_STRSIZE			65536
#define	WIN32_DEFAULT_CONSOLE_WIDTH	100

// Types of console
#define	CONSOLE_LOCAL				0	// Local console
#define	CONSOLE_CSV					1	// CSV output mode

// Parameters completion prompt function
typedef wchar_t *(PROMPT_PROC)(CONSOLE *c, void *param);

// Parameter validation prompt function
typedef bool (EVAL_PROC)(CONSOLE *c, wchar_t *str, void *param);

// Definition of the parameter item
struct PARAM
{
	char *Name;					// Parameter name
	PROMPT_PROC *PromptProc;	// Prompt function that automatically invoked if the parameter is not specified
								//  (This is not called in the case of NULL)
	void *PromptProcParam;		// Any pointers to pass to the prompt function
	EVAL_PROC *EvalProc;		// Parameter string validation function
	void *EvalProcParam;		// Any pointers to be passed to the validation function
	char *Tmp;					// Temporary variable
};

// Parameter value of the internal data
struct PARAM_VALUE
{
	char *Name;					// Name
	char *StrValue;				// String value
	wchar_t *UniStrValue;		// Unicode string value
	UINT IntValue;				// Integer value
};

// Console service structure
struct CONSOLE
{
	UINT ConsoleType;										// Type of console
	UINT RetCode;											// The last exit code
	void *Param;											// Data of any
	void (*Free)(CONSOLE *c);								// Release function
	wchar_t *(*ReadLine)(CONSOLE *c, wchar_t *prompt, bool nofile);		// Function to read one line
	char *(*ReadPassword)(CONSOLE *c, wchar_t *prompt);		// Function to read the password
	bool (*Write)(CONSOLE *c, wchar_t *str);				// Function to write a string
	UINT (*GetWidth)(CONSOLE *c);							// Get the width of the screen
	bool ProgrammingMode;									// Programming Mode
	LOCK *OutputLock;										// Output Lock
};

// Local console parameters
struct LOCAL_CONSOLE_PARAM
{
	IO *InFile;		// Input file
	BUF *InBuf;		// Input buffer
	IO *OutFile;	// Output file
	UINT Win32_OldConsoleWidth;	// Previous console size
};

// Command procedure
typedef UINT (COMMAND_PROC)(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);

// Definition of command
struct CMD
{
	char *Name;				// Command name
	COMMAND_PROC *Proc;		// Procedure function
};

// Evaluate the minimum / maximum value of the parameter
struct CMD_EVAL_MIN_MAX
{
	char *StrName;
	UINT MinValue, MaxValue;
};


// Function prototype
wchar_t *Prompt(wchar_t *prompt_str);
char *PromptA(wchar_t *prompt_str);
bool PasswordPrompt(char *password, UINT size);
void *SetConsoleRaw();
void RestoreConsole(void *p);
wchar_t *ParseCommandEx(wchar_t *str, wchar_t *name, TOKEN_LIST **param_list);
wchar_t *ParseCommand(wchar_t *str, wchar_t *name);
TOKEN_LIST *GetCommandNameList(wchar_t *str);
char *ParseCommandA(wchar_t *str, char *name);
LIST *NewParamValueList();
int CmpParamValue(void *p1, void *p2);
void FreeParamValueList(LIST *o);
PARAM_VALUE *FindParamValue(LIST *o, char *name);
char *GetParamStr(LIST *o, char *name);
wchar_t *GetParamUniStr(LIST *o, char *name);
UINT GetParamInt(LIST *o, char *name);
bool GetParamYes(LIST *o, char *name);
LIST *ParseCommandList(CONSOLE *c, char *cmd_name, wchar_t *command, PARAM param[], UINT num_param);
bool IsNameInRealName(char *input_name, char *real_name);
void GetOmissionName(char *dst, UINT size, char *src);
bool IsOmissionName(char *input_name, char *real_name);
TOKEN_LIST *GetRealnameCandidate(char *input_name, TOKEN_LIST *real_name_list);
bool SeparateCommandAndParam(wchar_t *src, char **cmd, wchar_t **param);
UINT GetConsoleWidth(CONSOLE *c);
bool DispatchNextCmd(CONSOLE *c, char *prompt, CMD cmd[], UINT num_cmd, void *param);
bool DispatchNextCmdEx(CONSOLE *c, wchar_t *exec_command, char *prompt, CMD cmd[], UINT num_cmd, void *param);
void PrintCandidateHelp(CONSOLE *c, char *cmd_name, TOKEN_LIST *candidate_list, UINT left_space);
UNI_TOKEN_LIST *SeparateStringByWidth(wchar_t *str, UINT width);
UINT GetNextWordWidth(wchar_t *str);
bool IsWordChar(wchar_t c);
void GetCommandHelpStr(char *command_name, wchar_t **description, wchar_t **args, wchar_t **help);
void GetCommandParamHelpStr(char *command_name, char *param_name, wchar_t **description);
bool CmdEvalMinMax(CONSOLE *c, wchar_t *str, void *param);
wchar_t *CmdPrompt(CONSOLE *c, void *param);
bool CmdEvalNotEmpty(CONSOLE *c, wchar_t *str, void *param);
bool CmdEvalInt1(CONSOLE *c, wchar_t *str, void *param);
bool CmdEvalIsFile(CONSOLE *c, wchar_t *str, void *param);
bool CmdEvalSafe(CONSOLE *c, wchar_t *str, void *param);
void PrintCmdHelp(CONSOLE *c, char *cmd_name, TOKEN_LIST *param_list);
int CompareCandidateStr(void *p1, void *p2);
bool IsHelpStr(char *str);

CONSOLE *NewLocalConsole(wchar_t *infile, wchar_t *outfile);
void ConsoleLocalFree(CONSOLE *c);
wchar_t *ConsoleLocalReadLine(CONSOLE *c, wchar_t *prompt, bool nofile);
char *ConsoleLocalReadPassword(CONSOLE *c, wchar_t *prompt);
bool ConsoleLocalWrite(CONSOLE *c, wchar_t *str);
void ConsoleWriteOutFile(CONSOLE *c, wchar_t *str, bool add_last_crlf);
wchar_t *ConsoleReadNextFromInFile(CONSOLE *c);
UINT ConsoleLocalGetWidth(CONSOLE *c);


#endif	// CONSOLE_H



