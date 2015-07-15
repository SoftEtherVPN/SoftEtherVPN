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


// Console.c
// Console Service

#include "CedarPch.h"


// Display the help for the command
void PrintCmdHelp(CONSOLE *c, char *cmd_name, TOKEN_LIST *param_list)
{
	wchar_t tmp[MAX_SIZE];
	wchar_t *buf;
	UINT buf_size;
	wchar_t *description, *args, *help;
	UNI_TOKEN_LIST *t;
	UINT width;
	UINT i;
	char *space;
	// Validate arguments
	if (c == NULL || cmd_name == NULL || param_list == NULL)
	{
		return;
	}

	width = GetConsoleWidth(c) - 2;

	buf_size = sizeof(wchar_t) * (width + 32);
	buf = Malloc(buf_size);

	GetCommandHelpStr(cmd_name, &description, &args, &help);

	space = MakeCharArray(' ', 2);

	// Title
	UniFormat(tmp, sizeof(tmp), _UU("CMD_HELP_TITLE"), cmd_name);
	c->Write(c, tmp);
	c->Write(c, L"");

	// Purpose
	c->Write(c, _UU("CMD_HELP_DESCRIPTION"));
	t = SeparateStringByWidth(description, width - 2);
	for (i = 0;i < t->NumTokens;i++)
	{
		UniFormat(buf, buf_size, L"%S%s", space, t->Token[i]);
		c->Write(c, buf);
	}
	UniFreeToken(t);
	c->Write(c, L"");

	// Description
	c->Write(c, _UU("CMD_HELP_HELP"));
	t = SeparateStringByWidth(help, width - 2);
	for (i = 0;i < t->NumTokens;i++)
	{
		UniFormat(buf, buf_size, L"%S%s", space, t->Token[i]);
		c->Write(c, buf);
	}
	UniFreeToken(t);
	c->Write(c, L"");

	// Usage
	c->Write(c, _UU("CMD_HELP_USAGE"));
	t = SeparateStringByWidth(args, width - 2);
	for (i = 0;i < t->NumTokens;i++)
	{
		UniFormat(buf, buf_size, L"%S%s", space, t->Token[i]);
		c->Write(c, buf);
	}
	UniFreeToken(t);

	// Arguments
	if (param_list->NumTokens >= 1)
	{
		c->Write(c, L"");
		c->Write(c, _UU("CMD_HELP_ARGS"));
		PrintCandidateHelp(c, cmd_name, param_list, 2);
	}

	Free(space);

	Free(buf);
}

// Evaluate whether it is SafeStr
bool CmdEvalSafe(CONSOLE *c, wchar_t *str, void *param)
{
	wchar_t *p = (param == NULL) ? _UU("CMD_EVAL_SAFE") : (wchar_t *)param;

	if (IsSafeUniStr(str))
	{
		return true;
	}

	c->Write(c, p);

	return false;
}

// String input prompt
wchar_t *CmdPrompt(CONSOLE *c, void *param)
{
	wchar_t *p = (param == NULL) ? _UU("CMD_PROMPT") : (wchar_t *)param;

	return c->ReadLine(c, p, true);
}

// Evaluation whether the specified file exists
bool CmdEvalIsFile(CONSOLE *c, wchar_t *str, void *param)
{
	wchar_t tmp[MAX_PATH];
	// Validate arguments
	if (c == NULL || str == NULL)
	{
		return false;
	}

	UniStrCpy(tmp, sizeof(tmp), str);

	if (IsEmptyUniStr(tmp))
	{
		c->Write(c, _UU("CMD_FILE_NAME_EMPTY"));
		return false;
	}

	if (IsFileExistsW(tmp) == false)
	{
		wchar_t tmp2[MAX_SIZE];

		UniFormat(tmp2, sizeof(tmp2), _UU("CMD_FILE_NOT_FOUND"), tmp);
		c->Write(c, tmp2);

		return false;
	}

	return true;
}

// Evaluation of integer
bool CmdEvalInt1(CONSOLE *c, wchar_t *str, void *param)
{
	wchar_t *p = (param == NULL) ? _UU("CMD_EVAL_INT") : (wchar_t *)param;

	if (UniToInt(str) == 0)
	{
		c->Write(c, p);

		return false;
	}

	return true;
}

// Evaluation of the parameters that a blank cannot be specified to
bool CmdEvalNotEmpty(CONSOLE *c, wchar_t *str, void *param)
{
	wchar_t *p = (param == NULL) ? _UU("CMD_EVAL_NOT_EMPTY") : (wchar_t *)param;

	if (UniIsEmptyStr(str) == false)
	{
		return true;
	}

	c->Write(c, p);

	return false;
}

// Evaluation function for minimum / maximum value of the parameter
bool CmdEvalMinMax(CONSOLE *c, wchar_t *str, void *param)
{
	CMD_EVAL_MIN_MAX *e;
	wchar_t *tag;
	UINT v;
	// Validate arguments
	if (param == NULL)
	{
		return false;
	}

	e = (CMD_EVAL_MIN_MAX *)param;

	if (e->StrName == NULL)
	{
		tag = _UU("CMD_EVAL_MIN_MAX");
	}
	else
	{
		tag = _UU(e->StrName);
	}

	v = UniToInt(str);

	if (v >= e->MinValue && v <= e->MaxValue)
	{
		return true;
	}
	else
	{
		wchar_t tmp[MAX_SIZE];

		UniFormat(tmp, sizeof(tmp), tag, e->MinValue, e->MaxValue);
		c->Write(c, tmp);

		return false;
	}
}

// Get the help string of command
void GetCommandHelpStr(char *command_name, wchar_t **description, wchar_t **args, wchar_t **help)
{
	char tmp1[128], tmp2[128], tmp3[128];

	Format(tmp1, sizeof(tmp1), "CMD_%s", command_name);
	Format(tmp2, sizeof(tmp2), "CMD_%s_ARGS", command_name);
	Format(tmp3, sizeof(tmp3), "CMD_%s_HELP", command_name);

	if (description != NULL)
	{
		*description = _UU(tmp1);
		if (UniIsEmptyStr(*description))
		{
			*description = _UU("CMD_UNKNOWM");
		}
	}

	if (args != NULL)
	{
		*args = _UU(tmp2);
		if (UniIsEmptyStr(*args))
		{
			*args = _UU("CMD_UNKNOWN_ARGS");
		}
	}

	if (help != NULL)
	{
		*help = _UU(tmp3);
		if (UniIsEmptyStr(*help))
		{
			*help = _UU("CMD_UNKNOWN_HELP");
		}
	}
}

// Get the help string for parameter
void GetCommandParamHelpStr(char *command_name, char *param_name, wchar_t **description)
{
	char tmp[160];
	if (description == NULL)
	{
		return;
	}

	Format(tmp, sizeof(tmp), "CMD_%s_%s", command_name, param_name);

	*description = _UU(tmp);

	if (UniIsEmptyStr(*description))
	{
		*description = _UU("CMD_UNKNOWN_PARAM");
	}
}

// String comparison function
int CompareCandidateStr(void *p1, void *p2)
{
	char *s1, *s2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	s1 = *(char **)p1;
	s2 = *(char **)p2;
	if (s1 == NULL || s2 == NULL)
	{
		return 0;
	}

	if (s1[0] == '[' && s2[0] != '[')
	{
		return -1;
	}
	else if (s2[0] == '[' && s1[0] != '[')
	{
		return 1;
	}

	return StrCmp(s1, s2);
}

// Display the help of the candidate list
void PrintCandidateHelp(CONSOLE *c, char *cmd_name, TOKEN_LIST *candidate_list, UINT left_space)
{
	UINT console_width;
	UINT max_keyword_width;
	LIST *o;
	UINT i;
	wchar_t *tmpbuf;
	UINT tmpbuf_size;
	char *left_space_array;
	char *max_space_array;
	// Validate arguments
	if (c == NULL || candidate_list == NULL)
	{
		return;
	}

	// Get the width of the screen
	console_width = GetConsoleWidth(c) - 1;

	tmpbuf_size = sizeof(wchar_t) * (console_width + 32);
	tmpbuf = Malloc(tmpbuf_size);

	left_space_array = MakeCharArray(' ', left_space);

	// Sort and enlist the command name
	// no need to sort the parameter name
	o = NewListFast(cmd_name == NULL ? CompareCandidateStr : NULL);

	max_keyword_width = 0;

	for (i = 0;i < candidate_list->NumTokens;i++)
	{
		UINT keyword_width;

		// Get the width of each keyword
		Insert(o, candidate_list->Token[i]);

		keyword_width = StrWidth(candidate_list->Token[i]);
		if (cmd_name != NULL)
		{
			if (candidate_list->Token[i][0] != '[')
			{
				keyword_width += 1;
			}
			else
			{
				keyword_width -= 2;
			}
		}

		max_keyword_width = MAX(max_keyword_width, keyword_width);
	}

	max_space_array = MakeCharArray(' ', max_keyword_width);

	// Display the candidate
	for (i = 0;i < LIST_NUM(o);i++)
	{
		char tmp[128];
		char *name = LIST_DATA(o, i);
		UNI_TOKEN_LIST *t;
		wchar_t *help;
		UINT j;
		UINT keyword_start_width = left_space;
		UINT descript_start_width = left_space + max_keyword_width + 1;
		UINT descript_width;
		char *space;

		if (console_width >= (descript_start_width + 5))
		{
			descript_width = console_width - descript_start_width - 3;
		}
		else
		{
			descript_width = 2;
		}

		// Generate the name
		if (cmd_name != NULL && name[0] != '[')
		{
			// Prepend a "/" in the case of a parameter
			Format(tmp, sizeof(tmp), "/%s", name);
		}
		else
		{
			// Use the characters as it is in the case of a command name
			if (cmd_name == NULL)
			{
				StrCpy(tmp, sizeof(tmp), name);
			}
			else
			{
				StrCpy(tmp, sizeof(tmp), name + 1);
				if (StrLen(tmp) >= 1)
				{
					tmp[StrLen(tmp) - 1] = 0;
				}
			}
		}

		// Get the help string
		if (cmd_name == NULL)
		{
			GetCommandHelpStr(name, &help, NULL, NULL);
		}
		else
		{
			GetCommandParamHelpStr(cmd_name, name, &help);
		}

		space = MakeCharArray(' ', max_keyword_width - StrWidth(name) - (cmd_name == NULL ? 0 : (name[0] != '[' ? 1 : -2)));

		t = SeparateStringByWidth(help, descript_width);

		for (j = 0;j < t->NumTokens;j++)
		{
			if (j == 0)
			{
				UniFormat(tmpbuf, tmpbuf_size, L"%S%S%S - %s",
					left_space_array, tmp, space, t->Token[j]);
			}
			else
			{
				UniFormat(tmpbuf, tmpbuf_size, L"%S%S   %s",
					left_space_array, max_space_array, t->Token[j]);
			}

			c->Write(c, tmpbuf);
		}

		Free(space);

		UniFreeToken(t);
	}

	ReleaseList(o);

	Free(max_space_array);
	Free(tmpbuf);
	Free(left_space_array);
}

// Acquisition whether word characters
bool IsWordChar(wchar_t c)
{
	if (c >= L'a' && c <= 'z')
	{
		return true;
	}
	if (c >= L'A' && c <= 'Z')
	{
		return true;
	}
	if (c >= L'0' && c <= '9')
	{
		return true;
	}
	if (c == L'_')
	{
		return true;
	}
	if (c == L'.')
	{
		return true;
	}
	if (c == L'\"')
	{
		return true;
	}
	if (c == L'\'')
	{
		return true;
	}
	if (c == L',')
	{
		return true;
	}
	if (c == L')')
	{
		return true;
	}
	if (c == L']')
	{
		return true;
	}

	return false;
}

// Get the character width of the word that comes next
UINT GetNextWordWidth(wchar_t *str)
{
	UINT i;
	UINT ret;
	// Validate arguments
	if (str == NULL)
	{
		return 0;
	}

	ret = 0;

	for (i = 0;;i++)
	{
		wchar_t c = str[i];

		if (c == 0)
		{
			break;
		}

		if (IsWordChar(c) == false)
		{
			break;
		}

		ret++;
	}

	return ret;
}

// Split a string into specified width
UNI_TOKEN_LIST *SeparateStringByWidth(wchar_t *str, UINT width)
{
	UINT wp;
	wchar_t *tmp;
	UINT len, i;
	LIST *o;
	UNI_TOKEN_LIST *ret;
	// Validate arguments
	if (str == NULL)
	{
		return UniNullToken();
	}
	if (width == 0)
	{
		width = 1;
	}

	o = NewListFast(NULL);

	len = UniStrLen(str);
	tmp = ZeroMalloc(sizeof(wchar_t) * (len + 32));
	wp = 0;

	for (i = 0;i < (len + 1);i++)
	{
		wchar_t c = str[i];
		UINT next_word_width;
		UINT remain_width;

		switch (c)
		{
		case 0:
		case L'\r':
		case L'\n':
			if (c == L'\r')
			{
				if (str[i + 1] == L'\n')
				{
					i++;
				}
			}

			tmp[wp++] = 0;
			wp = 0;

			Insert(o, UniCopyStr(tmp));
			break;

		default:
			next_word_width = GetNextWordWidth(&str[i]);
			remain_width = (width - UniStrWidth(tmp));

			if ((remain_width >= 1) && (next_word_width > remain_width) && (next_word_width <= width))
			{
				tmp[wp++] = 0;
				wp = 0;

				Insert(o, UniCopyStr(tmp));
			}

			tmp[wp++] = c;
			tmp[wp] = 0;
			if (UniStrWidth(tmp) >= width)
			{
				tmp[wp++] = 0;
				wp = 0;

				Insert(o, UniCopyStr(tmp));
			}
			break;
		}
	}

	if (LIST_NUM(o) == 0)
	{
		Insert(o, CopyUniStr(L""));
	}

	ret = ZeroMalloc(sizeof(UNI_TOKEN_LIST));
	ret->NumTokens = LIST_NUM(o);
	ret->Token = ZeroMalloc(sizeof(wchar_t *) * ret->NumTokens);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		wchar_t *s = LIST_DATA(o, i);

		UniTrimLeft(s);

		ret->Token[i] = s;
	}

	ReleaseList(o);
	Free(tmp);

	return ret;
}

// Check whether the specified string means 'help'
bool IsHelpStr(char *str)
{
	// Validate arguments
	if (str == NULL)
	{
		return false;
	}

	if (StrCmpi(str, "help") == 0 || StrCmpi(str, "?") == 0 ||
		StrCmpi(str, "man") == 0 || StrCmpi(str, "/man") == 0 ||
		StrCmpi(str, "-man") == 0 || StrCmpi(str, "--man") == 0 ||
		StrCmpi(str, "/help") == 0 || StrCmpi(str, "/?") == 0 ||
		StrCmpi(str, "-help") == 0 || StrCmpi(str, "-?") == 0 ||
		StrCmpi(str, "/h") == 0 || StrCmpi(str, "--help") == 0 ||
		StrCmpi(str, "--?") == 0)
	{
		return true;
	}

	return false;
}

// Execution of the command
bool DispatchNextCmd(CONSOLE *c, char *prompt, CMD cmd[], UINT num_cmd, void *param)
{
	return DispatchNextCmdEx(c, NULL, prompt, cmd, num_cmd, param);
}
bool DispatchNextCmdEx(CONSOLE *c, wchar_t *exec_command, char *prompt, CMD cmd[], UINT num_cmd, void *param)
{
	wchar_t *str;
	wchar_t *tmp;
	char *cmd_name;
	bool b_exit = false;
	wchar_t *cmd_param;
	UINT ret = ERR_NO_ERROR;
	TOKEN_LIST *t;
	TOKEN_LIST *candidate;
	bool no_end_crlf = false;
	UINT i;
	// Validate arguments
	if (c == NULL || (num_cmd >= 1 && cmd == NULL))
	{
		return false;
	}

	if (exec_command == NULL)
	{
		// Show the prompt
RETRY:
		tmp = CopyStrToUni(prompt);

		if (c->ProgrammingMode)
		{
			wchar_t tmp2[MAX_PATH];

			UniFormat(tmp2, sizeof(tmp2), L"[PROMPT:%u:%s]\r\n", c->RetCode, tmp);

			Free(tmp);

			tmp = CopyUniStr(tmp2);
		}

		str = c->ReadLine(c, tmp, false);
		Free(tmp);

		if (str != NULL && IsEmptyUniStr(str))
		{
			Free(str);
			goto RETRY;
		}
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		// Use exec_command
		if (UniStartWith(exec_command, L"vpncmd") == false)
		{
			if (prompt != NULL)
			{
				if (c->ConsoleType != CONSOLE_CSV)
				{
					UniFormat(tmp, sizeof(tmp), L"%S%s", prompt, exec_command);
					c->Write(c, tmp);
				}
			}
		}
		str = CopyUniStr(exec_command);
	}

	if (str == NULL)
	{
		// User canceled
		return false;
	}

	UniTrimCrlf(str);
	UniTrim(str);

	if (UniIsEmptyStr(str))
	{
		// Do Nothing
		Free(str);
		return true;
	}

	// Divide into command name and parameter
	if (SeparateCommandAndParam(str, &cmd_name, &cmd_param) == false)
	{
		// Do Nothing
		Free(str);
		return true;
	}

	if (StrLen(cmd_name) >= 2 && cmd_name[0] == '?' && cmd_name[1] != '?')
	{
		char tmp[MAX_SIZE];
		wchar_t *s;

		StrCpy(tmp, sizeof(tmp), cmd_name + 1);
		StrCpy(cmd_name, 0, tmp);

		s = UniCopyStr(L"/?");
		Free(cmd_param);

		cmd_param = s;
	}

	if (StrLen(cmd_name) >= 2 && EndWith(cmd_name, "?") && cmd_name[StrLen(cmd_name) - 2] != '?')
	{
		wchar_t *s;

		cmd_name[StrLen(cmd_name) - 1] = 0;

		s = UniCopyStr(L"/?");
		Free(cmd_param);

		cmd_param = s;
	}

	// Get the candidate of command
	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = num_cmd;
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);
	for (i = 0;i < t->NumTokens;i++)
	{
		t->Token[i] = CopyStr(cmd[i].Name);
	}

	if (IsHelpStr(cmd_name))
	{
		if (UniIsEmptyStr(cmd_param))
		{
			wchar_t tmp[MAX_SIZE];

			// Display the list of commands that can be used
			UniFormat(tmp, sizeof(tmp), _UU("CMD_HELP_1"), t->NumTokens);
			c->Write(c, tmp);

			PrintCandidateHelp(c, NULL, t, 1);

			c->Write(c, L"");
			c->Write(c, _UU("CMD_HELP_2"));
		}
		else
		{
			char *cmd_name;

			// Display the help for the specified command
			if (SeparateCommandAndParam(cmd_param, &cmd_name, NULL))
			{
				bool b = true;

				if (IsHelpStr(cmd_name))
				{
					b = false;
				}

				if (b)
				{
					wchar_t str[MAX_SIZE];

					UniFormat(str, sizeof(str), L"%S /help", cmd_name);
					DispatchNextCmdEx(c, str, NULL, cmd, num_cmd, param);
					no_end_crlf = true;
				}

				Free(cmd_name);
			}
		}
	}
	else if (StrCmpi(cmd_name, "exit") == 0 || StrCmpi(cmd_name, "quit") == 0)
	{
		// Exit
		b_exit = true;
	}
	else
	{
		candidate = GetRealnameCandidate(cmd_name, t);

		if (candidate == NULL || candidate->NumTokens == 0)
		{
			wchar_t tmp[MAX_SIZE];

			// No candidate
			UniFormat(tmp, sizeof(tmp), _UU("CON_UNKNOWN_CMD"), cmd_name);
			c->Write(c, tmp);

			c->RetCode = ERR_BAD_COMMAND_OR_PARAM;
		}
		else if (candidate->NumTokens >= 2)
		{
			wchar_t tmp[MAX_SIZE];

			// There is more than one candidate
			UniFormat(tmp, sizeof(tmp), _UU("CON_AMBIGIOUS_CMD"), cmd_name);
			c->Write(c, tmp);
			c->Write(c, _UU("CON_AMBIGIOUS_CMD_1"));
			PrintCandidateHelp(c, NULL, candidate, 1);
			c->Write(c, _UU("CON_AMBIGIOUS_CMD_2"));

			c->RetCode = ERR_BAD_COMMAND_OR_PARAM;
		}
		else
		{
			char *real_cmd_name;
			UINT i;

			// The candidate was shortlisted to one
			real_cmd_name = candidate->Token[0];

			for (i = 0;i < num_cmd;i++)
			{
				if (StrCmpi(cmd[i].Name, real_cmd_name) == 0)
				{
					if (cmd[i].Proc != NULL)
					{
						// Show the description of the command if it isn't in CSV mode
						if(c->ConsoleType != CONSOLE_CSV)
						{
							wchar_t tmp[256];
							wchar_t *note;

							GetCommandHelpStr(cmd[i].Name, &note, NULL, NULL);
							UniFormat(tmp, sizeof(tmp), _UU("CMD_EXEC_MSG_NAME"), cmd[i].Name, note);
							c->Write(c, tmp);
						}

						// Call the procedure of the command
						ret = cmd[i].Proc(c, cmd[i].Name, cmd_param, param);

						if (ret == INFINITE)
						{
							// Exit command
							b_exit = true;
						}
						else
						{
							c->RetCode = ret;
						}
					}
				}
			}
		}

		FreeToken(candidate);
	}

	FreeToken(t);
	Free(str);
	Free(cmd_name);
	Free(cmd_param);

	if (no_end_crlf == false)
	{
		//c->Write(c, L"");
	}

	if (b_exit)
	{
		return false;
	}

	return true;
}

// Get the width of the current console
UINT GetConsoleWidth(CONSOLE *c)
{
	UINT size;

	size = c->GetWidth(c);

	if (size == 0)
	{
		size = 80;
	}

	if (size < 32)
	{
		size = 32;
	}

	if (size > 65536)
	{
		size = 65535;
	}

	return size;
}

// Separate the command line into the command and the parameters
bool SeparateCommandAndParam(wchar_t *src, char **cmd, wchar_t **param)
{
	UINT i, len, wp;
	wchar_t *tmp;
	wchar_t *src_tmp;
	// Validate arguments
	if (src == NULL)
	{
		return false;
	}
	if (cmd != NULL)
	{
		*cmd = NULL;
	}
	if (param != NULL)
	{
		*param = NULL;
	}

	src_tmp = UniCopyStr(src);
	UniTrimCrlf(src_tmp);
	UniTrim(src_tmp);

	len = UniStrLen(src_tmp);
	tmp = Malloc(sizeof(wchar_t) * (len + 32));
	wp = 0;

	for (i = 0;i < (len + 1);i++)
	{
		wchar_t c = src_tmp[i];

		switch (c)
		{
		case 0:
		case L' ':
		case L'\t':
			tmp[wp] = 0;
			if (UniIsEmptyStr(tmp))
			{
				Free(tmp);
				Free(src_tmp);
				return false;
			}
			if (cmd != NULL)
			{
				*cmd = CopyUniToStr(tmp);
				Trim(*cmd);
			}
			goto ESCAPE;

		default:
			tmp[wp++] = c;
			break;
		}
	}

ESCAPE:
	if (param != NULL)
	{
		*param = CopyUniStr(&src_tmp[wp]);
		UniTrim(*param);
	}

	Free(tmp);
	Free(src_tmp);

	return true;
}

// Get the candidates list of of the real command name whose abbreviation matches to the command specified by the user
TOKEN_LIST *GetRealnameCandidate(char *input_name, TOKEN_LIST *real_name_list)
{
	TOKEN_LIST *ret;
	LIST *o;
	UINT i;
	bool ok = false;
	// Validate arguments
	if (input_name == NULL || real_name_list == NULL)
	{
		return NullToken();
	}

	o = NewListFast(NULL);

	for (i = 0;i < real_name_list->NumTokens;i++)
	{
		char *name = real_name_list->Token[i];

		// Search for an exact match with the highest priority first
		if (StrCmpi(name, input_name) == 0)
		{
			Insert(o, name);
			ok = true;
			break;
		}
	}

	if (ok == false)
	{
		// If there is no command to exact match, check whether it matches to a short form command
		for (i = 0;i < real_name_list->NumTokens;i++)
		{
			char *name = real_name_list->Token[i];

			if (IsOmissionName(input_name, name) || IsNameInRealName(input_name, name))
			{
				// A abbreviation is found
				Insert(o, name);
				ok = true;
			}
		}
	}

	if (ok)
	{
		// One or more candidate is found
		ret = ListToTokenList(o);
	}
	else
	{
		ret = NullToken();
	}

	ReleaseList(o);

	return ret;
}

// Check whether the command specified by the user is a abbreviation of existing commands
bool IsOmissionName(char *input_name, char *real_name)
{
	char oname[128];
	// Validate arguments
	if (input_name == NULL || real_name == NULL)
	{
		return false;
	}

	if (IsAllUpperStr(real_name))
	{
		// Command of all capital letters do not take abbreviations
		return false;
	}

	GetOmissionName(oname, sizeof(oname), real_name);

	if (IsEmptyStr(oname))
	{
		return false;
	}

	if (StartWith(oname, input_name))
	{
		// Example: The oname of AccountSecureCertSet is "ascs".
		// But if the user enters "asc", returns true
		return true;
	}

	if (StartWith(input_name, oname))
	{
		// Example: When two commands AccountCreate and AccountConnect exist,
		// if the user enter "aconnect" , only AccountConnect is true

		if (EndWith(real_name, &input_name[StrLen(oname)]))
		{
			return true;
		}
	}

	return false;
}

// Get the short name of the specified command
void GetOmissionName(char *dst, UINT size, char *src)
{
	UINT i, len;
	// Validate arguments
	if (dst == NULL || src == NULL)
	{
		return;
	}

	StrCpy(dst, size, "");
	len = StrLen(src);

	for (i = 0;i < len;i++)
	{
		char c = src[i];

		if ((c >= '0' && c <= '9') ||
			(c >= 'A' && c <= 'Z'))
		{
			char tmp[2];
			tmp[0] = c;
			tmp[1] = 0;

			StrCat(dst, size, tmp);
		}
	}
}

// Check whether the command specified by the user matches the existing commands
bool IsNameInRealName(char *input_name, char *real_name)
{
	// Validate arguments
	if (input_name == NULL || real_name == NULL)
	{
		return false;
	}

	if (StartWith(real_name, input_name))
	{
		return true;
	}

	return false;
}

// Parse the command list
LIST *ParseCommandList(CONSOLE *c, char *cmd_name, wchar_t *command, PARAM param[], UINT num_param)
{
	UINT i;
	LIST *o;
	bool ok = true;
	TOKEN_LIST *param_list;
	TOKEN_LIST *real_name_list;
	bool help_mode = false;
	wchar_t *tmp;
	// Validate arguments
	if (c == NULL || command == NULL || (num_param >= 1 && param == NULL) || cmd_name == NULL)
	{
		return NULL;
	}

	// Initialization
	for (i = 0;i < num_param;i++)
	{
		if (IsEmptyStr(param[i].Name) == false)
		{
			if (param[i].Name[0] == '[')
			{
				param[i].Tmp = "";
			}
			else
			{
				param[i].Tmp = NULL;
			}
		}
		else
		{
			param[i].Tmp = "";
		}
	}

	real_name_list = ZeroMalloc(sizeof(TOKEN_LIST));
	real_name_list->NumTokens = num_param;
	real_name_list->Token = ZeroMalloc(sizeof(char *) * real_name_list->NumTokens);

	for (i = 0;i < real_name_list->NumTokens;i++)
	{
		real_name_list->Token[i] = CopyStr(param[i].Name);
	}

	// Generate a list of parameter name specified by the user
	param_list = GetCommandNameList(command);

	for (i = 0;i < param_list->NumTokens;i++)
	{
		char *s = param_list->Token[i];

		if (StrCmpi(s, "help") == 0 || StrCmpi(s, "?") == 0)
		{
			help_mode = true;
			break;
		}
	}

	tmp = ParseCommand(command, L"");
	if (tmp != NULL)
	{
		if (UniStrCmpi(tmp, L"?") == 0)
		{
			help_mode = true;
		}
		Free(tmp);
	}

	if (help_mode)
	{
		// Show the help
		PrintCmdHelp(c, cmd_name, real_name_list);
		FreeToken(param_list);
		FreeToken(real_name_list);
		return NULL;
	}

	for (i = 0;i < param_list->NumTokens;i++)
	{
		// Get the corresponding commands for all parameter names which is specified by the user
		TOKEN_LIST *candidate = GetRealnameCandidate(param_list->Token[i], real_name_list);

		if (candidate != NULL && candidate->NumTokens >= 1)
		{
			if (candidate->NumTokens >= 2)
			{
				wchar_t tmp[MAX_SIZE];

				// There is more than one candidate
				UniFormat(tmp, sizeof(tmp), _UU("CON_AMBIGIOUS_PARAM"), param_list->Token[i]);
				c->Write(c, tmp);
				UniFormat(tmp, sizeof(tmp), _UU("CON_AMBIGIOUS_PARAM_1"), cmd_name);
				c->Write(c, tmp);

				PrintCandidateHelp(c, cmd_name, candidate, 1);

				c->Write(c, _UU("CON_AMBIGIOUS_PARAM_2"));

				ok = false;
			}
			else
			{
				UINT j;
				char *real_name = candidate->Token[0];

				// There is only one candidate
				for (j = 0;j < num_param;j++)
				{
					if (StrCmpi(param[j].Name, real_name) == 0)
					{
						param[j].Tmp = param_list->Token[i];
					}
				}
			}
		}
		else
		{
			wchar_t tmp[MAX_SIZE];

			// No candidate
			UniFormat(tmp, sizeof(tmp), _UU("CON_INVALID_PARAM"), param_list->Token[i], cmd_name, cmd_name);
			c->Write(c, tmp);

			ok = false;
		}

		FreeToken(candidate);
	}

	if (ok == false)
	{
		FreeToken(param_list);
		FreeToken(real_name_list);

		return NULL;
	}

	// Creating a list
	o = NewParamValueList();

	// Read all the parameters of the specified name in the parameter list
	for (i = 0;i < num_param;i++)
	{
		bool prompt_input_value = false;
		PARAM *p = &param[i];

		if (p->Tmp != NULL || p->PromptProc != NULL)
		{
			wchar_t *name = CopyStrToUni(p->Name);
			wchar_t *tmp;
			wchar_t *str;

			if (p->Tmp != NULL)
			{
				tmp = CopyStrToUni(p->Tmp);
			}
			else
			{
				tmp = CopyStrToUni(p->Name);
			}

			str = ParseCommand(command, tmp);
			Free(tmp);
			if (str != NULL)
			{
				wchar_t *unistr;
				bool ret;
EVAL_VALUE:
				// Reading succeeded
				unistr = str;

				if (p->EvalProc != NULL)
				{
					// Evaluate the value if EvalProc is specified
					ret = p->EvalProc(c, unistr, p->EvalProcParam);
				}
				else
				{
					// Accept any value if EvalProc is not specified
					ret = true;
				}

				if (ret == false)
				{
					// The specified value is invalid
					if (p->PromptProc == NULL)
					{
						// Cancel
						ok = false;
						Free(name);
						Free(str);
						break;
					}
					else if (c->ProgrammingMode)
					{
						// In the programming mode, return the error immediately.
						ok = false;
						Free(name);
						Free(str);
						break;
					}
					else
					{
						// Request to re-enter
						Free(str);
						str = NULL;
						goto SHOW_PROMPT;
					}
				}
				else
				{
					PARAM_VALUE *v;
					// Finished loading, add it to the list
					v = ZeroMalloc(sizeof(PARAM_VALUE));
					v->Name = CopyStr(p->Name);
					v->StrValue = CopyUniToStr(str);
					v->UniStrValue = CopyUniStr(str);
					v->IntValue = ToInt(v->StrValue);
					Insert(o, v);
				}
			}
			else
			{
				// Failed to read. The parameter is not specified
				if (p->PromptProc != NULL)
				{
					wchar_t *tmp;
SHOW_PROMPT:
					// Prompt because it is a mandatory parameter
					tmp = NULL;
					if (c->ProgrammingMode == false)
					{
						tmp = p->PromptProc(c, p->PromptProcParam);
					}
					if (tmp == NULL)
					{
						// User canceled
						ok = false;
						Free(str);
						Free(name);
						break;
					}
					else
					{
						// Entered by the user
						c->Write(c, L"");
						str = tmp;
						prompt_input_value = true;
						goto EVAL_VALUE;
					}
				}
			}

			Free(str);
			Free(name);
		}
	}

	FreeToken(param_list);
	FreeToken(real_name_list);

	if (ok)
	{
		return o;
	}
	else
	{
		FreeParamValueList(o);
		return NULL;
	}
}

// Acquisition of [Yes] or [No]
bool GetParamYes(LIST *o, char *name)
{
	char *s;
	char tmp[64];
	// Validate arguments
	if (o == NULL)
	{
		return false;
	}

	s = GetParamStr(o, name);
	if (s == NULL)
	{
		return false;
	}

	StrCpy(tmp, sizeof(tmp), s);
	Trim(tmp);

	if (StartWith(tmp, "y"))
	{
		return true;
	}

	if (StartWith(tmp, "t"))
	{
		return true;
	}

	if (ToInt(tmp) != 0)
	{
		return true;
	}

	return false;
}

// Acquisition of parameter value Int
UINT GetParamInt(LIST *o, char *name)
{
	PARAM_VALUE *v;
	// Validate arguments
	if (o == NULL)
	{
		return 0;
	}

	v = FindParamValue(o, name);
	if (v == NULL)
	{
		return 0;
	}
	else
	{
		return v->IntValue;
	}
}

// Acquisition of parameter value Unicode string
wchar_t *GetParamUniStr(LIST *o, char *name)
{
	PARAM_VALUE *v;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

	v = FindParamValue(o, name);
	if (v == NULL)
	{
		return NULL;
	}
	else
	{
		return v->UniStrValue;
	}
}

// Acquisition of the parameter value string
char *GetParamStr(LIST *o, char *name)
{
	PARAM_VALUE *v;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

	v = FindParamValue(o, name);
	if (v == NULL)
	{
		return NULL;
	}
	else
	{
		return v->StrValue;
	}
}

// Acquisition of parameter value
PARAM_VALUE *FindParamValue(LIST *o, char *name)
{
	PARAM_VALUE t, *ret;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}
	if (name == NULL)
	{
		name = "";
	}

	Zero(&t, sizeof(t));
	t.Name = name;

	ret = Search(o, &t);

	return ret;
}

// Release of the parameter value list
void FreeParamValueList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		PARAM_VALUE *v = LIST_DATA(o, i);

		Free(v->StrValue);
		Free(v->UniStrValue);
		Free(v->Name);
		Free(v);
	}

	ReleaseList(o);
}

// Parameter value list sort function
int CmpParamValue(void *p1, void *p2)
{
	PARAM_VALUE *v1, *v2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	v1 = *(PARAM_VALUE **)p1;
	v2 = *(PARAM_VALUE **)p2;
	if (v1 == NULL || v2 == NULL)
	{
		return 0;
	}

	if (IsEmptyStr(v1->Name) && IsEmptyStr(v2->Name))
	{
		return 0;
	}
	return StrCmpi(v1->Name, v2->Name);
}

// Generation of the parameter value list
LIST *NewParamValueList()
{
	return NewListFast(CmpParamValue);
}

// Get the list of parameter names that were included in the entered command
TOKEN_LIST *GetCommandNameList(wchar_t *str)
{
	TOKEN_LIST *t;
	// Validate arguments
	if (str == NULL)
	{
		return NullToken();
	}

	Free(ParseCommandEx(str, L"dummy_str", &t));

	return t;
}

// Get the commands that start with the specified name
wchar_t *ParseCommand(wchar_t *str, wchar_t *name)
{
	return ParseCommandEx(str, name, NULL);
}
wchar_t *ParseCommandEx(wchar_t *str, wchar_t *name, TOKEN_LIST **param_list)
{
	UNI_TOKEN_LIST *t;
	UINT i;
	wchar_t *tmp;
	wchar_t *ret = NULL;
	LIST *o;
	// Validate arguments
	if (str == NULL)
	{
		return NULL;
	}
	if (name != NULL && UniIsEmptyStr(name))
	{
		name = NULL;
	}

	o = NULL;
	if (param_list != NULL)
	{
		o = NewListFast(CompareStr);
	}

	tmp = CopyUniStr(str);
	UniTrim(tmp);

	i = UniSearchStrEx(tmp, L"/CMD ", 0, false);

	if (i != INFINITE && i >= 1 && tmp[i - 1] == L'/')
	{
		i = INFINITE;
	}
	if (i == INFINITE)
	{
		i = UniSearchStrEx(tmp, L"/CMD\t", 0, false);
		if (i != INFINITE && i >= 1 && tmp[i - 1] == L'/')
		{
			i = INFINITE;
		}
	}
	if (i == INFINITE)
	{
		i = UniSearchStrEx(tmp, L"/CMD:", 0, false);
		if (i != INFINITE && i >= 1 && tmp[i - 1] == L'/')
		{
			i = INFINITE;
		}
	}
	if (i == INFINITE)
	{
		i = UniSearchStrEx(tmp, L"/CMD=", 0, false);
		if (i != INFINITE && i >= 1 && tmp[i - 1] == L'/')
		{
			i = INFINITE;
		}
	}
	if (i == INFINITE)
	{
		i = UniSearchStrEx(tmp, L"-CMD ", 0, false);
		if (i != INFINITE && i >= 1 && tmp[i - 1] == L'-')
		{
			i = INFINITE;
		}
	}
	if (i == INFINITE)
	{
		i = UniSearchStrEx(tmp, L"-CMD\t", 0, false);
		if (i != INFINITE && i >= 1 && tmp[i - 1] == L'-')
		{
			i = INFINITE;
		}
	}
	if (i == INFINITE)
	{
		i = UniSearchStrEx(tmp, L"-CMD:", 0, false);
		if (i != INFINITE && i >= 1 && tmp[i - 1] == L'-')
		{
			i = INFINITE;
		}
	}
	if (i == INFINITE)
	{
		i = UniSearchStrEx(tmp, L"-CMD=", 0, false);
		if (i != INFINITE && i >= 1 && tmp[i - 1] == L'-')
		{
			i = INFINITE;
		}
	}

	if (i != INFINITE)
	{
		char *s = CopyStr("CMD");
		if (InsertStr(o, s) == false)
		{
			Free(s);
		}
		if (UniStrCmpi(name, L"CMD") == 0)
		{
			ret = CopyUniStr(&str[i + 5]);
			UniTrim(ret);
		}
		else
		{
			tmp[i] = 0;
		}
	}

	if (ret == NULL)
	{
		t = UniParseCmdLine(tmp);

		if (t != NULL)
		{
			for (i = 0;i < t->NumTokens;i++)
			{
				wchar_t *token = t->Token[i];

				if ((token[0] == L'-' && token[1] != L'-') ||
					(UniStrCmpi(token, L"--help") == 0) ||
					(token[0] == L'/' && token[1] != L'/'))
				{
					UINT i;

					// Named parameter
					// Examine whether there is a colon character

					if (UniStrCmpi(token, L"--help") == 0)
					{
						token++;
					}

					i = UniSearchStrEx(token, L":", 0, false);
					if (i == INFINITE)
					{
						i = UniSearchStrEx(token, L"=", 0, false);
					}
					if (i != INFINITE)
					{
						wchar_t *tmp;
						char *a;

						// There is a colon character
						tmp = CopyUniStr(token);
						tmp[i] = 0;

						a = CopyUniToStr(&tmp[1]);
						if (InsertStr(o, a) == false)
						{
							Free(a);
						}

						if (UniStrCmpi(name, &tmp[1]) == 0)
						{
							if (ret == NULL)
							{
								// Content
								ret = UniCopyStr(&token[i + 1]);
							}
						}

						Free(tmp);
					}
					else
					{
						// There is no colon character
						char *a;

						a = CopyUniToStr(&token[1]);
						if (InsertStr(o, a) == false)
						{
							Free(a);
						}

						if (UniStrCmpi(name, &token[1]) == 0)
						{
							if (ret == NULL)
							{
								// Empty character
								ret = UniCopyStr(L"");
							}
						}
					}
				}
				else
				{
					// Nameless argument
					if (name == NULL)
					{
						if (ret == NULL)
						{
							if (token[0] == L'-' && token[1] == L'-')
							{
								ret = UniCopyStr(&token[1]);
							}
							else if (token[0] == L'/' && token[1] == L'/')
							{
								ret = UniCopyStr(&token[1]);
							}
							else
							{
								ret = UniCopyStr(token);
							}
						}
					}
				}
			}

			UniFreeToken(t);
		}
	}

	Free(tmp);

	if (o != NULL)
	{
		TOKEN_LIST *t = ZeroMalloc(sizeof(TOKEN_LIST));
		UINT i;

		t->NumTokens = LIST_NUM(o);
		t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);

		for (i = 0;i < t->NumTokens;i++)
		{
			t->Token[i] = LIST_DATA(o, i);
		}

		ReleaseList(o);

		*param_list = t;
	}

	if (UniStrCmpi(ret, L"none") == 0 || UniStrCmpi(ret, L"null") == 0)
	{
		// Null and none are reserved words
		ret[0] = 0;
	}

	return ret;
}
char *ParseCommandA(wchar_t *str, char *name)
{
	wchar_t *tmp1, *tmp2;
	char *ret;
	// Validate arguments
	if (str == NULL)
	{
		return NULL;
	}

	if (name != NULL)
	{
		tmp1 = CopyStrToUni(name);
	}
	else
	{
		tmp1 = NULL;
	}

	tmp2 = ParseCommand(str, tmp1);

	if (tmp2 == NULL)
	{
		ret = NULL;
	}
	else
	{
		ret = CopyUniToStr(tmp2);
		Free(tmp2);
	}

	Free(tmp1);

	return ret;
}

// Password prompt
bool PasswordPrompt(char *password, UINT size)
{
	UINT wp;
	bool escape = false;
	void *console;
	// Validate arguments
	if (password == NULL || size <= 1)
	{
		if (size >= 1)
		{
			password[0] = 0;
		}
		return false;
	}

	wp = 0;

	Zero(password, size);

	console = SetConsoleRaw();

	while (true)
	{
		int c;

#ifdef	OS_WIN32
		c = getch();
#else	// OS_WIN32
		c = getc(stdin);
#endif	// OS_WIN32

		if (c >= 0x20 && c <= 0x7E)
		{
			// Character
			if ((wp + 1) < size)
			{
				password[wp++] = (char)c;
				putc('*', stdout);
			}
		}
		else if (c == 0x03)
		{
			// Break
			exit(0);
		}
		else if (c == 0x04 || c == 0x1a || c == 0x0D || c==0x0A)
		{
			// Exit
			if (c == 0x04 || c == 0x1a)
			{
				escape = true;
			}
			break;
		}
		else if (c == 0xE0)
		{
			// Read one more character
			c = getch();
			if (c == 0x4B || c == 0x53)
			{
				// Backspace
				goto BACKSPACE;
			}
		}
		else if (c == 0x08)
		{
BACKSPACE:
			// Backspace
			if (wp >= 1)
			{
				password[--wp] = 0;
				putc(0x08, stdout);
				putc(' ', stdout);
				putc(0x08, stdout);
			}
		}
	}
	Print("\n");

	RestoreConsole(console);

	return (escape ? false : true);
}

// Show the prompt
wchar_t *Prompt(wchar_t *prompt_str)
{
	wchar_t *ret = NULL;
	wchar_t *tmp = NULL;
	// Validate arguments
	if (prompt_str == NULL)
	{
		prompt_str = L"";
	}

#ifdef	OS_WIN32
	UniPrint(L"%s", prompt_str);
	tmp = Malloc(MAX_PROMPT_STRSIZE);
	if (fgetws(tmp, MAX_PROMPT_STRSIZE - 1, stdin) != NULL)
	{
		bool escape = false;
		UINT i, len;

		len = UniStrLen(tmp);
		for (i = 0;i < len;i++)
		{
			if (tmp[i] == 0x04 || tmp[i] == 0x1A)
			{
				escape = true;
				break;
			}
		}

		if (escape == false)
		{
			UniTrimCrlf(tmp);

			ret = UniCopyStr(tmp);
		}
	}
	Free(tmp);
#else	// OS_WIN32
	{
		char *prompt = CopyUniToStr(prompt_str);
		char *s = readline(prompt);
		Free(prompt);

		if (s != NULL)
		{
			TrimCrlf(s);
			Trim(s);

			if (IsEmptyStr(s) == false)
			{
				add_history(s);
			}

			ret = CopyStrToUni(s);

			free(s);
		}
	}
#endif	// OS_WIN32

	if (ret == NULL)
	{
		Print("\n");
	}

	return ret;
}
char *PromptA(wchar_t *prompt_str)
{
	wchar_t *str = Prompt(prompt_str);

	if (str == NULL)
	{
		return NULL;
	}
	else
	{
		char *ret = CopyUniToStr(str);

		Free(str);
		return ret;
	}
}

// Set the console to raw mode
void *SetConsoleRaw()
{
#ifdef	OS_UNIX
	struct termios t, *ret;

	Zero(&t, sizeof(t));
	if (tcgetattr(0, &t) != 0)
	{
		// Failed
		return NULL;
	}

	// Copy the current settings
	ret = Clone(&t, sizeof(t));

	// Change the settings
	t.c_lflag &= (~ICANON);
	t.c_lflag &= (~ECHO);
	t.c_cc[VTIME] = 0;
	t.c_cc[VMIN] = 1;
	tcsetattr(0, TCSANOW, &t);

	return ret;
#else	// OS_UNIX
	return Malloc(0);
#endif	// OS_UNIX
}

// Restore the mode of the console
void RestoreConsole(void *p)
{
#ifdef	OS_UNIX
	struct termios *t;
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	t = (struct termios *)p;

	// Restore the settings
	tcsetattr(0, TCSANOW, t);

	Free(t);
#else	// OS_UNIX
	if (p != NULL)
	{
		Free(p);
	}
#endif	// OS_UNIX
}

////////////////////////////
// Local console function

// Creating a new local console
CONSOLE *NewLocalConsole(wchar_t *infile, wchar_t *outfile)
{
	IO *in_io = NULL, *out_io = NULL;
	CONSOLE *c = ZeroMalloc(sizeof(CONSOLE));
	LOCAL_CONSOLE_PARAM *p;
	UINT old_size = 0;

#ifdef	OS_WIN32
	if (MsGetConsoleWidth() == 80)
	{
		//old_size = MsSetConsoleWidth(WIN32_DEFAULT_CONSOLE_WIDTH);
	}
#endif	// OS_WIN32

	c->ConsoleType = CONSOLE_LOCAL;
	c->Free = ConsoleLocalFree;
	c->ReadLine = ConsoleLocalReadLine;
	c->ReadPassword = ConsoleLocalReadPassword;
	c->Write = ConsoleLocalWrite;
	c->GetWidth = ConsoleLocalGetWidth;

	if (UniIsEmptyStr(infile) == false)
	{
		// Input file is specified
		in_io = FileOpenW(infile, false);
		if (in_io == NULL)
		{
			wchar_t tmp[MAX_SIZE];

			UniFormat(tmp, sizeof(tmp), _UU("CON_INFILE_ERROR"), infile);
			c->Write(c, tmp);
			Free(c);
			return NULL;
		}
		else
		{
			wchar_t tmp[MAX_SIZE];

			UniFormat(tmp, sizeof(tmp), _UU("CON_INFILE_START"), infile);
			c->Write(c, tmp);
		}
	}

	if (UniIsEmptyStr(outfile) == false)
	{
		// Output file is specified
		out_io = FileCreateW(outfile);
		if (out_io == NULL)
		{
			wchar_t tmp[MAX_SIZE];

			UniFormat(tmp, sizeof(tmp), _UU("CON_OUTFILE_ERROR"), outfile);
			c->Write(c, tmp);
			Free(c);

			if (in_io != NULL)
			{
				FileClose(in_io);
			}
			return NULL;
		}
		else
		{
			wchar_t tmp[MAX_SIZE];

			UniFormat(tmp, sizeof(tmp), _UU("CON_OUTFILE_START"), outfile);
			c->Write(c, tmp);
		}
	}

	p = ZeroMalloc(sizeof(LOCAL_CONSOLE_PARAM));
	c->Param = p;

	p->InFile = in_io;
	p->OutFile = out_io;
	p->Win32_OldConsoleWidth = old_size;

	if (in_io != NULL)
	{
		UINT size;
		void *buf;

		size = FileSize(in_io);
		buf = ZeroMalloc(size + 1);
		FileRead(in_io, buf, size);

		p->InBuf = NewBuf();
		WriteBuf(p->InBuf, buf, size);
		Free(buf);

		p->InBuf->Current = 0;
	}

	return c;
}

// Release Console
void ConsoleLocalFree(CONSOLE *c)
{
	LOCAL_CONSOLE_PARAM *p;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	p = (LOCAL_CONSOLE_PARAM *)c->Param;

#ifdef	OS_WIN32
	if (p->Win32_OldConsoleWidth != 0)
	{
		MsSetConsoleWidth(p->Win32_OldConsoleWidth);
	}
#endif	// OS_WIN32

	if (p != NULL)
	{
		if (p->InFile != NULL)
		{
			FileClose(p->InFile);
			FreeBuf(p->InBuf);
		}

		if (p->OutFile != NULL)
		{
			FileClose(p->OutFile);
		}

		Free(p);
	}

	// Memory release
	Free(c);
}

// Get the width of the screen
UINT ConsoleLocalGetWidth(CONSOLE *c)
{
	UINT ret = 0;
	// Validate arguments
	if (c == NULL)
	{
		return 0;
	}

#ifdef	OS_WIN32
	ret = MsGetConsoleWidth();
#else	// OS_WIN32
	{
		struct winsize t;

		Zero(&t, sizeof(t));

		if (ioctl(1, TIOCGWINSZ, &t) == 0)
		{
			ret = t.ws_col;
		}
	}
#endif	// OS_WIN32

	return ret;
}

// Read one line from the console
wchar_t *ConsoleLocalReadLine(CONSOLE *c, wchar_t *prompt, bool nofile)
{
	wchar_t *ret;
	LOCAL_CONSOLE_PARAM *p;
	// Validate arguments
	if (c == NULL)
	{
		return NULL;
	}
	p = (LOCAL_CONSOLE_PARAM *)c->Param;
	if (prompt == NULL)
	{
		prompt = L">";
	}

	ConsoleWriteOutFile(c, prompt, false);

	if (nofile == false && p->InBuf != NULL)
	{
		// Read the next line from the file
		ret = ConsoleReadNextFromInFile(c);

		if (ret != NULL)
		{
			// Display the pseudo prompt
			UniPrint(L"%s", prompt);

			// Display on the screen
			UniPrint(L"%s\n", ret);
		}
	}
	else
	{
		// Read the following line from the console
		ret = Prompt(prompt);
	}

	if (ret != NULL)
	{
		ConsoleWriteOutFile(c, ret, true);
	}
	else
	{
		ConsoleWriteOutFile(c, _UU("CON_USER_CANCEL"), true);
	}

	return ret;
}

// Read the password from the console
char *ConsoleLocalReadPassword(CONSOLE *c, wchar_t *prompt)
{
	char tmp[64];
	// Validate arguments
	if (c == NULL)
	{
		return NULL;
	}
	if (prompt == NULL)
	{
		prompt = L"Password>";
	}

	UniPrint(L"%s", prompt);
	ConsoleWriteOutFile(c, prompt, false);

	if (PasswordPrompt(tmp, sizeof(tmp)))
	{
		ConsoleWriteOutFile(c, L"********", true);
		return CopyStr(tmp);
	}
	else
	{
		ConsoleWriteOutFile(c, _UU("CON_USER_CANCEL"), true);
		return NULL;
	}
}

// Display a string to the console
bool ConsoleLocalWrite(CONSOLE *c, wchar_t *str)
{
	// Validate arguments
	if (c == NULL || str == NULL)
	{
		return false;
	}

	UniPrint(L"%s%s", str, (UniEndWith(str, L"\n") ? L"" : L"\n"));

	ConsoleWriteOutFile(c, str, true);

	return true;
}

// Read the next line from the input file
wchar_t *ConsoleReadNextFromInFile(CONSOLE *c)
{
	LOCAL_CONSOLE_PARAM *p;
	char *str;
	// Validate arguments
	if (c == NULL)
	{
		return NULL;
	}

	p = (LOCAL_CONSOLE_PARAM *)c->Param;

	if (p->InBuf == NULL)
	{
		return NULL;
	}

	while (true)
	{
		str = CfgReadNextLine(p->InBuf);

		if (str == NULL)
		{
			return NULL;
		}

		Trim(str);

		if (IsEmptyStr(str) == false)
		{
			UINT size;
			wchar_t *ret;

			size = CalcUtf8ToUni((BYTE *)str, StrLen(str));
			ret = ZeroMalloc(size + 32);
			Utf8ToUni(ret, size, (BYTE *)str, StrLen(str));

			Free(str);

			return ret;
		}

		Free(str);
	}
}

// Write when the output file is specified
void ConsoleWriteOutFile(CONSOLE *c, wchar_t *str, bool add_last_crlf)
{
	LOCAL_CONSOLE_PARAM *p;
	// Validate arguments
	if (c == NULL || str == NULL)
	{
		return;
	}

	p = (LOCAL_CONSOLE_PARAM *)c->Param;

	if (p != NULL && p->OutFile != NULL)
	{
		wchar_t *tmp = UniNormalizeCrlf(str);
		UINT utf8_size;
		UCHAR *utf8;

		utf8_size = CalcUniToUtf8(tmp);
		utf8 = ZeroMalloc(utf8_size + 1);
		UniToUtf8(utf8, utf8_size + 1, tmp);

		FileWrite(p->OutFile, utf8, utf8_size);

		if (UniEndWith(str, L"\n") == false && add_last_crlf)
		{
			char *crlf = "\r\n";
			FileWrite(p->OutFile, "\r\n", StrLen(crlf));
		}

		Free(utf8);
		Free(tmp);
	}

}


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
