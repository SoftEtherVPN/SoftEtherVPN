// SoftEther VPN Source Code - Developer Edition Master Branch
// VPN Driver Installer

// List of test functions
typedef void (TEST_PROC)(UINT num, char **arg);

typedef struct TEST_LIST
{
	char *command_str;
	TEST_PROC *proc;
} TEST_LIST;

// function prototypes
void disablevlan(UINT num, char **arg);
void enablevlan(UINT num, char **arg);
void instvlan(UINT num, char **arg);
void upgradevlan(UINT num, char **arg);
void uninstvlan(UINT num, char **arg);

void MainFunction(char *cmd);
int PASCAL WinMain(HINSTANCE hInst, HINSTANCE hPrev, char *CmdLine, int CmdShow);


