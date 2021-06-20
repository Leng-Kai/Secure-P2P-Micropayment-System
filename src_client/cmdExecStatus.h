#ifndef CMDEXECSTATUS_H
#define CMDEXECSTATUS_H

using namespace std;

enum CmdExecStatus
{
    CMD_EXEC_DONE  = 0,
    CMD_EXEC_ERROR = 1,
    CMD_EXEC_QUIT  = 2,
    CMD_EXEC_NOP   = 3,
    
    // dummy
    CMD_EXEC_TOT
};

#endif // CMDEXECSTATUS_H
