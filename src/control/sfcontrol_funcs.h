#ifndef __SF_CONTROL_FUNCS_H__
#define __SF_CONTROL_FUNCS_H__

#include "sfcontrol.h"

void ControlSocketConfigureDirectory(const char *optarg);
void ControlSocketInit(void);
void ControlSocketCleanUp(void);
int ControlSocketRegisterHandler(uint16_t type, OOBPreControlFunc oobpre, IBControlFunc ib,
                                 OOBPostControlFunc oobpost);

#ifdef CONTROL_SOCKET
void ControlSocketDoWork(int idle);
#else
#define ControlSocketDoWork(idle)   do {} while(0)
#endif

#endif

