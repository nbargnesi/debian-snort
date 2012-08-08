/****************************************************************************
 * Copyright (C) 2008-2012 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 ****************************************************************************
 * 
 ****************************************************************************/

#ifndef SPP_DCE2_H
#define SPP_DCE2_H

/********************************************************************
 * Externs
 ********************************************************************/
#ifdef PERF_PROFILING
#include "profiler.h"
extern PreprocStats dce2_pstat_main;
extern PreprocStats dce2_pstat_session;
extern PreprocStats dce2_pstat_new_session;
extern PreprocStats dce2_pstat_session_state;
extern PreprocStats dce2_pstat_detect;
extern PreprocStats dce2_pstat_log;
extern PreprocStats dce2_pstat_smb_seg;
extern PreprocStats dce2_pstat_smb_req;
extern PreprocStats dce2_pstat_smb_uid;
extern PreprocStats dce2_pstat_smb_tid;
extern PreprocStats dce2_pstat_smb_fid;
extern PreprocStats dce2_pstat_smb_fingerprint;
extern PreprocStats dce2_pstat_smb_negotiate;
extern PreprocStats dce2_pstat_co_seg;
extern PreprocStats dce2_pstat_co_frag;
extern PreprocStats dce2_pstat_co_reass;
extern PreprocStats dce2_pstat_co_ctx;
extern PreprocStats dce2_pstat_cl_acts;
extern PreprocStats dce2_pstat_cl_frag;
extern PreprocStats dce2_pstat_cl_reass;
#endif

#endif  /* SPP_DCE2_H */

