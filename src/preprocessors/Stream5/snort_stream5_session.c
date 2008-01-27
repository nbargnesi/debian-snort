/* $Id$ */

/*
** Copyright (C) 2005 Sourcefire, Inc.
** AUTHOR: Steven Sturges <ssturges@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* snort_stream5_session.c
 * 
 * Purpose: Hash Table implementation of session management functions for
 *          Stream5 preprocessor.
 *
 * Arguments:
 *   
 * Effect:
 *
 * Comments:
 *
 * Any comments?
 *
 */

#include "decode.h"
#include "debug.h"
#include "log.h"
#include "util.h"
#include "snort_stream5_session.h"

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include "bitop_funcs.h"
extern unsigned int giFlowbitSize;

void PrintSessionKey(SessionKey *skey)
{
    LogMessage("SessionKey:\n");
    LogMessage("    ip_l     = 0x%08X\n", skey->ip_l);
    LogMessage("    ip_h     = 0x%08X\n", skey->ip_h);
    LogMessage("    prt_l    = %d\n", skey->port_l);
    LogMessage("    prt_h    = %d\n", skey->port_h);
    LogMessage("    vlan_tag = %d\n", skey->vlan_tag); 
}

int GetLWSessionCount(Stream5SessionCache *sessionCache)
{
    if (sessionCache && sessionCache->hashTable)
        return sessionCache->hashTable->count;
    else
        return 0;
}

int GetLWSessionKey(Packet *p, SessionKey *key)
{
    u_int16_t sport;
    u_int16_t dport;

    /* Because the key is going to be used for hash lookups,
     * the lower of the values of the IP address field is
     * stored in the key->ip_l and the port for that ip is
     * stored in key->port_l.
     */

    if (!key)
        return 0;

    switch (p->iph->ip_proto)
    {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
            sport = p->sp;
            dport = p->dp;
            break;
        case IPPROTO_ICMP:
        default:
            sport = dport = 0;
            break;
    }
    
    if (p->iph->ip_src.s_addr < p->iph->ip_dst.s_addr)
    {
        key->ip_l = p->iph->ip_src.s_addr;
        key->port_l = sport;
        key->ip_h = p->iph->ip_dst.s_addr;
        key->port_h = dport;
    }
    else if (p->iph->ip_src.s_addr == p->iph->ip_dst.s_addr)
    {
        key->ip_l = p->iph->ip_src.s_addr;
        key->ip_h = p->iph->ip_dst.s_addr;
        if (sport < dport)
        {
            key->port_l = sport;
            key->port_h = dport;
        }
        else
        {
            key->port_l = dport;
            key->port_h = sport;
        }
    }
    else
    {
        key->ip_l = p->iph->ip_dst.s_addr;
        key->port_l = dport;
        key->ip_h = p->iph->ip_src.s_addr;
        key->port_h = sport;
    }

    key->protocol = p->iph->ip_proto;

    if (p->vh)
        key->vlan_tag = (u_int16_t)VTH_VLAN(p->vh);
    else
        key->vlan_tag = 0;

    key->pad = 0;

    return 1;
}

void GetLWPacketDirection(Packet *p, Stream5LWSession *ssn)
{
    if (p->iph->ip_src.s_addr == ssn->client_ip)
    {
        if (p->iph->ip_proto == IPPROTO_TCP)
        {
            if (p->tcph->th_sport == ssn->client_port)
            {
                p->packet_flags |= PKT_FROM_CLIENT;
            }
            else
            {
                p->packet_flags |= PKT_FROM_SERVER;
            }
        }
        else if (p->iph->ip_proto == IPPROTO_UDP)
        {
            if (p->udph->uh_sport == ssn->client_port)
            {
                p->packet_flags |= PKT_FROM_CLIENT;
            }
            else
            {
                p->packet_flags |= PKT_FROM_SERVER;
            }
        }
        else if (p->iph->ip_proto == IPPROTO_ICMP)
        {
            p->packet_flags |= PKT_FROM_CLIENT;
        }
    }
    else if (p->iph->ip_dst.s_addr == ssn->client_ip)
    {
        if  (p->iph->ip_proto == IPPROTO_TCP)
        {
            if (p->tcph->th_dport == ssn->client_port)
            {
                p->packet_flags |= PKT_FROM_SERVER;
            }
            else
            {
                p->packet_flags |= PKT_FROM_CLIENT;
            }
        }
        else if (p->iph->ip_proto == IPPROTO_UDP)
        {
            if (p->udph->uh_dport == ssn->client_port)
            {
                p->packet_flags |= PKT_FROM_SERVER;
            }
            else
            {
                p->packet_flags |= PKT_FROM_CLIENT;
            }
        }
        else if (p->iph->ip_proto == IPPROTO_ICMP)
        {
            p->packet_flags |= PKT_FROM_CLIENT;
        }
    }
    else
    {
        /* Uh, no match of the packet to the session. */
        /* Probably should log an error */
    }
}

Stream5LWSession *GetLWSession(Stream5SessionCache *sessionCache, Packet *p, SessionKey *key)
{
    Stream5LWSession *returned = NULL;
    SFXHASH_NODE *hnode;

    if (!GetLWSessionKey(p, key))
        return NULL;

    hnode = sfxhash_find_node(sessionCache->hashTable, key);

    if (hnode && hnode->data)
    {
        /* This is a unique hnode, since the sfxhash finds the
         * same key before returning this node.
         */
        returned = (Stream5LWSession *)hnode->data;
        if (returned && (returned->last_data_seen < p->pkth->ts.tv_sec))
        {
            returned->last_data_seen = p->pkth->ts.tv_sec;
        }
    }
    return returned;
}

Stream5LWSession *GetLWSessionFromKey(Stream5SessionCache *sessionCache, SessionKey *key)
{
    Stream5LWSession *returned = NULL;
    SFXHASH_NODE *hnode;

    hnode = sfxhash_find_node(sessionCache->hashTable, key);

    if (hnode && hnode->data)
    {
        /* This is a unique hnode, since the sfxhash finds the
         * same key before returning this node.
         */
        returned = (Stream5LWSession *)hnode->data;
    }
    return returned;
}

void FreeLWApplicationData(Stream5LWSession *ssn)
{
    Stream5AppData *tmpData, *appData = ssn->appDataList;
    while (appData)
    {
        if (appData->freeFunc && appData->dataPointer)
        {
            appData->freeFunc(appData->dataPointer);
        }

        tmpData = appData->next;
        free(appData);
        appData = tmpData;
    }

    ssn->appDataList = NULL;
}

int RemoveLWSession(Stream5SessionCache *sessionCache, Stream5LWSession *ssn)
{
    mempool_free(&s5FlowMempool, ssn->flowdata);
    ssn->flowdata = NULL;
    return sfxhash_remove(sessionCache->hashTable, &(ssn->key));
}

int DeleteLWSession(Stream5SessionCache *sessionCache,
                   Stream5LWSession *ssn)
{
    /* 
     * Call callback to cleanup the protocol (TCP/UDP/ICMP)
     * specific session details
     */
    if (sessionCache->cleanup_fcn)
        sessionCache->cleanup_fcn(ssn);

    FreeLWApplicationData(ssn);

    return RemoveLWSession(sessionCache, ssn);
}

int PurgeLWSessionCache(Stream5SessionCache *sessionCache)
{
    int retCount = 0;
    Stream5LWSession *idx;
    SFXHASH_NODE *hnode;

    if (!sessionCache)
        return 0;

    /* Remove all sessions from the hash table. */
    hnode = sfxhash_mru_node(sessionCache->hashTable);
    while (hnode)
    {
        idx = (Stream5LWSession *)hnode->data;
        if (!idx)
        {
            sfxhash_free_node(sessionCache->hashTable, hnode);
        }
        else
        {
            idx->session_flags |= SSNFLAG_PRUNED;
            DeleteLWSession(sessionCache, idx);
        }
        hnode = sfxhash_mru_node(sessionCache->hashTable);
        retCount++;
    }
    sfxhash_delete(sessionCache->hashTable);
    free(sessionCache);

    return retCount;
}

int PruneLWSessionCache(Stream5SessionCache *sessionCache,
                   u_int32_t thetime,
                   Stream5LWSession *save_me,
                   int memCheck)
{
    Stream5LWSession *idx;
    u_int32_t pruned = 0;

    if (thetime != 0)
    {
        /* Pruning, look for sessions that have time'd out */
        char got_one;
        idx = (Stream5LWSession *) sfxhash_lru(sessionCache->hashTable);

        if(idx == NULL)
        {
            return 0;
        }

        do
        {
            got_one = 0;            
            if(idx == save_me)
            {
                SFXHASH_NODE *lastNode = sfxhash_lru_node(sessionCache->hashTable);
                sfxhash_gmovetofront(sessionCache->hashTable, lastNode);
                lastNode = sfxhash_lru_node(sessionCache->hashTable);
                if ((lastNode) && (lastNode->data != idx))
                {
                    idx = (Stream5LWSession *)lastNode->data;
                    continue;
                }
                else
                {
                    return pruned;
                }
            }

            if((idx->last_data_seen+sessionCache->timeout) < thetime)
            {
                Stream5LWSession *savidx = idx;

                if(sfxhash_count(sessionCache->hashTable) > 1)
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "pruning stale session\n"););
                    savidx->session_flags |= SSNFLAG_TIMEDOUT;
                    DeleteLWSession(sessionCache, savidx);
                    idx = (Stream5LWSession *) sfxhash_lru(sessionCache->hashTable);
                    pruned++;
                    got_one = 1;
                }
                else
                {
                    savidx->session_flags |= SSNFLAG_TIMEDOUT;
                    DeleteLWSession(sessionCache, savidx);
                    pruned++;
                    return pruned;
                }
            }
            else
            {
                return pruned;
            }

            if (pruned > sessionCache->cleanup_sessions)
            {
                /* Don't bother cleaning more than 'n' at a time */
                break;
            }
        } while ((idx != NULL) && (got_one == 1));

        return pruned;
    }
    else
    {
        /* Free up 'n' sessions at a time until we get under the
         * memcap or free enough sessions to be able to create
         * new ones.
         */
         unsigned int session_count;
#define s5_sessions_in_table() \
     ((session_count = sfxhash_count(sessionCache->hashTable)) > 1)
#define s5_over_session_limit() \
     (session_count > (sessionCache->max_sessions - sessionCache->cleanup_sessions))
#define s5_havent_pruned_yet() \
     (pruned == 0)
#define s5_over_memcap() \
     (s5_global_config.mem_in_use > s5_global_config.memcap)

        while (s5_sessions_in_table() &&
               ((!memCheck && (s5_over_session_limit() || s5_havent_pruned_yet())) ||
               (memCheck && s5_over_memcap() )))
        {
            unsigned int i;
            DEBUG_WRAP(
                DebugMessage(DEBUG_STREAM,
                    "S5: Pruning session cache by %d ssns for %s: %d/%d\n",
                    sessionCache->cleanup_sessions,
                    memCheck ? "memcap" : "hash limit",
                    s5_global_config.mem_in_use, 
                    s5_global_config.memcap););
            
            idx = (Stream5LWSession *) sfxhash_lru(sessionCache->hashTable);

            for (i=0;i<sessionCache->cleanup_sessions && 
                     (sfxhash_count(sessionCache->hashTable) >= 1); i++)
            {
                if(idx != save_me)
                {
                    idx->session_flags |= SSNFLAG_PRUNED;
                    DeleteLWSession(sessionCache, idx);
                    pruned++;
                    idx = (Stream5LWSession *) sfxhash_lru(sessionCache->hashTable);
                }
                else
                {
                    SFXHASH_NODE *lastNode = sfxhash_lru_node(sessionCache->hashTable);
                    sfxhash_gmovetofront(sessionCache->hashTable, lastNode);
                    lastNode = sfxhash_lru_node(sessionCache->hashTable);
                    if ((lastNode) && (lastNode->data == idx))
                    {
                        /* Okay, this session is the only one left */
                        break;
                    }
                    idx = (Stream5LWSession *) sfxhash_lru(sessionCache->hashTable);
                    i--; /* Didn't clean this one */
                }
            }

            /* Nothing (or the one we're working with) in table, couldn't 
             * kill it */
            if (!memCheck && (pruned == 0))
            {
                break;
            }
        }
    }
    if (memCheck && pruned)
    {
        LogMessage("S5: Pruned %d sessions from cache. %d ssns for memcap: %d/%d\n",
            pruned, sfxhash_count(sessionCache->hashTable),
            s5_global_config.mem_in_use, 
            s5_global_config.memcap);
        DEBUG_WRAP(
            if (sfxhash_count(sessionCache->hashTable) == 1)
            {
                DebugMessage(DEBUG_STREAM, "S5: Pruned, one session remains\n");
            }
        );
    }
    return pruned;
}

Stream5LWSession *NewLWSession(Stream5SessionCache *sessionCache, Packet *p, SessionKey *key)
{
    Stream5LWSession *retSsn = NULL;
    SFXHASH_NODE *hnode;
    StreamFlowData *flowdata;

    hnode = sfxhash_get_node(sessionCache->hashTable, key);
    if (!hnode)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "HashTable full, clean it\n"););
        if (!PruneLWSessionCache(sessionCache, p->pkth->ts.tv_sec, NULL, 0))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "HashTable full, no timeouts, clean it\n"););
            PruneLWSessionCache(sessionCache, 0, NULL, 0);
        }

        /* Should have some freed nodes now */
        hnode = sfxhash_get_node(sessionCache->hashTable, key);
#ifdef DEBUG
        if (!hnode)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Problem, no freed nodes\n"););
        }
#endif
    }
    if (hnode && hnode->data)
    {
        retSsn = hnode->data;

        /* Zero everything out */
        memset(retSsn, 0, sizeof(Stream5LWSession));

        /* Save the session key for future use */
        memcpy(&(retSsn->key), key, sizeof(SessionKey));

        retSsn->protocol = key->protocol;
        retSsn->last_data_seen = p->pkth->ts.tv_sec;
        retSsn->flowdata = mempool_alloc(&s5FlowMempool);
        flowdata = retSsn->flowdata->data;
        boInitStaticBITOP(&(flowdata->boFlowbits), giFlowbitSize,
                flowdata->flowb);
    }
    return retSsn;
}

Stream5SessionCache *InitLWSessionCache(int max_sessions,
                                        u_int32_t session_timeout,
                                        u_int32_t cleanup_sessions,
                                        u_int32_t cleanup_percent,
                                        Stream5SessionCleanup cleanup_fcn)
{
    Stream5SessionCache *sessionCache = NULL;
    /* Rule of thumb, size should be 1.4 times max to avoid
     * collisions.
     */
    int hashTableSize = sfxhash_calcrows((int) (max_sessions * 1.4));
    /* Memory required for 1 node: LW Session + Session Key +
     * Node + NodePtr.
     */
    //int maxSessionMem = max_sessions * (
    //                        sizeof(Stream5LWSession) +
    //                        sizeof(SFXHASH_NODE) +
    //                        sizeof(SessionKey) +
    //                        sizeof(SFXHASH_NODE *));
    /* Memory required for table entries */
    //int tableMem = (hashTableSize +1) * sizeof(SFXHASH_NODE*);

    sessionCache = SnortAlloc(sizeof(Stream5SessionCache));
    if (sessionCache)
    {
        sessionCache->timeout = session_timeout;
        sessionCache->max_sessions = max_sessions;
        if (cleanup_percent)
        {
            sessionCache->cleanup_sessions = max_sessions * cleanup_percent/100;
        }
        else
        {
            sessionCache->cleanup_sessions = cleanup_sessions;
        }
        if (sessionCache->cleanup_sessions == 0)
        {
            sessionCache->cleanup_sessions = 1;
        }
        sessionCache->cleanup_fcn = cleanup_fcn;

        /* Okay, now create the table */
        sessionCache->hashTable = sfxhash_new(
            hashTableSize,
            sizeof(SessionKey),
            sizeof(Stream5LWSession),
            //maxSessionMem + tableMem, 0, NULL, NULL, 1);
            0, 0, NULL, NULL, 1);

        sfxhash_set_max_nodes(sessionCache->hashTable, max_sessions);
    }

    return sessionCache;
}

void PrintLWSessionCache(Stream5SessionCache *sessionCache)
{
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "%lu sessions active\n", 
                            sfxhash_count(sessionCache->hashTable)););
}

