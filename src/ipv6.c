/****************************************************************************
 *
 * Copyright (C) 2007 Sourcefire, Inc.
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
 ****************************************************************************/
 
#include "debug.h"
#include "ipv6.h"
#include "snort.h"
#include "util.h"

static SFXHASH *ipv6_frag_hash = NULL;

void ipv6_cleanup()
{
    if (ipv6_frag_hash)
    {
        sfxhash_delete(ipv6_frag_hash);
        ipv6_frag_hash = NULL;
    }
}

void ipv6_init(int max)
{
    int rows = sfxhash_calcrows((int) (max * 1.4));

    ipv6_frag_hash = sfxhash_new( 
            /* one row per element in table, when possible */
            rows,
            36,      /* key size :  padded with zeros */
            4,       /* data size:  padded with zeros */
            /* Set max to the sizeof a hash node, plus the size of 
             * the stored data, plus the size of the key (32), plus
             * this size of a node pointer plus max rows plus 1. */
            max * (36 + sizeof(SFXHASH_NODE) + sizeof(u_int32_t) + sizeof(SFXHASH_NODE*)) 
                + (rows+1) * sizeof(SFXHASH_NODE*),   
            1,       /* enable AutoNodeRecovery */
            NULL, /* provide a function to let user know we want to kill a node */
            NULL, /* provide a function to release user memory */
            1);      /* Recycle nodes */

    if (!ipv6_frag_hash) {
        FatalError("could not allocate ipv6_frag_hash");
    }
}

int CheckIPV6Frag (char *data, u_int32_t size, Packet *p)
{
    IP6RawHdr *hdr;
    IP6Frag  *frag;
    IP6HdrChain *chain;
    u_int8_t next_header;
    u_int32_t offset;
    unsigned int header_length;
    unsigned short frag_data;
    char key[36]; /* Two 16 bit IP addresses and one fragmentation ID */
    SFXHASH_NODE *hash_node;

    if (sizeof(IP6RawHdr) > size)
        return IPV6_TRUNCATED;

    hdr = (IP6RawHdr *) data;

    if (sizeof(IP6RawHdr) + ntohs(hdr->ip6plen) > size)
        return IPV6_TRUNCATED;

    if(((hdr->ip6vfc & 0xf0) >> 4) != 6) 
    {
        return IPV6_IS_NOT;
    }

    /* Check TTL */
    if(hdr->ip6hops < pv.min_ttl) 
    {
        return IPV6_MIN_TTL_EXCEEDED;
    }

    next_header = hdr->ip6nxt;
    offset = sizeof(IP6RawHdr);

    while (offset < size)
    {
        switch (next_header) {
            case IP_PROTO_IPV6:
                return CheckIPV6Frag(data + offset, size - offset, p);
            case IP_PROTO_HOPOPTS:
            case IP_PROTO_ROUTING:
            case IP_PROTO_AH:
            case IP_PROTO_DSTOPTS:
                if (sizeof(IP6HdrChain) + offset > size)
                    return IPV6_TRUNCATED_EXT;

                chain = (IP6HdrChain* ) (data + offset);

                next_header     = chain->next_header;
                header_length   = 8 + (8 * chain->length);

                if (offset + header_length > size)
                    return IPV6_TRUNCATED_EXT;

                offset += header_length;
                break;

            case IP_PROTO_FRAGMENT:
                if (offset + sizeof(IP6Frag) > size)
                    return IPV6_TRUNCATED_EXT;

                frag = (IP6Frag *) (data + offset); 
                frag_data = frag->ip6f_offlg;

                /* srcip / dstip */
                memcpy(key, (data + 8), 32);
                *(u_int32_t*)(key+32) = frag->ip6f_ident;

                hash_node = sfxhash_find_node(ipv6_frag_hash, key);

                /* Check if the frag offset mask is set. 
                 * If it is, we're not looking at the exploit in question */
                if(frag_data & IP6F_OFF_MASK)
                {
                    /* If this arrives before the two 0 offset frags, we will
                     * still add them as though they were the first, and false
                     * positive */
                    if(hash_node) sfxhash_free_node(ipv6_frag_hash, hash_node);
                    return IPV6_FRAG_NO_ALERT;
                }

                /* Check if there are no more frags */
                if(!(frag_data & IP6F_MORE_FRAG))
                {
                    /* At this point, we've seen a frag header with no offset 
                     * that doesn't have the more flags set.  Need to see if 
                     * this follows a packet that did have the more flag set. */
                    if(hash_node)
                    {
                        /* Check if the first packet timed out */
                        if( (p->pkth->ts.tv_sec - *(u_int32_t*)hash_node->data)
                             > pv.ipv6_frag_timeout ) 
                        {
                            sfxhash_free_node(ipv6_frag_hash, hash_node);
                            return IPV6_FRAG_BAD_PKT;
                        }

                        if(size - offset > 100)
                        {
                            return IPV6_FRAG_ALERT;
                        }

                        sfxhash_free_node(ipv6_frag_hash, hash_node);
                         
                        return IPV6_FRAG_BAD_PKT;
                    }
                
                    /* We never saw the first packet, but this one is still bogus */
                    return IPV6_FRAG_BAD_PKT;
                }
                
                /* At this point, we've seen a header with no offset and a 
                 * more flag */
                if(!hash_node) 
                {
                    /* There are more frags remaining, add current to hash */
                    if(sfxhash_add(ipv6_frag_hash, key, &p->pkth->ts.tv_sec) 
                        == SFXHASH_NOMEM)
                    {
                        return -1;
                    }
                }
                else
                {
                    /* Update this node's timestamp */
                    *(u_int32_t*)hash_node->data = p->pkth->ts.tv_sec;
                }

            default:
                return IPV6_FRAG_NO_ALERT;
        }
    }

    return IPV6_FRAG_NO_ALERT;
}
