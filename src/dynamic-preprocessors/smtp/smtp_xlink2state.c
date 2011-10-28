/*
 * smtp_xlink2state.c
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
 * Copyright (C) 2005 Sourcefire Inc.
 *
 * Author: Andy  Mullican
 *
 * Description:
 *
 * This file handles the X-Link2State vulnerability.
 *
 * Entry point function:
 *
 *    ParseXLink2State()
 *
 *
 */

#ifndef WIN32
#include <strings.h>
#endif

#include <ctype.h>

#include "snort_packet_header.h"

#include "snort_smtp.h"
#include "smtp_util.h"
#include "smtp_xlink2state.h"

extern SMTP         *_smtp;
extern SMTP_CONFIG   _smtp_config;

#define XLINK_OTHER     1
#define XLINK_FIRST     2
#define XLINK_CHUNK     3

#define XLINK_LEN      12   /* strlen("X-LINK2STATE") */

/* Prototypes */
static u_int32_t get_xlink_hex_value(u_int8_t *buf, u_int8_t *end);
static char      get_xlink_keyword(u_int8_t *ptr, u_int8_t *end);

/*
 * Extract a number from a string
 *
 * @param   buf         pointer to beginning of buffer to parse
 * @param   end         end pointer of buffer to parse
 *
 * @return  unsigned long   value of number extracted          
 *
 * @note    this could be more efficient, but the search buffer should be pretty short
 */
static u_int32_t get_xlink_hex_value(u_int8_t *buf, u_int8_t *end)
{
    char       c;
    u_int32_t  value = 0;
    u_int8_t *hex_end;

    if ((end - buf) < 8)
        return 0;

    hex_end = buf + 8;

    while (buf < hex_end)
    {
        c = toupper((int)*buf);

        /* Make sure it is a number or hex char; if not return with what we have */
        if (isdigit((int)c))
        {
            c = c - '0';
        }
        else if (c >= 'A' && c <= 'F')
        {
            c = (c - 'A') + 10;
        }
        else
        {
            return value;
        }

        value = (value * 16) + c;

        buf++;
    }

    return value;
}

/*
 * Check for X-LINK2STATE keywords FIRST or CHUNK
 *   
 *
 * @param   x           pointer to "X-LINK2STATE" in buffer
 * @param   x_len       length of buffer after x
 *
 * @retval  int         identifies which keyword found, if any
 */
static char get_xlink_keyword(u_int8_t *ptr, u_int8_t *end)
{
    int len;

    if (ptr == NULL || end == NULL)
        return XLINK_OTHER;

    ptr += XLINK_LEN;
    if (ptr >= end)
        return XLINK_OTHER;

    /* Skip over spaces */
    while (ptr < end && isspace((int)*ptr))
    {
        ptr++;
    }

    len = end - ptr;

    if (len > 5 && strncasecmp((const char *)ptr, "FIRST", 5) == 0) 
    {
        return XLINK_FIRST;
    }
    else if (len > 5 && strncasecmp((const char *)ptr, "CHUNK", 5) == 0)
    {
        return XLINK_CHUNK;
    }

    return XLINK_OTHER;
}


/*
 * Handle X-Link2State vulnerability
 *   
 *  From Lurene Grenier:
 
    The X-LINK2STATE command always takes the following form:

    X-LINK2STATE [FIRST|NEXT|LAST] CHUNK=<SOME DATA>

    The overwrite occurs when three criteria are met:

    No chunk identifier exists - ie neither FIRST, NEXT, or LAST are specified
    No previous FIRST chunk was sent
    <SOME DATA> has a length greater than 520 bytes

    Normally you send a FIRST chunk, then some intermediary chunks marked with
    either NEXT or not marked, then finally a LAST chunk.  If no first chunk is
    sent, and a chunk with no specifier is sent, it assumes it must append to
    something, but it has nothing to append to, so an overwrite occurs. Sending out
    of order chunks WITH specifiers results in an exception.

    So simply:

    if (gotFirstChunk)
        next; # chunks came with proper first chunk specified
    if (/X-LINK2STATE [FIRST|NEXT|LAST] CHUNK/) {
        if (/X-LINK2STATE FIRST CHUNK/) gotFirstChunk = TRUE;
        next; # some specifier is marked 
    }
    if (chunkLen > 520)
       attempt = TRUE; # Gotcha!

    Usually it takes more than one unspecified packet in a row, but I think this is
    just a symptom of the fact that we're triggering a heap overwrite, and not a
    condition of the bug. However, if we're still getting FPs this might be an
    avenue to try.

 *
 * @param   p           standard Packet structure
 * @param   x           pointer to "X-LINK2STATE" in buffer
 *
 * @retval  1           if alert raised
 * @retval  0           if no alert raised
 */
int ParseXLink2State(SFSnortPacket *p, u_int8_t *ptr)
{
    u_int8_t  *lf = NULL;
    u_int32_t  len = 0;
    char       x_keyword;
    u_int8_t  *end;

    if (p == NULL || ptr == NULL)
        return 0;

    /* If we got a FIRST chunk on this stream, this is not an exploit */
    if (_smtp->xlink2state_gotfirstchunk)
        return 0;

    /* Calculate length from pointer to end of packet data */
    end = p->payload + p->payload_size;
    if (ptr >= end)
        return 0;

    /* Check for "FIRST" or "CHUNK" after X-LINK2STATE */
    x_keyword = get_xlink_keyword(ptr, end);
    if (x_keyword != XLINK_CHUNK)
    {
        if (x_keyword == XLINK_FIRST)
            _smtp->xlink2state_gotfirstchunk = 1;

        return 0;
    }

    ptr = (u_int8_t *)safe_strchr((char *)ptr, '=', end - ptr);
    if (ptr == NULL)
        return 0;

    /* move past '=' and make sure we're within bounds */
    ptr++;
    if (ptr >= end)
        return 0;

    /*  Look for one of two patterns:
     *
     *  ... CHUNK={0000006d} MULTI (5) ({00000000051} ...
     *  ... CHUNK=AAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n
     */

    if (*ptr == '{')
    {
        /* move past '{' and make sure we're within bounds */
        ptr++;
        if ((ptr + 8) >= end)
            return 0;

        /* Get length - can we always trust it? */
        len = get_xlink_hex_value(ptr, end);
    }
    else
    {
        lf = (u_int8_t *)safe_strchr((char *)ptr, '\n', end - ptr);
        if (lf == NULL)
            return 0;

        len = lf - ptr;
    }

    if ( len > XLINK2STATE_MAX_LEN )
    {
        /* Need to drop the packet if we're told to
         * and we're inline mode (outside of whether its
         * thresholded). */
        if (_smtp_config.drop_xlink2state && _dpd.inlineMode())
        {
            _dpd.inlineDrop(p);
        }

        _dpd.alertAdd(GENERATOR_SMTP, 1, 1, 0, 3, "X-Link2State command: attempted buffer overflow", 0);
        _smtp->xlink2state_alerted = 1;

        return 1;
    }

    /* Check for more than one command in packet */
    ptr = (u_int8_t *)safe_strchr((char *)ptr, '\n', end - ptr);
    if (ptr == NULL)
        return 0;

    /* move past '\n' */
    ptr++;

    if (ptr < end)
    {
        ParseXLink2State(p, ptr);
    }

    return 0;
}

