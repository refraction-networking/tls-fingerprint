
#include "postgres.h"
#include "fmgr.h"

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif


#define MIN3(a, b, c) ((a) < (b) ? ((a) < (c) ? (a) : (c)) : ((b) < (c) ? (b) : (c)))

int levenshtein_u8(uint8_t *s1, size_t s1len, uint8_t *s2, size_t s2len) {
    unsigned int x, y, lastdiag, olddiag;
    //s1len = strlen(s1);
    //s2len = strlen(s2);
    unsigned int column[s1len+1];
    column[0] = 0;
    for (y = 1; y <= s1len; y++)
        column[y] = y;
    for (x = 1; x <= s2len; x++) {
        column[0] = x;
        for (y = 1, lastdiag = x-1; y <= s1len; y++) {
            olddiag = column[y];
            column[y] = MIN3(column[y] + 1, column[y-1] + 1, lastdiag + (s1[y-1] == s2[x-1] ? 0 : 1));
            lastdiag = olddiag;
        }
    }
    return(column[s1len]);
}




int levenshtein_u16(uint16_t *s1, size_t s1len, uint16_t *s2, size_t s2len) {
    unsigned int x, y, lastdiag, olddiag;
    //s1len = strlen(s1);
    //s2len = strlen(s2);
    unsigned int column[s1len+1];
    column[0] = 0;
    for (y = 1; y <= s1len; y++)
        column[y] = y;
    for (x = 1; x <= s2len; x++) {
        column[0] = x;
        for (y = 1, lastdiag = x-1; y <= s1len; y++) {
            olddiag = column[y];
            column[y] = MIN3(column[y] + 1, column[y-1] + 1, lastdiag + (s1[y-1] == s2[x-1] ? 0 : 1));
            lastdiag = olddiag;
        }
    }
    return(column[s1len]);
}

// Prefix string: e.g. "026832 = "\x02" + "h2"
struct __attribute__((__packed__)) pstr {
    uint8_t len;
    uint8_t data[0];
};

// given "\x026832"
int pstr_cmp(struct pstr *p1, struct pstr *p2)
{
    if (p1->len != p2->len) {
        return 1;   // different (replacement cost)
    }
    if (memcmp(p1->data, p2->data, p1->len) == 0) {
        return 0;
    }
    return 1;
}

// s1/s2 are lists of prefix strings
// e.g. 026832 = "\x02" + "h2"
int levenshtein_pstr(struct pstr **s1, size_t s1len, struct pstr **s2, size_t s2len) {
    unsigned int x, y, lastdiag, olddiag;
    //s1len = strlen(s1);
    //s2len = strlen(s2);
    unsigned int column[s1len+1];
    column[0] = 0;
    for (y = 1; y <= s1len; y++)
        column[y] = y;
    for (x = 1; x <= s2len; x++) {
        column[0] = x;
        for (y = 1, lastdiag = x-1; y <= s1len; y++) {
            olddiag = column[y];
            column[y] = MIN3(column[y] + 1, column[y-1] + 1, lastdiag + pstr_cmp(s1[y-1], s2[x-1]));
            lastdiag = olddiag;
        }
    }
    return(column[s1len]);
}




PG_FUNCTION_INFO_V1(u8_lev);

Datum
u8_lev(PG_FUNCTION_ARGS)
{
    bytea  *arg1 = PG_GETARG_BYTEA_P(0);
    bytea  *arg2 = PG_GETARG_BYTEA_P(1);


    int ret = levenshtein_u8((uint8_t*)VARDATA(arg1), (VARSIZE(arg1)-VARHDRSZ),
                              (uint8_t*)VARDATA(arg2), (VARSIZE(arg2)-VARHDRSZ));

    PG_RETURN_INT32(ret);
}



PG_FUNCTION_INFO_V1(ipv4);
Datum
ipv4(PG_FUNCTION_ARGS)
{
    Oid addr = PG_GETARG_OID(0);

    text *result = (text *) palloc(20+VARHDRSZ);
    //VARATT_SIZEP(result) = 20+VARHDRSZ;
    SET_VARSIZE(result, 20+VARHDRSZ);

    snprintf((char *)VARDATA(result), 20, "%d.%d.%d.%d",
            ((addr >> 24) & 0xff),
            ((addr >> 16) & 0xff),
            ((addr >> 8) & 0xff),
            ((addr >> 0) & 0xff));
    PG_RETURN_TEXT_P(result);
}

PG_FUNCTION_INFO_V1(ipv4net);
Datum
ipv4net(PG_FUNCTION_ARGS)
{
    int16 net = PG_GETARG_INT16(0);

    text *result = (text *) palloc(20+VARHDRSZ);
    //VARATT_SIZEP(result) = 20+VARHDRSZ;
    SET_VARSIZE(result, 20+VARHDRSZ);

    snprintf((char *)VARDATA(result), 20, "%d.%d.0.0/16",
            ((net >> 8) & 0xff),
            ((net >> 0) & 0xff));
    PG_RETURN_TEXT_P(result);
}

PG_FUNCTION_INFO_V1(u16_lev);

Datum
u16_lev(PG_FUNCTION_ARGS)
{
    bytea  *arg1 = PG_GETARG_BYTEA_P(0);
    bytea  *arg2 = PG_GETARG_BYTEA_P(1);

    int ret = levenshtein_u16((uint16_t*)VARDATA(arg1), (VARSIZE(arg1)-VARHDRSZ)/2,
                              (uint16_t*)VARDATA(arg2), (VARSIZE(arg2)-VARHDRSZ)/2);

    PG_RETURN_INT32(ret);
}


// This function is the same as u16_lev, but it skips the first 2 bytes (header) of each bytea
PG_FUNCTION_INFO_V1(u16_lev_skiphdr);

Datum
u16_lev_skiphdr(PG_FUNCTION_ARGS)
{
    bytea  *arg1 = PG_GETARG_BYTEA_P(0);
    bytea  *arg2 = PG_GETARG_BYTEA_P(1);

    if ((VARSIZE(arg1)-VARHDRSZ) <= 2) {
        PG_RETURN_INT32((VARSIZE(arg2) - VARHDRSZ) / 2);
    } else if ((VARSIZE(arg2)-VARHDRSZ) <= 2) {
        PG_RETURN_INT32((VARSIZE(arg1) - VARHDRSZ) / 2);
    }

    int ret = levenshtein_u16(&((uint16_t*)VARDATA(arg1))[1], (VARSIZE(arg1)-VARHDRSZ-2)/2,
                              &((uint16_t*)VARDATA(arg2))[1], (VARSIZE(arg2)-VARHDRSZ-2)/2);

    PG_RETURN_INT32(ret);
}

PG_FUNCTION_INFO_V1(u16_lev_skipu8hdr);
Datum
u16_lev_skipu8hdr(PG_FUNCTION_ARGS)
{
    bytea *arg1 = PG_GETARG_BYTEA_P(0);
    bytea *arg2 = PG_GETARG_BYTEA_P(1);

    if ((VARSIZE(arg1)-VARHDRSZ) <= 1) {
        PG_RETURN_INT32((VARSIZE(arg2) - VARHDRSZ)/2);
    } else if ((VARSIZE(arg2)-VARHDRSZ) <= 1) {
        PG_RETURN_INT32((VARSIZE(arg1) - VARHDRSZ)/2);
    }
    int ret = levenshtein_u16((uint16_t*)&((uint8_t*)VARDATA(arg1))[1], (VARSIZE(arg1)-VARHDRSZ-1)/2,
                             (uint16_t*)&((uint8_t*)VARDATA(arg2))[2], (VARSIZE(arg2)-VARHDRSZ-1)/2);
    PG_RETURN_INT32(ret);
}



PG_FUNCTION_INFO_V1(u8_lev_skiphdr);
Datum
u8_lev_skiphdr(PG_FUNCTION_ARGS)
{
    bytea *arg1 = PG_GETARG_BYTEA_P(0);
    bytea *arg2 = PG_GETARG_BYTEA_P(1);

    if ((VARSIZE(arg1)-VARHDRSZ) <= 1) {
        PG_RETURN_INT32((VARSIZE(arg2) - VARHDRSZ));
    } else if ((VARSIZE(arg2)-VARHDRSZ) <= 1) {
        PG_RETURN_INT32((VARSIZE(arg1) - VARHDRSZ));
    }
    int ret = levenshtein_u8(&((uint8_t*)VARDATA(arg1))[1], (VARSIZE(arg1)-VARHDRSZ-1),
                             &((uint8_t*)VARDATA(arg2))[2], (VARSIZE(arg2)-VARHDRSZ-1));
    PG_RETURN_INT32(ret);
}

// Parses ba into ps
// E.g.
// 001b 08 687474702f312e31 08 737064792f332e31 05 68322d3134 02 6832
// becomes "http/1.1", "spdy/3.1", "h2-14", "h2"
// (in prefix-strings)
// We do this in place; ps is just a list of pointers; the prefix
// is in the data already for us.
// e.g. if ba starts at 0, ps will have [+2, +11, +20, +26]
// and returns 4.
// Returns number of elements written in ps
size_t pstr_parse(uint8_t *ba, size_t ba_len, struct pstr **ps, size_t ps_len)
{
    int i=0;
    if (ba_len <= 2) {
        return 0;   // Don't have enough for even header
    }
    uint8_t *ptr = ba;
    uint16_t tot_len = (ptr[0] << 8) | ptr[1];
    ptr += 2;   // Skip length header

    for (i=0; i<ps_len && (ptr-ba)<ba_len; i++) {
        ps[i] = (struct pstr*)(ptr);
        ptr += ps[i]->len + 1;
    }
    return i;
}

// Given two alpn lists, do lev dist between.
// Note: starts with length header, and each element has length header.
// E.g.
//  27     http/1.1            spdy/3.1            h2-14         h2
// 001b 08 687474702f312e31 08 737064792f332e31 05 68322d3134 02 6832
//
// We turn this into an array ["http/1.1", "spdy/3.1", "h2-14", "h2"]
// and take levenshtein over this list, e.g. ["spdy/3.1", "h2"]
// should have a distance of 2
PG_FUNCTION_INFO_V1(alpn_lev);
Datum
alpn_lev(PG_FUNCTION_ARGS)
{
    bytea *arg1 = PG_GETARG_BYTEA_P(0);
    bytea *arg2 = PG_GETARG_BYTEA_P(1);

    // Only parse first 8 ALPNs...
    struct pstr *p1[8];
    struct pstr *p2[8];

    // These return 0 if the ba_len is 0 (or less than header)
    size_t p1_len = pstr_parse(VARDATA(arg1), VARSIZE(arg1)-VARHDRSZ, p1, 8);
    size_t p2_len = pstr_parse(VARDATA(arg2), VARSIZE(arg2)-VARHDRSZ, p2, 8);

    int ret = levenshtein_pstr(p1, p1_len, p2, p2_len);

    PG_RETURN_INT32(ret);
}
