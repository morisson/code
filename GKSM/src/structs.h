#ifndef _GKSM_STRUCTS_H
#define _GKSM_STRUCTS_H

/*
 * structure with user ID an Port number
 *  it can bind to.
 *  TODO: protocol (STREAM/DGRAM)
 */
typedef struct gksm_up {
        uid_t uid;
        unsigned short port;
} t_gksm_up;


/*
 * Structure with configuration
 * options, with linked list for 
 * uid/port privileges
 *
 */
typedef struct gksm_opts_t {
   t_ptr *privlst;
} t_gksm_opts;


/* IOCTL commands definition
 */
#define GKSM_ADDUIDPORT 0x1
#define GKSM_DELUIDPORT 0x2
#endif
