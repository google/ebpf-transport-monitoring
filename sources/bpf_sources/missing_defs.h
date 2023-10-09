#ifndef _MISSING_DEFS_H_
#define _MISSING_DEFS_H_


#define AF_INET 2      /* Internet IP Protocol */
#define AF_INET6 10    /* IP version 6 */

static inline struct tcp_sock *tcp_sk(const struct sock *sk) {
  return (struct tcp_sock *)sk;
}

static inline struct inet_sock *inet_sk(const struct sock *sk) {
  return (struct inet_sock *)sk;
}

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define SK_FL_PROTO_SHIFT 16
#define SK_FL_PROTO_MASK 0x00ff0000

#define SK_FL_TYPE_SHIFT 0
#define SK_FL_TYPE_MASK 0x0000ffff

#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define SK_FL_PROTO_SHIFT 8
#define SK_FL_PROTO_MASK 0x0000ff00

#define SK_FL_TYPE_SHIFT 16
#define SK_FL_TYPE_MASK 0xffff0000
#else
#error "Fix your compiler's __BYTE_ORDER__?!"
#endif
#endif  // _MISSING_DEFS_H_
