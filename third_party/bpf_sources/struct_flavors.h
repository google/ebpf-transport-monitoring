#ifndef SOURCES_BPF_SOURCES_STRUCT_FLAVORS_H_
#define SOURCES_BPF_SOURCES_STRUCT_FLAVORS_H_

// This is a a libbpf struct flavors mechanism. Please refer
// https://nakryiko.com/posts/bpf-portability-and-co-re/

struct sock___old {
  struct sock_common __sk_common;
  unsigned int __sk_flags_offset[0];
  unsigned int sk_padding : 1, sk_kern_sock : 1, sk_no_check_tx : 1,
      sk_no_check_rx : 1, sk_userlocks : 4, sk_protocol : 8, sk_type : 16;
  u16 sk_gso_max_segs;
};

struct iov_iter___old {
  u8 iter_type;
  bool nofault;
  bool data_source;
  bool user_backed;
  union {
    size_t iov_offset;
    int last_offset;
  };
  size_t count;
  const struct iovec *iov;
};

#endif
