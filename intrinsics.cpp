#include "intrinsics.h"

unsigned int crandom_features = 0;

unsigned int crandom_detect_features() {
  unsigned int out = 0;
  
# if (defined(__i386__) || defined(__x86_64__))
    u_int32_t a,b,c,d;
    
    a=1; asm("cpuid" : "+a"(a), "=b"(b), "=c"(c), "=d"(d));
    out |= GEN;
    if (d & 1<<26) out |= SSE2;
    if (d & 1<< 9) out |= SSSE3;
    if (c & 1<<25) out |= AESNI;
    
    a=0x80000001; asm("cpuid" : "+a"(a), "=b"(b), "=c"(c), "=d"(d));
    if (c & 1<<11) out |= XOP;
# endif
  
  return out;
}