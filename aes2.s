  .text
  .globl _aes_refill
_aes_refill:
  movdqa (%rdx), %xmm8
  
  # rsi = iv high side
  movd %rsi, %xmm9
  pslldq $8, %xmm9
  pxor %xmm8, %xmm9
  
  movd %rdi, %xmm0
  pxor %xmm9, %xmm0
  incq %rdi
  movd %rdi, %xmm1
  pxor %xmm9, %xmm1
  incq %rdi
  movd %rdi, %xmm2
  pxor %xmm9, %xmm2
  incq %rdi
  movd %rdi, %xmm3
  pxor %xmm9, %xmm3
  incq %rdi
  movd %rdi, %xmm4
  pxor %xmm9, %xmm4
  incq %rdi
  movd %rdi, %xmm5
  pxor %xmm9, %xmm5
  incq %rdi
  movd %rdi, %xmm6
  pxor %xmm9, %xmm6
  incq %rdi
  movd %rdi, %xmm7
  pxor %xmm9, %xmm7
  
  mov $0x1, %rdi
  movd %edi, %xmm12
  
  mov $7, %rdi

  movdqa 0x10(%rdx), %xmm11
  
L.loop:
  aeskeygenassist $0, %xmm11, %xmm10
  aesenc %xmm11, %xmm0
  aesenc %xmm11, %xmm1
  aesenc %xmm11, %xmm2
  aesenc %xmm11, %xmm3
  aesenc %xmm11, %xmm4
  aesenc %xmm11, %xmm5
  aesenc %xmm11, %xmm6
  aesenc %xmm11, %xmm7
  pshufd $0xff, %xmm10, %xmm10
  
  pxor %xmm12, %xmm8
  pslld  $1, %xmm12
  movdqa %xmm8, %xmm9
  
  pslldq $4, %xmm9
  pxor   %xmm9, %xmm8
  pslldq $4, %xmm9
  pxor   %xmm9, %xmm8
  pslldq $4, %xmm9
  pxor   %xmm9, %xmm8
  
  pxor   %xmm10, %xmm8

  dec %rdi
  jz L.exit
  
  aeskeygenassist $0, %xmm8, %xmm10
  aesenc %xmm8, %xmm0
  aesenc %xmm8, %xmm1
  aesenc %xmm8, %xmm2
  aesenc %xmm8, %xmm3
  aesenc %xmm8, %xmm4
  aesenc %xmm8, %xmm5
  aesenc %xmm8, %xmm6
  aesenc %xmm8, %xmm7
  pshufd $0xaa, %xmm10, %xmm10
  
  movdqa %xmm11, %xmm9
  pslldq $4, %xmm9
  pxor   %xmm9, %xmm11
  pslldq $4, %xmm9
  pxor   %xmm9, %xmm11
  pslldq $4, %xmm9
  pxor   %xmm9, %xmm11
  
  pxor   %xmm10, %xmm11
  
  jmp L.loop
  
L.exit:
  aesenclast %xmm8, %xmm0
  movdqa %xmm0, (%rdx)
  aesenclast %xmm8, %xmm1
  movdqa %xmm1, 0x10(%rdx)
  aesenclast %xmm8, %xmm2
  movdqa %xmm2, 0x20(%rdx)
  aesenclast %xmm8, %xmm3
  movdqa %xmm3, 0x30(%rdx)
  aesenclast %xmm8, %xmm4
  movdqa %xmm4, 0x40(%rdx)
  aesenclast %xmm8, %xmm5
  movdqa %xmm5, 0x50(%rdx)
  aesenclast %xmm8, %xmm6
  movdqa %xmm6, 0x60(%rdx)
  aesenclast %xmm8, %xmm7
  movdqa %xmm7, 0x70(%rdx)
  
  ret
