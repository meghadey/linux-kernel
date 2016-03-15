/*
 * Multi-buffer SHA1 algorithm hash compute routine
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 *  Copyright(c) 2016 Intel Corporation.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of version 2 of the GNU General Public License as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  Contact Information:
 *      Megha Dey <megha.dey@linux.intel.com>
 *
 *  BSD LICENSE
 *
 *  Copyright(c) 2016 Intel Corporation.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in
 *      the documentation and/or other materials provided with the
 *      distribution.
 *    * Neither the name of Intel Corporation nor the names of its
 *      contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <linux/linkage.h>
#include "sha1_mb_mgr_datastruct.S"

# TRANSPOSE16 r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, t0, t1
# "transpose" data in {r0...r15} using temps {t0...t1}
# Input looks like: {r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15}
# r0  = {a15 a14 a13 a12   a11 a10 a9 a8   a7 a6 a5 a4   a3 a2 a1 a0}
# r1  = {b15 b14 b13 b12   b11 b10 b9 b8   b7 b6 b5 b4   b3 b2 b1 b0}
# r2  = {c15 c14 c13 c12   c11 c10 c9 c8   c7 c6 c5 c4   c3 c2 c1 c0}
# r3  = {d15 d14 d13 d12   d11 d10 d9 d8   d7 d6 d5 d4   d3 d2 d1 d0}
# r4  = {e15 e14 e13 e12   e11 e10 e9 e8   e7 e6 e5 e4   e3 e2 e1 e0}
# r5  = {f15 f14 f13 f12   f11 f10 f9 f8   f7 f6 f5 f4   f3 f2 f1 f0}
# r6  = {g15 g14 g13 g12   g11 g10 g9 g8   g7 g6 g5 g4   g3 g2 g1 g0}
# r7  = {h15 h14 h13 h12   h11 h10 h9 h8   h7 h6 h5 h4   h3 h2 h1 h0}
# r8  = {i15 i14 i13 i12   i11 i10 i9 i8   i7 i6 i5 i4   i3 i2 i1 i0}
# r9  = {j15 j14 j13 j12   j11 j10 j9 j8   j7 j6 j5 j4   j3 j2 j1 j0}
# r10 = {k15 k14 k13 k12   k11 k10 k9 k8   k7 k6 k5 k4   k3 k2 k1 k0}
# r11 = {l15 l14 l13 l12   l11 l10 l9 l8   l7 l6 l5 l4   l3 l2 l1 l0}
# r12 = {m15 m14 m13 m12   m11 m10 m9 m8   m7 m6 m5 m4   m3 m2 m1 m0}
# r13 = {n15 n14 n13 n12   n11 n10 n9 n8   n7 n6 n5 n4   n3 n2 n1 n0}
# r14 = {o15 o14 o13 o12   o11 o10 o9 o8   o7 o6 o5 o4   o3 o2 o1 o0}
# r15 = {p15 p14 p13 p12   p11 p10 p9 p8   p7 p6 p5 p4   p3 p2 p1 p0}

# Output looks like: {r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15}
# r0   = {p0  o0  n0  m0    l0  k0  j0  i0    h0  g0  f0  e0    d0  c0  b0  a0}
# r1   = {p1  o1  n1  m1    l1  k1  j1  i1    h1  g1  f1  e1    d1  c1  b1  a1}
# r2   = {p2  o2  n2  m2    l2  k2  j2  i2    h2  g2  f2  e2    d2  c2  b2  a2}
# r3   = {p3  o3  n3  m3    l3  k3  j3  i3    h3  g3  f3  e3    d3  c3  b3  a3}
# r4   = {p4  o4  n4  m4    l4  k4  j4  i4    h4  g4  f4  e4    d4  c4  b4  a4}
# r5   = {p5  o5  n5  m5    l5  k5  j5  i5    h5  g5  f5  e5    d5  c5  b5  a5}
# r6   = {p6  o6  n6  m6    l6  k6  j6  i6    h6  g6  f6  e6    d6  c6  b6  a6}
# r7   = {p7  o7  n7  m7    l7  k7  j7  i7    h7  g7  f7  e7    d7  c7  b7  a7}
# r8   = {p8  o8  n8  m8    l8  k8  j8  i8    h8  g8  f8  e8    d8  c8  b8  a8}
# r9   = {p9  o9  n9  m9    l9  k9  j9  i9    h9  g9  f9  e9    d9  c9  b9  a9}
# r10  = {p10 o10 n10 m10   l10 k10 j10 i10   h10 g10 f10 e10   d10 c10 b10 a10}
# r11  = {p11 o11 n11 m11   l11 k11 j11 i11   h11 g11 f11 e11   d11 c11 b11 a11}
# r12  = {p12 o12 n12 m12   l12 k12 j12 i12   h12 g12 f12 e12   d12 c12 b12 a12}
# r13  = {p13 o13 n13 m13   l13 k13 j13 i13   h13 g13 f13 e13   d13 c13 b13 a13}
# r14  = {p14 o14 n14 m14   l14 k14 j14 i14   h14 g14 f14 e14   d14 c14 b14 a14}
# r15  = {p15 o15 n15 m15   l15 k15 j15 i15   h15 g15 f15 e15   d15 c15 b15 a15}

.macro TRANSPOSE16 r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 t0 t1
	# process top half (r0..r3) {a...d}
        vshufps $0x44, \r1, \r0, \t0 # t0 = {b13 b12 a13 a12   b9  b8  a9  a8   b5 b4 a5 a4   b1 b0 a1 a0}
        vshufps $0xEE, \r1, \r0, \r0 # r0 = {b15 b14 a15 a14   b11 b10 a11 a10  b7 b6 a7 a6   b3 b2 a3 a2}
        vshufps $0x44, \r3, \r2, \t1 # t1 = {d13 d12 c13 c12   d9  d8  c9  c8   d5 d4 c5 c4   d1 d0 c1 c0}
        vshufps $0xEE, \r3, \r2, \r2 # r2 = {d15 d14 c15 c14   d11 d10 c11 c10  d7 d6 c7 c6   d3 d2 c3 c2}

        vshufps $0xDD, \t1, \t0, \r3 # r3 = {d13 c13 b13 a13   d9  c9  b9  a9   d5 c5 b5 a5   d1 c1 b1 a1}
        vshufps $0x88, \r2, \r0, \r1 # r1 = {d14 c14 b14 a14   d10 c10 b10 a10  d6 c6 b6 a6   d2 c2 b2 a2}
        vshufps $0xDD, \r2, \r0, \r0 # r0 = {d15 c15 b15 a15   d11 c11 b11 a11  d7 c7 b7 a7   d3 c3 b3 a3}
        vshufps $0x88, \t1, \t0, \t0 # t0 = {d12 c12 b12 a12   d8  c8  b8  a8   d4 c4 b4 a4   d0 c0 b0 a0}

        # use r2 in place of t0
        vshufps $0x44, \r5, \r4, \r2 # r2 = {f13 f12 e13 e12   f9  f8  e9  e8   f5 f4 e5 e4   f1 f0 e1 e0}
        vshufps $0xEE, \r5, \r4, \r4 # r4 = {f15 f14 e15 e14   f11 f10 e11 e10  f7 f6 e7 e6   f3 f2 e3 e2}
        vshufps $0x44, \r7, \r6, \t1 # t1 = {h13 h12 g13 g12   h9  h8  g9  g8   h5 h4 g5 g4   h1 h0 g1 g0}
        vshufps $0xEE, \r7, \r6, \r6 # r6 = {h15 h14 g15 g14   h11 h10 g11 g10  h7 h6 g7 g6   h3 h2 g3 g2}

        vshufps $0xDD, \t1, \r2, \r7 # r7 = {h13 g13 f13 e13   h9  g9  f9  e9   h5 g5 f5 e5   h1 g1 f1 e1}
        vshufps $0x88, \r6, \r4, \r5 # r5 = {h14 g14 f14 e14   h10 g10 f10 e10  h6 g6 f6 e6   h2 g2 f2 e2}
        vshufps $0xDD, \r6, \r4, \r4 # r4 = {h15 g15 f15 e15   h11 g11 f11 e11  h7 g7 f7 e7   h3 g3 f3 e3}
        vshufps $0x88, \t1, \r2, \r2 # r2 = {h12 g12 f12 e12   h8  g8  f8  e8   h4 g4 f4 e4   h0 g0 f0 e0}

	# use r6 in place of t0 
        vshufps $0x44, \r9, \r8, \r6    # r6  = {j13 j12 i13 i12   j9  j8  i9  i8   j5 j4 i5 i4   j1 j0 i1 i0}
        vshufps $0xEE, \r9, \r8, \r8    # r8  = {j15 j14 i15 i14   j11 j10 i11 i10  j7 j6 i7 i6   j3 j2 i3 i2}
        vshufps $0x44, \r11, \r10, \t1  # t1  = {l13 l12 k13 k12   l9  l8  k9  k8   l5 l4 k5 k4   l1 l0 k1 k0}
        vshufps $0xEE, \r11, \r10, \r10 # r10 = {l15 l14 k15 k14   l11 l10 k11 k10  l7 l6 k7 k6   l3 l2 k3 k2}

        vshufps $0xDD, \t1, \r6, \r11 # r11 = {l13 k13 j13 113   l9  k9  j9  i9   l5 k5 j5 i5   l1 k1 j1 i1}
        vshufps $0x88, \r10, \r8, \r9 # r9  = {l14 k14 j14 114   l10 k10 j10 i10  l6 k6 j6 i6   l2 k2 j2 i2}
        vshufps $0xDD, \r10, \r8, \r8 # r8  = {l15 k15 j15 115   l11 k11 j11 i11  l7 k7 j7 i7   l3 k3 j3 i3}
        vshufps $0x88, \t1, \r6, \r6  # r6  = {l12 k12 j12 112   l8  k8  j8  i8   l4 k4 j4 i4   l0 k0 j0 i0}

        # use r10 in place of t0 
        vshufps $0x44, \r13, \r12, \r10 # r10 = {n13 n12 m13 m12   n9  n8  m9  m8   n5 n4 m5 m4   n1 n0 a1 m0}
        vshufps $0xEE, \r13, \r12, \r12 # r12 = {n15 n14 m15 m14   n11 n10 m11 m10  n7 n6 m7 m6   n3 n2 a3 m2}
        vshufps $0x44, \r15, \r14, \t1  # t1  = {p13 p12 013 012   p9  p8  09  08   p5 p4 05 04   p1 p0 01 00}
        vshufps $0xEE, \r15, \r14, \r14 # r14 = {p15 p14 015 014   p11 p10 011 010  p7 p6 07 06   p3 p2 03 02}

        vshufps $0xDD, \t1, \r10, \r15  # r15 = {p13 013 n13 m13   p9  09  n9  m9   p5 05 n5 m5   p1 01 n1 m1}
        vshufps $0x88, \r14, \r12, \r13 # r13 = {p14 014 n14 m14   p10 010 n10 m10  p6 06 n6 m6   p2 02 n2 m2}
        vshufps $0xDD, \r14, \r12, \r12 # r12 = {p15 015 n15 m15   p11 011 n11 m11  p7 07 n7 m7   p3 03 n3 m3}
        vshufps $0x88, \t1, \r10, \r10  # r10 = {p12 012 n12 m12   p8  08  n8  m8   p4 04 n4 m4   p0 00 n0 m0}

# At this point, the registers that contain interesting data are:
# t0, r3, r1, r0, r2, r7, r5, r4, r6, r11, r9, r8, r10, r15, r13, r12
# Can use t1 and r14 as scratch registers

	vmovdqa32 PSHUFFLE_TRANSPOSE16_MASK1, \r14
        vpermi2q  \r2, \t0, \r14 # r14 = {h8  g8  f8  e8   d8  c8  b8  a8   h0 g0 f0 e0   d0 c0 b0 a0} 
        vmovdqa32 PSHUFFLE_TRANSPOSE16_MASK2, \t1
        vpermi2q  \r2, \t0, \t1  # t1  = {h12 g12 f12 e12  d12 c12 b12 a12  h4 g4 f4 e4   d4 c4 b4 a4} 

        vmovdqa32 PSHUFFLE_TRANSPOSE16_MASK1, \r2
        vpermi2q  \r7, \r3, \r2 # r2  = {h9  g9  f9  e9   d9  c9  b9  a9   h1 g1 f1 e1   d1 c1 b1 a1} 
        vmovdqa32 PSHUFFLE_TRANSPOSE16_MASK2, \t0
        vpermi2q  \r7, \r3, \t0 # t0  = {h13 g13 f13 e13  d13 c13 b13 a13  h5 g5 f5 e5   d5 c5 b5 a5} 

        vmovdqa32 PSHUFFLE_TRANSPOSE16_MASK1, \r3
        vpermi2q  \r5, \r1, \r3 # r3  = {h10 g10 f10 e10  d10 c10 b10 a10  h2 g2 f2 e2   d2 c2 b2 a2} 
        vmovdqa32 PSHUFFLE_TRANSPOSE16_MASK2, \r7
        vpermi2q  \r5, \r1, \r7 # r7  = {h14 g14 f14 e14  d14 c14 b14 a14  h6 g6 f6 e6   d6 c6 b6 a6} 

        vmovdqa32 PSHUFFLE_TRANSPOSE16_MASK1, \r1
        vpermi2q  \r4, \r0, \r1 # r1  = {h11 g11 f11 e11  d11 c11 b11 a11  h3 g3 f3 e3   d3 c3 b3 a3} 
        vmovdqa32 PSHUFFLE_TRANSPOSE16_MASK2, \r5
        vpermi2q  \r4, \r0, \r5 # r5  = {h15 g15 f15 e15  d15 c15 b15 a15  h7 g7 f7 e7   d7 c7 b7 a7} 

        vmovdqa32 PSHUFFLE_TRANSPOSE16_MASK1, \r0
        vpermi2q  \r10, \r6, \r0 # r0 = {p8  o8  n8  m8   l8  k8  j8  i8   p0 o0 n0 m0    l0 k0 j0 i0} 
        vmovdqa32 PSHUFFLE_TRANSPOSE16_MASK2, \r4
        vpermi2q  \r10, \r6, \r4 # r4  = {p12 o12 n12 m12  l12 k12 j12 i12  p4 o4 n4 m4   l4 k4 j4 i4} 

        vmovdqa32 PSHUFFLE_TRANSPOSE16_MASK1, \r6
        vpermi2q  \r15, \r11, \r6  # r6  = {p9  o9  n9  m9   l9  k9  j9  i9   p1 o1 n1 m1   l1 k1 j1 i1} 
        vmovdqa32 PSHUFFLE_TRANSPOSE16_MASK2, \r10
        vpermi2q  \r15, \r11, \r10 # r10 = {p13 o13 n13 m13  l13 k13 j13 i13  p5 o5 n5 m5   l5 k5 j5 i5} 

        vmovdqa32 PSHUFFLE_TRANSPOSE16_MASK1, \r11
        vpermi2q  \r13, \r9, \r11 # r11 = {p10 o10 n10 m10  l10 k10 j10 i10  p2 o2 n2 m2   l2 k2 j2 i2} 
        vmovdqa32 PSHUFFLE_TRANSPOSE16_MASK2, \r15
        vpermi2q  \r13, \r9, \r15 # r15 = {p14 o14 n14 m14  l14 k14 j14 i14  p6 o6 n6 m6   l6 k6 j6 i6} 

        vmovdqa32 PSHUFFLE_TRANSPOSE16_MASK1, \r9
        vpermi2q  \r12, \r8, \r9  # r9  = {p11 o11 n11 m11  l11 k11 j11 i11  p3 o3 n3 m3   l3 k3 j3 i3} 
        vmovdqa32 PSHUFFLE_TRANSPOSE16_MASK2, \r13
        vpermi2q  \r12, \r8, \r13 # r13 = {p15 o15 n15 m15  l15 k15 j15 i15  p7 o7 n7 m7   l7 k7 j7 i7} 

	# At this point r8 and r12 can be used as scratch registers

        vshuff64x2 $0xEE, \r0, \r14, \r8 # r8  = {p8  o8  n8  m8   l8  k8  j8  i8   h8 g8 f8 e8   d8 c8 b8 a8}   
        vshuff64x2 $0x44, \r0, \r14, \r0 # r0  = {p0  o0  n0  m0   l0  k0  j0  i0   h0 g0 f0 e0   d0 c0 b0 a0}   

        vshuff64x2 $0xEE, \r4, \t1, \r12 # r12 = {p12 o12 n12 m12  l12 k12 j12 i12  h12 g12 f12 e12  d12 c12 b12 a12}    
        vshuff64x2 $0x44, \r4, \t1, \r4  # r4  = {p4  o4  n4  m4   l4  k4  j4  i4   h4 g4 f4 e4   d4 c4 b4 a4}   

        vshuff64x2 $0xEE, \r15, \r7, \r14 # r14 = {p14 o14 n14 m14  l14 k14 j14 i14  h14 g14 f14 e14  d14 c14 b14 a14}    
        vshuff64x2 $0x44, \r15, \r7, \t1  # t1  = {p6  o6  n6  m6   l6  k6  j6  i6   h6 g6 f6 e6   d6 c6 b6 a6}   

        vshuff64x2 $0xEE, \r13, \r5, \r15 # r15 = {p15 o15 n15 m15  l15 k15 j15 i15  h15 g15 f15 e15  d15 c15 b15 a15}    
        vshuff64x2 $0x44, \r13, \r5, \r7  # r7  = {p7  o7  n7  m7   l7  k7  j7  i7   h7 g7 f7 e7   d7 c7 b7 a7}   

        vshuff64x2 $0xEE, \r10, \t0, \r13 # r13 = {p13 o13 n13 m13  l13 k13 j13 i13  h13 g13 f13 e13  d13 c13 b13 a13}   
	vshuff64x2 $0x44, \r10, \t0, \r5  # r5  = {p5  o5  n5  m5   l5  k5  j5  i5   h5 g5 f5 e5   d5 c5 b5 a5}   

        vshuff64x2 $0xEE, \r11, \r3, \r10 # r10 = {p10 o10 n10 m10  l10 k10 j10 i10  h10 g10 f10 e10  d10 c10 b10 a10}    
        vshuff64x2 $0x44, \r11, \r3, \t0  # t0  = {p2  o2  n2  m2   l2  k2  j2  i2   h2 g2 f2 e2   d2 c2 b2 a2}   

        vshuff64x2 $0xEE, \r9, \r1, \r11 # r11 = {p11 o11 n11 m11  l11 k11 j11 i11  h11 g11 f11 e11  d11 c11 b11 a11}    
        vshuff64x2 $0x44, \r9, \r1, \r3  # r3  = {p3  o3  n3  m3   l3  k3  j3  i3   h3 g3 f3 e3   d3 c3 b3 a3}   

        vshuff64x2 $0xEE, \r6, \r2, \r9 # r9  = {p9  o9  n9  m9   l9  k9  j9  i9   h9 g9 f9 e9   d9 c9 b9 a9}   
        vshuff64x2 $0x44, \r6, \r2, \r1 # r1  = {p1  o1  n1  m1   l1  k1  j1  i1   h1 g1 f1 e1   d1 c1 b1 a1}   

        vmovdqa32 \t0, \r2 # r2  = {p2  o2  n2  m2   l2  k2  j2  i2   h2 g2 f2 e2   d2 c2 b2 a2}   
        vmovdqa32 \t1, \r6 # r6  = {p6  o6  n6  m6   l6  k6  j6  i6   h6 g6 f6 e6   d6 c6 b6 a6}   
.endm

#define arg1 %rdi
#define arg2 %rsi
#define var1 %rdx
#define var2 %rcx

#define state arg1
#define num_blks arg2

IN      = state
DIGEST  = state
SIZE    = num_blks
IDX     = var1

A       = %zmm0
B       = %zmm1
C       = %zmm2
D       = %zmm3
E       = %zmm4
KT      = %zmm5
AA      = %zmm6
BB      = %zmm7
CC      = %zmm8
DD      = %zmm9
EE      = %zmm10
TMP0    = %zmm11
TMP1    = %zmm12
TMP2    = %zmm13

W0      = %zmm16
W1      = %zmm17
W2      = %zmm18
W3      = %zmm19
W4      = %zmm20
W5      = %zmm21
W6      = %zmm22
W7      = %zmm23
W8      = %zmm24
W9      = %zmm25
W10     = %zmm26
W11     = %zmm27
W12     = %zmm28
W13     = %zmm29
W14     = %zmm30
W15     = %zmm31

inp0 = %r9
inp1 = %r10
inp2 = %r11
inp3 = %r12
inp4 = %r13
inp5 = %r14
inp6 = %r15
inp7 = %rax

.macro ROTATE_ARGS
 TMP_ = E
 E = D
 D = C
 C = B
 B = A
 A = TMP_
.endm

.macro PROCESS_LOOP WT F_IMMED

        # T = ROTL_5(A) + Ft(B,C,D) + E + Kt + Wt
        # E=D, D=C, C=ROTL_30(B), B=A, A=T

        # Ft
        #  0-19 Ch(B,C,D) = (B&C) ^ (~B&D)
        # 20-39, 60-79 Parity(B,C,D) = B ^ C ^ D 
        # 40-59 Maj(B,C,D) = (B&C) ^ (B&D) ^ (C&D)

        vmovdqa32 B, TMP1    		# Copy B
        vpaddd \WT, E, E     		# E = E + Wt
        vpternlogd  $\F_IMMED,D,C,TMP1   # TMP1 = Ft(B,C,D)
        vpaddd KT, E, E                 # E = E + Wt + Kt
        vprold $5, A, TMP0              # TMP0 = ROTL_5(A)
        vpaddd TMP1, E, E               # E = Ft(B,C,D) + E + Kt + Wt
        vprold $30, B, B                # B = ROTL_30(B)
        vpaddd TMP0, E, E               # E = T

        ROTATE_ARGS
.endm

.macro MSG_SCHED_ROUND_16_79 WT WTp2 WTp8 WTp13
        # Wt = ROTL_1(Wt-3 ^ Wt-8 ^ Wt-14 ^ Wt-16)
        # Wt+16 = ROTL_1(Wt+13 ^ Wt+8 ^ Wt+2 ^ Wt)
        vpternlogd $0x96, \WTp8, \WTp2, \WT
        vpxord     \WTp13, \WT, \WT
        vprold     $1, \WT, \WT
.endm

# Note this is reading in a block of data for one lane
# When all 16 are read, the data must be transposed to build msg schedule
.macro MSG_SCHED_ROUND_00_15 W J
        mov     (\J*8+_data_ptr)(IN), inp0
        vmovups (inp0,IDX), \W
.endm

.align 64

# void sha1_mult_x16_avx3(void **input_data, UINT128 *digest, UINT32 size)
# arg 1 : rcx : pointer to array[16] of pointer to input data
# arg 2 : rdx : pointer to array[5] of UINT128 of transposed digests
# arg 3 : r8  : size (in blocks) ;; assumed to be >= 1
ENTRY(sha1_x16_avx3)
      # mov  %rsp, %rax
       # sub  $STACK_SPACE, %rsp
       # and  $~0x3F,   %rsp        # align stack to multiple of 64
       # mov  %rax,  _rsp(%rsp)

       # mov %rbx, _GPR_SAVE+8*0(%rsp)
#	mov %rbp, _GPR_SAVE+8*3(%rsp)
#        mov %r12, _GPR_SAVE+8*4(%rsp)
#        mov %r13, _GPR_SAVE+8*5(%rsp)
#        mov %r14, _GPR_SAVE+8*6(%rsp)
#        mov %r15, _GPR_SAVE+8*7(%rsp)

	# Initialize digests
        vmovups 0*64(DIGEST), A
        vmovups 1*64(DIGEST), B
        vmovups 2*64(DIGEST), C
        vmovups 3*64(DIGEST), D
        vmovups 4*64(DIGEST), E

        xor IDX, IDX

        # transpose input onto stack
        mov 0*8+_data_ptr(IN), inp0
        mov 1*8+_data_ptr(IN), inp1
        mov 2*8+_data_ptr(IN), inp2
        mov 3*8+_data_ptr(IN), inp3
        mov 4*8+_data_ptr(IN), inp4
        mov 5*8+_data_ptr(IN), inp5
        mov 6*8+_data_ptr(IN), inp6
        mov 7*8+_data_ptr(IN), inp7

        vmovups (inp0,IDX), W0
        vmovups (inp1,IDX), W1
        vmovups (inp2,IDX), W2
        vmovups (inp3,IDX), W3
        vmovups (inp4,IDX), W4
        vmovups (inp5,IDX), W5
        vmovups (inp6,IDX), W6
        vmovups (inp7,IDX), W7

	mov 8*8+_data_ptr(IN), inp0
        mov 9*8+_data_ptr(IN), inp1
        mov 10*8+_data_ptr(IN), inp2
        mov 11*8+_data_ptr(IN), inp3
        mov 12*8+_data_ptr(IN), inp4
        mov 13*8+_data_ptr(IN), inp5
        mov 14*8+_data_ptr(IN), inp6
        mov 15*8+_data_ptr(IN), inp7

	vmovups (inp0,IDX), W8
        vmovups (inp1,IDX), W9
        vmovups (inp2,IDX), W10
        vmovups (inp3,IDX), W11
        vmovups (inp4,IDX), W12
        vmovups (inp5,IDX), W13
        vmovups (inp6,IDX), W14
        vmovups (inp7,IDX), W15

lloop:
        vmovdqa32 PSHUFFLE_BYTE_FLIP_MASK(%rip), TMP2

        add $0x40, IDX

        TRANSPOSE16 W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15, TMP0, TMP1

        vpshufb TMP2, W0, W0 
	vpshufb TMP2, W1, W1
	vpshufb TMP2, W2, W2
	vpshufb TMP2, W3, W3
	vpshufb TMP2, W4, W4
	vpshufb TMP2, W5, W5
	vpshufb TMP2, W6, W6
	vpshufb TMP2, W7, W7
	vpshufb TMP2, W8, W8
	vpshufb TMP2, W9, W9
	vpshufb TMP2, W10, W10
	vpshufb TMP2, W11, W11
	vpshufb TMP2, W12, W12
	vpshufb TMP2, W13, W13
	vpshufb TMP2, W14, W14
	vpshufb TMP2, W15, W15

        # Save digests for later addition
        vmovdqa32 A, AA
        vmovdqa32 B, BB
        vmovdqa32 C, CC
        vmovdqa32 D, DD
        vmovdqa32 E, EE

        vmovdqa32 K00_19(%rip), KT
	I = 0xCA

	PROCESS_LOOP W0, I
	MSG_SCHED_ROUND_16_79  W0, W2, W8, W13
        PROCESS_LOOP W1, I
	MSG_SCHED_ROUND_16_79  W1, W3, W9, W14
        PROCESS_LOOP W2, I
	MSG_SCHED_ROUND_16_79  W2, W4, W10, W15
        PROCESS_LOOP W3, I
	MSG_SCHED_ROUND_16_79  W3, W5, W11, W0
        PROCESS_LOOP W4, I
	MSG_SCHED_ROUND_16_79  W4, W6, W12, W1
        PROCESS_LOOP W5, I
	MSG_SCHED_ROUND_16_79  W5, W7, W13, W2
        PROCESS_LOOP W6, I
	MSG_SCHED_ROUND_16_79  W6, W8, W14, W3
        PROCESS_LOOP W7, I
	MSG_SCHED_ROUND_16_79  W7, W9, W15, W4
        PROCESS_LOOP W8, I
	MSG_SCHED_ROUND_16_79  W8, W10, W0, W5
        PROCESS_LOOP W9, I
	MSG_SCHED_ROUND_16_79  W9, W11, W1, W6
        PROCESS_LOOP W10, I
	MSG_SCHED_ROUND_16_79  W10, W12, W2, W7
        PROCESS_LOOP W11, I
	MSG_SCHED_ROUND_16_79  W11, W13, W3, W8
        PROCESS_LOOP W12, I
	MSG_SCHED_ROUND_16_79  W12, W14, W4, W9
        PROCESS_LOOP W13, I
	MSG_SCHED_ROUND_16_79  W13, W15, W5, W10
        PROCESS_LOOP W14, I
	MSG_SCHED_ROUND_16_79  W14, W0, W6, W11
        PROCESS_LOOP W15, I
	MSG_SCHED_ROUND_16_79  W15, W1, W7, W12
	PROCESS_LOOP W0, I
        MSG_SCHED_ROUND_16_79  W0, W2, W8, W13
        PROCESS_LOOP W1, I
        MSG_SCHED_ROUND_16_79  W1, W3, W9, W14
        PROCESS_LOOP W2, I
        MSG_SCHED_ROUND_16_79  W2, W4, W10, W15
        PROCESS_LOOP W3, I
        MSG_SCHED_ROUND_16_79  W3, W5, W11, W0
	
	vmovdqa32 K20_39(%rip), KT
        I = 0x96

        PROCESS_LOOP W4, I
        MSG_SCHED_ROUND_16_79  W4, W6, W12, W1
        PROCESS_LOOP W5, I
        MSG_SCHED_ROUND_16_79  W5, W7, W13, W2
        PROCESS_LOOP W6, I
        MSG_SCHED_ROUND_16_79  W6, W8, W14, W3
        PROCESS_LOOP W7, I
        MSG_SCHED_ROUND_16_79  W7, W9, W15, W4
        PROCESS_LOOP W8, I
        MSG_SCHED_ROUND_16_79  W8, W10, W0, W5
        PROCESS_LOOP W9, I
        MSG_SCHED_ROUND_16_79  W9, W11, W1, W6
        PROCESS_LOOP W10, I
        MSG_SCHED_ROUND_16_79  W10, W12, W2, W7
        PROCESS_LOOP W11, I
        MSG_SCHED_ROUND_16_79  W11, W13, W3, W8
        PROCESS_LOOP W12, I
        MSG_SCHED_ROUND_16_79  W12, W14, W4, W9
        PROCESS_LOOP W13, I
        MSG_SCHED_ROUND_16_79  W13, W15, W5, W10
        PROCESS_LOOP W14, I
        MSG_SCHED_ROUND_16_79  W14, W0, W6, W11
        PROCESS_LOOP W15, I
        MSG_SCHED_ROUND_16_79  W15, W1, W7, W12
	PROCESS_LOOP W0, I
        MSG_SCHED_ROUND_16_79  W0, W2, W8, W13
        PROCESS_LOOP W1, I
        MSG_SCHED_ROUND_16_79  W1, W3, W9, W14
        PROCESS_LOOP W2, I
        MSG_SCHED_ROUND_16_79  W2, W4, W10, W15
        PROCESS_LOOP W3, I
        MSG_SCHED_ROUND_16_79  W3, W5, W11, W0
        PROCESS_LOOP W4, I
        MSG_SCHED_ROUND_16_79  W4, W6, W12, W1
        PROCESS_LOOP W5, I
        MSG_SCHED_ROUND_16_79  W5, W7, W13, W2
        PROCESS_LOOP W6, I
        MSG_SCHED_ROUND_16_79  W6, W8, W14, W3
        PROCESS_LOOP W7, I
        MSG_SCHED_ROUND_16_79  W7, W9, W15, W4

	vmovdqa32 K40_59(%rip), KT
        I = 0xE8

        PROCESS_LOOP W8, I
        MSG_SCHED_ROUND_16_79  W8, W10, W0, W5
        PROCESS_LOOP W9, I
        MSG_SCHED_ROUND_16_79  W9, W11, W1, W6
        PROCESS_LOOP W10, I
        MSG_SCHED_ROUND_16_79  W10, W12, W2, W7
        PROCESS_LOOP W11, I
        MSG_SCHED_ROUND_16_79  W11, W13, W3, W8
        PROCESS_LOOP W12, I
        MSG_SCHED_ROUND_16_79  W12, W14, W4, W9
        PROCESS_LOOP W13, I
        MSG_SCHED_ROUND_16_79  W13, W15, W5, W10
        PROCESS_LOOP W14, I
        MSG_SCHED_ROUND_16_79  W14, W0, W6, W11
        PROCESS_LOOP W15, I
        MSG_SCHED_ROUND_16_79  W15, W1, W7, W12
	PROCESS_LOOP W0, I
        MSG_SCHED_ROUND_16_79  W0, W2, W8, W13
        PROCESS_LOOP W1, I
        MSG_SCHED_ROUND_16_79  W1, W3, W9, W14
        PROCESS_LOOP W2, I
        MSG_SCHED_ROUND_16_79  W2, W4, W10, W15
        PROCESS_LOOP W3, I
        MSG_SCHED_ROUND_16_79  W3, W5, W11, W0
        PROCESS_LOOP W4, I
        MSG_SCHED_ROUND_16_79  W4, W6, W12, W1
        PROCESS_LOOP W5, I
        MSG_SCHED_ROUND_16_79  W5, W7, W13, W2
        PROCESS_LOOP W6, I
        MSG_SCHED_ROUND_16_79  W6, W8, W14, W3
        PROCESS_LOOP W7, I
        MSG_SCHED_ROUND_16_79  W7, W9, W15, W4
        PROCESS_LOOP W8, I
        MSG_SCHED_ROUND_16_79  W8, W10, W0, W5
        PROCESS_LOOP W9, I
        MSG_SCHED_ROUND_16_79  W9, W11, W1, W6
        PROCESS_LOOP W10, I
        MSG_SCHED_ROUND_16_79  W10, W12, W2, W7
        PROCESS_LOOP W11, I
        MSG_SCHED_ROUND_16_79  W11, W13, W3, W8

	vmovdqa32 K60_79(%rip), KT
        I = 0x96

        PROCESS_LOOP W12, I
        MSG_SCHED_ROUND_16_79  W12, W14, W4, W9
        PROCESS_LOOP W13, I
        MSG_SCHED_ROUND_16_79  W13, W15, W5, W10
        PROCESS_LOOP W14, I
        MSG_SCHED_ROUND_16_79  W14, W0, W6, W11
        PROCESS_LOOP W15, I
        MSG_SCHED_ROUND_16_79  W15, W1, W7, W12

        # Check if this is the last block
        sub  $1, SIZE
        je   lastLoop

	I = 0x96

	PROCESS_LOOP W0, I
	mov     0*8+_data_ptr(IN), inp0
        vmovups (inp0,IDX), W0
	PROCESS_LOOP W1, I
	mov     1*8+_data_ptr(IN), inp0
        vmovups (inp0,IDX), W1
        PROCESS_LOOP W2, I
	mov     2*8+_data_ptr(IN), inp0
        vmovups (inp0,IDX), W2
	PROCESS_LOOP W3, I
	mov     3*8+_data_ptr(IN), inp0
        vmovups (inp0,IDX), W3
	PROCESS_LOOP W4, I
	mov     4*8+_data_ptr(IN), inp0
        vmovups (inp0,IDX), W4
	PROCESS_LOOP W5, I
	mov     5*8+_data_ptr(IN), inp0
        vmovups (inp0,IDX), W5
	PROCESS_LOOP W6, I
	mov     6*8+_data_ptr(IN), inp0
        vmovups (inp0,IDX), W6
	PROCESS_LOOP W7, I
	mov     7*8+_data_ptr(IN), inp0
        vmovups (inp0,IDX), W7
	PROCESS_LOOP W8, I
	mov     8*8+_data_ptr(IN), inp0
        vmovups (inp0,IDX), W8
	PROCESS_LOOP W9, I
	mov     9*8+_data_ptr(IN), inp0
        vmovups (inp0,IDX), W9
        PROCESS_LOOP W10, I
	mov     10*8+_data_ptr(IN), inp0
        vmovups (inp0,IDX), W10
        PROCESS_LOOP W11, I
	mov     11*8+_data_ptr(IN), inp0
        vmovups (inp0,IDX), W11
        PROCESS_LOOP W12, I
	mov     12*8+_data_ptr(IN), inp0
        vmovups (inp0,IDX), W12
        PROCESS_LOOP W13, I
	mov     13*8+_data_ptr(IN), inp0
        vmovups (inp0,IDX), W13
        PROCESS_LOOP W14, I
	mov     14*8+_data_ptr(IN), inp0
        vmovups (inp0,IDX), W14
        PROCESS_LOOP W15, I
	mov     15*8+_data_ptr(IN), inp0
        vmovups (inp0,IDX), W15

        # Add old digest
        vpaddd AA, A, A
        vpaddd BB, B, B
        vpaddd CC, C, C
        vpaddd DD, D, D
        vpaddd EE, E, E

        jmp lloop

lastLoop:
#Need to reset argument rotation values to Round 64 values
TMP_ = A
A = B
B = C
C = D
D = E
E = TMP_

# Process last 16 rounds
I = 0x96

        PROCESS_LOOP W0, I
	PROCESS_LOOP W1, I
	PROCESS_LOOP W2, I
	PROCESS_LOOP W3, I
	PROCESS_LOOP W4, I
	PROCESS_LOOP W5, I
	PROCESS_LOOP W6, I
	PROCESS_LOOP W7, I
	PROCESS_LOOP W8, I
	PROCESS_LOOP W9, I
	PROCESS_LOOP W10, I
	PROCESS_LOOP W11, I
	PROCESS_LOOP W12, I
	PROCESS_LOOP W13, I
	PROCESS_LOOP W14, I
	PROCESS_LOOP W15, I

	# Add old digest
	vpaddd AA, A, A
        vpaddd BB, B, B
        vpaddd CC, C, C
        vpaddd DD, D, D
        vpaddd EE, E, E
	
	mov 0*8+_data_ptr(IN), inp0
	mov 1*8+_data_ptr(IN), inp1
	add IDX, inp0
	add IDX, inp1
	mov inp0, 0*8+_data_ptr(IN)
	mov inp1, 1*8+_data_ptr(IN)

	mov 2*8+_data_ptr(IN), inp0
        mov 3*8+_data_ptr(IN), inp1
        add IDX, inp0
        add IDX, inp1
        mov inp0, 2*8+_data_ptr(IN)
        mov inp1, 3*8+_data_ptr(IN)

	mov 4*8+_data_ptr(IN), inp0
        mov 5*8+_data_ptr(IN), inp1
        add IDX, inp0
        add IDX, inp1
        mov inp0, 4*8+_data_ptr(IN)
        mov inp1, 5*8+_data_ptr(IN)

	mov 6*8+_data_ptr(IN), inp0
        mov 7*8+_data_ptr(IN), inp1
        add IDX, inp0
        add IDX, inp1
        mov inp0, 6*8+_data_ptr(IN)
        mov inp1, 7*8+_data_ptr(IN)

	mov 8*8+_data_ptr(IN), inp0
        mov 9*8+_data_ptr(IN), inp1
        add IDX, inp0
        add IDX, inp1
        mov inp0, 8*8+_data_ptr(IN)
        mov inp1, 9*8+_data_ptr(IN)

	mov 10*8+_data_ptr(IN), inp0
        mov 11*8+_data_ptr(IN), inp1
        add IDX, inp0
        add IDX, inp1
        mov inp0, 10*8+_data_ptr(IN)
        mov inp1, 11*8+_data_ptr(IN)

	mov 12*8+_data_ptr(IN), inp0
        mov 13*8+_data_ptr(IN), inp1
        add IDX, inp0
        add IDX, inp1
        mov inp0, 12*8+_data_ptr(IN)
        mov inp1, 13*8+_data_ptr(IN)

	mov 14*8+_data_ptr(IN), inp0
        mov 15*8+_data_ptr(IN), inp1
        add IDX, inp0
        add IDX, inp1
        mov inp0, 14*8+_data_ptr(IN)
        mov inp1, 15*8+_data_ptr(IN)

        # Write out digest
        # Do we need to untranspose digests???
	vmovups A,0*64(DIGEST)
        vmovups B,1*64(DIGEST)
        vmovups C,2*64(DIGEST)
        vmovups D,3*64(DIGEST)
        vmovups E,4*64(DIGEST)
	
	#mov %rbx, _GPR_SAVE+8*0(%rsp)
        #mov %rbp, _GPR_SAVE+8*3(%rsp)
        #mov %r12, _GPR_SAVE+8*4(%rsp)
        #mov %r13, _GPR_SAVE+8*5(%rsp)
        #mov %r14, _GPR_SAVE+8*6(%rsp)
        #mov %r15, _GPR_SAVE+8*7(%rsp)

        #mov _rsp(%rsp), %rsp
        ret

ENDPROC(sha1_x16_avx3)

.data
.align 64

K00_19:                 .octa 0x5A8279995A8279995A8279995A827999
                        .octa 0x5A8279995A8279995A8279995A827999
                        .octa 0x5A8279995A8279995A8279995A827999
                        .octa 0x5A8279995A8279995A8279995A827999
K20_39:                 .octa 0x6ED9EBA16ED9EBA16ED9EBA16ED9EBA1
                        .octa 0x6ED9EBA16ED9EBA16ED9EBA16ED9EBA1
                        .octa 0x6ED9EBA16ED9EBA16ED9EBA16ED9EBA1
                        .octa 0x6ED9EBA16ED9EBA16ED9EBA16ED9EBA1
K40_59:                 .octa 0x8F1BBCDC8F1BBCDC8F1BBCDC8F1BBCDC
                        .octa 0x8F1BBCDC8F1BBCDC8F1BBCDC8F1BBCDC
                        .octa 0x8F1BBCDC8F1BBCDC8F1BBCDC8F1BBCDC
                        .octa 0x8F1BBCDC8F1BBCDC8F1BBCDC8F1BBCDC
K60_79:                 .octa 0xCA62C1D6CA62C1D6CA62C1D6CA62C1D6
                        .octa 0xCA62C1D6CA62C1D6CA62C1D6CA62C1D6
                        .octa 0xCA62C1D6CA62C1D6CA62C1D6CA62C1D6
                        .octa 0xCA62C1D6CA62C1D6CA62C1D6CA62C1D6

PSHUFFLE_BYTE_FLIP_MASK: .octa 0x0c0d0e0f08090a0b0405060700010203
                         .octa 0x0c0d0e0f08090a0b0405060700010203
                         .octa 0x0c0d0e0f08090a0b0405060700010203
                         .octa 0x0c0d0e0f08090a0b0405060700010203

PSHUFFLE_TRANSPOSE16_MASK1:     .quad 0x0000000000000000
                                .quad 0x0000000000000001
                                .quad 0x0000000000000008
                                .quad 0x0000000000000009
                                .quad 0x0000000000000004
                                .quad 0x0000000000000005
                                .quad 0x000000000000000C
                                .quad 0x000000000000000D


PSHUFFLE_TRANSPOSE16_MASK2:     .quad 0x0000000000000002
                                .quad 0x0000000000000003
                                .quad 0x000000000000000A
                                .quad 0x000000000000000B
                                .quad 0x0000000000000006
                                .quad 0x0000000000000007
                                .quad 0x000000000000000E
                                .quad 0x000000000000000F
