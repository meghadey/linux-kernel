#include <linux/linkage.h>
#include "sha1_mb_mgr_datastruct.S"

.extern sha1_x16_avx3

# LINUX register definitions
arg1    = %rdi
arg2    = %rsi

# Common definitions
#define state   arg1
#define job     arg2
#define len2    arg2

# idx must be a register not clobberred by sha1_x16_avx3
idx		= %r8
DWORD_idx	= %r8d

p               = %r11

unused_lanes    = %rbx
BYTE_unused_lanes = %bl
                        
job_rax         = %rax
len             = %rax
DWORD_len	= %eax

lane            = %rbp
                        
tmp             = %r9
DWORD_tmp	= %r9d

num_lanes_inuse = %r9
DWORD_num_lanes_inuse = %r9d
lane_data       = %r10

# STACK_SPACE needs to be an odd multiple of 8
STACK_SPACE     = 8*8 + 16*10 + 8

# JOB* submit_mb_mgr_submit_avx3(MB_MGR *state, JOB_SHA1 *job)
# arg 1 : rcx : state
# arg 2 : rdx : job
ENTRY(sha1_mb_mgr_submit_avx3)

#	mov	%rsp, %r10
        sub     $STACK_SPACE, %rsp
#	and	$~31, %rsp
	
        mov     %rbx, (%rsp)
#	mov	%r10, 8*2(%rsp)	#save old rsp
        mov     %rbp, 8*3(%rsp)
	mov	%r12, 8*4(%rsp)
	mov	%r13, 8*5(%rsp)
	mov	%r14, 8*6(%rsp)
	mov	%r15, 8*7(%rsp)

        mov     _unused_lanes(state), unused_lanes
        mov	unused_lanes, lane
	and	$0xF, lane
        shr     $4, unused_lanes
        imul    $_LANE_DATA_size, lane, lane_data
        movl    $STS_BEING_PROCESSED, _status(job)
        lea     _ldata(state, lane_data), lane_data
        mov     unused_lanes, _unused_lanes(state)
        movl    _len(job),  DWORD_len

	mov	job, _job_in_lane(lane_data)
	shl	$4, len
	or	lane, len

        movl    DWORD_len,  _lens(state , lane, 4)

	# Load digest words from result_digest
	vmovdqu	_result_digest(job), %xmm0
        mov	_result_digest+1*16(job), DWORD_tmp 
        vmovd    %xmm0, _args_digest(state, lane, 4)
        vpextrd  $1, %xmm0, _args_digest+1*64(state , lane, 4)
        vpextrd  $2, %xmm0, _args_digest+2*64(state , lane, 4)
        vpextrd  $3, %xmm0, _args_digest+3*64(state , lane, 4)
        movl    DWORD_tmp, _args_digest+4*64(state , lane, 4)

        mov     _buffer(job), p
        mov     p, _args_data_ptr(state, lane, 8)

	mov	_num_lanes_inuse(state), DWORD_num_lanes_inuse
	add	$1, num_lanes_inuse
	mov	DWORD_num_lanes_inuse, _num_lanes_inuse(state)
        cmp     $0x10, num_lanes_inuse
        jne     return_null

start_loop:
        # Find min length
	vmovdqu _lens(state), %ymm0
	vmovdqu _lens+1*32(state), %ymm1

	vpminud %ymm1, %ymm0, %ymm2        # xmm2 has {D,C,B,A}
	vpalignr $8, %ymm2, %ymm3, %ymm3   # xmm3 has {x,x,D,C}
	vpminud %ymm3, %ymm2, %ymm2        # xmm2 has {x,x,E,F}
	vpalignr $4, %ymm2, %ymm3, %ymm3   # xmm3 has {x,x,x,E}
	vpminud %ymm3, %ymm2, %ymm2        # xmm2 has min value in low dword
	vperm2i128 $1, %ymm2, %ymm2, %ymm3
	vpminud %ymm3, %ymm2, %ymm2

	vmovd   %xmm2, DWORD_idx
	mov    idx, len2
	and    $0xF, idx
	shr    $4, len2
	jz     len_is_0

	vpand   clear_low_nibble(%rip), %ymm2, %ymm2
	vpshufd $0, %ymm2, %ymm2

	vpsubd  %ymm2, %ymm0, %ymm0
	vpsubd  %ymm2, %ymm1, %ymm1

	vmovdqu %ymm0, _lens(state)
	vmovdqu %ymm1, _lens + 1*32(state)

	# "state" and "args" are the same address, arg1
	# len is arg2
	call    sha1_x16_avx3
	
        # state and idx are intact

len_is_0:
        # process completed job "idx"
        imul    $_LANE_DATA_size, idx, lane_data
        lea     _ldata(state, lane_data), lane_data
        
        mov     _job_in_lane(lane_data), job_rax
        mov     _unused_lanes(state), unused_lanes
        movq    $0, _job_in_lane(lane_data)
        movl    $STS_COMPLETED, _status(job_rax)
        shl     $4, unused_lanes
        or      idx, unused_lanes
        mov     unused_lanes, _unused_lanes(state)

	mov	_num_lanes_inuse(state), DWORD_num_lanes_inuse
	sub	$1, num_lanes_inuse
	mov	DWORD_num_lanes_inuse, _num_lanes_inuse(state)

        vmovd    _args_digest(state, idx, 4), %xmm0
        vpinsrd  $1, _args_digest+1*64(state , idx, 4), %xmm0, %xmm0
        vpinsrd  $2, _args_digest+2*64(state , idx, 4), %xmm0, %xmm0
        vpinsrd  $3, _args_digest+3*64(state , idx, 4), %xmm0, %xmm0
        movl     _args_digest+4*64(state, idx, 4), DWORD_tmp
 
        vmovdqa  %xmm0, _result_digest(job_rax)
        movl    DWORD_tmp, _result_digest+1*16(job_rax)

return:

        mov     (%rsp), %rbx
#	mov	8*2(%rsp), %r10	#save old rsp
        mov     8*3(%rsp), %rbp
	mov	8*4(%rsp), %r12
	mov	8*5(%rsp), %r13
	mov	8*6(%rsp), %r14
	mov	8*7(%rsp), %r15
 #       mov     %r10, %rsp
	add	$STACK_SPACE, %rsp
        ret

return_null:
        xor     job_rax, job_rax
        jmp     return
ENDPROC(sha1_mb_mgr_submit_avx3)

.data 

.align 32
clear_low_nibble:
	.quad	0x00000000FFFFFFF0, 0x0000000000000000
	.quad	0x00000000FFFFFFF0, 0x0000000000000000
