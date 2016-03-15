#include <linux/linkage.h>
#include "sha1_mb_mgr_datastruct.S"

.extern sha1_x16_avx3

# LINUX register definitions
#define arg1    %rdi
#define arg2    %rsi

# Common definitions
#define state   arg1
#define job     arg2
#define len2    arg2

# idx must be a register not clobbered by sha1_x16_avx3
#define idx		%r8
#define DWORD_idx	%r8d

#define unused_lanes    %rbx
#define lane_data       %rbx
#define tmp2            %rbx
#define tmp2_w		%ebx
#define num_lanes_inuse %r9     
#define DWORD_num_lanes_inuse %r9d                   
#define job_rax         %rax
#define tmp             %rax

# STACK_SPACE needs to be an odd multiple of 8
_XMM_SAVE_SIZE  = 10*16
_GPR_SAVE_SIZE  = 8*8
_ALIGN_SIZE     = 8

_XMM_SAVE       = 0
_GPR_SAVE       = _XMM_SAVE + _XMM_SAVE_SIZE
STACK_SPACE     = _GPR_SAVE + _GPR_SAVE_SIZE + _ALIGN_SIZE

.macro LABEL prefix n
\prefix\n\():
.endm 

.macro JNE_SKIP i
jne     skip_\i
.endm

.altmacro
.macro SET_OFFSET _offset
offset = \_offset
.endm
.noaltmacro

# JOB* sha1_mb_mgr_flush_avx3(MB_MGR *state)
# arg 1 : rcx : state
ENTRY(sha1_mb_mgr_flush_avx3)

#	mov	%rsp, %r10
        sub     $STACK_SPACE, %rsp
#	and     $~31, %rsp
        mov     %rbx, _GPR_SAVE(%rsp)
#        mov     %r10, _GPR_SAVE+8*1(%rsp) #save rsp
	mov	%rbp, _GPR_SAVE+8*3(%rsp)
	mov	%r12, _GPR_SAVE+8*4(%rsp)
	mov	%r13, _GPR_SAVE+8*5(%rsp)
	mov	%r14, _GPR_SAVE+8*6(%rsp)
	mov	%r15, _GPR_SAVE+8*7(%rsp)

	# If bit (32+3) is set, then all lanes are empty
        mov     _num_lanes_inuse(state), DWORD_num_lanes_inuse
	cmp	$0, num_lanes_inuse        
	jz      return_null

        # find a lane with a non-null job
        xor     idx, idx

	offset = (_ldata + 1 * _LANE_DATA_size + _job_in_lane)
        cmpq    $0, offset(state)
        cmovne  one, idx
	offset = (_ldata + 2 * _LANE_DATA_size + _job_in_lane)
        cmpq    $0, offset(state)
        cmovne  two, idx
	offset = (_ldata + 3 * _LANE_DATA_size + _job_in_lane)
        cmpq    $0, offset(state)
        cmovne  three, idx
	offset = (_ldata + 4 * _LANE_DATA_size + _job_in_lane)
        cmpq    $0, offset(state)
        cmovne  four, idx
	offset = (_ldata + 5 * _LANE_DATA_size + _job_in_lane)
        cmpq    $0, offset(state)
        cmovne  five, idx
	offset = (_ldata + 6 * _LANE_DATA_size + _job_in_lane)
        cmpq    $0, offset(state)
        cmovne  six, idx
	offset = (_ldata + 7 * _LANE_DATA_size + _job_in_lane)
	cmpq    $0, offset(state)
        cmovne  seven, idx
        offset = (_ldata + 8 * _LANE_DATA_size + _job_in_lane)
	cmpq    $0, offset(state)
        cmovne  eight, idx
	offset = (_ldata + 9 * _LANE_DATA_size + _job_in_lane)
        cmpq    $0, offset(state)
        cmovne  nine, idx
        offset = (_ldata + 10 * _LANE_DATA_size + _job_in_lane)
        cmpq    $0, offset(state)
        cmovne  ten, idx
        offset = (_ldata + 11 * _LANE_DATA_size + _job_in_lane)
        cmpq    $0, offset(state)
        cmovne  eleven, idx
        offset = (_ldata + 12 * _LANE_DATA_size + _job_in_lane)
        cmpq    $0, offset(state)
        cmovne  twelve, idx
        offset = (_ldata + 13 * _LANE_DATA_size + _job_in_lane)
        cmpq    $0, offset(state)
        cmovne  thirteen, idx
        offset = (_ldata + 14 * _LANE_DATA_size + _job_in_lane)
        cmpq    $0, offset(state)
        cmovne  fourteen, idx
        offset = (_ldata + 15 * _LANE_DATA_size + _job_in_lane)
        cmpq    $0, offset(state)
        cmovne  fifteen, idx

        # copy idx to empty lanes
copy_lane_data:
	offset =  (_args + _data_ptr)
        mov     offset(state,idx,8), tmp

	I = 0
.rep 16
	offset =  (_ldata + I * _LANE_DATA_size + _job_in_lane)
        cmpq    $0, offset(state)
.altmacro
        JNE_SKIP %I
	offset =  (_args + _data_ptr + 8*I)
        mov     tmp, offset(state)
	offset =  (_lens + 4*I)
        movl    $0xFFFFFFFF, offset(state)
LABEL skip_ %I
	I = (I+1)
.noaltmacro
.endr

        # Find min length
	vmovdqu _lens+0*32(state), %ymm0
	vmovdqu _lens+1*32(state), %ymm1

	vpminud %ymm1, %ymm0, %ymm2     # xmm2 has {D,C,B,A}
	vpalignr $8, %ymm2, %ymm3, %ymm3   # xmm3 has {x,x,D,C}
	vpminud %ymm3, %ymm2, %ymm2        # xmm2 has {x,x,E,F}
	vpalignr $4, %ymm2, %ymm3, %ymm3    # xmm3 has {x,x,x,E}
	vpminud %ymm3, %ymm2, %ymm2        # xmm2 has min value in low dword
	vperm2i128 $1,%ymm2,%ymm2,%ymm3
	vpminud %ymm3,%ymm2,%ymm2

	vmovd   %xmm2, DWORD_idx
	mov	idx, len2
	and	$0xF, idx
	shr	$4, len2
	jz	len_is_0

	vpand   clear_low_nibble(%rip), %ymm2, %ymm2
	vpshufd $0, %ymm2, %ymm2

	vpsubd  %ymm2, %ymm0, %ymm0
	vpsubd  %ymm2, %ymm1, %ymm1

	vmovdqu %ymm0, _lens+0*32(state)
	vmovdqu %ymm1, _lens+1*32(state)

	# "state" and "args" are the same address, arg1
	# len is arg2
	call	sha1_x16_avx3
	# state and idx are intact


len_is_0:
        # process completed job "idx"
        imul    $_LANE_DATA_size, idx, lane_data
        lea     _ldata(state, lane_data), lane_data

        mov     _job_in_lane(lane_data), job_rax
        movq    $0, _job_in_lane(lane_data)
        movl    $STS_COMPLETED, _status(job_rax)
        mov     _unused_lanes(state), unused_lanes
        shl     $4, unused_lanes
        or      idx, unused_lanes
        mov     unused_lanes, _unused_lanes(state)

	mov	_num_lanes_inuse(state), DWORD_num_lanes_inuse
	sub	$1, num_lanes_inuse
	mov	DWORD_num_lanes_inuse, _num_lanes_inuse(state)

        vmovd    _args_digest(state , idx, 4) , %xmm0
        vpinsrd  $1, _args_digest+1*64(state, idx, 4), %xmm0, %xmm0
        vpinsrd  $2, _args_digest+2*64(state, idx, 4), %xmm0, %xmm0
        vpinsrd  $3, _args_digest+3*64(state, idx, 4), %xmm0, %xmm0
        movl    _args_digest+4*64(state, idx, 4), tmp2_w 

        vmovdqa  %xmm0, _result_digest(job_rax)
	offset =  (_result_digest + 1*16)
        mov     tmp2_w, offset(job_rax)

return:

        mov     _GPR_SAVE(%rsp), %rbx
 # mov     _GPR_SAVE+8*1(%rsp), %r10 #saved rsp
	mov	_GPR_SAVE+8*3(%rsp), %rbp
	mov	_GPR_SAVE+8*4(%rsp), %r12
	mov	_GPR_SAVE+8*5(%rsp), %r13
	mov	_GPR_SAVE+8*6(%rsp), %r14
	mov	_GPR_SAVE+8*7(%rsp), %r15
  #  mov     %r10, %rsp
	add	$STACK_SPACE,%rsp
        ret
ENDPROC(sha1_mb_mgr_flush_avx3)

return_null:
        xor     job_rax, job_rax
        jmp     return
        
.data 

.align 16
clear_low_nibble:
.quad	0x00000000FFFFFFF0, 0x0000000000000000
.quad   0x00000000FFFFFFF0, 0x0000000000000000

one:    
.quad  1
two:    
.quad  2
three:  
.quad  3
four:  
.quad  4
five:  
.quad  5
six:  
.quad  6
seven:  
.quad  7
eight:
.quad  8
nine:
.quad  9
ten:
.quad  10
eleven:
.quad  11
twelve:
.quad  12
thirteen:
.quad  13
fourteen:
.quad  14
fifteen:
.quad  15
