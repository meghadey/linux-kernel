########################################################################
# Copyright 2012 Intel Corporation All Rights Reserved.
# 
# The source code contained or described herein and all documents
# related to the source code ("Material") are owned by Intel Corporation
# or its suppliers or licensors. Title to the Material remains with
# Intel Corporation or its suppliers and licensors. The Material may
# contain trade secrets and proprietary and confidential information of
# Intel Corporation and its suppliers and licensors, and is protected by
# worldwide copyright and trade secret laws and treaty provisions. No
# part of the Material may be used, copied, reproduced, modified,
# published, uploaded, posted, transmitted, distributed, or disclosed in
# any way without Intel's prior express written permission.
# 
# No license under any patent, copyright, trade secret or other
# intellectual property right is granted to or conferred upon you by
# disclosure or delivery of the Materials, either expressly, by
# implication, inducement, estoppel or otherwise. Any license under such
# intellectual property rights must be express and approved by Intel in
# writing.
# 
# Unless otherwise agreed by Intel in writing, you may not remove or
# alter this notice or any other notice embedded in Materials by Intel
# or Intel's suppliers or licensors in any way.
########################################################################

# Macros for defining data structures

# Usage example

#START_FIELDS	# JOB_AES
###	name		size	align
#FIELD	_plaintext,	8,	8	# pointer to plaintext
#FIELD	_ciphertext,	8,	8	# pointer to ciphertext
#FIELD	_IV,		16,	8	# IV
#FIELD	_keys,		8,	8	# pointer to keys
#FIELD	_len,		4,	4	# length in bytes
#FIELD	_status,	4,	4	# status enumeration
#FIELD	_user_data,	8,	8	# pointer to user data
#UNION  _union,         size1,  align1, \
#	                size2,  align2, \
#	                size3,  align3, \
#	                ...
#END_FIELDS
#%assign _JOB_AES_size	_FIELD_OFFSET
#%assign _JOB_AES_align	_STRUCT_ALIGN

#########################################################################

# Alternate "struc-like" syntax:
#	STRUCT job_aes2
#	RES_Q	.plaintext,	1
#	RES_Q	.ciphertext, 	1
#	RES_DQ	.IV,		1
#	RES_B	.nested,	_JOB_AES_SIZE, _JOB_AES_ALIGN
#	RES_U	.union,		size1, align1, \
#				size2, align2, \
#				...
#	ENDSTRUCT
#	# Following only needed if nesting
#	%assign job_aes2_size	_FIELD_OFFSET
#	%assign job_aes2_align	_STRUCT_ALIGN
#
# RES_* macros take a name, a count and an optional alignment.
# The count in in terms of the base size of the macro, and the
# default alignment is the base size.
# The macros are:
# Macro    Base size
# RES_B	    1
# RES_W	    2
# RES_D     4
# RES_Q     8
# RES_DQ   16
# RES_Y    32
# RES_Z    64
# 
# RES_U defines a union. It's arguments are a name and two or more
# pairs of "size, alignment"
#
# The two assigns are only needed if this structure is being nested
# within another. Even if the assigns are not done, one can still use
# STRUCT_NAME_size as the size of the structure.
# 
# Note that for nesting, you still need to assign to STRUCT_NAME_size.
# 
# The differences between this and using "struc" directly are that each
# type is implicitly aligned to its natural length (although this can be
# over-ridden with an explicit third parameter), and that the structure
# is padded at the end to its overall alignment.
# 

#########################################################################

#ifndef _DATASTRUCT_ASM_
#define _DATASTRUCT_ASM_

## START_FIELDS
.macro START_FIELDS
 _FIELD_OFFSET = 0
 _STRUCT_ALIGN = 0
.endm

## FIELD name size align
.macro FIELD name size align
 _FIELD_OFFSET = (_FIELD_OFFSET + (\align) - 1) & (~ ((\align)-1))
 \name	= _FIELD_OFFSET
 _FIELD_OFFSET = _FIELD_OFFSET + (\size)
.if (\align > _STRUCT_ALIGN)
 _STRUCT_ALIGN = \align
.endif
.endm

## END_FIELDS
.macro END_FIELDS
 _FIELD_OFFSET = (_FIELD_OFFSET + _STRUCT_ALIGN-1) & (~ (_STRUCT_ALIGN-1))
.endm

########################################################################

.macro STRUCT p1 
START_FIELDS
.struc \p1
.endm

.macro ENDSTRUCT
 tmp = _FIELD_OFFSET
 END_FIELDS
 tmp = (_FIELD_OFFSET - %%tmp)
.if (tmp > 0)
	.lcomm	tmp
.endif
.endstruc
.endm

## RES_int name size align
.macro RES_int p1 p2 p3 
 name = \p1
 size = \p2
 align = .\p3

 _FIELD_OFFSET = (_FIELD_OFFSET + (align) - 1) & (~ ((align)-1))
.align align
.lcomm name size
 _FIELD_OFFSET = _FIELD_OFFSET + (size)
.if (align > _STRUCT_ALIGN)
 _STRUCT_ALIGN = align
.endif
.endm



# macro RES_B name, size [, align]
.macro RES_B _name, _size, _align=1 
RES_int _name _size _align 
.endm

# macro RES_W name, size [, align]
.macro RES_W _name, _size, _align=2 
RES_int _name 2*(_size) _align 
.endm

# macro RES_D name, size [, align]
.macro RES_D _name, _size, _align=4 
RES_int _name 4*(_size) _align 
.endm

# macro RES_Q name, size [, align]
.macro RES_Q _name, _size, _align=8 
RES_int _name 8*(_size) _align 
.endm

# macro RES_DQ name, size [, align]
.macro RES_DQ _name, _size, _align=16 
RES_int _name 16*(_size) _align 
.endm

# macro RES_Y name, size [, align]
.macro RES_Y _name, _size, _align=32 
RES_int _name 32*(_size) _align 
.endm

# macro RES_Z name, size [, align]
.macro RES_Z _name, _size, _align=64 
RES_int _name 64*(_size) _align 
.endm


#endif

########################################################################
#### Define constants
########################################################################

########################################################################
#### Define SHA1 Out Of Order Data Structures
########################################################################

START_FIELDS    # LANE_DATA
###     name            size    align
FIELD   _job_in_lane,   8,      8       # pointer to job object
END_FIELDS

 _LANE_DATA_size = _FIELD_OFFSET
 _LANE_DATA_align = _STRUCT_ALIGN

########################################################################

START_FIELDS    # SHA1_ARGS_X16
###     name            size    align
FIELD   _digest,        4*5*16,  16      # transposed digest
FIELD   _data_ptr,      8*16,    8       # array of pointers to data
END_FIELDS

 _SHA1_ARGS_X4_size =     _FIELD_OFFSET
 _SHA1_ARGS_X4_align =    _STRUCT_ALIGN
 _SHA1_ARGS_X8_size =     _FIELD_OFFSET
 _SHA1_ARGS_X8_align =    _STRUCT_ALIGN
 _SHA1_ARGS_X16_size	=	_FIELD_OFFSET
 _SHA1_ARGS_X16_align	=	_STRUCT_ALIGN

########################################################################

START_FIELDS    # MB_MGR
###     name            size    align
FIELD   _args,          _SHA1_ARGS_X4_size, _SHA1_ARGS_X4_align
FIELD   _lens,          4*16,    8
FIELD   _unused_lanes,  8,      8
FIELD   _ldata,         _LANE_DATA_size*16, _LANE_DATA_align
FIELD	_num_lanes_inuse,4,	4
END_FIELDS

 _MB_MGR_size =   _FIELD_OFFSET
 _MB_MGR_align =  _STRUCT_ALIGN

_args_digest    =     _args + _digest
_args_data_ptr  =     _args + _data_ptr

########################################################################
# Define Stack Layout
START_FIELDS
###     name            size    align
FIELD   _GPR_SAVE,      8*8,    8
FIELD   _ZMM_SAVE,      10*64,  64
FIELD   _rsp,           8,      8

STACK_SPACE  =   _FIELD_OFFSET

########################################################################
#### Define constants
########################################################################

#define STS_UNKNOWN             0
#define STS_BEING_PROCESSED     1
#define STS_COMPLETED           2

########################################################################
#### Define JOB_SHA1 structure
########################################################################

START_FIELDS    # JOB_SHA1

###     name                            size    align
FIELD   _buffer,                        8,      8       # pointer to buffer
FIELD   _len,                           4,      4       # length in bytes
FIELD   _result_digest,                 5*4,    32      # Digest (output)
FIELD   _status,                        4,      4
FIELD   _user_data,                     8,      8
END_FIELDS

 _JOB_SHA1_size =  _FIELD_OFFSET
 _JOB_SHA1_align = _STRUCT_ALIGN
