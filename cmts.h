/*
	BSD 2-Clause License
	
	Copyright (c) 2020, Marcel Pi Nacy
	All rights reserved.
	
	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:
	
	1. Redistributions of source code must retain the above copyright notice, this
	   list of conditions and the following disclaimer.
	
	2. Redistributions in binary form must reproduce the above copyright notice,
	   this list of conditions and the following disclaimer in the documentation
	   and/or other materials provided with the distribution.
	
	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
	AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
	IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
	DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
	FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
	DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
	SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
	CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
	OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
	OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef CMTS_HEADER_INCLUDED
#define CMTS_HEADER_INCLUDED

#include <stdint.h>

#ifndef CMTS_QUEUE_PRIORITY_COUNT
#define CMTS_QUEUE_PRIORITY_COUNT 4
#endif

#if CMTS_QUEUE_PRIORITY_COUNT > 256
#error "Error, CMTS_QUEUE_PRIORITY_COUNT must not exceed 256"
#endif

#ifndef CMTS_TASK_STACK_SIZE
#define CMTS_TASK_STACK_SIZE 65536
#endif

#ifndef CMTS_CALLING_CONVENTION
#define CMTS_CALLING_CONVENTION
#endif

#ifdef __cplusplus
typedef bool cmts_boolean_t;
#else
typedef _Bool cmts_boolean_t;
#endif

typedef void(*cmts_function_pointer_t)(void*);
typedef uint64_t cmts_fence_t;
typedef uint64_t cmts_counter_t;

#ifdef CMTS_MAX_TASKS
#error "Error, attempted to redefine CMTS_MAX_TASKS."
#endif

#ifdef CMTS_NIL_COUNTER
#error "Error, attempted to redefine CMTS_NIL_COUNTER."
#endif

#ifdef CMTS_NIL_FENCE
#error "Error, attempted to redefine CMTS_NIL_FENCE."
#endif

#define CMTS_MAX_TASKS ((uint32_t)(1U << 24U))
#define CMTS_NIL_COUNTER (~(uint32_t)0)
#define CMTS_NIL_FENCE (~(uint32_t)0)

#ifdef __cplusplus
extern "C"
{
#endif

	void			CMTS_CALLING_CONVENTION cmts_initialize(uint32_t max_tasks, uint32_t max_cpus);
	void			CMTS_CALLING_CONVENTION cmts_break();
	void			CMTS_CALLING_CONVENTION cmts_resume();
	void			CMTS_CALLING_CONVENTION cmts_signal_finalize();
	void			CMTS_CALLING_CONVENTION cmts_finalize();
	void			CMTS_CALLING_CONVENTION cmts_terminate();
	cmts_boolean_t	CMTS_CALLING_CONVENTION cmts_is_task();
	cmts_boolean_t	CMTS_CALLING_CONVENTION cmts_is_running();
	void			CMTS_CALLING_CONVENTION cmts_dispatch(cmts_function_pointer_t task_function, void* param, uint8_t priority_level);
	void			CMTS_CALLING_CONVENTION cmts_yield();
	void			CMTS_CALLING_CONVENTION cmts_exit();
	cmts_fence_t	CMTS_CALLING_CONVENTION cmts_new_fence();
	cmts_boolean_t	CMTS_CALLING_CONVENTION cmts_is_fence_valid(cmts_fence_t fence);
	void			CMTS_CALLING_CONVENTION cmts_signal_fence(cmts_fence_t fence);
	void			CMTS_CALLING_CONVENTION cmts_await_fence(cmts_fence_t fence);
	void			CMTS_CALLING_CONVENTION cmts_await_fence_and_delete(cmts_fence_t fence);
	void			CMTS_CALLING_CONVENTION cmts_delete_fence(cmts_fence_t fence);
	cmts_counter_t	CMTS_CALLING_CONVENTION cmts_new_counter(uint32_t start_value);
	cmts_boolean_t	CMTS_CALLING_CONVENTION cmts_is_counter_valid(cmts_counter_t counter);
	void			CMTS_CALLING_CONVENTION cmts_set_counter(cmts_counter_t counter, uint32_t value);
	void			CMTS_CALLING_CONVENTION cmts_increment_counter(cmts_counter_t counter);
	void			CMTS_CALLING_CONVENTION cmts_decrement_counter(cmts_counter_t counter);
	void			CMTS_CALLING_CONVENTION cmts_await_counter(cmts_counter_t counter);
	void			CMTS_CALLING_CONVENTION cmts_await_counter_and_delete(cmts_counter_t counter);
	void			CMTS_CALLING_CONVENTION cmts_delete_counter(cmts_counter_t counter);
	void			CMTS_CALLING_CONVENTION cmts_dispatch_with_fence(cmts_function_pointer_t task_function, void* param, uint8_t priority_level, cmts_fence_t fence);
	void			CMTS_CALLING_CONVENTION cmts_dispatch_with_counter(cmts_function_pointer_t task_function, void* param, uint8_t priority_level, cmts_counter_t counter);
	uint32_t		CMTS_CALLING_CONVENTION cmts_current_task_id();
	uint32_t		CMTS_CALLING_CONVENTION cmts_current_cpu();
	uint32_t		CMTS_CALLING_CONVENTION cmts_used_cpu_count();
	uint32_t		CMTS_CALLING_CONVENTION cmts_available_cpu_count();

#ifdef __cplusplus
}
#endif

#ifdef CMTS_IMPLEMENTATION
#include "cmts_windows.cpp"
#endif

#endif //CMTS_HEADER_INCLUDED