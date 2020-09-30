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

#pragma once
#include <stdint.h>

enum : uint32_t
{
	CMTS_MAX_TASKS		= 1 << 24,
	CMTS_NIL_HANDLE		= UINT32_MAX,
	CMTS_NIL_COUNTER	= CMTS_NIL_HANDLE,
	CMTS_NIL_FENCE		= CMTS_NIL_HANDLE,
};

#ifndef CMTS_NODISCARD
	#ifdef __cplusplus
		#if defined(__has_attribute)
			#ifdef __has_attribute(nodiscard)
				#define CMTS_NODISCARD [[nodiscard]]
			#else
				#define CMTS_NODISCARD
			#endif
		#else
			#define CMTS_NODISCARD
		#endif
	#else
		#define CMTS_NODISCARD
	#endif
#endif


#ifndef CMTS_MAX_PRIORITY
#define CMTS_MAX_PRIORITY 3
#endif

#if CMTS_MAX_PRIORITY > 256
#error "Error, CMTS_MAX_PRIORITY must not exceed 256"
#endif

#ifndef CMTS_EXPECTED_CACHE_LINE_SIZE
#define CMTS_EXPECTED_CACHE_LINE_SIZE 64
#endif

#ifndef CMTS_NOTHROW
#ifdef __cplusplus
#define CMTS_NOTHROW noexcept
#else
#define CMTS_NOTHROW
#endif
#endif

#ifndef CMTS_CALLING_CONVENTION
#define CMTS_CALLING_CONVENTION
#endif

#ifdef __cplusplus
typedef bool cmts_boolean_t;
#else
typedef _Bool cmts_boolean_t;
#endif

typedef void(*cmts_function_pointer_t)(void* parameter);
typedef void*(*cmts_allocate_function_pointer_t)(size_t size);
typedef void(*cmts_deallocate_function_pointer_t)(void* memory, size_t size);
typedef uint64_t cmts_fence_t;
typedef uint64_t cmts_counter_t;

typedef struct _cmts_allocation_callbacks_t
{
	cmts_allocate_function_pointer_t allocate;
	cmts_deallocate_function_pointer_t deallocate;
} cmts_allocation_callbacks_t;

typedef struct _cmts_init_options_t
{
	uint32_t max_tasks;
	uint32_t max_threads;
	uint32_t thread_stack_size;
	uint32_t task_stack_size;
	union
	{
		uint32_t first_core;
		uint32_t* cpu_indices;
	};
	const cmts_allocation_callbacks_t* allocator;
	cmts_boolean_t use_affinity;
	cmts_boolean_t use_manual_affinity;
} cmts_init_options_t;

typedef enum _cmts_synchronization_type_t
{
	CMTS_SYNCHRONIZATION_TYPE_NONE,
	CMTS_SYNCHRONIZATION_TYPE_FENCE,
	CMTS_SYNCHRONIZATION_TYPE_COUNTER,
	CMTS_SYNCHRONIZATION_TYPE_MAX_ENUM,
} cmts_synchronization_type_t;

typedef struct _cmts_dispatch_options_t
{
	void* parameter;
	union
	{
		cmts_fence_t fence;
		cmts_counter_t counter;
	};
	cmts_synchronization_type_t synchronization_type;
	uint8_t priority;
} cmts_dispatch_options_t;

#ifdef __cplusplus
extern "C" {
#endif
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_init(const cmts_init_options_t* options);
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_break();
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_continue();
	void CMTS_CALLING_CONVENTION cmts_signal_finalize();
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_finalize();
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_terminate();
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_initialized();
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_task();
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_running();
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_dispatch(cmts_function_pointer_t task_function, const cmts_dispatch_options_t* options);
	void CMTS_CALLING_CONVENTION cmts_yield();
	void CMTS_CALLING_CONVENTION cmts_exit();
	CMTS_NODISCARD cmts_fence_t CMTS_CALLING_CONVENTION cmts_new_fence();
	CMTS_NODISCARD cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_fence_valid(cmts_fence_t fence);
	void CMTS_CALLING_CONVENTION cmts_signal_fence(cmts_fence_t fence);
	void CMTS_CALLING_CONVENTION cmts_await_fence(cmts_fence_t fence);
	void CMTS_CALLING_CONVENTION cmts_await_fence_and_delete(cmts_fence_t fence);
	void CMTS_CALLING_CONVENTION cmts_delete_fence(cmts_fence_t fence);
	CMTS_NODISCARD cmts_counter_t CMTS_CALLING_CONVENTION cmts_new_counter(uint32_t start_value);
	CMTS_NODISCARD cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_counter_valid(cmts_counter_t counter);
	void CMTS_CALLING_CONVENTION cmts_await_counter(cmts_counter_t counter);
	void CMTS_CALLING_CONVENTION cmts_await_counter_and_delete(cmts_counter_t counter);
	void CMTS_CALLING_CONVENTION cmts_delete_counter(cmts_counter_t counter);
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_dispatch_with_fence(cmts_function_pointer_t task_function, void* param, uint8_t priority_level, cmts_fence_t fence);
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_dispatch_with_counter(cmts_function_pointer_t task_function, void* param, uint8_t priority_level, cmts_counter_t counter);
	uint32_t CMTS_CALLING_CONVENTION cmts_current_task_id();
	uint32_t CMTS_CALLING_CONVENTION cmts_worker_thread_index();
	uint32_t CMTS_CALLING_CONVENTION cmts_thread_count();
	uint32_t CMTS_CALLING_CONVENTION cmts_available_cpu_count();
#ifdef __cplusplus
}
#endif



#ifdef CMTS_IMPLEMENTATION
#include "source/implementation.cpp"
#endif