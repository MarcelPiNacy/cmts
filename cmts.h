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

#ifndef CMTS_NODISCARD
#if defined(__cplusplus) && defined(__has_attribute)
#if __has_attribute(nodiscard)
#define CMTS_NODISCARD [[nodiscard]]
#else
#define CMTS_NODISCARD
#endif
#else
#define CMTS_NODISCARD
#endif
#endif

#ifndef CMTS_MAX_PRIORITY
#define CMTS_MAX_PRIORITY 3
#elif CMTS_MAX_PRIORITY > 256
#error "Error, CMTS_MAX_PRIORITY must not exceed 256"
#endif

#ifndef CMTS_EXPECTED_CACHE_LINE_SIZE
#define CMTS_EXPECTED_CACHE_LINE_SIZE 64
#endif

#if !defined(CMTS_NOTHROW) && defined(__cplusplus)
#define CMTS_NOTHROW noexcept
#else
#define CMTS_NOTHROW
#endif

#ifndef CMTS_CALLING_CONVENTION
#define CMTS_CALLING_CONVENTION
#endif

#ifdef __cplusplus
typedef bool cmts_boolean_t;
#else
typedef _Bool cmts_boolean_t;
#endif

/// <summary>
/// The function pointer type of a task entry point.
/// </summary>
typedef void(*cmts_function_pointer_t)(void*);

/// <summary>
/// A pointer to a memory allocation funcntion used during library initialization.
/// </summary>
/// /// <param name="size">
/// The size of the desired memory block.
/// </param>
typedef void*(*cmts_allocate_function_pointer_t)(size_t size);

/// <summary>
/// A pointer to a memory deallocation funcntion used during library cleanup.
/// <param name="ptr">
/// A pointer to a previously allocated memory block.
/// Guaranteed to not be nullptr.
/// </param>
/// /// <param name="size">
/// The size of the memory block ptr points to.
/// </param>
/// </summary>
typedef void(*cmts_deallocate_function_pointer_t)(void* memory, size_t size);

/// <summary>
/// A handle to either a fence or a counter object.
/// </summary>
typedef uint64_t cmts_handle_t;

/// <summary>
/// The type of a fence handle.
/// A fence may be used by one or more tasks to wait for another task to finish or for the user to manually signal the fence.
/// </summary>
typedef cmts_handle_t cmts_fence_t;

/// <summary>
/// The type of a counter handle.
/// A counter may be used by one or more tasks to wait for a group of tasks to finish.
/// </summary>
typedef cmts_handle_t cmts_counter_t;

typedef struct cmts_init_options_t
{
	/// <summary>
	/// Specifies the maximum number of submitted tasks. This value must be a power of 2.
	/// </summary>
	uint32_t max_tasks;

	/// <summary>
	/// Specifies the number of worker threads to launch.
	/// </summary>
	uint32_t max_threads;

	/// <summary>
	/// Specifies the stack size of the worker threads.
	/// </summary>
	uint32_t thread_stack_size;

	/// <summary>
	/// Specifies the stack size of a task.
	/// </summary>
	uint32_t task_stack_size;

	/// <summary>
	/// Specifies the CPU core index of the first worker thread.
	/// Ignored if use_affinity is false.
	/// </summary>
	uint32_t first_core;

	/// <summary>
	/// A pointer to an array of indices.
	/// Used to assign each worker thread to the corresponding CPU core.
	/// Ignored if use_affinity or use_manual_affinity is false.
	/// </summary>
	const uint32_t* cpu_indices;

	/// <summary>
	/// Specifies the memory allocation function used during initialization.
	/// If set to nullptr, the operating system's memory allocator is used (VirtualAlloc on Windows, mmap on Linux).
	/// This function will be invoked once.
	/// </summary>
	cmts_allocate_function_pointer_t allocate_function;

	/// <summary>
	/// Specifies whether to lock worker threads to CPU cores.
	/// </summary>
	cmts_boolean_t use_affinity;

	/// <summary>
	/// Specifies whether to use the cpu_indices member to lock worker threads to CPU cores.
	/// </summary>
	cmts_boolean_t use_manual_affinity;

} cmts_init_options_t;

typedef struct cmts_parallel_for_options_t
{
	uint32_t	begin;
	uint32_t	end;
	uint8_t		priority;
} cmts_parallel_for_options_t;

#define CMTS_MAX_TASKS (1U << 24U)
#define CMTS_NIL_HANDLE UINT32_MAX

typedef enum cmts_synchronization_type_t
{
	/// <summary>
	/// Specifies that a task has no associated synchronization object.
	/// </summary>
	CMTS_SYNCHRONIZATION_TYPE_NONE,

	/// <summary>
	/// Specifies that a task has a fence associated.
	/// </summary>
	CMTS_SYNCHRONIZATION_TYPE_FENCE,

	/// <summary>
	/// Specifies that a task has a counter associated.
	/// </summary>
	CMTS_SYNCHRONIZATION_TYPE_COUNTER,

	CMTS_SYNCHRONIZATION_TYPE_MAX_ENUM,

} cmts_synchronization_type_t;

typedef struct cmts_dispatch_options_t
{
	/// <summary>
	/// The parameter to pass the task entry point.
	/// </summary>
	void* parameter;

	/// <summary>
	/// Either a fence or a counter handle.
	/// Ignored if synchronization_type is set to CMTS_SYNCHRONIZATION_TYPE_NONE.
	/// </summary>
	cmts_handle_t sync_object;

	/// <summary>
	/// Specifies the type of the handle assigned to sync_object.
	/// </summary>
	cmts_synchronization_type_t sync_type;

	/// <summary>
	/// The scheduling priority of the task to submit. This value must not exceed CMTS_MAX_PRIORITY.
	/// </summary>
	uint8_t priority;

} cmts_dispatch_options_t;

#ifdef __cplusplus
extern "C" {
#endif

	/// <summary>
	/// Initializes the internal state of the library.
	/// </summary>
	/// <param name="options">
	/// Either nullptr or a valid pointer to a cmts_init_options_t structure.
	/// </param>
	/// <returns>
	/// True the library was successfully initialized, false otherwise.
	/// </returns>
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_init(const cmts_init_options_t* options);

	/// <summary>
	/// Halts all worker threads.
	/// </summary>
	/// <returns>
	/// True if the operation succeeded, false otherwise.
	/// </returns>
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_break();

	/// <summary>
	/// Resumes all worker threads.
	/// </summary>
	/// <returns>
	/// True if the operation succeeded, false otherwise.
	/// </returns>
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_continue();

	/// <summary>
	/// Signals to the worker threads to quit once the current task yields or exits.
	/// </summary>
	void CMTS_CALLING_CONVENTION cmts_signal_finalize();

	/// <summary>
	/// Waits for all worker threads to exit and releases the resources used by the library.
	/// </summary>
	/// <param name="deallocate">
	/// Specifies the memory deallocation function. If set to nullptr, the operating system's memory allocator is used (VirtualFree on Windows, munmap on Linux)
	/// </param>
	/// <returns>
	/// True if the operation succeeded, false otherwise.
	/// </returns>
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_finalize(cmts_deallocate_function_pointer_t deallocate);

	/// <summary>
	/// Forcibly terminates all worker threads and releases the resources used by the library.
	/// </summary>
	/// <param name="deallocate">
	/// Specifies the memory deallocation function.
	/// </param>
	/// <returns>
	/// True if the operation succeeded, false otherwise.
	/// </returns>
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_terminate(cmts_deallocate_function_pointer_t deallocate);

	/// <summary>
	/// Returns whether the calling function is being executed inside of a task.
	/// </summary>
	/// <returns>
	/// True if the calling function is being executed inside of a task, false otherwise.
	/// </returns>
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_task();

	/// <summary>
	/// Returns whether the library is initialized
	/// </summary>
	/// <returns>
	/// True if the library is initialized, false otherwise.
	/// </returns>
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_initialized();

	/// <summary>
	/// Returns whether the scheduler is running
	/// </summary>
	/// <returns>
	/// True if the scheduler is running, false otherwise.
	/// </returns>
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_live();

	/// <summary>
	/// Returns whether the scheduler is running
	/// </summary>
	/// <returns>
	/// True if the scheduler is running, false otherwise.
	/// </returns>
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_paused();

	/// <summary>
	/// Submits a task to the cmts scheduler.
	/// </summary>
	/// <param name="entry_point">
	/// A function pointer to be used as the task entry point.
	/// </param>
	/// <param name="options">
	/// Either nullptr or a valid pointer to a cmts_dispatch_options_t structure.
	/// </param>
	/// <returns>
	/// True if the operation succeeded, false if the internal task pool is at maximum capacity.
	/// </returns>
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_dispatch(cmts_function_pointer_t entry_point, const cmts_dispatch_options_t* options);

	/// <summary>
	/// Suspends execution of the current task.
	/// </summary>
	void CMTS_CALLING_CONVENTION cmts_yield();

	/// <summary>
	/// Finishes execution of the current task.
	/// WARNING: This function does NOT call the destructors of stack-allocated objects.
	/// </summary>
	void CMTS_CALLING_CONVENTION cmts_exit();

	/// <summary>
	/// Allocates a fence object.
	/// </summary>
	/// <returns>
	/// A valid handle to a fence object if the operation succeeded, CMTS_NIL_HANDLE otherwise.
	/// </returns>
	CMTS_NODISCARD cmts_fence_t CMTS_CALLING_CONVENTION cmts_new_fence();

	/// <summary>
	/// Determines whether the specified handle references a previously allocated fence.
	/// </summary>
	/// <param name="fence">
	/// The fence handle to test.
	/// </param>
	/// <returns>
	/// True if the handle is valid, false otherwise.
	/// </returns>
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_fence_valid(cmts_fence_t fence);

	/// <summary>
	/// Sets the flag of the fence and resumes execution of any waiting tasks.
	/// </summary>
	/// <param name="fence">
	/// The fence handle to signal.
	/// </param>
	void CMTS_CALLING_CONVENTION cmts_signal_fence(cmts_fence_t fence);

	/// <summary>
	/// Waits for the fence to be signaled.
	/// </summary>
	/// <param name="fence">
	/// The fence handle to wait on.
	/// </param>
	void CMTS_CALLING_CONVENTION cmts_await_fence(cmts_fence_t fence);

	/// <summary>
	/// Waits for the fence to be signaled and then deletes it.
	/// </summary>
	/// <param name="fence">
	/// The fence handle to wait on.
	/// </param>
	void CMTS_CALLING_CONVENTION cmts_await_fence_and_delete(cmts_fence_t fence);

	/// <summary>
	/// Deletes the specified fence.
	/// </summary>
	/// <param name="fence">
	/// The fence handle to delete.
	/// </param>
	void CMTS_CALLING_CONVENTION cmts_delete_fence(cmts_fence_t fence);

	/// <summary>
	/// Allocates a counter object.
	/// </summary>
	/// <param name="start_value">
	/// The initial value stored internally by the counter.
	/// </param>
	/// <returns>
	/// A valid handle to a counter object if the operation succeeded, CMTS_NIL_HANDLE otherwise.
	/// </returns>
	CMTS_NODISCARD cmts_counter_t CMTS_CALLING_CONVENTION cmts_new_counter(uint32_t start_value);

	/// <summary>
	/// Determines whether the specified handle references a previously allocated counter.
	/// </summary>
	/// <param name="counter">
	/// The counter handle to test.
	/// </param>
	/// <returns>
	/// True if the handle is valid, false otherwise.
	/// </returns>
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_counter_valid(cmts_counter_t counter);

	/// <summary>
	/// Waits for the counter's value to reach zero.
	/// </summary>
	/// <param name="counter">
	/// The counter handle to wait on.
	/// </param>
	void CMTS_CALLING_CONVENTION cmts_await_counter(cmts_counter_t counter);

	/// <summary>
	/// Waits for the counter's value to reach zero and then deletes it.
	/// </summary>
	/// <param name="counter">
	/// The counter handle to wait on.
	/// </param>
	void CMTS_CALLING_CONVENTION cmts_await_counter_and_delete(cmts_counter_t counter);

	/// <summary>
	/// Deletes the specified counter.
	/// </summary>
	/// <param name="counter">
	/// The counter handle to delete.
	/// </param>
	void CMTS_CALLING_CONVENTION cmts_delete_counter(cmts_counter_t counter);

	/// <summary>
	/// Submits a task to the cmts scheduler.
	/// </summary>
	/// <param name="entry_point">
	/// A function pointer to be used as the task entry point.
	/// </param>
	/// <param name="param">
	/// The parameter to be passed to the task entry point.
	/// </param>
	/// <param name="priority">
	/// The scheduling priority of the task.
	/// </param>
	/// <param name="fence">
	/// A handle to the fence to signal once the task completes.
	/// </param>
	/// <returns>
	/// True if the operation succeeded, false if the internal task pool is at maximum capacity.
	/// </returns>
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_dispatch_with_fence(cmts_function_pointer_t entry_point, void* param, uint8_t priority, cmts_fence_t fence);

	/// <summary>
	/// Submits a task to the cmts scheduler.
	/// </summary>
	/// <param name="entry_point">
	/// A function pointer to be used as the task entry point.
	/// </param>
	/// <param name="param">
	/// The parameter to be passed to the task entry point.
	/// </param>
	/// <param name="priority">
	/// The scheduling priority of the task.
	/// </param>
	/// <param name="counter">
	/// A handle to the counter to decrement once the task completes.
	/// </param>
	/// <returns>
	/// True if the operation succeeded, false if the internal task pool is at maximum capacity.
	/// </returns>
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_dispatch_with_counter(cmts_function_pointer_t entry_point, void* param, uint8_t priority, cmts_counter_t counter);

	/// <returns>
	/// Returns the entry point of the current task.
	/// </returns>
	cmts_function_pointer_t CMTS_CALLING_CONVENTION cmts_task_entry_point();

	/// <returns>
	/// Returns the parameter of the current task.
	/// </returns>
	void* CMTS_CALLING_CONVENTION cmts_task_parameter();

	/// <returns>
	/// Returns the id of the current task.
	/// </returns>
	uint64_t CMTS_CALLING_CONVENTION cmts_task_id();

	/// <returns>
	/// Returns the priority of the current task.
	/// </returns>
	uint8_t CMTS_CALLING_CONVENTION cmts_task_priority();

	/// <returns>
	/// The index of the current worker thread.
	/// Equivalent to the current CPU core index if options.use_affinity was true when passed to cmts_init.
	/// </returns>
	uint32_t CMTS_CALLING_CONVENTION cmts_thread_index();

	/// <returns>
	/// The number of worker threads.
	/// </returns>
	uint32_t CMTS_CALLING_CONVENTION cmts_thread_count();

	/// <returns>
	/// The number of CPU cores of the current processor.
	/// This function does not require the library to be initialized.
	/// </returns>
	uint32_t CMTS_CALLING_CONVENTION cmts_core_count();

	/// <summary>Dispatches a group of tasks and then waits for them to complete.</summary>
	/// <param name="begin">The initial value of the internal for loop counter.</param>
	/// <param name="end">The limit value of the internal for loop counter.</param>
	/// <param name="body">The task to execute in the for loop body. The current index of the loop counter is passed to the task, casted to void*.</param>
	void CMTS_CALLING_CONVENTION cmts_parallel_for(cmts_function_pointer_t body, const cmts_parallel_for_options_t* options);

#ifdef __cplusplus
}
#endif



#ifdef CMTS_IMPLEMENTATION
#include "src/cmts_implementation.cpp"
#endif