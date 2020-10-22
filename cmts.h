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
#if defined(__cplusplus)
#if __has_cpp_attribute(nodiscard)
#define CMTS_NODISCARD [[nodiscard]]
#else
#define CMTS_NODISCARD
#endif
#else
#define CMTS_NODISCARD
#endif
#endif

#ifndef CMTS_NORETURN
#if defined(__cplusplus)
#if __has_cpp_attribute(noreturn)
#define CMTS_NORETURN [[noreturn]]
#else
#define CMTS_NORETURN
#endif
#else
#define CMTS_NORETURN
#endif
#endif

#ifndef CMTS_MAX_PRIORITY
#define CMTS_MAX_PRIORITY 3
#elif CMTS_MAX_PRIORITY > 256
#error "Error, CMTS_MAX_PRIORITY must not exceed 256"
#endif

#ifndef CMTS_EXPECTED_CACHE_LINE_SIZE
#ifdef __cplusplus
#if __cplusplus < 201703L
#define CMTS_EXPECTED_CACHE_LINE_SIZE 64
#else
#if __cplusplus < 201703L
#define CMTS_FALSE_SHARING_THRESHOLD 64
#else
#define CMTS_FALSE_SHARING_THRESHOLD std::hardware_destructive_interference_size
#endif
#endif
#else
#define CMTS_EXPECTED_CACHE_LINE_SIZE 64
#endif
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

#define CMTS_MAX_TASKS (1U << 24U)
#define CMTS_NIL_HANDLE (~(uint32_t)0)

/// <summary>
/// CMTS error code enumeration. Negative values indicate an error.
/// </summary>
typedef enum cmts_result_t
{
	CMTS_SUCCESS = 0,
	CMTS_SYNC_OBJECT_EXPIRED = 1,

	CMTS_ERROR_INVALID_PARAMETER = -1,
	CMTS_ERROR_ALLOCATION_FAILURE = -2,
	CMTS_ERROR_DEALLOCATION_FAILURE = -3,
	CMTS_ERROR_THREAD_CREATION_FAILURE = -4,
	CMTS_ERROR_THREAD_AFFINITY_FAILURE = -5,
	CMTS_ERROR_FAILED_TO_RESUME_WORKER_THREAD = -6,
	CMTS_ERROR_FAILED_TO_SUSPEND_WORKER_THREAD = -7,
	CMTS_ERROR_FAILED_TO_TERMINATE_WORKER_THREAD = -8,
	CMTS_ERROR_FAILED_TO_AWAIT_WORKER_THREADS = -9,
	CMTS_DISPATCH_ERROR_TASK_POOL_LIMIT_REACHED = -10,
	CMTS_DISPATCH_ERROR_EXPIRED_SYNC_OBJECT = -11,
	CMTS_ERROR_INVALID_SYNC_OBJECT_HANDLE = -12,
	CMTS_ERROR_EXPIRED_SYNC_OBJECT = -14,

} cmts_result_t;

/// <summary>
/// The function pointer type of a task entry point.
/// </summary>
typedef void(*cmts_function_pointer_t)(void* param);

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
typedef cmts_boolean_t(*cmts_deallocate_function_pointer_t)(void* memory, size_t size);

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

typedef enum cmts_synchronization_type_t
{
	CMTS_SYNC_TYPE_NONE,
	CMTS_SYNC_TYPE_FENCE,
	CMTS_SYNC_TYPE_COUNTER,
	CMTS_SYNC_TYPE_MAX_ENUM,

} cmts_synchronization_type_t;

typedef struct cmts_dispatch_options_t
{
	/// <summary>
	/// The parameter to pass the task entry point.
	/// </summary>
	void* parameter;

	/// <summary>
	/// Either a fence or a counter handle.
	/// Ignored if synchronization_type is set to CMTS_SYNC_TYPE_NONE.
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
extern "C"
{
#endif

	/// <summary>
	/// Initializes the CMTS scheduler.
	/// </summary>
	/// <param name="options">
	/// Either nullptr or a valid pointer to a cmts_init_options_t structure.
	/// </param>
	/// <returns>
	/// CMTS_SUCCESS or an error code.
	/// </returns>
	cmts_result_t CMTS_CALLING_CONVENTION cmts_init(const cmts_init_options_t* options);

	/// <summary>
	/// Halts all worker threads.
	/// </summary>
	/// <returns>
	/// CMTS_SUCCESS or an error code.
	/// </returns>
	cmts_result_t CMTS_CALLING_CONVENTION cmts_break();

	/// <summary>
	/// Resumes all worker threads.
	/// </summary>
	/// <returns>
	/// CMTS_SUCCESS or an error code.
	/// </returns>
	cmts_result_t CMTS_CALLING_CONVENTION cmts_continue();

	/// <summary>
	/// Signals to all worker threads to exit once their current task yields or finishes.
	/// </summary>
	void CMTS_CALLING_CONVENTION cmts_signal_finalize();

	/// <summary>
	/// Waits for all worker threads to finish and releases the resources owned by the scheduler.
	/// </summary>
	/// <param name="deallocate">
	/// Either nullptr or a pointer to a memory deallocation function. If nullptr is passed, the operating system's memory allocator is used (VirtualFree on Windows, munmap on POSIX).
	/// </param>
	/// <returns>
	/// CMTS_SUCCESS or an error code.
	/// </returns>
	cmts_result_t CMTS_CALLING_CONVENTION cmts_finalize(cmts_deallocate_function_pointer_t deallocate);

	/// <summary>
	/// Forcibly terminates all worker threads and releases the resources owned by the scheduler.
	/// </summary>
	/// <param name="deallocate">
	/// Either nullptr or a pointer to a memory deallocation function. If nullptr is passed, the operating system's memory allocator is used (VirtualFree on Windows, munmap on POSIX).
	/// </param>
	/// <returns>
	/// CMTS_SUCCESS or an error code.
	/// </returns>
	cmts_result_t CMTS_CALLING_CONVENTION cmts_terminate(cmts_deallocate_function_pointer_t deallocate);

	/// <returns>
	/// Non-zero if the caller is begin executed as a task.
	/// </returns>
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_task();

	/// <returns>
	/// Non-zero if the CMTS scheduler is initialized.
	/// </returns>
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_initialized();

	/// <returns>
	/// Non-zero if the CMTS scheduler is running and cmts_signal_finalize() has not yet been called.
	/// </returns>
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_live();

	/// <returns>
	/// Non-zero if the worker threads are paused.
	/// </returns>
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_paused();

	/// <summary>
	/// Submits a task to the scheduler.
	/// </summary>
	/// <param name="entry_point">
	/// A function pointer used as the entry point of the task.
	/// </param>
	/// <param name="options">
	/// Either nullptr or a valid pointer to a cmts_dispatch_options_t structure. If nullptr is passed, then nullptr is also passed to the task, no synchronization object (fence or counter) is attached and the task priority is set to 0, indicating maximum priority.
	/// </param>
	/// <returns>
	/// CMTS_SUCCESS or an error code.
	/// </returns>
	cmts_result_t CMTS_CALLING_CONVENTION cmts_dispatch(cmts_function_pointer_t entry_point, const cmts_dispatch_options_t* options);

	/// <summary>
	/// Halts execution of the current task and pushes it to the end of the corresponding queue.
	/// </summary>
	void CMTS_CALLING_CONVENTION cmts_yield();

	/// <summary>
	/// Finishes execution of the current task.
	/// Warning: calling this function does NOT call the destructors of stack-allocated objects.
	/// </summary>
	CMTS_NORETURN void CMTS_CALLING_CONVENTION cmts_exit();

	/// <summary>
	/// Acquires ownership of a fence object.
	/// </summary>
	/// <returns>
	/// Either CMTS_NIL_HANDLE or a valid fence handle.
	/// </returns>
	CMTS_NODISCARD cmts_fence_t CMTS_CALLING_CONVENTION cmts_new_fence();

	/// <param name="fence">
	/// The fence handle to test.
	/// </param>
	/// <returns>
	/// CMTS_ERROR_INVALID_SYNC_OBJECT_HANDLE if the handle is invalid. Otherwise, returns a boolean value casted to cmts_result_t indicating whether the fence has expired.
	/// </returns>
	cmts_result_t CMTS_CALLING_CONVENTION cmts_is_fence_valid(cmts_fence_t fence);

	/// <summary>
	/// Signals the fence, submiting all waiting tasks back to their corresponding queues.
	/// </summary>
	/// <param name="fence">
	/// A handle to the fence to signal.
	/// </param>
	/// <returns>
	/// CMTS_SUCCESS if the operation has succeeded, CMTS_ERROR_EXPIRED_SYNC_OBJECT if the fence has already expired.
	/// </returns>
	cmts_result_t CMTS_CALLING_CONVENTION cmts_signal_fence(cmts_fence_t fence);

	/// <summary>
	/// Halts execution of the current task until the fence is signaled.
	/// </summary>
	/// <param name="fence">
	/// A valid handle to a fence object.
	/// </param>
	/// <returns>
	/// CMTS_SUCCESS if the operation has succeeded, CMTS_SYNC_OBJECT_EXPIRED if the fence expired while attepting to add the current task to its wait list or CMTS_ERROR_EXPIRED_SYNC_OBJECT if the fence expired before that.
	/// </returns>
	cmts_result_t CMTS_CALLING_CONVENTION cmts_await_fence(cmts_fence_t fence);

	/// <summary>
	/// Halts execution of the current task until the fence is signaled. Then it releases ownership of the fence object.
	/// </summary>
	/// <param name="fence">
	/// A valid handle to a fence object.
	/// </param>
	/// <returns>
	/// CMTS_SUCCESS if the operation has succeeded, CMTS_SYNC_OBJECT_EXPIRED if the fence expired while attepting to add the current task to its wait list or CMTS_ERROR_EXPIRED_SYNC_OBJECT if the fence expired before that.
	/// </returns>
	cmts_result_t CMTS_CALLING_CONVENTION cmts_await_fence_and_delete(cmts_fence_t fence);

	/// <summary>
	/// Releases ownership of the specified fence object.
	/// </summary>
	/// <param name="fence">
	/// A valid handle to a fence object.
	/// </param>
	/// <returns>
	/// CMTS_SUCCESS if the operation has succeeded, CMTS_ERROR_EXPIRED_SYNC_OBJECT if the handle has already expired.
	/// </returns>
	cmts_result_t CMTS_CALLING_CONVENTION cmts_delete_fence(cmts_fence_t fence);

	/// <summary>
	/// Acquires ownership of a counter object.
	/// </summary>
	/// <returns>
	/// Either CMTS_NIL_HANDLE or a valid counter handle.
	/// </returns>
	CMTS_NODISCARD cmts_counter_t CMTS_CALLING_CONVENTION cmts_new_counter(uint32_t start_value);

	/// <param name="counter">
	/// The counter handle to test.
	/// </param>
	/// <returns>
	/// CMTS_ERROR_INVALID_SYNC_OBJECT_HANDLE if the handle is invalid. Otherwise, returns a boolean value casted to cmts_result_t indicating whether the counter has expired.
	/// </returns>
	cmts_result_t CMTS_CALLING_CONVENTION cmts_is_counter_valid(cmts_counter_t counter);

	/// <summary>
	/// Halts execution of the current task until the counter is signaled.
	/// </summary>
	/// <param name="counter">
	/// A valid handle to a counter object.
	/// </param>
	/// <returns>
	/// CMTS_SUCCESS if the operation has succeeded, CMTS_SYNC_OBJECT_EXPIRED if the counter expired while attepting to add the current task to its wait list or CMTS_ERROR_EXPIRED_SYNC_OBJECT if the counter expired before that.
	/// </returns>
	cmts_result_t CMTS_CALLING_CONVENTION cmts_await_counter(cmts_counter_t counter);

	/// <summary>
	/// Halts execution of the current task until the counter is signaled. Then it releases ownership of the counter object.
	/// </summary>
	/// <param name="counter">
	/// A valid handle to a counter object.
	/// </param>
	/// <returns>
	/// CMTS_SUCCESS if the operation has succeeded, CMTS_SYNC_OBJECT_EXPIRED if the counter expired while attepting to add the current task to its wait list or CMTS_ERROR_EXPIRED_SYNC_OBJECT if the counter expired before that.
	/// </returns>
	cmts_result_t CMTS_CALLING_CONVENTION cmts_await_counter_and_delete(cmts_counter_t counter);

	/// <summary>
	/// Releases ownership of the specified counter object.
	/// </summary>
	/// <param name="counter">
	/// A valid handle to a counter object.
	/// </param>
	/// <returns>
	/// CMTS_SUCCESS if the operation has succeeded, CMTS_ERROR_EXPIRED_SYNC_OBJECT if the handle has already expired.
	/// </returns>
	cmts_result_t CMTS_CALLING_CONVENTION cmts_delete_counter(cmts_counter_t counter);

	/// <returns>
	/// The function pointer used as the entry point of the current task.
	/// </returns>
	cmts_function_pointer_t CMTS_CALLING_CONVENTION cmts_task_entry_point();

	/// <returns>
	/// The parameter passed to the entry point of the current task.
	/// </returns>
	void* CMTS_CALLING_CONVENTION cmts_task_parameter();

	/// <returns>
	/// The ID of the current task.
	/// </returns>
	uint64_t CMTS_CALLING_CONVENTION cmts_task_id();

	/// <returns>
	/// A value ranging from 0 (highest) to CMTS_MAX_PRIORITY (lowest), indicating the priority of the current task.
	/// </returns>
	uint8_t CMTS_CALLING_CONVENTION cmts_task_priority();

	/// <returns>
	/// The index of the current worker thread.
	/// </returns>
	uint32_t CMTS_CALLING_CONVENTION cmts_thread_index();

	/// <returns>
	/// The number of worker threads used by CMTS.
	/// </returns>
	uint32_t CMTS_CALLING_CONVENTION cmts_thread_count();

	/// <returns>
	/// The number of cores of the current CPU.
	/// </returns>
	uint32_t CMTS_CALLING_CONVENTION cmts_cpu_core_count();

	/// <summary>
	/// Executes a group of tasks, emulating a parallel for-loop.
	/// </summary>
	/// <param name="body">
	/// The body of the for-loop.
	/// </param>
	/// <param name="options">
	/// A valid pointer to a cmts_parallel_for_options_t structure.
	/// </param>
	void CMTS_CALLING_CONVENTION cmts_parallel_for(cmts_function_pointer_t body, const cmts_parallel_for_options_t* options);

#ifdef __cplusplus
}
#endif


#ifdef CMTS_IMPLEMENTATION
#include "src/cmts_implementation.cpp"
#endif