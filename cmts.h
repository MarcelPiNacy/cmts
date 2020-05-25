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



#ifndef CMTS_INCLUDED
#define CMTS_INCLUDED

#include <stdint.h>

typedef void(*cmts_function_pointer_t)(void*);

#ifdef __cplusplus
typedef bool cmts_boolean_t;
#else
typedef _Bool cmts_boolean_t;
#endif

typedef uint64_t cmts_fence_t;
typedef uint64_t cmts_counter_t;

enum
{
	CMTS_MAX_TASKS = 1 << 24
};

#ifdef __cplusplus
extern "C"
{
#endif

	void			cmts_initialize(uint32_t max_tasks, uint32_t max_cpus);
	void			cmts_halt();
	void			cmts_resume();
	void			cmts_signal_finalize();
	void			cmts_finalize();
	void			cmts_terminate();
	cmts_boolean_t	cmts_is_running();
	void			cmts_dispatch(cmts_function_pointer_t task_function, void* param, uint8_t priority_level);
	void			cmts_yield();
	void			cmts_exit();

	cmts_fence_t	cmts_new_fence();
	cmts_boolean_t	cmts_is_fence_valid(cmts_fence_t fence);
	void			cmts_signal_fence(cmts_fence_t fence);
	void			cmts_await_fence(cmts_fence_t fence);
	void			cmts_await_fence_and_delete(cmts_fence_t fence);
	void			cmts_delete_fence(cmts_fence_t fence);

	cmts_counter_t	cmts_new_counter(uint32_t start_value);
	cmts_boolean_t	cmts_is_counter_valid(cmts_counter_t counter);
	void			cmts_increment_counter(cmts_counter_t counter);
	void			cmts_decrement_counter(cmts_counter_t counter);
	void			cmts_await_counter(cmts_counter_t counter);
	void			cmts_await_counter_and_delete(cmts_counter_t counter);
	void			cmts_delete_counter(cmts_counter_t counter);

	void			cmts_dispatch_with_fence(cmts_function_pointer_t task_function, void* param, uint8_t priority_level, cmts_fence_t fence);
	void			cmts_dispatch_with_counter(cmts_function_pointer_t task_function, void* param, uint8_t priority_level, cmts_counter_t counter);

	uint32_t		cmts_current_task_id();
	uint32_t		cmts_current_cpu();
	uint32_t		cmts_used_cpu_count();
	uint32_t		cmts_available_cpu_count();

#ifdef __cplusplus
}
#endif






#if defined(CMTS_IMPLEMENTATION_WINDOWS)

#include <atomic>
#include <intrin.h>
#define WIN32_LEAN_AND_MEAN
#define VC_EXTRALEAN
#define NOMINMAX
#include <Windows.h>

enum : cmts_boolean_t
{
	CMTS_FALSE = 0,
	CMTS_TRUE = 1
};

static uint32_t										cmts_capacity;
static uint32_t										used_cpu_count;
static uint32_t										queue_shard_mod_mask;
static HANDLE* threads;

static thread_local uint32_t						processor_index;
static thread_local HANDLE							root_fiber;
static thread_local uint32_t						current_fiber;


#if defined(DEBUG) || defined(_DEBUG) || !defined(NDEBUG)
#define CMTS_DEBUG
#endif

#ifdef __clang__

#define CMTS_LIKELY_IF(expression) if (__builtin_expect((expression), 1))
#define CMTS_UNLIKELY_IF(expression) if (__builtin_expect((expression), 0))
#define CMTS_ASSUME(expression) __builtin_assume((expression))

#ifdef CMTS_DEBUG
#define CMTS_INLINE_ALWAYS
#define CMTS_INLINE_NEVER
#else
#define CMTS_INLINE_ALWAYS __attribute__((always_inline))
#define CMTS_INLINE_NEVER __attribute__((noinline))
#endif

#elif defined(_MSC_VER) || defined(_MSVC_LANG)

#define CMTS_LIKELY_IF(expression) if ((expression))
#define CMTS_UNLIKELY_IF(expression) if ((expression))
#define CMTS_ASSUME(expression) __assume((expression))

#ifdef CMTS_DEBUG
#define CMTS_INLINE_ALWAYS
#define CMTS_INLINE_NEVER
#else
#define CMTS_INLINE_ALWAYS __forceinline
#define CMTS_INLINE_NEVER __declspec(noinline)
#endif

#else

static_assert(false, "CMTS: Unsupported compiler.");

#endif



#ifdef CMTS_DEBUG

CMTS_INLINE_NEVER
static void cmts_assertion_handler(const char* const message)
{
	for (uint32_t i = 0; i < used_cpu_count; ++i)
		CMTS_LIKELY_IF(i != processor_index)
			SuspendThread(threads[i]);
	OutputDebugStringA(message);
	DebugBreak();
	abort();
}

#define CMTS_ASSERT(expression, message) CMTS_UNLIKELY_IF (!(expression)) cmts_assertion_handler("CMTS:\t" message "\n")

#else

#define CMTS_ASSERT(expression, message) CMTS_ASSUME((expression) == CMTS_TRUE)

#endif



union flag_type
{
	std::atomic<cmts_boolean_t>	safe;
	cmts_boolean_t				unsafe;
};

template <typename A, typename B>
struct cmts_pair
{
	A first;
	B second;
};

struct sharded_lockfree_queue
{
	struct control_block
	{
		uint8_t head, tail, generation, unused;

		constexpr cmts_boolean_t operator == (control_block other) const
		{
			return (head == other.head) & (tail == other.tail) & (generation == other.generation);
		}
	};

	alignas(64) std::atomic<control_block> ctrl;
	alignas(64) std::atomic<uint32_t>* values;

	static uint32_t adjust_index(uint32_t index)
	{
		//return index & queue_shard_mod_mask;
		const uint32_t high = ((uint16_t)(index << 8));
		const uint32_t low = (uint8_t)(index >> 16);
		return (high | low) & queue_shard_mod_mask;
	}

	void initialize(void* memory)
	{
		values = (std::atomic<uint32_t>*)memory;
		memset(values, 255, cmts_capacity * sizeof(std::atomic<uint32_t>));
	}

	cmts_boolean_t store(uint32_t value)
	{
		control_block c, nc;
		while (1)
		{
			nc = c = ctrl.load(std::memory_order_acquire);
			++nc.head;
			CMTS_UNLIKELY_IF(nc.head == c.tail)
				return CMTS_FALSE;
			++nc.generation;

			CMTS_LIKELY_IF(ctrl.load(std::memory_order_relaxed) == c)
			{
				CMTS_LIKELY_IF(ctrl.compare_exchange_strong(c, nc, std::memory_order_acquire, std::memory_order_relaxed))
				{
					const uint32_t i = adjust_index(c.head);
					uint32_t empty = (uint32_t)-1;
					while (1)
					{
						if (values[i].load(std::memory_order_acquire) == empty)
							if (values[i].compare_exchange_weak(empty, value, std::memory_order_release, std::memory_order_relaxed))
								return CMTS_TRUE;
						_mm_pause();
					}
				}
			}
			_mm_pause();
		}
	}

	cmts_pair<cmts_boolean_t, uint32_t> fetch()
	{
		control_block c, nc;
		while (1)
		{
			c = ctrl.load(std::memory_order_acquire);
			CMTS_UNLIKELY_IF(c.head == c.tail)
				return {};
			nc = c;
			++nc.tail;
			++nc.generation;

			CMTS_LIKELY_IF(ctrl.load(std::memory_order_relaxed) == c)
			{
				CMTS_LIKELY_IF(ctrl.compare_exchange_strong(c, nc, std::memory_order_acquire, std::memory_order_relaxed))
				{
					const uint32_t i = adjust_index(c.tail);
					uint32_t empty = (uint32_t)-1;
					while (1)
					{
						uint32_t r = values[i].load(std::memory_order_acquire);
						if (r != empty)
							if (values[i].compare_exchange_weak(r, empty, std::memory_order_release, std::memory_order_relaxed))
								return { CMTS_TRUE, r };
						_mm_pause();
					}
				}
			}
			_mm_pause();
		}
	}
};

using queue_type = sharded_lockfree_queue;

struct alignas(64) fiber_synchronization_state
{
	struct alignas(8) wait_list_control_block { uint32_t head, generation; };

	uint32_t fence_next = (uint32_t)-1;
	uint32_t fence_id = (uint32_t)-1;
	uint32_t counter_id = (uint32_t)-1;
	uint32_t counter_next = (uint32_t)-1;
	std::atomic<wait_list_control_block> fence_wait_list = wait_list_control_block{ (uint32_t)-1, 0 };
	std::atomic<wait_list_control_block> counter_wait_list = wait_list_control_block{ (uint32_t)-1, 0 };
};

struct alignas(64) fiber_state
{
	HANDLE handle;
	cmts_function_pointer_t function;
	void* parameter;
	uint32_t pool_next = (uint32_t)-1;
	uint32_t	priority : 3,
		has_fence : 1,
		has_counter : 1,
		sleeping : 1,
		done : 1;
};

struct fence_state
{
	union { std::atomic<cmts_boolean_t> flag; cmts_boolean_t flag_unsafe; };
	uint32_t generation;
	uint32_t owning_fiber;
	uint32_t pool_next;

	CMTS_INLINE_ALWAYS
	fence_state()
	{
#ifdef CMTS_DEBUG
		owning_fiber = (uint32_t)-1;
#endif
		pool_next = (uint32_t)-1;
	}

	CMTS_INLINE_ALWAYS ~fence_state() { }
};

struct counter_state
{
	union { std::atomic<uint32_t> counter; uint32_t counter_unsafe; };
	uint32_t generation;
	uint32_t owning_fiber;
	uint32_t pool_next;

	CMTS_INLINE_ALWAYS
	counter_state()
	{
#ifdef CMTS_DEBUG
		owning_fiber = (uint32_t)-1;
#endif
		pool_next = (uint32_t)-1;
	}

	CMTS_INLINE_ALWAYS ~counter_state() { }
};

struct pool_control_block
{
	uint32_t freelist = (uint32_t)-1;
	uint32_t generation = 0;
};



//@region thread-shared state group 2

static fiber_state* fiber_pool;
static fence_state* fence_pool;
static counter_state* counter_pool;
static fiber_synchronization_state* fiber_sync;

alignas(64) static std::atomic<pool_control_block>	fiber_pool_ctrl;
alignas(64) static std::atomic<uint32_t>			fiber_pool_size;

alignas(64) static std::atomic<pool_control_block>	fence_pool_ctrl;
alignas(64) static std::atomic<uint32_t>			fence_pool_size;

alignas(64) static std::atomic<pool_control_block>	counter_pool_ctrl;
alignas(64) static std::atomic<uint32_t>			counter_pool_size;

alignas(64) static queue_type						queues[4];

alignas(64) static flag_type						should_continue = {};

//!@region thread-shared state group 2



CMTS_INLINE_ALWAYS
static uint64_t make_user_handle(uint32_t value, uint32_t generation)
{
	return (uint64_t)((uint64_t)value | ((uint64_t)generation << 32));
}

CMTS_INLINE_ALWAYS
static uint32_t timestamp_frequency()
{
	LARGE_INTEGER i;
	QueryPerformanceFrequency(&i);
	return (uint32_t)i.LowPart;
}

CMTS_INLINE_ALWAYS
static uint32_t timestamp()
{
	LARGE_INTEGER i;
	QueryPerformanceCounter(&i);
	return (uint32_t)i.LowPart;
}

CMTS_INLINE_ALWAYS
static uint32_t timestamp_ns()
{
	return (timestamp() * 1000'000'000) / timestamp_frequency();
}

CMTS_INLINE_NEVER
static void conditionally_exit_thread()
{
	CMTS_UNLIKELY_IF(!should_continue.safe.load(std::memory_order_acquire))
		ExitThread(0);
}

CMTS_INLINE_ALWAYS
static void append_fence_wait_list(uint32_t fiber, uint32_t value)
{
	fiber_synchronization_state::wait_list_control_block c, nc;
	fiber_synchronization_state& s = fiber_sync[fiber];
	while (1)
	{
		nc = c = s.fence_wait_list.load(std::memory_order_acquire);
		s.fence_next = nc.head;
		nc.head = value;
		++nc.generation;
		CMTS_LIKELY_IF(s.fence_wait_list.compare_exchange_strong(c, nc, std::memory_order_release, std::memory_order_relaxed))
			break;
		_mm_pause();
	}
}

CMTS_INLINE_ALWAYS
static uint32_t fetch_fence_wait_list(uint32_t fiber)
{
	fiber_synchronization_state::wait_list_control_block c, nc;
	fiber_synchronization_state& s = fiber_sync[fiber];
	while (1)
	{
		nc = c = s.fence_wait_list.load(std::memory_order_acquire);
		const uint32_t r = c.head;
		CMTS_UNLIKELY_IF(r == (uint32_t)-1)
			return (uint32_t)-1;
		nc.head = fiber_sync[nc.head].fence_next;
		++nc.generation;
		CMTS_LIKELY_IF(s.fence_wait_list.compare_exchange_strong(c, nc, std::memory_order_release, std::memory_order_relaxed))
			return r;
		_mm_pause();
	}
}

CMTS_INLINE_ALWAYS
static void append_counter_wait_list(uint32_t fiber, uint32_t value)
{
	fiber_synchronization_state::wait_list_control_block c, nc;
	fiber_synchronization_state& s = fiber_sync[fiber];
	while (1)
	{
		nc = c = s.counter_wait_list.load(std::memory_order_acquire);
		s.fence_next = nc.head;
		nc.head = value;
		++nc.generation;
		CMTS_LIKELY_IF(s.counter_wait_list.compare_exchange_strong(c, nc, std::memory_order_release, std::memory_order_relaxed))
			break;
		_mm_pause();
	}
}

CMTS_INLINE_ALWAYS
static uint32_t fetch_counter_wait_list(uint32_t fiber)
{
	fiber_synchronization_state::wait_list_control_block c, nc;
	fiber_synchronization_state& s = fiber_sync[fiber];
	while (1)
	{
		nc = c = s.counter_wait_list.load(std::memory_order_acquire);
		const uint32_t r = c.head;
		CMTS_UNLIKELY_IF(r == (uint32_t)-1)
			return (uint32_t)-1;
		nc.head = fiber_sync[nc.head].fence_next;
		++nc.generation;
		CMTS_LIKELY_IF(s.counter_wait_list.compare_exchange_strong(c, nc, std::memory_order_release, std::memory_order_relaxed))
			return r;
		_mm_pause();
	}
}

CMTS_INLINE_ALWAYS
static uint32_t new_fiber()
{
	pool_control_block c, nc;
	uint32_t r = (uint32_t)-1;
	while (1)
	{
		while (fiber_pool_size.load(std::memory_order_acquire) == cmts_capacity)
			_mm_pause();

		c = fiber_pool_ctrl.load(std::memory_order_acquire);
		CMTS_LIKELY_IF(c.freelist != (uint32_t)-1)
		{
			nc = c;
			r = nc.freelist;
			nc.freelist = fiber_pool[r].pool_next;
			++nc.generation;
			CMTS_LIKELY_IF(fiber_pool_ctrl.compare_exchange_strong(c, nc, std::memory_order_release, std::memory_order_relaxed))
				break;
		}
		else
		{
			uint32_t k = fiber_pool_size.load(std::memory_order_acquire);
			CMTS_UNLIKELY_IF(k == cmts_capacity)
				continue;
			r = k + 1;
			CMTS_LIKELY_IF(fiber_pool_size.compare_exchange_strong(k, r, std::memory_order_release, std::memory_order_relaxed))
				break;
		}
		_mm_pause();
	}
	return r;
}

CMTS_INLINE_ALWAYS
static void delete_fiber(uint32_t fiber)
{
	fiber_state& f = fiber_pool[fiber];
	HANDLE h = f.handle;
	new (&f) fiber_state();
	f.handle = h;
	pool_control_block c, nc;
	while (1)
	{
		c = fiber_pool_ctrl.load(std::memory_order_acquire);
		nc = c;
		f.pool_next = nc.freelist;
		nc.freelist = fiber;
		++nc.generation;
		CMTS_LIKELY_IF(fiber_pool_ctrl.compare_exchange_strong(c, nc, std::memory_order_release, std::memory_order_relaxed))
			break;
		_mm_pause();
	}
}

CMTS_INLINE_ALWAYS
static void push_fiber(uint32_t fiber, uint8_t priority)
{
	while (1)
	{
		CMTS_UNLIKELY_IF(!should_continue.unsafe)
			conditionally_exit_thread();
		CMTS_LIKELY_IF(queues[priority].store(fiber))
			return;
		_mm_pause();
	}
}

CMTS_INLINE_ALWAYS
static uint32_t fetch_fiber()
{
	uint32_t threshold = 64;
	const uint32_t start = timestamp_ns();
	uint32_t last = start;
	uint32_t long_delay = 1;

	while (1)
	{
		CMTS_UNLIKELY_IF(!should_continue.unsafe)
			conditionally_exit_thread();

		for (queue_type& q : queues)
		{
			const cmts_pair<cmts_boolean_t, uint32_t> r = q.fetch();
			CMTS_LIKELY_IF(r.first)
				return r.second;
		}

		const uint32_t now = timestamp_ns();
		const uint32_t dt = now - last;
		CMTS_LIKELY_IF(dt < threshold)
		{
			_mm_pause();
		}
		else
		{
			CMTS_LIKELY_IF(dt < 1024)
			{
				SwitchToThread();
				last = now;
				threshold = (threshold * 3) / 4;
			}
			else
			{
				Sleep(long_delay);
				++long_delay;
			}
		}
	}
}

CMTS_INLINE_NEVER
static void fence_wake_fibers(uint32_t fence)
{
	while (1)
	{
		const uint32_t n = fetch_fence_wait_list(fence);
		CMTS_UNLIKELY_IF(n == (uint32_t)-1)
			break;
		push_fiber(n, fiber_pool[n].priority);
	}
}

CMTS_INLINE_ALWAYS
static void fence_conditionally_wake_fibers(uint32_t fiber)
{
	fiber_synchronization_state& s = fiber_sync[fiber];
	CMTS_ASSERT(s.fence_id != (uint32_t)-1, "Invalid fiber_sync.counter_id value.");
	CMTS_LIKELY_IF(!fence_pool[s.fence_id].flag.exchange(CMTS_TRUE, std::memory_order_release))
		fence_wake_fibers(s.fence_id);
}

CMTS_INLINE_NEVER
static void counter_wake_fibers(uint32_t fence)
{
	while (1)
	{
		const uint32_t n = fetch_counter_wait_list(fence);
		CMTS_UNLIKELY_IF(n == (uint32_t)-1)
			break;
		push_fiber(n, fiber_pool[n].priority);
	}
}

CMTS_INLINE_ALWAYS
static void counter_conditionally_wake_fibers(uint32_t fiber)
{
	fiber_synchronization_state& s = fiber_sync[fiber];
	CMTS_ASSERT(s.counter_id != (uint32_t)-1, "Invalid fiber_sync.counter_id value.");
	CMTS_LIKELY_IF(counter_pool[s.counter_id].counter.fetch_sub(1, std::memory_order_release) == 0)
		counter_wake_fibers(s.counter_id);
}

static void __stdcall fiber_main(fiber_state* f)
{
	while (1)
	{
		CMTS_UNLIKELY_IF(!should_continue.unsafe)
			conditionally_exit_thread();
		f->function(f->parameter);
		f->done = CMTS_TRUE;
		SwitchToFiber(root_fiber);
	}
}

static DWORD __stdcall thread_main(void* param)
{
	processor_index = (uint32_t)(size_t)param;
	root_fiber = ConvertThreadToFiberEx(nullptr, FIBER_FLAG_FLOAT_SWITCH);
	while (1)
	{
		CMTS_UNLIKELY_IF(!should_continue.unsafe)
			conditionally_exit_thread();
		current_fiber = fetch_fiber();
		fiber_state& f = fiber_pool[current_fiber];
		SwitchToFiber(f.handle);
		if (!f.done)
		{
			if (!f.sleeping)
				push_fiber(current_fiber, f.priority);
		}
		else
		{
			if (f.has_fence)
				fence_conditionally_wake_fibers(current_fiber);
			if (f.has_counter)
				counter_conditionally_wake_fibers(current_fiber);
			delete_fiber(current_fiber);
		}
	}
}



#ifdef __cplusplus
extern "C"
{
#endif

	// Initializes CMTS with the specified maximum number of tasks.
	void cmts_initialize(uint32_t max_fibers, uint32_t max_cpus)
	{
		CMTS_ASSERT(max_fibers <= CMTS_MAX_TASKS, "The requested scheduler capacity passed to cmts_initialize exceeds the supported limit");
		CMTS_ASSERT(__popcnt(max_fibers) == 1, "The requested scheduler capacity passed to cmts_initialize must be a power of 2");

		CMTS_UNLIKELY_IF(should_continue.safe.load(std::memory_order_acquire))
			return;

		cmts_capacity = max_fibers;
		queue_shard_mod_mask = max_fibers - 1;
		should_continue.safe.store(CMTS_TRUE, std::memory_order_release);
		const uint32_t core_count = cmts_available_cpu_count();
		used_cpu_count = max_cpus < core_count ? max_cpus : core_count;
		constexpr uint32_t queue_count = sizeof(queues) / sizeof(queues[0]);
		const uint32_t qss = cmts_capacity * sizeof(std::atomic<uint32_t>);
		const size_t allocation_size =
			(used_cpu_count * sizeof(HANDLE)) +
			(qss * queue_count) +
			(max_fibers * (sizeof(fiber_state) + sizeof(fence_state) + sizeof(counter_state) + sizeof(fiber_synchronization_state)));

		uint8_t* ptr = (uint8_t*)VirtualAlloc(nullptr, allocation_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		threads = (HANDLE*)ptr;
		fiber_pool = (fiber_state*)(threads + used_cpu_count);
		fence_pool = (fence_state*)(fiber_pool + max_fibers);
		counter_pool = (counter_state*)(fence_pool + max_fibers);
		fiber_sync = (fiber_synchronization_state*)(counter_pool + max_fibers);
		uint8_t* qptr = (uint8_t*)(fiber_sync + max_fibers);

		for (uint32_t i = 0; i < queue_count; ++i)
			queues[i].initialize(qptr + i * qss);

		for (uint32_t i = 0; i < max_fibers; ++i)
		{
			new (&fiber_pool[i]) fiber_state();
			new (&fence_pool[i]) fence_state();
			new (&counter_pool[i]) counter_state();
			new (&fiber_sync[i]) fiber_synchronization_state();
		}

		DWORD tmp;
		for (uint32_t i = 0; i < used_cpu_count; ++i)
		{
			threads[i] = CreateThread(nullptr, 1 << 21, thread_main, (void*)(size_t)i, CREATE_SUSPENDED, &tmp);
			SetThreadAffinityMask(threads[i], ((DWORD_PTR)1U << (DWORD_PTR)i));
			ResumeThread(threads[i]);
		}
	}

	// Pauses all CMTS worker threads.
	void cmts_halt()
	{
		for (uint32_t i = 0; i < used_cpu_count; ++i)
			SuspendThread(threads[i]);
	}

	// Resumes execution of all CMTS worker threads.
	void cmts_resume()
	{
		for (uint32_t i = 0; i < used_cpu_count; ++i)
			ResumeThread(threads[i]);
	}

	// Tells CMTS to finish execution: all threads will finish once all running tasks either yield or exit.
	void cmts_signal_finalize()
	{
		should_continue.safe.store(CMTS_FALSE, std::memory_order_release);
	}

	// Waits for all CMTS threads to exit and returns allocated memory to the OS.
	void cmts_finalize()
	{
		WaitForMultipleObjects(used_cpu_count, threads, CMTS_TRUE, INFINITE);
		VirtualFree(threads, 0, MEM_RELEASE);
		ConvertFiberToThread();
	}

	// Terminates all CMTS threads and calls cmts_finalize.
	void cmts_terminate()
	{
		cmts_signal_finalize();
		for (uint32_t i = 0; i < used_cpu_count; ++i)
			TerminateThread(threads[i], -1);
		VirtualFree(threads, 0, MEM_RELEASE);
		ConvertFiberToThread();
	}

	// Returns whether CMTS is running.
	cmts_boolean_t cmts_is_running()
	{
		return should_continue.unsafe;
	}

	// Submits a task to CMTS.
	void cmts_dispatch(
		cmts_function_pointer_t fiber_function,
		void* param,
		uint8_t priority_level)
	{
		const uint32_t id = new_fiber();
		fiber_state& s = fiber_pool[id];
		s.function = fiber_function;
		s.parameter = param;
		CMTS_UNLIKELY_IF(s.handle == nullptr)
			s.handle = CreateFiberEx(1 << 16, 1 << 16, FIBER_FLAG_FLOAT_SWITCH, (LPFIBER_START_ROUTINE)fiber_main, &fiber_pool[id]);
		push_fiber(id, s.priority);
	}

	// Halts execution of the current task.
	void cmts_yield()
	{
		SwitchToFiber(root_fiber);
	}

	// Finishes execution of the current task.
	void cmts_exit()
	{
		fiber_pool[current_fiber].done = CMTS_TRUE;
		cmts_yield();
	}

	cmts_fence_t cmts_new_fence()
	{
		pool_control_block c, nc;
		uint32_t index = (uint32_t)-1;
		while (1)
		{
			while (fence_pool_size.load(std::memory_order_acquire) == cmts_capacity)
				_mm_pause();

			c = fence_pool_ctrl.load(std::memory_order_acquire);
			CMTS_LIKELY_IF(c.freelist != (uint32_t)-1)
			{
				nc = c;
				index = nc.freelist;
				nc.freelist = fence_pool[index].pool_next;
				++nc.generation;
				CMTS_LIKELY_IF(fence_pool_ctrl.compare_exchange_strong(c, nc, std::memory_order_release, std::memory_order_relaxed))
					break;
			}
			else
			{
				uint32_t k = fence_pool_size.load(std::memory_order_acquire);
				CMTS_UNLIKELY_IF(k == cmts_capacity)
					continue;
				index = k + 1;
				CMTS_LIKELY_IF(fence_pool_size.compare_exchange_strong(k, index, std::memory_order_release, std::memory_order_relaxed))
					break;
			}
		}

		fence_state& f = fence_pool[index];
		f.flag_unsafe = CMTS_FALSE;
		const uint32_t generation = f.generation;
		return make_user_handle(index, generation);
	}

	cmts_boolean_t cmts_is_fence_valid(cmts_fence_t fence)
	{
		const uint32_t index = (uint32_t)fence;
		const uint32_t generation = (uint32_t)(fence >> 32);
		const cmts_boolean_t a = fence_pool[index].owning_fiber != (uint32_t)-1;
		const cmts_boolean_t b = fence_pool[index].generation == generation;
		return a & b;
	}

	void cmts_signal_fence(cmts_fence_t fence)
	{
		const uint32_t index = (uint32_t)fence;
		const uint32_t generation = (uint32_t)(fence >> 32);
		CMTS_ASSERT(fence_pool[index].owning_fiber != (uint32_t)-1, "Invalid fence handle.");
		CMTS_ASSERT(fence_pool[index].generation == generation, "Invalid fence handle, generation mismatch.");
		fence_wake_fibers(fence_pool[index].owning_fiber);
	}

	void cmts_delete_fence(cmts_fence_t fence)
	{
		const uint32_t index = (uint32_t)fence;
		const uint32_t generation = (uint32_t)(fence >> 32);
		CMTS_ASSERT(fence_pool[index].owning_fiber != (uint32_t)-1, "Invalid fence handle.");
		CMTS_ASSERT(fence_pool[index].generation == generation, "Invalid fence handle, generation mismatch.");
		new (&fence_pool[index]) fence_state();
		pool_control_block c, nc;
		while (1)
		{
			c = fence_pool_ctrl.load(std::memory_order_acquire);
			nc = c;
			fence_pool[index].pool_next = nc.freelist;
			nc.freelist = index;
			++nc.generation;
			CMTS_LIKELY_IF(fence_pool_ctrl.compare_exchange_strong(c, nc, std::memory_order_release, std::memory_order_relaxed))
				break;
		}
	}

	void cmts_await_fence(cmts_fence_t fence)
	{
		const uint32_t index = (uint32_t)fence;
		const uint32_t generation = (uint32_t)(fence >> 32);
		CMTS_ASSERT(fence_pool[index].owning_fiber != (uint32_t)-1, "Invalid fence handle.");
		CMTS_ASSERT(fence_pool[index].generation == generation, "Invalid fence handle, generation mismatch.");
		auto& f = fiber_pool[current_fiber];
		f.sleeping = CMTS_TRUE;
		append_fence_wait_list(current_fiber, index);
		cmts_yield();
	}

	void cmts_await_fence_and_delete(cmts_fence_t fence)
	{
		const uint32_t index = (uint32_t)fence;
		const uint32_t generation = (uint32_t)(fence >> 32);
		CMTS_ASSERT(fence_pool[index].owning_fiber != (uint32_t)-1, "Invalid fence handle.");
		CMTS_ASSERT(fence_pool[index].generation == generation, "Invalid fence handle, generation mismatch.");

		auto& f = fiber_pool[current_fiber];
		f.sleeping = CMTS_TRUE;
		append_fence_wait_list(current_fiber, index);
		cmts_yield();
		new (&fence_pool[index]) fence_state();
		pool_control_block c, nc;
		while (1)
		{
			c = fence_pool_ctrl.load(std::memory_order_acquire);
			nc = c;
			fence_pool[index].pool_next = nc.freelist;
			nc.freelist = index;
			++nc.generation;
			CMTS_LIKELY_IF(fence_pool_ctrl.compare_exchange_strong(c, nc, std::memory_order_release, std::memory_order_relaxed))
				break;
		}
	}

	cmts_counter_t cmts_new_counter(uint32_t start_value)
	{
		pool_control_block c;
		uint32_t index = (uint32_t)-1;
		while (1)
		{
			while (counter_pool_size.load(std::memory_order_acquire) == cmts_capacity)
				_mm_pause();

			c = counter_pool_ctrl.load(std::memory_order_acquire);
			CMTS_LIKELY_IF(c.freelist != (uint32_t)-1)
			{
				auto nc = c;
				index = nc.freelist;
				nc.freelist = counter_pool[index].pool_next;
				++nc.generation;
				CMTS_LIKELY_IF(counter_pool_ctrl.compare_exchange_strong(c, nc, std::memory_order_release, std::memory_order_relaxed))
					break;
			}
			else
			{
				auto k = counter_pool_size.load(std::memory_order_acquire);
				CMTS_UNLIKELY_IF(k == cmts_capacity)
					continue;
				index = k + 1;
				CMTS_LIKELY_IF(counter_pool_size.compare_exchange_strong(k, index, std::memory_order_release, std::memory_order_relaxed))
					break;
			}
		}
		counter_pool[index].counter_unsafe = start_value;
		const uint32_t generation = counter_pool[index].generation;
		return make_user_handle(index, generation);
	}

	cmts_boolean_t cmts_is_counter_valid(cmts_counter_t counter)
	{
		const uint32_t index = (uint32_t)counter;
		const uint32_t generation = (uint32_t)(counter >> 32);
		const cmts_boolean_t a = counter_pool[index].owning_fiber != (uint32_t)-1;
		const cmts_boolean_t b = counter_pool[index].generation == generation;
		return a & b;
	}

	void cmts_increment_counter(cmts_counter_t counter)
	{
		const uint32_t index = (uint32_t)counter;
		const uint32_t generation = (uint32_t)(counter >> 32);
		CMTS_ASSERT(counter_pool[index].owning_fiber != (uint32_t)-1, "Invalid counter handle.");
		CMTS_ASSERT(counter_pool[index].generation == generation, "Invalid counter handle, generation mismatch.");
		counter_pool[index].counter.fetch_add(1, std::memory_order_relaxed);
	}

	void cmts_decrement_counter(cmts_counter_t counter)
	{
		const uint32_t index = (uint32_t)counter;
		const uint32_t generation = (uint32_t)(counter >> 32);
		CMTS_ASSERT(counter_pool[index].owning_fiber != (uint32_t)-1, "Invalid counter handle.");
		CMTS_ASSERT(counter_pool[index].generation == generation, "Invalid counter handle, generation mismatch.");
		counter_pool[index].counter.fetch_sub(1, std::memory_order_relaxed);
	}

	void cmts_await_counter(cmts_counter_t counter)
	{
		const uint32_t index = (uint32_t)counter;
		const uint32_t generation = (uint32_t)(counter >> 32);
		CMTS_ASSERT(counter_pool[index].owning_fiber != (uint32_t)-1, "Invalid counter handle.");
		CMTS_ASSERT(counter_pool[index].generation == generation, "Invalid counter handle, generation mismatch.");
		auto& f = fiber_pool[current_fiber];
		f.sleeping = CMTS_TRUE;
		append_counter_wait_list(current_fiber, index);
		cmts_yield();
	}

	void cmts_await_counter_and_delete(cmts_counter_t counter)
	{
		const uint32_t index = (uint32_t)counter;
		const uint32_t generation = (uint32_t)(counter >> 32);
		CMTS_ASSERT(counter_pool[index].owning_fiber != (uint32_t)-1, "Invalid counter handle.");
		CMTS_ASSERT(counter_pool[index].generation == generation, "Invalid counter handle, generation mismatch.");
		auto& f = fiber_pool[current_fiber];
		f.sleeping = CMTS_TRUE;
		append_counter_wait_list(current_fiber, index);
		cmts_yield();
		new (&counter_pool[index]) counter_state();
		pool_control_block c, nc;
		while (1)
		{
			c = counter_pool_ctrl.load(std::memory_order_acquire);
			nc = c;
			counter_pool[index].pool_next = nc.freelist;
			nc.freelist = index;
			++nc.generation;
			CMTS_LIKELY_IF(counter_pool_ctrl.compare_exchange_strong(c, nc, std::memory_order_release, std::memory_order_relaxed))
				break;
		}
	}

	void cmts_delete_counter(cmts_counter_t counter)
	{
		const uint32_t index = (uint32_t)counter;
		const uint32_t generation = (uint32_t)(counter >> 32);
		CMTS_ASSERT(counter_pool[index].owning_fiber != (uint32_t)-1, "Invalid counter handle.");
		CMTS_ASSERT(counter_pool[index].generation == generation, "Invalid counter handle, generation mismatch.");
		new (&counter_pool[index]) counter_state();
		pool_control_block c, nc;
		while (1)
		{
			c = counter_pool_ctrl.load(std::memory_order_acquire);
			nc = c;
			counter_pool[index].pool_next = nc.freelist;
			nc.freelist = index;
			++nc.generation;
			CMTS_LIKELY_IF(counter_pool_ctrl.compare_exchange_strong(c, nc, std::memory_order_release, std::memory_order_relaxed))
				break;
		}
	}

	void cmts_dispatch_with_fence(cmts_function_pointer_t task_function, void* param, uint8_t priority_level, cmts_fence_t fence)
	{
		const uint32_t index = (uint32_t)fence;
		const uint32_t generation = (uint32_t)(fence >> 32);
		CMTS_ASSERT(fence_pool[index].owning_fiber != (uint32_t)-1, "Invalid fence handle.");
		CMTS_ASSERT(fence_pool[index].generation == generation, "Invalid fence handle, generation mismatch.");
		const uint32_t id = new_fiber();
		auto& f = fiber_pool[id];
		f.function = task_function;
		f.parameter = param;
		f.has_fence = CMTS_TRUE;
		fiber_sync[id].fence_id = index;
		fence_pool[index].owning_fiber = current_fiber;
		CMTS_UNLIKELY_IF(f.handle == nullptr)
			f.handle = CreateFiberEx(1 << 16, 1 << 16, FIBER_FLAG_FLOAT_SWITCH, (LPFIBER_START_ROUTINE)fiber_main, &f);
		push_fiber(id, f.priority);
	}

	void cmts_dispatch_with_counter(cmts_function_pointer_t task_function, void* param, uint8_t priority_level, cmts_counter_t counter)
	{
		const uint32_t index = (uint32_t)counter;
		const uint32_t generation = (uint32_t)(counter >> 32);
		CMTS_ASSERT(fence_pool[index].owning_fiber != (uint32_t)-1, "Invalid counter handle.");
		CMTS_ASSERT(fence_pool[index].generation == generation, "Invalid counter handle, generation mismatch.");
		const uint32_t id = new_fiber();
		auto& f = fiber_pool[id];
		f.function = task_function;
		f.parameter = param;
		f.has_counter = CMTS_TRUE;
		fiber_sync[id].counter_id = index;
		counter_pool[index].owning_fiber = current_fiber;
		CMTS_UNLIKELY_IF(f.handle == nullptr)
			f.handle = CreateFiberEx(1 << 16, 1 << 16, FIBER_FLAG_FLOAT_SWITCH, (LPFIBER_START_ROUTINE)fiber_main, &f);
		push_fiber(id, f.priority);
	}

	uint32_t cmts_current_task_id()
	{
		return current_fiber;
	}

	uint32_t cmts_current_cpu()
	{
		return processor_index;
	}

	uint32_t cmts_used_cpu_count()
	{
		return used_cpu_count;
	}

	uint32_t cmts_available_cpu_count()
	{
		SYSTEM_INFO info;
		GetSystemInfo(&info);
		return (uint32_t)info.dwNumberOfProcessors;
	}

#ifdef __cplusplus
}
#endif

#undef CMTS_DEBUG
#undef CMTS_LIKELY_IF
#undef CMTS_UNLIKELY_IF
#undef CMTS_ASSERT
#undef CMTS_ASSUME
#undef CMTS_INLINE_ALWAYS
#undef CMTS_INLINE_NEVER

#endif //CMTS_IMPLEMENTATION_WINDOWS



#endif //CMTS_INCLUDED