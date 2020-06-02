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



#include "cmts.h"
#include <atomic>
#include <intrin.h>
#define WIN32_LEAN_AND_MEAN
#define VC_EXTRALEAN
#define NOMINMAX
#include <Windows.h>

alignas(64) static thread_local uint32_t			current_fiber;
static thread_local HANDLE							root_fiber;
static thread_local uint32_t						processor_index;

static const uint32_t cache_line_size_log2 = []() noexcept
{
	DWORD k = 0;
	GetLogicalProcessorInformation(nullptr, &k);
	SYSTEM_LOGICAL_PROCESSOR_INFORMATION* const buffer = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION*)alloca(k);
	GetLogicalProcessorInformation(buffer, &k);
	for (uint32_t i = 0; i < k; ++i)
		if ((buffer[i].Cache.Level == 1) & (buffer[i].Relationship == RelationCache))
		{
			unsigned long n;
			const uint32_t l = buffer[i].Cache.LineSize;
			_BitScanForward(&n, l);
			return n;
		}
	abort();
}();

static uint32_t										max_tasks;
static uint32_t										used_cpu_count;
static uint32_t										queue_shard_mod_mask;
static HANDLE*										threads;


#if (defined(DEBUG) || defined(_DEBUG) || !defined(NDEBUG)) && !defined(CMTS_DEBUG)
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
CMTS_INLINE_NEVER static void cmts_assertion_handler(const char* const message) noexcept
{
	cmts_halt();
	OutputDebugStringA(message);
	DebugBreak();
	abort();
}
#define CMTS_ASSERT(expression, message) CMTS_UNLIKELY_IF (!(expression)) cmts_assertion_handler("CMTS:\t" message "\n")
#else
#define CMTS_ASSERT(expression, message) CMTS_ASSUME((expression) == true)
#endif

#define CMTS_ASSERT_IS_TASK CMTS_ASSERT(cmts_is_task(), "CMTS: function " __FUNCTION__ " must be called from a task.")



union flag_type
{
	std::atomic_bool safe;
	bool unsafe;
};

struct lockfree_queue
{
	struct alignas(64) control_block
	{
		uint64_t head : 24, tail : 24, generation : 8;

		CMTS_INLINE_ALWAYS
		bool operator==(const control_block& other) const noexcept
		{
			return *(const uint64_t*)this == *(const uint64_t*)&other;
		}

		CMTS_INLINE_ALWAYS
		bool operator!=(const control_block& other) const noexcept
		{
			return !this->operator==(other);
		}
	};

	alignas(64) std::atomic<control_block> ctrl;
	alignas(64) std::atomic<uint32_t>* values;

	CMTS_INLINE_ALWAYS
	static uint32_t adjust_index(const uint32_t index) noexcept
	{
		const uint32_t sl = cache_line_size_log2;
		const uint32_t sr = 24 - sl;
		const uint32_t high = index << sl;
		const uint32_t low = index >> sr;
		return (high | low) & queue_shard_mod_mask;
	}

	CMTS_INLINE_ALWAYS
	void initialize(void* memory) noexcept
	{
		values = (std::atomic<uint32_t>*)memory;
		memset(values, 255, max_tasks * sizeof(std::atomic<uint32_t>));
	}

	bool store(const uint32_t value) noexcept
	{
		control_block c, nc;
		while (true)
		{
			nc = c = ctrl.load(std::memory_order_acquire);
			++nc.head;
			CMTS_UNLIKELY_IF(nc.head == c.tail)
				return false;
			++nc.generation;
			CMTS_LIKELY_IF(ctrl.load(std::memory_order_relaxed) == c)
			{
				CMTS_LIKELY_IF(ctrl.compare_exchange_strong(c, nc, std::memory_order_acquire, std::memory_order_relaxed))
				{
					const uint32_t i = adjust_index(c.head);
					uint32_t empty = (uint32_t)-1;
					while (true)
					{
						CMTS_LIKELY_IF(values[i].load(std::memory_order_acquire) == empty)
							CMTS_LIKELY_IF(values[i].compare_exchange_strong(empty, value, std::memory_order_release, std::memory_order_relaxed))
								return true;
						_mm_pause();
					}
				}
			}
		}
	}

	bool fetch(uint32_t& out) noexcept
	{
		control_block c, nc;
		while (true)
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
					while (true)
					{
						out = values[i].load(std::memory_order_acquire);
						CMTS_LIKELY_IF(out != empty)
							CMTS_LIKELY_IF(values[i].compare_exchange_strong(out, empty, std::memory_order_release, std::memory_order_relaxed))
								return true;
						_mm_pause();
					}
				}
			}
		}
	}
};

struct alignas(8) wait_list_control_block
{
	uint32_t head;
	uint32_t generation;

	CMTS_INLINE_ALWAYS
	bool operator==(const wait_list_control_block& other) const noexcept
	{
		return *(const uint64_t*)this == *(const uint64_t*)&other;
	}

	CMTS_INLINE_ALWAYS
	bool operator!=(const wait_list_control_block& other) const noexcept
	{
		return !this->operator==(other);
	}
};

struct alignas(64) fiber_state
{
	using F = cmts_function_pointer_t;

	HANDLE		handle;
	F			function;
	void*		parameter;
	uint32_t	pool_next;
	uint32_t	priority : 3,
				has_fence : 1,
				has_counter : 1,
				sleeping : 1,
				done : 1;

	uint32_t	fence_id;
	uint32_t	counter_id;

	uint32_t	fence_next;
	uint32_t	counter_next;

	CMTS_INLINE_ALWAYS
	void reset() noexcept
	{
		has_fence = false;
		has_counter = false;
		sleeping = false;
		done = false;
		pool_next = (uint32_t)-1;
		fence_id = (uint32_t)-1;
		counter_id = (uint32_t)-1;
		fence_next = (uint32_t)-1;
		counter_next = (uint32_t)-1;
	}

};

struct alignas(64) fence_state
{
	union
	{
		std::atomic_bool flag;
		bool flag_unsafe;
	};
	std::atomic_uint32_t generation;
	uint32_t pool_next;
	union
	{
		std::atomic<wait_list_control_block> wait_list;
		wait_list_control_block wait_list_unsafe;
	};

	CMTS_INLINE_ALWAYS
	void reset() noexcept
	{
		pool_next = (uint32_t)-1;
		wait_list_unsafe.head = (uint32_t)-1;
	}

};

struct alignas(64) counter_state
{
	union
	{
		std::atomic_uint32_t counter;
		uint32_t counter_unsafe;
	};
	std::atomic_uint32_t generation;
	uint32_t pool_next;
	union
	{
		std::atomic<wait_list_control_block> wait_list;
		wait_list_control_block wait_list_unsafe;
	};

	CMTS_INLINE_ALWAYS
	void reset() noexcept
	{
		pool_next = (uint32_t)-1;
		wait_list_unsafe.head = (uint32_t)-1;
	}

};

struct alignas(8) pool_control_block
{
	uint32_t freelist = (uint32_t)-1;
	uint32_t generation = 0;
};



//@region thread-shared state group 2

static fiber_state* fiber_pool;
static fence_state* fence_pool;
static counter_state* counter_pool;

alignas(64) static std::atomic<pool_control_block>	fiber_pool_ctrl;
alignas(64) static std::atomic<uint32_t>			fiber_pool_size;
alignas(64) static std::atomic<pool_control_block>	fence_pool_ctrl;
alignas(64) static std::atomic<uint32_t>			fence_pool_size;
alignas(64) static std::atomic<pool_control_block>	counter_pool_ctrl;
alignas(64) static std::atomic<uint32_t>			counter_pool_size;
alignas(64) static lockfree_queue					queues[CMTS_QUEUE_PRIORITY_COUNT];
alignas(64) static flag_type						should_continue = {};

//!@region thread-shared state group 2



CMTS_INLINE_ALWAYS
static uint64_t make_user_handle(const uint32_t value, const uint32_t generation) noexcept
{
	return (uint64_t)((uint64_t)value | ((uint64_t)generation << 32));
}

CMTS_INLINE_ALWAYS
static uint32_t timestamp_frequency() noexcept
{
	LARGE_INTEGER i;
	QueryPerformanceFrequency(&i);
	return (uint32_t)i.LowPart;
}

CMTS_INLINE_ALWAYS
static uint32_t timestamp() noexcept
{
	LARGE_INTEGER i;
	QueryPerformanceCounter(&i);
	return (uint32_t)i.LowPart;
}

CMTS_INLINE_ALWAYS
static uint32_t timestamp_ns() noexcept
{
	return (timestamp() * 1000'000'000) / timestamp_frequency();
}

CMTS_INLINE_NEVER
static void conditionally_exit_thread() noexcept
{
	CMTS_UNLIKELY_IF(!should_continue.safe.load(std::memory_order_acquire))
		ExitThread(0);
}

CMTS_INLINE_ALWAYS
static bool counter_append_wait_list(counter_state& state, const uint32_t fiber) noexcept
{
	wait_list_control_block c, nc;
	while (true)
	{
		if (state.counter.load(std::memory_order_acquire) == 0)
			return false;
		c = nc = state.wait_list.load(std::memory_order_acquire);
		fiber_pool[fiber].fence_next = c.head;
		nc.head = fiber;
		++nc.generation;
		CMTS_LIKELY_IF(state.wait_list.load(std::memory_order_relaxed) == c)
			CMTS_LIKELY_IF(state.wait_list.compare_exchange_strong(c, nc, std::memory_order_acquire, std::memory_order_relaxed))
				break;
	}
	return true;
}

CMTS_INLINE_ALWAYS
static bool fence_append_wait_list(fence_state& state, const uint32_t fiber) noexcept
{
	wait_list_control_block c, nc;
	while (true)
	{
		if (state.flag.load(std::memory_order_acquire))
			return false;
		c = nc = state.wait_list.load(std::memory_order_acquire);
		fiber_pool[fiber].fence_next = c.head;
		nc.head = fiber;
		++nc.generation;
		CMTS_LIKELY_IF(state.wait_list.load(std::memory_order_relaxed) == c)
			CMTS_LIKELY_IF(state.wait_list.compare_exchange_strong(c, nc, std::memory_order_acquire, std::memory_order_relaxed))
				break;
	}
	return true;
}

CMTS_INLINE_ALWAYS
static uint32_t fetch_wait_list(std::atomic<wait_list_control_block>& ctrl) noexcept
{
	uint32_t r;
	wait_list_control_block c, nc;
	while (true)
	{
		c = nc = ctrl.load(std::memory_order_acquire);
		r = c.head;
		if (r == (uint32_t)-1)
			break;
		nc.head = fiber_pool[c.head].fence_next;
		++nc.generation;
		CMTS_LIKELY_IF(ctrl.load(std::memory_order_relaxed) == c)
			CMTS_LIKELY_IF(ctrl.compare_exchange_strong(c, nc, std::memory_order_release, std::memory_order_relaxed))
				break;
	}
	return r;
}

CMTS_INLINE_NEVER
static void wait_for_available_resource(const std::atomic_uint32_t& pool_size) noexcept
{
	while (pool_size.load(std::memory_order_acquire) == max_tasks)
	{
		if (root_fiber != nullptr)
			cmts_yield();
		else
			SwitchToThread();
	}
}

CMTS_INLINE_ALWAYS
static uint32_t new_fiber() noexcept
{
	pool_control_block c, nc;
	uint32_t r = (uint32_t)-1;
	while (true)
	{
		CMTS_UNLIKELY_IF(fiber_pool_size.load(std::memory_order_acquire) == max_tasks)
			wait_for_available_resource(fiber_pool_size);

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
			CMTS_UNLIKELY_IF(k == max_tasks)
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
static void delete_fiber(const uint32_t fiber) noexcept
{
	fiber_state& f = fiber_pool[fiber];
	HANDLE h = f.handle;
	f.reset();
	f.handle = h;
	pool_control_block c, nc;
	while (true)
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
static void push_fiber(const uint32_t fiber, const uint8_t priority) noexcept
{
	while (true)
	{
		CMTS_UNLIKELY_IF(!should_continue.unsafe)
			conditionally_exit_thread();
		CMTS_LIKELY_IF(queues[priority].store(fiber))
			return;
		_mm_pause();
	}
}

CMTS_INLINE_NEVER
static void fence_wake_fibers(const uint32_t fence_index) noexcept
{
	uint32_t i;
	while (true)
	{
		i = fetch_wait_list(fence_pool[fence_index].wait_list);
		CMTS_UNLIKELY_IF(i == (uint32_t)-1)
			break;
		fiber_pool[i].sleeping = false;
		push_fiber(i, fiber_pool[i].priority);
	}
}

CMTS_INLINE_ALWAYS
static void fence_conditionally_wake_fibers(const uint32_t fence_index) noexcept
{
	CMTS_LIKELY_IF(!fence_pool[fence_index].flag.exchange(true, std::memory_order_acquire))
		fence_wake_fibers(fence_index);
}

CMTS_INLINE_NEVER
static void counter_wake_fibers(const uint32_t counter_index) noexcept
{
	uint32_t i;
	while (true)
	{
		i = fetch_wait_list(counter_pool[counter_index].wait_list);
		CMTS_UNLIKELY_IF(i == (uint32_t)-1)
			break;
		fiber_pool[i].sleeping = false;
		push_fiber(i, fiber_pool[i].priority);
	}
}

CMTS_INLINE_ALWAYS
static void counter_conditionally_wake_fibers(const uint32_t counter_index) noexcept
{
	const uint32_t value = counter_pool[counter_index].counter.fetch_sub(1, std::memory_order_acquire) - 1;
	CMTS_LIKELY_IF(value == 0)
		counter_wake_fibers(counter_index);
}

CMTS_INLINE_ALWAYS
static uint32_t fetch_fiber() noexcept
{
	uint32_t threshold = 64;
	const uint32_t start = timestamp_ns();
	uint32_t last = start;
	uint32_t long_delay = 1;

	while (true)
	{
		CMTS_UNLIKELY_IF(!should_continue.unsafe)
			conditionally_exit_thread();
		for (lockfree_queue& q : queues)
		{
			uint32_t r;
			CMTS_LIKELY_IF(q.fetch(r))
				return r;
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

static void __stdcall fiber_main(void* const param) noexcept
{
	fiber_state& f = *(fiber_state*)param;
	while (true)
	{
		CMTS_UNLIKELY_IF(!should_continue.unsafe)
			conditionally_exit_thread();
		f.function(f.parameter);
		f.done = true;
		SwitchToFiber(root_fiber);
	}
}

static DWORD __stdcall thread_main(void* const param) noexcept
{
	processor_index = (uint32_t)(size_t)param;
	root_fiber = ConvertThreadToFiberEx(nullptr, FIBER_FLAG_FLOAT_SWITCH);

	while (true)
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
			const bool fence = f.has_fence;
			const bool counter = f.has_counter;
			const uint32_t fence_index = f.fence_id;
			const uint32_t counter_index = f.counter_id;
			delete_fiber(current_fiber);
			if (fence)
				fence_conditionally_wake_fibers(fence_index);
			if (counter)
				counter_conditionally_wake_fibers(counter_index);
			
		}
	}
}



#ifdef __cplusplus
extern "C"
{
#endif

	void CMTS_CALLING_CONVENTION cmts_initialize(uint32_t max_fibers, uint32_t max_cpus)
	{
		CMTS_ASSERT(max_fibers <= CMTS_MAX_TASKS, "The requested scheduler capacity passed to cmts_initialize exceeds the supported limit");
		CMTS_ASSERT(__popcnt(max_fibers) == 1, "The requested scheduler capacity passed to cmts_initialize must be a power of 2");
		CMTS_UNLIKELY_IF(should_continue.safe.load(std::memory_order_acquire))
			return;
		max_tasks = max_fibers;
		queue_shard_mod_mask = max_fibers - 1;
		should_continue.safe.store(true, std::memory_order_release);
		const uint32_t c = cmts_available_cpu_count();
		used_cpu_count = max_cpus < c ? max_cpus : c;
		const uint32_t qss = max_tasks * sizeof(std::atomic<uint32_t>);
		const size_t allocation_size = (used_cpu_count * sizeof(HANDLE)) + (qss * CMTS_QUEUE_PRIORITY_COUNT) + (max_fibers * (sizeof(fiber_state) + sizeof(fence_state) + sizeof(counter_state)));
		uint8_t* const ptr = (uint8_t*)VirtualAlloc(nullptr, allocation_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		threads = (HANDLE*)ptr;
		fiber_pool = (fiber_state*)(threads + used_cpu_count);
		fence_pool = (fence_state*)(fiber_pool + max_fibers);
		counter_pool = (counter_state*)(fence_pool + max_fibers);
		uint8_t* const qptr = (uint8_t*)(counter_pool + max_fibers);
		for (uint32_t i = 0; i < CMTS_QUEUE_PRIORITY_COUNT; ++i)
		{
			queues[i].initialize(qptr + i * qss);
		}
		for (uint32_t i = 0; i < max_fibers; ++i)
		{
			fiber_pool[i].reset();
			fence_pool[i].reset();
			counter_pool[i].reset();
		}
		DWORD tmp;
		for (uint32_t i = 0; i < used_cpu_count; ++i)
		{
			threads[i] = CreateThread(nullptr, 1 << 21, thread_main, (void*)(size_t)i, CREATE_SUSPENDED, &tmp);
			SetThreadAffinityMask(threads[i], ((DWORD_PTR)1U << (DWORD_PTR)i));
			ResumeThread(threads[i]);
		}
	}

	void CMTS_CALLING_CONVENTION cmts_halt()
	{
		for (uint32_t i = 0; i < used_cpu_count; ++i)
			SuspendThread(threads[i]);
	}

	void CMTS_CALLING_CONVENTION cmts_resume()
	{
		for (uint32_t i = 0; i < used_cpu_count; ++i)
			ResumeThread(threads[i]);
	}

	void CMTS_CALLING_CONVENTION cmts_signal_finalize()
	{
		should_continue.safe.store(false, std::memory_order_release);
	}

	void CMTS_CALLING_CONVENTION cmts_finalize()
	{
		WaitForMultipleObjects(used_cpu_count, threads, true, INFINITE);
		VirtualFree(threads, 0, MEM_RELEASE);
		ConvertFiberToThread();
	}

	void CMTS_CALLING_CONVENTION cmts_terminate()
	{
		cmts_signal_finalize();
		for (uint32_t i = 0; i < used_cpu_count; ++i)
			TerminateThread(threads[i], -1);
		VirtualFree(threads, 0, MEM_RELEASE);
		ConvertFiberToThread();
	}

	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_task()
	{
		return root_fiber != nullptr;
	}

	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_running()
	{
		return should_continue.unsafe;
	}

	void CMTS_CALLING_CONVENTION cmts_dispatch(
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

	void CMTS_CALLING_CONVENTION cmts_yield()
	{
		CMTS_ASSERT_IS_TASK;
		SwitchToFiber(root_fiber);
	}

	void CMTS_CALLING_CONVENTION cmts_exit()
	{
		CMTS_ASSERT_IS_TASK;
		fiber_pool[current_fiber].done = true;
		cmts_yield();
	}

	cmts_fence_t CMTS_CALLING_CONVENTION cmts_new_fence()
	{
		pool_control_block c, nc;
		uint32_t index;
		while (true)
		{
			CMTS_UNLIKELY_IF(fence_pool_size.load(std::memory_order_acquire) == max_tasks)
				wait_for_available_resource(fence_pool_size);
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
				index = fence_pool_size.load(std::memory_order_acquire);
				CMTS_UNLIKELY_IF(index == max_tasks)
					continue;
				CMTS_LIKELY_IF(fence_pool_size.compare_exchange_strong(index, index + 1, std::memory_order_release, std::memory_order_relaxed))
					break;
			}
		}
		fence_state& f = fence_pool[index];
		f.flag_unsafe = false;
		const uint32_t generation = f.generation.fetch_add(1, std::memory_order_acquire) + 1;
		return make_user_handle(index, generation);
	}

	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_fence_valid(cmts_fence_t fence)
	{
		const uint32_t index = (uint32_t)fence;
		const uint32_t generation = (uint32_t)(fence >> 32);
		return fence_pool[index].generation == generation;
	}

	void CMTS_CALLING_CONVENTION cmts_signal_fence(cmts_fence_t fence)
	{
		const uint32_t index = (uint32_t)fence;
		const uint32_t generation = (uint32_t)(fence >> 32);
		CMTS_ASSERT(fence_pool[index].generation == generation, "Invalid fence handle, generation mismatch.");
		fence_wake_fibers(index);
	}

	void CMTS_CALLING_CONVENTION cmts_delete_fence(cmts_fence_t fence)
	{
		const uint32_t index = (uint32_t)fence;
		const uint32_t generation = (uint32_t)(fence >> 32);
		CMTS_ASSERT(fence_pool[index].generation == generation, "Invalid fence handle, generation mismatch.");
		fence_pool[index].reset();
		pool_control_block c, nc;
		while (true)
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

	void CMTS_CALLING_CONVENTION cmts_await_fence(cmts_fence_t fence)
	{
		CMTS_ASSERT_IS_TASK;
		const uint32_t index = (uint32_t)fence;
		const uint32_t generation = (uint32_t)(fence >> 32);
		if (fence_pool[index].generation != generation)
			return;
		fiber_state& f = fiber_pool[current_fiber];
		if (!fence_append_wait_list(fence_pool[index], current_fiber))
			return;
		f.sleeping = true;
		cmts_yield();
	}

	void CMTS_CALLING_CONVENTION cmts_await_fence_and_delete(cmts_fence_t fence)
	{
		CMTS_ASSERT_IS_TASK;
		const uint32_t index = (uint32_t)fence;
		const uint32_t generation = (uint32_t)(fence >> 32);
		if (fence_pool[index].generation != generation)
			return;
		fiber_state& f = fiber_pool[current_fiber];
		if (!fence_append_wait_list(fence_pool[index], current_fiber))
			return;
		f.sleeping = true;
		cmts_yield();
		fence_pool[index].reset();
		pool_control_block c, nc;
		while (true)
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

	cmts_counter_t CMTS_CALLING_CONVENTION cmts_new_counter(uint32_t start_value)
	{
		pool_control_block c, nc;
		uint32_t index;
		while (true)
		{
			CMTS_UNLIKELY_IF(counter_pool_size.load(std::memory_order_acquire) == max_tasks)
				wait_for_available_resource(counter_pool_size);
			c = counter_pool_ctrl.load(std::memory_order_acquire);
			CMTS_LIKELY_IF(c.freelist != (uint32_t)-1)
			{
				nc = c;
				index = nc.freelist;
				nc.freelist = counter_pool[index].pool_next;
				++nc.generation;
				CMTS_LIKELY_IF(counter_pool_ctrl.compare_exchange_strong(c, nc, std::memory_order_release, std::memory_order_relaxed))
					break;
			}
			else
			{
				index = counter_pool_size.load(std::memory_order_acquire);
				CMTS_UNLIKELY_IF(index == max_tasks)
					continue;
				CMTS_LIKELY_IF(counter_pool_size.compare_exchange_strong(index, index + 1, std::memory_order_release, std::memory_order_relaxed))
					break;
			}
		}
		counter_state& s = counter_pool[index];
		s.counter_unsafe = start_value;
		const uint32_t generation = s.generation.fetch_add(1, std::memory_order_acquire) + 1;
		return make_user_handle(index, generation);
	}

	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_counter_valid(cmts_counter_t counter)
	{
		const uint32_t index = (uint32_t)counter;
		const uint32_t generation = (uint32_t)(counter >> 32);
		return counter_pool[index].generation == generation;
	}

	void CMTS_CALLING_CONVENTION cmts_increment_counter(cmts_counter_t counter)
	{
		const uint32_t index = (uint32_t)counter;
		const uint32_t generation = (uint32_t)(counter >> 32);
		CMTS_ASSERT(counter_pool[index].generation == generation, "Invalid counter handle, generation mismatch.");
		counter_pool[index].counter.fetch_add(1, std::memory_order_acquire);
	}

	void CMTS_CALLING_CONVENTION cmts_decrement_counter(cmts_counter_t counter)
	{
		const uint32_t index = (uint32_t)counter;
		const uint32_t generation = (uint32_t)(counter >> 32);
		CMTS_ASSERT(counter_pool[index].generation == generation, "Invalid counter handle, generation mismatch.");
		counter_pool[index].counter.fetch_sub(1, std::memory_order_release);
	}

	void CMTS_CALLING_CONVENTION cmts_await_counter(cmts_counter_t counter)
	{
		CMTS_ASSERT_IS_TASK;
		const uint32_t index = (uint32_t)counter;
		const uint32_t generation = (uint32_t)(counter >> 32);
		fiber_state& f = fiber_pool[current_fiber];
		CMTS_UNLIKELY_IF(counter_pool[index].generation != generation)
			return;
		CMTS_UNLIKELY_IF(!counter_append_wait_list(counter_pool[index], current_fiber))
			return;
		f.sleeping = true;
		cmts_yield();
	}

	void CMTS_CALLING_CONVENTION cmts_await_counter_and_delete(cmts_counter_t counter)
	{
		CMTS_ASSERT_IS_TASK;
		const uint32_t index = (uint32_t)counter;
		const uint32_t generation = (uint32_t)(counter >> 32);
		counter_state& s = counter_pool[index];
		CMTS_UNLIKELY_IF(s.generation != generation)
			return;
		fiber_state& f = fiber_pool[current_fiber];
		CMTS_UNLIKELY_IF(!counter_append_wait_list(s, current_fiber))
			return;
		f.sleeping = true;
		cmts_yield();
		s.reset();
		pool_control_block c, nc;
		while (true)
		{
			c = counter_pool_ctrl.load(std::memory_order_acquire);
			nc = c;
			s.pool_next = nc.freelist;
			nc.freelist = index;
			++nc.generation;
			CMTS_LIKELY_IF(counter_pool_ctrl.compare_exchange_strong(c, nc, std::memory_order_release, std::memory_order_relaxed))
				break;
		}
	}

	void CMTS_CALLING_CONVENTION cmts_delete_counter(cmts_counter_t counter)
	{
		const uint32_t index = (uint32_t)counter;
		const uint32_t generation = (uint32_t)(counter >> 32);
		CMTS_ASSERT(counter_pool[index].generation == generation, "Invalid counter handle, generation mismatch.");
		counter_pool[index].reset();
		pool_control_block c, nc;
		while (true)
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

	void CMTS_CALLING_CONVENTION cmts_dispatch_with_fence(cmts_function_pointer_t task_function, void* param, uint8_t priority_level, cmts_fence_t fence)
	{
		const uint32_t fence_index = (uint32_t)fence;
		const uint32_t fence_generation = (uint32_t)(fence >> 32);
		CMTS_UNLIKELY_IF(fence_pool[fence_index].generation != fence_generation)
			return;
		const uint32_t id = new_fiber();
		fiber_state& f = fiber_pool[id];
		f.function = task_function;
		f.parameter = param;
		f.has_fence = true;
		f.fence_id = fence_index;
		CMTS_UNLIKELY_IF(f.handle == nullptr)
			f.handle = CreateFiberEx(1 << 16, 1 << 16, FIBER_FLAG_FLOAT_SWITCH, (LPFIBER_START_ROUTINE)fiber_main, &f);
		push_fiber(id, f.priority);
	}

	void CMTS_CALLING_CONVENTION cmts_dispatch_with_counter(cmts_function_pointer_t task_function, void* param, uint8_t priority_level, cmts_counter_t counter)
	{
		const uint32_t counter_index = (uint32_t)counter;
		const uint32_t counter_generation = (uint32_t)(counter >> 32);
		CMTS_UNLIKELY_IF(counter_pool[counter_index].generation != counter_generation)
			return;
		const uint32_t id = new_fiber();
		fiber_state& f = fiber_pool[id];
		f.function = task_function;
		f.parameter = param;
		f.has_counter = true;
		f.counter_id = counter_index;
		CMTS_UNLIKELY_IF(f.handle == nullptr)
			f.handle = CreateFiberEx(1 << 16, 1 << 16, FIBER_FLAG_FLOAT_SWITCH, (LPFIBER_START_ROUTINE)fiber_main, &f);
		push_fiber(id, f.priority);
	}

	uint32_t CMTS_CALLING_CONVENTION cmts_current_task_id()
	{
		return current_fiber;
	}

	uint32_t CMTS_CALLING_CONVENTION cmts_current_cpu()
	{
		return processor_index;
	}

	uint32_t CMTS_CALLING_CONVENTION cmts_used_cpu_count()
	{
		return used_cpu_count;
	}

	uint32_t CMTS_CALLING_CONVENTION cmts_available_cpu_count()
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