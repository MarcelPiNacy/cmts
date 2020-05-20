#include "cmts.h"
#include <Windows.h>
#include <atomic>
#include <memory>
#include <utility>
#include <intrin.h>
using namespace std;

using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using uptr = size_t;

using i8 = int8_t;
using i16 = int16_t;
using i32 = int32_t;
using i64 = int64_t;
using iptr = ptrdiff_t;

using f32 = float;
using f64 = double;
using xfloat = long double;

using cstring = const char*;



enum : u32
{
	U24_MAX = (1 << 24) - 1
};



//@region thread-shared state group

static u32										cmts_capacity;
static HANDLE*									threads;

//!@region thread-shared state group



//@region thread-local state group

static thread_local u32							processor_index;
static thread_local HANDLE						root_fiber;
static thread_local u32							current_fiber;

//!@region thread-local state group



#if defined(DEBUG) || defined(_DEBUG) || !defined(NDEBUG)
#define debug
#define inline_always
#define inline_never
#else
#define debug if constexpr (false)
#define inline_always __forceinline
#define inline_never __declspec(noinline)
#endif

#define likely_if(expression) if (__builtin_expect((expression), 1))
#define unlikely_if(expression) if (__builtin_expect((expression), 0))
#define array_size(array) ((sizeof(array)) / (sizeof(array[0])))
#define concatenate_impl(l, r) l##r
#define concatenate(l, r) concatenate_impl(l, r)
#define anonymous concatenate(_anon_, __LINE__)
#define internal_alloca(size) __builtin_alloca(size)
#define stackalloc(type, count) ((type*)__builtin_alloca((count) * sizeof(type)))
#define range_for(name, start, end) for (u32 name = start; name < end; ++name)
#define extern_c __cdecl
#define extern_windows __stdcall



#ifdef _DEBUG
#define cmts_assert(expression, message) if (!(expression)) cmts_assertion_handler(message "\n")

inline_never
static void cmts_assertion_handler(cstring message)
{
	for (u32 i = 0; i < cmts_processor_count(); ++i)
		if (i != processor_index)
			SuspendThread(threads[i]);
	OutputDebugStringA(message);
	DebugBreak();
	abort();
}
#else
#define cmts_assert(expression, message)
#endif



union alignas(64) flag_type
{
	atomic_bool	safe;
	bool		unsafe;
};

static flag_type should_continue = {};

struct alignas(64) shared_queue_256
{
	struct control_block
	{
		u8 head, tail, generation, unused;
	};

	atomic<control_block> ctrl;
	atomic<u32> values[256];

	bool store(u32 value)
	{
		while (true)
		{
			auto c = ctrl.load(memory_order_acquire);
			auto nc = c;
			++nc.head;
			if (nc.head == c.tail)
				return false;
			++nc.generation;
			if (ctrl.compare_exchange_strong(c, nc, memory_order_acquire, memory_order_relaxed))
			{
				values[c.head].store(value, memory_order_release);
				return true;
			}
		}
	}

	pair<bool, u32> fetch()
	{
		while (true)
		{
			auto c = ctrl.load(memory_order_acquire);
			if (c.head == c.tail)
				return pair<bool, u32>();
			auto nc = c;
			++nc.tail;
			++nc.generation;
			const u32 r = values[c.tail].load(memory_order_acquire);
			if (ctrl.compare_exchange_strong(c, nc, memory_order_release, memory_order_relaxed))
				return pair<bool, u32>(true, r);
		}
	}
};

struct alignas(64) sharded_queue
{
	struct control_block
	{
		u64 head : 24, tail : 24, generation : 16;
	};

	atomic<control_block> ctrl = {};
	shared_queue_256* queues = nullptr;

	void initialize(u32 capacity)
	{
		queues = (shared_queue_256*)VirtualAlloc(nullptr, capacity * sizeof(shared_queue_256), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	}

	void finalize()
	{
		VirtualFree(queues, 0, MEM_RELEASE);
		new (this) sharded_queue();
	}

	bool store(u32 value)
	{
		control_block c, nc;
		
		while (true)
		{
			c = ctrl.load(memory_order_acquire);
			nc = c;
			++nc.head;
			if (nc.head == c.tail)
				return false;
			++nc.generation;
			if (ctrl.compare_exchange_strong(c, nc, memory_order_acquire, memory_order_relaxed))
				break;
		}

		if (queues[(u16)c.head].store(value))
			return true;
		else if (ctrl.compare_exchange_strong(nc, c, memory_order_release, memory_order_relaxed))
			return false;
		
		while (true)
		{
			if (queues[(u16)c.head].store(value))
				return true;
			_mm_pause();
		}
	}

	pair<bool, u32> fetch()
	{
		control_block c, nc;
		while (true)
		{
			c = ctrl.load(memory_order_acquire);
			if (c.head == c.tail)
				return pair<bool, u32>();
			nc = c;
			++nc.tail;
			++nc.generation;
			if (ctrl.compare_exchange_strong(c, nc, memory_order_release, memory_order_relaxed))
			{
				const auto r = queues[(u16)c.tail].fetch();
				cmts_assert(r.first, "Bug spotted: fetching from sub-queue failed after successful compare_exchange.");
				return r;
			}
		}
	}
};

struct alignas(64) fiber_synchronization_state
{
	struct alignas(8) wait_list_control_block
	{
		u32 head;
		u32 generation;
	};

	u32 fence_next = (u32)-1;
	u32 fence_id = (u32)-1;
	u32 counter_id = (u32)-1;
	u32 counter_next = (u32)-1;
	atomic<wait_list_control_block> fence_wait_list = wait_list_control_block{ (u32)-1, 0 };
	atomic<wait_list_control_block> counter_wait_list = wait_list_control_block{ (u32)-1, 0 };
};

struct alignas(64) fiber_state
{
	HANDLE handle;
	cmts_function_pointer_t function;
	void* parameter;
	u32 pool_next = (u32)-1;
	u32	priority : 3,
		has_fence : 1,
		has_counter : 1,
		sleeping : 1,
		done : 1;
};

struct fence_state
{
	union
	{
		atomic_bool flag;
		bool flag_unsafe;
	};
	u32 owning_fiber;
	u32 pool_next;

	inline_always
	fence_state()
	{
		debug{ owning_fiber = (u32)-1; }
		pool_next = (u32)-1;
	}

	inline_always
	~fence_state()
	{
	}
};

struct counter_state
{
	union
	{
		atomic<u32> counter;
		u32 counter_unsafe;
	};
	u32 owning_fiber;
	u32 pool_next;

	inline_always
	counter_state()
	{
		debug{ owning_fiber = (u32)-1; }
		pool_next = (u32)-1;
	}

	inline_always
	~counter_state()
	{
	}
};

struct pool_control_block
{
	u32 freelist = (u32)-1;
	u32 generation = 0;
};



//@region thread-shared state group 2

static fiber_state*								fiber_pool;
static fence_state*								fence_pool;
static counter_state*							counter_pool;
static fiber_synchronization_state*				fiber_sync;

alignas(64) static atomic<pool_control_block>	fiber_pool_ctrl;
alignas(64) static atomic<u32>					fiber_pool_size;

alignas(64) static atomic<pool_control_block>	fence_pool_ctrl;
alignas(64) static atomic<u32>					fence_pool_size;

alignas(64) static atomic<pool_control_block>	counter_pool_ctrl;
alignas(64) static atomic<u32>					counter_pool_size;

alignas(64) static sharded_queue				queues[4];

//!@region thread-shared state group 2



inline_never
static void conditionally_exit_thread()
{
	if (!should_continue.safe.load(memory_order::memory_order_acquire))
		ExitThread(0);
}

inline_always
static void append_fence_wait_list(u32 fiber, u32 value)
{
	auto& s = fiber_sync[fiber];
	while (true)
	{
		auto c = s.fence_wait_list.load(memory_order_acquire);
		auto nc = c;
		s.fence_next = nc.head;
		nc.head = value;
		++nc.generation;
		if (s.fence_wait_list.compare_exchange_strong(c, nc, memory_order_release, memory_order_relaxed))
			break;
	}
}

inline_always
static u32 fetch_fence_wait_list(u32 fiber)
{
	auto& s = fiber_sync[fiber];
	while (true)
	{
		auto c = s.fence_wait_list.load(memory_order_acquire);
		auto nc = c;
		const u32 r = c.head;
		if (r == (u32)-1)
			return (u32)-1;
		nc.head = fiber_sync[nc.head].fence_next;
		++nc.generation;
		if (s.fence_wait_list.compare_exchange_strong(c, nc, memory_order_release, memory_order_relaxed))
			return r;
	}
}

inline_always
static void append_counter_wait_list(u32 fiber, u32 value)
{
	auto& s = fiber_sync[fiber];
	while (true)
	{
		auto c = s.counter_wait_list.load(memory_order_acquire);
		auto nc = c;
		s.fence_next = nc.head;
		nc.head = value;
		++nc.generation;
		if (s.counter_wait_list.compare_exchange_strong(c, nc, memory_order_release, memory_order_relaxed))
			break;
	}
}

inline_always
static u32 fetch_counter_wait_list(u32 fiber)
{
	auto& s = fiber_sync[fiber];
	while (true)
	{
		auto c = s.counter_wait_list.load(memory_order_acquire);
		auto nc = c;
		const u32 r = c.head;
		if (r == (u32)-1)
			return (u32)-1;
		nc.head = fiber_sync[nc.head].fence_next;
		++nc.generation;
		if (s.counter_wait_list.compare_exchange_strong(c, nc, memory_order_release, memory_order_relaxed))
			return r;
	}
}

inline_always
static u32 new_fiber()
{
	pool_control_block c;
	u32 r = (u32)-1;
	while (true)
	{
		while (fiber_pool_size.load(memory_order_acquire) == cmts_capacity)
			_mm_pause();
		c = fiber_pool_ctrl.load(memory_order_acquire);
		if (c.freelist != (u32)-1)
		{
			auto nc = c;
			r = nc.freelist;
			nc.freelist = fiber_pool[r].pool_next;
			++nc.generation;
			if (fiber_pool_ctrl.compare_exchange_strong(c, nc, memory_order_release, memory_order_relaxed))
				break;
		}
		else
		{
			auto k = fiber_pool_size.load(memory_order_acquire);
			if (k == cmts_capacity)
				continue;
			r = k + 1;
			if (fiber_pool_size.compare_exchange_strong(k, r, memory_order_release, memory_order_relaxed))
				break;
		}
	}
	return r;
}

inline_always
static void delete_fiber(u32 fiber)
{
	auto& f = fiber_pool[fiber];
	auto h = f.handle;
	new (&f) fiber_state();
	f.handle = h;

	pool_control_block c, nc;
	while (true)
	{
		c = fiber_pool_ctrl.load(memory_order_acquire);
		nc = c;
		f.pool_next = nc.freelist;
		nc.freelist = fiber;
		++nc.generation;
		if (fiber_pool_ctrl.compare_exchange_strong(c, nc, memory_order_release, memory_order_relaxed))
			break;
	}
}

inline_always
static void push_fiber(u32 fiber, u8 priority)
{
	while (true)
	{
		if (!should_continue.unsafe)
			conditionally_exit_thread();
		if (queues[priority].store(fiber))
			return;
		_mm_pause();
	}
}

inline_always
static u32 fetch_fiber()
{
	while (true)
	{
		if (!should_continue.unsafe)
			conditionally_exit_thread();
		for (auto& q : queues)
		{
			const auto r = q.fetch();
			if (r.first)
				return r.second;
		}
		_mm_pause();
	}
}

inline_never
static void fence_wake_fibers(u32 fence)
{
	while (true)
	{
		const u32 n = fetch_fence_wait_list(fence);
		if (n == (u32)-1)
			break;
		push_fiber(n, fiber_pool[n].priority);
	}
}

inline_always
static void fence_conditionally_wake_fibers(u32 fiber)
{
	auto& s = fiber_sync[fiber];
	cmts_assert(s.fence_id != (u32)-1, "Invalid fiber_sync.counter_id value.");
	if (!fence_pool[s.fence_id].flag.exchange(true, memory_order_release))
		fence_wake_fibers(s.fence_id);
}

inline_never
static void counter_wake_fibers(u32 fence)
{
	while (true)
	{
		const u32 n = fetch_counter_wait_list(fence);
		if (n == (u32)-1)
			break;
		push_fiber(n, fiber_pool[n].priority);
	}
}

inline_always
static void counter_conditionally_wake_fibers(u32 fiber)
{
	auto& s = fiber_sync[fiber];
	cmts_assert(s.counter_id != (u32)-1, "Invalid fiber_sync.counter_id value.");
	if (counter_pool[s.counter_id].counter.fetch_sub(1, memory_order_release) == 0)
		counter_wake_fibers(s.counter_id);
}

static void __stdcall fiber_main(void* param)
{
	auto& state = *(fiber_state*)param;
	while (true)
	{
		if (!should_continue.unsafe)
			conditionally_exit_thread();
		state.function(state.parameter);
		state.done = true;
		SwitchToFiber(root_fiber);
	}
}

static DWORD __stdcall thread_main(void* param)
{
	processor_index = (u32)param;
	root_fiber = ConvertThreadToFiber(nullptr);
	while (true)
	{
		if (!should_continue.unsafe)
			conditionally_exit_thread();
		current_fiber = fetch_fiber();
		auto& f = fiber_pool[current_fiber];
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



extern "C"
{

	void cmts_initialize(uint32_t max_fibers)
	{
		cmts_assert(max_fibers <= CMTS_MAX_TASKS, "The requested scheduler capacity passed to cmts_initialize exceeds the supported limit");

		if (should_continue.safe.load(memory_order_acquire))
			return;

		cmts_capacity = max_fibers;
		should_continue.safe.store(true, memory_order_release);
		const u32 core_count = cmts_processor_count();
		const size_t allocation_size =
			(core_count * sizeof(HANDLE)) +
			(max_fibers * (sizeof(fiber_state) + sizeof(fence_state) + sizeof(counter_state) + sizeof(fiber_synchronization_state)));

		auto ptr = (u8*)VirtualAlloc(nullptr, allocation_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		threads = (HANDLE*)ptr;
		fiber_pool = (fiber_state*)(threads + core_count);
		fence_pool = (fence_state*)(fiber_pool + max_fibers);
		counter_pool = (counter_state*)(fence_pool + max_fibers);
		fiber_sync = (fiber_synchronization_state*)(counter_pool + max_fibers);
		for (u32 i = 0; i < max_fibers; ++i)
			new (&fiber_pool[i]) fiber_state();
		for (u32 i = 0; i < max_fibers; ++i)
			new (&fence_pool[i]) fence_state();
		for (u32 i = 0; i < max_fibers; ++i)
			new (&counter_pool[i]) counter_state();
		for (u32 i = 0; i < max_fibers; ++i)
			new (&fiber_sync[i]) fiber_synchronization_state();
		for (auto& q : queues)
			q.initialize(max_fibers);
		DWORD tmp;
		for (u32 i = 0; i < core_count; ++i)
		{
			threads[i] = CreateThread(nullptr, 1 << 21, thread_main, (void*)(uptr)i, CREATE_SUSPENDED, &tmp);
			SetThreadAffinityMask(threads[i], 1 << i);
			ResumeThread(threads[i]);
		}
	}

	void cmts_signal_finalize()
	{
		should_continue.safe.store(false, memory_order_release);
	}

	void cmts_finalize()
	{
		const u32 core_count = cmts_processor_count();
		WaitForMultipleObjects(core_count, threads, true, INFINITE);
		VirtualFree(threads, 0, MEM_RELEASE);
		for (auto& q : queues)
			q.finalize();
		ConvertFiberToThread();
	}

	void cmts_terminate()
	{
		cmts_signal_finalize();
		for (u32 i = 0; i < cmts_processor_count(); ++i)
			TerminateThread(threads[i], -1);
		VirtualFree(threads, 0, MEM_RELEASE);
		for (auto& q : queues)
			q.finalize();
		ConvertFiberToThread();
	}

	bool cmts_is_running()
	{
		return should_continue.unsafe;
	}

	void cmts_dispatch(
		cmts_function_pointer_t fiber_function,
		void* param,
		uint8_t priority_level)
	{
		const u32 id = new_fiber();
		auto& s = fiber_pool[id];
		s.function = fiber_function;
		s.parameter = param;
		if (s.handle == nullptr)
			s.handle = CreateFiberEx(1 << 16, 1 << 16, FIBER_FLAG_FLOAT_SWITCH, fiber_main, &fiber_pool[id]);
		push_fiber(id, s.priority);
	}

	void cmts_yield()
	{
		SwitchToFiber(root_fiber);
	}

	void cmts_exit()
	{
		fiber_pool[current_fiber].done = true;
		cmts_yield();
	}

	cmts_fence_t cmts_new_fence()
	{
		pool_control_block c;
		u32 r = (u32)-1;
		while (true)
		{
			while (fence_pool_size.load(memory_order_acquire) == cmts_capacity)
				_mm_pause();
			c = fence_pool_ctrl.load(memory_order_acquire);
			if (c.freelist != (u32)-1)
			{
				auto nc = c;
				r = nc.freelist;
				nc.freelist = fence_pool[r].pool_next;
				++nc.generation;
				if (fence_pool_ctrl.compare_exchange_strong(c, nc, memory_order_release, memory_order_relaxed))
					break;
			}
			else
			{
				auto k = fence_pool_size.load(memory_order_acquire);
				if (k == cmts_capacity)
					continue;
				r = k + 1;
				if (fence_pool_size.compare_exchange_strong(k, r, memory_order_release, memory_order_relaxed))
					break;
			}
		}
		fence_pool[r].flag_unsafe = false;
		return r;
	}

	void cmts_signal_fence(cmts_fence_t fence)
	{
		cmts_assert(fence_pool[fence].owning_fiber != (u32)-1, "Invalid fence handle.");
		fence_wake_fibers(fence_pool[fence].owning_fiber);
	}

	void cmts_delete_fence(cmts_fence_t fence)
	{
		cmts_assert(fence_pool[fence].owning_fiber != (u32)-1, "Invalid fence handle.");
		new (&fence_pool[fence]) fence_state();
		pool_control_block c, nc;
		while (true)
		{
			c = fence_pool_ctrl.load(memory_order_acquire);
			nc = c;
			fence_pool[fence].pool_next = nc.freelist;
			nc.freelist = fence;
			++nc.generation;
			if (fence_pool_ctrl.compare_exchange_strong(c, nc, memory_order_release, memory_order_relaxed))
				break;
		}
	}

	void cmts_await_fence(cmts_fence_t fence)
	{
		cmts_assert(fence_pool[fence].owning_fiber != (u32)-1, "Invalid fence handle.");
		auto& f = fiber_pool[current_fiber];
		f.sleeping = true;
		append_fence_wait_list(current_fiber, fence);
		cmts_yield();
	}

	void cmts_await_fence_and_delete(cmts_fence_t fence)
	{
		cmts_assert(fence_pool[fence].owning_fiber != (u32)-1, "Invalid fence handle.");
		cmts_await_fence(fence);
		cmts_delete_fence(fence);
	}

	cmts_counter_t cmts_new_counter(uint32_t start_value)
	{
		pool_control_block c;
		u32 r = (u32)-1;
		while (true)
		{
			while (counter_pool_size.load(memory_order_acquire) == cmts_capacity)
				_mm_pause();

			c = counter_pool_ctrl.load(memory_order_acquire);
			if (c.freelist != (u32)-1)
			{
				auto nc = c;
				r = nc.freelist;
				nc.freelist = counter_pool[r].pool_next;
				++nc.generation;
				if (counter_pool_ctrl.compare_exchange_strong(c, nc, memory_order_release, memory_order_relaxed))
					break;
			}
			else
			{
				auto k = counter_pool_size.load(memory_order_acquire);
				if (k == cmts_capacity)
					continue;
				r = k + 1;
				if (counter_pool_size.compare_exchange_strong(k, r, memory_order_release, memory_order_relaxed))
					break;
			}
		}
		counter_pool[r].counter_unsafe = start_value;
		return r;
	}

	void cmts_increment_counter(cmts_counter_t counter)
	{
		cmts_assert(counter_pool[counter].owning_fiber != (u32)-1, "Invalid counter handle.");
		counter_pool[counter].counter.fetch_add(1, memory_order_relaxed);
	}

	void cmts_decrement_counter(cmts_counter_t counter)
	{
		cmts_assert(counter_pool[counter].owning_fiber != (u32)-1, "Invalid counter handle.");
		counter_pool[counter].counter.fetch_sub(1, memory_order_relaxed);
	}

	void cmts_await_counter(cmts_counter_t counter)
	{
		cmts_assert(counter_pool[counter].owning_fiber != (u32)-1, "Invalid counter handle.");
		auto& f = fiber_pool[current_fiber];
		f.sleeping = true;
		append_counter_wait_list(current_fiber, counter);
		cmts_yield();
	}

	void cmts_await_counter_and_delete(cmts_counter_t counter)
	{
		cmts_assert(counter_pool[counter].owning_fiber != (u32)-1, "Invalid counter handle.");
		cmts_await_counter(counter);
		cmts_delete_counter(counter);
	}

	void cmts_delete_counter(cmts_counter_t counter)
	{
		cmts_assert(counter_pool[counter].owning_fiber != (u32)-1, "Invalid counter handle.");
		new (&counter_pool[counter]) counter_state();
		pool_control_block c, nc;
		while (true)
		{
			c = counter_pool_ctrl.load(memory_order_acquire);
			nc = c;
			counter_pool[counter].pool_next = nc.freelist;
			nc.freelist = counter;
			++nc.generation;
			if (counter_pool_ctrl.compare_exchange_strong(c, nc, memory_order_release, memory_order_relaxed))
				break;
		}
	}

	void cmts_dispatch_with_fence(cmts_function_pointer_t task_function, void* param, uint8_t priority_level, cmts_fence_t fence)
	{
		const u32 id = new_fiber();
		auto& f = fiber_pool[id];
		f.function = task_function;
		f.parameter = param;
		f.has_fence = true;
		fiber_sync[id].fence_id = fence;
		fence_pool[fence].owning_fiber = current_fiber;
		if (f.handle == nullptr)
			f.handle = CreateFiberEx(1 << 16, 1 << 16, FIBER_FLAG_FLOAT_SWITCH, fiber_main, &f);
		push_fiber(id, f.priority);
	}

	void cmts_dispatch_with_counter(cmts_function_pointer_t task_function, void* param, uint8_t priority_level, cmts_counter_t counter)
	{
		const u32 id = new_fiber();
		auto& f = fiber_pool[id];
		f.function = task_function;
		f.parameter = param;
		f.has_counter = true;
		fiber_sync[id].counter_id = counter;
		counter_pool[counter].owning_fiber = current_fiber;
		if (f.handle == nullptr)
			f.handle = CreateFiberEx(1 << 16, 1 << 16, FIBER_FLAG_FLOAT_SWITCH, fiber_main, &f);
		push_fiber(id, f.priority);
	}

	uint32_t cmts_processor_index()
	{
		return processor_index;
	}

	uint32_t cmts_current_task_id()
	{
		return current_fiber;
	}

	uint32_t cmts_processor_count()
	{
		SYSTEM_INFO info;
		GetSystemInfo(&info);
		return (uint32_t)info.dwNumberOfProcessors;
	}

}



static_assert(atomic<bool>::is_always_lock_free);
static_assert(atomic<u32>::is_always_lock_free);
static_assert(atomic<pool_control_block>::is_always_lock_free);
static_assert(atomic<shared_queue_256::control_block>::is_always_lock_free);
static_assert(atomic<sharded_queue::control_block>::is_always_lock_free);
static_assert(atomic<fiber_synchronization_state::wait_list_control_block>::is_always_lock_free);