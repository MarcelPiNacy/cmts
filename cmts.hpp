/*
	Copyright 2021 Marcel Pi Nacy

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/



#ifndef CMTS_CPP_INCLUDED
#define CMTS_CPP_INCLUDED
#include "cmts.h"
#include <cassert>
#include <iterator>
#include <variant>
#include <string_view>

namespace CMTS
{
	using TaskID = uint64_t;
	using TaskFn = cmts_fn_task;
	using AllocateFn = cmts_fn_allocate;
	using DeallocateFn = cmts_fn_deallocate;
	using StringRef = std::basic_string_view<CMTS_CHAR>;

	enum class Result : int32_t
	{
		Ok = 0,
		SyncObjectExpired = 1,
		NotReady = 2,
		AlreadyInitialized = 3,
		InitializationInProgress = 4,

		ErrorMemoryAllocation = -1,
		ErrorMemoryDeallocation = -2,
		ErrorThreadCreation = -3,
		ErrorThreadAffinity = -4,
		ErrorResumeThread = -5,
		ErrorSuspendThread = -6,
		ErrorThreadTermination = -7,
		ErrorAwaitThread = -8,
		ErrorTaskPoolCapacity = -9,
		ErrorAffinity = -10,
		ErrorTaskAllocation = -11,
		ErrorFutex = -12,
		ErrorLibraryUninitialized = -13,
		ErrorOsInit = -14,
		InvalidExtensionType = -15,
		UnsupportedExtension = -16,

		BeginEnum = UnsupportedExtension,
		EndEnum = InitializationInProgress + 1,
	};

	enum class MessageSeverity : uint8_t
	{
		Info,
		Warning,
		Error,

		BeginEnum = Info,
		EndEnum = Error + 1,
	};

	enum class SyncObjectType : uint8_t
	{
		None,
		Event,
		Counter,

		BeginEnum = None,
		EndEnum = Counter + 1,
	};

	enum class InitFlags : uint64_t
	{
	};

	constexpr InitFlags operator ~ (InitFlags other) { return (InitFlags)~(uint64_t)other; }
	constexpr InitFlags operator & (InitFlags lhs, InitFlags rhs) { return (InitFlags)((uint64_t)lhs & (uint64_t)lhs); }
	constexpr InitFlags operator | (InitFlags lhs, InitFlags rhs) { return (InitFlags)((uint64_t)lhs | (uint64_t)lhs); }
	constexpr InitFlags operator ^ (InitFlags lhs, InitFlags rhs) { return (InitFlags)((uint64_t)lhs ^ (uint64_t)lhs); }

	enum class DispatchFlags : uint64_t
	{
		Force = 1
	};

	constexpr DispatchFlags operator ~ (DispatchFlags other) { return (DispatchFlags)~(uint64_t)other; }
	constexpr DispatchFlags operator & (DispatchFlags lhs, DispatchFlags rhs) { return (DispatchFlags)((uint64_t)lhs & (uint64_t)lhs); }
	constexpr DispatchFlags operator | (DispatchFlags lhs, DispatchFlags rhs) { return (DispatchFlags)((uint64_t)lhs | (uint64_t)lhs); }
	constexpr DispatchFlags operator ^ (DispatchFlags lhs, DispatchFlags rhs) { return (DispatchFlags)((uint64_t)lhs ^ (uint64_t)lhs); }

	enum class ExtensionType : uint32_t
	{
		Debugger,

		BeginEnum = Debugger,
		EndEnum = Debugger + 1,
	};

	struct MemoryRequirements
	{
		size_t size, alignment;
	};

	class Fence;
	class Event;
	class Counter;
	class Mutex;

	using SyncObjectPtrVariant = std::variant<
		Event*,
		Counter*>;

	struct InitOptions
	{
		AllocateFn allocate_function;
		uint32_t task_stack_size;
		uint32_t thread_count;
		const uint32_t* thread_affinities;
		InitFlags flags;
		uint32_t max_tasks;
		const void* next_ext;
	};

	struct DispatchOptions
	{
		DispatchFlags flags;
		cmts_task_id* out_task_id;
		const uint32_t* locked_thread;
		void* parameter;
		SyncObjectPtrVariant sync_object;
		uint8_t priority;
		const void* next_ext;
	};

	class Fence
	{
		using Base = cmts_fence;
		Base impl;
	public:

		constexpr Fence()
			: impl(CMTS_FENCE_INIT)
		{
		}

		~Fence() = default;

		Fence(const Fence&) = delete;
		Fence& operator=(const Fence&) = delete;

		void Signal();
		void Await();
		void Reset();
	};

	class Event
	{
		using Base = cmts_event;
		Base impl;
	public:

		constexpr Event()
			: impl(CMTS_EVENT_INIT)
		{
		}

		~Event() = default;

		Event(const Event&) = delete;
		Event& operator=(const Event&) = delete;

		Result GetState() const;
		Result Signal();
		Result Await();
		Result Reset();
	};

	class Counter
	{
		using Base = cmts_counter;
		Base impl;
	public:

		constexpr Counter(uint64_t start_value)
			: impl(CMTS_COUNTER_INIT(start_value))
		{
		}

		Counter() = default;
		~Counter() = default;

		Counter(const Counter&) = delete;
		Counter& operator=(const Counter&) = delete;

		Result GetState() const;
		uint64_t GetValue() const;
		Result Increment();
		Result Decrement();
		Result Await();
		Result Reset(uint64_t new_start_value);
	};

	class Mutex
	{
		using Base = cmts_mutex;
		Base impl;
	public:

		constexpr Mutex()
			: impl(CMTS_MUTEX_INIT)
		{
		}

		~Mutex() = default;

		Mutex(const Mutex&) = delete;
		Mutex& operator=(const Mutex&) = delete;

		bool IsLocked() const;
		bool TryLock();
		void Lock();
		void Unlock();
	};

	Result Init();
	Result Init(const InitOptions& options);
	Result Pause();
	Result Resume();
	void FinalizeSignal();
	Result FinalizeAwait(DeallocateFn deallocate = nullptr);
	Result Terminate(DeallocateFn deallocate = nullptr);
	bool IsInitialized();
	bool IsOnline();
	bool IsPaused();
	bool IsWorkerThread();
	bool IsTask();
	uint32_t WorkerThreadIndex();
	uint32_t WorkerThreadCount();
	size_t ProcessorCount();
	size_t ThisProcessorIndex();
	size_t DefaultTaskStackSize();
	uint32_t Purge(uint32_t max_purged_count);
	uint32_t PurgeAll();
	Result Dispatch(TaskFn entry_point);
	Result Dispatch(TaskFn entry_point, DispatchOptions& options);
#undef Yield
	void Yield();
	void Exit();
	TaskID ThisTaskID();

	template <typename I, typename F, typename K = ptrdiff_t>
	void ParallelForEach(I begin, I end, F&& body, uint8_t priority = 0, K step = 0)
	{
		struct LoopContext
		{
			F loop_body;
			I iterator;
			Fence fence;
		};

		Counter counter = Counter((uint64_t)std::distance(begin, end));
		LoopContext context = { begin, std::forward<F>(body) };
		DispatchOptions options = {};
		options.flags = DispatchFlags::FORCE;
		options.parameter = &context;
		options.sync_object = &counter;
		for (; context.iterator != end; ++context.iterator)
		{
			context.fence.Reset();
			Dispatch([&](void* ptr)
			{
				LoopContext& ctx = *(LoopContext*)ptr;
				I it = ctx.iterator;
				ctx.fence.Signal();
				ctx.loop_body(it);
			});
			context.fence.Await();
		}
		counter.Await();
	}

	namespace Task
	{
		TaskID New();
		uint8_t GetPriority(TaskID task_id);
		void SetPriority(TaskID task_id, uint8_t new_priority);
		void* GetParameter(TaskID task_id);
		void SetParameter(TaskID task_id, void* new_parameter);
		TaskFn GetFunction(TaskID task_id);
		void SetFunction(TaskID task_id, TaskFn new_function);
		void AttachSyncObject(TaskID task_id, Event& event);
		void AttachSyncObject(TaskID task_id, Counter& counter);
		void Sleep(TaskID task_id);
		void Wake(TaskID task_id);
		bool IsValid(TaskID task_id);
		bool IsSleeping(TaskID task_id);
		bool IsRunning(TaskID task_id);
		void Dispatch(TaskID task_id);
		void Delete(TaskID task_id);
	}

	class TaskRef
	{
		TaskID id;
	public:
		static TaskRef NewTask();
		uint8_t GetPriority() const;
		void SetPriority(uint8_t new_priority);
		void* GetParameter() const;
		void SetParameter(void* new_parameter);
		TaskFn GetFunction() const;
		void SetFunction(TaskFn new_function);
		void AttachSyncObject(Event& event);
		void AttachSyncObject(Counter& counter);
		void Sleep();
		void Wake();
		bool IsValid() const;
		bool IsSleeping() const;
		bool IsRunning() const;
		void Dispatch();
		void Delete();
	};

	namespace RCU
	{
		void ReadBegin();
		void ReadEnd();
		void Sync();
		MemoryRequirements GetSnapshotMemoryRequirements();
		void GetSnapshot(void* snapshot_buffer);
		uint32_t TrySync(const void* snapshot_buffer, uint32_t prior_result = 0);
		void Sync(const void* snapshot_buffer);
	}

	class HazardPtr
	{
		using Base = cmts_hazard_context;
		Base impl;
	public:

		static MemoryRequirements GetMemoryRequirements();
		void Init(void* buffer);
		void Protect(void* ptr);
		void Release();
		bool IsUnreachable(void* ptr) const;
		void* Get();
		void* GetBuffer();
		const void* GetBuffer() const;
	};

	namespace Debug
	{
		using MessageFn = cmts_fn_debugger_message;

		struct InitOptions
		{
			const void* next;
			cmts_ext_type type;
			void* context;
			MessageFn message_callback;
		};

		struct MessageInfo
		{
			StringRef message;
			MessageSeverity severity;
			const void* next_ext;
		};

		bool IsEnabled();
		bool EnableYieldTrap(bool enable);
		void Write(StringRef message, MessageSeverity severity = MessageSeverity::Info);
		void Write(const MessageInfo& message);
	}

	namespace Util
	{
#ifdef CMTS_FORMAT_RESULT
		StringRef Format(Result result);
#endif
	}
}
#endif // CMTS_CPP_INCLUDED



#ifdef CMTS_CPP_IMPLEMENTATION
namespace CMTS
{
	void Fence::Signal()
	{
		cmts_fence_signal((Base*)this);
	}

	void Fence::Await()
	{
		cmts_fence_await((Base*)this);
	}

	void Fence::Reset()
	{
		cmts_fence_init((Base*)this);
	}

	Result Event::GetState() const
	{
		return (Result)cmts_event_state((Base*)this);
	}

	Result Event::Signal()
	{
		return (Result)cmts_event_signal((Base*)this);
	}

	Result Event::Await()
	{
		return (Result)cmts_event_await((Base*)this);
	}

	Result Event::Reset()
	{
		return (Result)cmts_event_reset((Base*)this);
	}

	Result Counter::GetState() const
	{
		return (Result)cmts_counter_state((Base*)this);
	}

	uint64_t Counter::GetValue() const
	{
		return cmts_counter_value((Base*)this);
	}

	Result Counter::Increment()
	{
		return (Result)cmts_counter_increment((Base*)this);
	}

	Result Counter::Decrement()
	{
		return (Result)cmts_counter_decrement((Base*)this);
	}

	Result Counter::Await()
	{
		return (Result)cmts_counter_await((Base*)this);
	}

	Result Counter::Reset(uint64_t new_start_value)
	{
		return (Result)cmts_counter_reset((Base*)this, new_start_value);
	}

	bool Mutex::IsLocked() const
	{
		return cmts_mutex_is_locked((Base*)this);
	}

	bool Mutex::TryLock()
	{
		return cmts_mutex_try_lock((Base*)this);
	}

	void Mutex::Lock()
	{
		cmts_mutex_lock((Base*)this);
	}

	void Mutex::Unlock()
	{
		cmts_mutex_unlock((Base*)this);
	}

	Result Init()
	{
		return (Result)cmts_init(nullptr);
	}

	Result Init(const InitOptions& options)
	{
		return (Result)cmts_init((const cmts_init_options*)&options);
	}

	Result Pause()
	{
		return (Result)cmts_pause();
	}

	Result Resume()
	{
		return (Result)cmts_resume();
	}

	void FinalizeSignal()
	{
		cmts_finalize_signal();
	}

	Result FinalizeAwait(DeallocateFn deallocate)
	{
		return (Result)cmts_finalize_await(deallocate);
	}

	Result Terminate(DeallocateFn deallocate)
	{
		return (Result)cmts_terminate(deallocate);
	}

	bool IsInitialized()
	{
		return cmts_is_initialized();
	}

	bool IsOnline()
	{
		return cmts_is_online();
	}

	bool IsPaused()
	{
		return cmts_is_paused();
	}

	bool IsWorkerThread()
	{
		return cmts_is_worker_thread();
	}

	bool IsTask()
	{
		return cmts_is_task();
	}

	uint32_t WorkerThreadIndex()
	{
		return cmts_worker_thread_index();
	}

	uint32_t WorkerThreadCount()
	{
		return cmts_worker_thread_count();
	}

	size_t ProcessorCount()
	{
		return cmts_processor_count();
	}

	size_t ThisProcessorIndex()
	{
		return cmts_this_processor_index();
	}

	size_t DefaultTaskStackSize()
	{
		return cmts_default_task_stack_size();
	}

	uint32_t Purge(uint32_t max_purged_count)
	{
		return cmts_purge(max_purged_count);
	}

	uint32_t PurgeAll()
	{
		return cmts_purge_all();
	}

	Result Dispatch(TaskFn entry_point)
	{
		return (Result)cmts_dispatch(entry_point, nullptr);
	}

	Result Dispatch(TaskFn entry_point, DispatchOptions& options)
	{
		constexpr size_t offset = offsetof(DispatchOptions, sync_object);
		cmts_dispatch_options o;
		(void)memcpy(&o, &options, offset);
		o.sync_type = (cmts_sync_type)options.sync_object.index();
		std::visit([&](auto e) { o.sync_object = e; }, options.sync_object);
		o.priority = options.priority;
		o.next_ext = options.next_ext;
		return (Result)cmts_dispatch(entry_point, &o);
	}

	void Yield()
	{
		cmts_yield();
	}

	void Exit()
	{
		cmts_exit();
	}

	TaskID ThisTaskID()
	{
		return (TaskID)cmts_this_task_id();
	}

	TaskID Task::New()
	{
		return cmts_task_allocate();
	}

	uint8_t Task::GetPriority(TaskID task_id)
	{
		return cmts_task_get_priority(task_id);
	}

	void Task::SetPriority(TaskID task_id, uint8_t new_priority)
	{
		cmts_task_set_priority(task_id, new_priority);
	}

	void* Task::GetParameter(TaskID task_id)
	{
		return cmts_task_get_parameter(task_id);
	}

	void Task::SetParameter(TaskID task_id, void* new_parameter)
	{
		cmts_task_set_parameter(task_id, new_parameter);
	}

	TaskFn Task::GetFunction(TaskID task_id)
	{
		return cmts_task_get_function(task_id);
	}

	void Task::SetFunction(TaskID task_id, TaskFn new_function)
	{
		cmts_task_set_function(task_id, new_function);
	}

	void Task::AttachSyncObject(TaskID task_id, Event& event)
	{
		cmts_task_attach_event(task_id, (cmts_event*)&event);
	}

	void Task::AttachSyncObject(TaskID task_id, Counter& counter)
	{
		cmts_task_attach_counter(task_id, (cmts_counter*)&counter);
	}

	void Task::Sleep(TaskID task_id)
	{
		cmts_task_sleep(task_id);
	}

	void Task::Wake(TaskID task_id)
	{
		cmts_task_resume(task_id);
	}

	bool Task::IsValid(TaskID task_id)
	{
		return cmts_is_valid_task_id(task_id);
	}

	bool Task::IsSleeping(TaskID task_id)
	{
		return cmts_task_is_sleeping(task_id);
	}

	bool Task::IsRunning(TaskID task_id)
	{
		return cmts_task_is_running(task_id);
	}

	void Task::Dispatch(TaskID task_id)
	{
		cmts_task_dispatch(task_id);
	}

	void Task::Delete(TaskID task_id)
	{
		cmts_task_deallocate(task_id);
	}

	TaskRef TaskRef::NewTask()
	{
		TaskRef r;
		r.id = Task::New();
		return r;
	}

	uint8_t TaskRef::GetPriority() const
	{
		return Task::GetPriority(id);
	}

	void TaskRef::SetPriority(uint8_t new_priority)
	{
		Task::SetPriority(id, new_priority);
	}

	void* TaskRef::GetParameter() const
	{
		return Task::GetParameter(id);
	}

	void TaskRef::SetParameter(void* new_parameter)
	{
		Task::SetParameter(id, new_parameter);
	}

	TaskFn TaskRef::GetFunction() const
	{
		return Task::GetFunction(id);
	}

	void TaskRef::SetFunction(TaskFn new_function)
	{
		Task::SetFunction(id, new_function);
	}

	void TaskRef::AttachSyncObject(Event& event)
	{
		Task::AttachSyncObject(id, event);
	}

	void TaskRef::AttachSyncObject(Counter& counter)
	{
		Task::AttachSyncObject(id, counter);
	}

	void TaskRef::Sleep()
	{
		Task::Sleep(id);
	}

	void TaskRef::Wake()
	{
		Task::Wake(id);
	}

	bool TaskRef::IsValid() const
	{
		return Task::IsValid(id);
	}

	bool TaskRef::IsSleeping() const
	{
		return Task::IsSleeping(id);
	}

	bool TaskRef::IsRunning() const
	{
		return Task::IsRunning(id);
	}

	void TaskRef::Dispatch()
	{
		Task::Dispatch(id);
	}

	void TaskRef::Delete()
	{
		Task::Delete(id);
	}

	void RCU::ReadBegin()
	{
		cmts_rcu_read_begin();
	}

	void RCU::ReadEnd()
	{
		cmts_rcu_read_end();
	}

	void RCU::Sync()
	{
		cmts_rcu_sync();
	}

	MemoryRequirements RCU::GetSnapshotMemoryRequirements()
	{
		MemoryRequirements r;
		cmts_rcu_snapshot_requirements((cmts_memory_requirements*)&r);
		return r;
	}

	void RCU::GetSnapshot(void* snapshot_buffer)
	{
		cmts_rcu_snapshot(snapshot_buffer);
	}

	uint32_t RCU::TrySync(const void* snapshot_buffer, uint32_t prior_result)
	{
		return cmts_rcu_try_snapshot_sync(snapshot_buffer, prior_result);
	}

	void RCU::Sync(const void* snapshot_buffer)
	{
		cmts_rcu_snapshot_sync(snapshot_buffer);
	}

	MemoryRequirements HazardPtr::GetMemoryRequirements()
	{
		MemoryRequirements r;
		cmts_hazard_ptr_requirements((cmts_memory_requirements*)&r);
		return r;
	}

	void HazardPtr::Init(void* buffer)
	{
		cmts_hazard_ptr_init((Base*)this, buffer);
	}

	void HazardPtr::Protect(void* ptr)
	{
		cmts_hazard_ptr_protect((Base*)this, ptr);
	}

	void HazardPtr::Release()
	{
		cmts_hazard_ptr_release((Base*)this);
	}

	bool HazardPtr::IsUnreachable(void* ptr) const
	{
		return cmts_hazard_ptr_is_unreachable((Base*)this, ptr);
	}

	void* HazardPtr::Get()
	{
		return cmts_hazard_ptr_get((Base*)this);
	}

	void* HazardPtr::GetBuffer()
	{
		return (void*)impl;
	}

	const void* HazardPtr::GetBuffer() const
	{
		return (void*)impl;
	}

	bool Debug::IsEnabled()
	{
		return cmts_ext_debug_enabled();
	}

	bool Debug::EnableYieldTrap(bool enable)
	{
		return cmts_ext_debug_enable_yield_trap(true);
	}

	void Debug::Write(StringRef message, MessageSeverity severity)
	{
		cmts_ext_debug_message m;
		m.message = message.data();
		m.message_length = message.size();
		m.severity = (cmts_ext_debug_message_severity)severity;
		m.next_ext = nullptr;
		cmts_ext_debug_write(&m);
	}

	void Debug::Write(const MessageInfo& message)
	{
		cmts_ext_debug_message m;
		m.message = message.message.data();
		m.message_length = message.message.size();
		m.severity = (cmts_ext_debug_message_severity)message.severity;
		m.next_ext = message.next_ext;
		cmts_ext_debug_write(&m);
	}

#ifdef CMTS_FORMAT_RESULT
	StringRef Util::Format(Result result)
	{
		const CMTS_CHAR* text;
		size_t size;
		text = cmts_format_result((cmts_result)result, &size);
		return StringRef(text, size);
	}
#endif
}
#endif // CMTS_CPP_IMPLEMENTATION