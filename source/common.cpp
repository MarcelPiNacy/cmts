#include <atomic>

#if (defined(DEBUG) || defined(_DEBUG) || !defined(NDEBUG)) && !defined(CMTS_DEBUG)
#define CMTS_DEBUG
#endif

#ifdef _WIN32
#define CMTS_OS_WINDOWS
#define WIN32_LEAN_AND_MEAN
#define VC_EXTRALEAN
#define NOMINMAX
#include <Windows.h>
#define CMTS_OS_ALLOCATE(size) VirtualAlloc(nullptr, (size), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
#define CMTS_YIELD_CURRENT_THREAD SwitchToThread()
#define CMTS_DEFAULT_THREAD_STACK_SIZE (1 << 21)
#else
#error "cmts: UNSUPPORTED OPERATING SYSTEM"
#endif

#ifdef __clang__
#if defined(__arm__) || defined(__aarch64__)
#define CMTS_NOOP __nop()
#define CMTS_YIELD_CPU __yield()
#elif defined(__i386__) || defined(__x86_64__)
#include <intrin.h>
#define CMTS_NOOP __nop()
#define CMTS_YIELD_CPU _mm_pause()
#else
#error "UNSUPPORTED PROCESSOR ARCHITECTURE"
#endif
#define CMTS_LIKELY_IF(expression) if (__builtin_expect((expression), 1))
#define CMTS_UNLIKELY_IF(expression) if (__builtin_expect((expression), 0))
#define CMTS_ASSUME(expression) __builtin_assume((expression))
#define CMTS_UNREACHABLE __builtin_unreachable()
#define CMTS_ALLOCA(size) __builtin_alloca((size))
#define CMTS_POPCOUNT(value) __builtin_popcount((value))
#ifdef CMTS_DEBUG
#define CMTS_INLINE_ALWAYS
#define CMTS_INLINE_NEVER
#else
#define CMTS_INLINE_ALWAYS __attribute__((always_inline))
#define CMTS_INLINE_NEVER __attribute__((noinline))
#endif
#elif defined(_MSC_VER) || defined(_MSVC_LANG)
#if defined(_M_ARM) || defined(_M_ARM64)
#define CMTS_YIELD_CPU __yield()
#elif defined(_M_IX86) || defined(_M_AMD64)
#include <intrin.h>
#define CMTS_YIELD_CPU _mm_pause()
#else
#error "UNSUPPORTED PROCESSOR ARCHITECTURE"
#endif
#define CMTS_LIKELY_IF(expression) if ((expression))
#define CMTS_UNLIKELY_IF(expression) if ((expression))
#define CMTS_ASSUME(expression) __assume((expression))
#define CMTS_UNREACHABLE CMTS_ASSUME(0)
#define CMTS_ALLOCA(size) _alloca((size))
#define CMTS_POPCOUNT(value) __popcnt((value))
#ifdef CMTS_DEBUG
#define CMTS_INLINE_ALWAYS
#define CMTS_INLINE_NEVER
#else
#define CMTS_INLINE_ALWAYS __forceinline
#define CMTS_INLINE_NEVER __declspec(noinline)
#endif
#else
#error "cmts: UNSUPPORTED COMPILER";
#endif

#if CMTS_EXPECTED_CACHE_LINE_SIZE != 64
static_assert(CMTS_POPCOUNT(CMTS_EXPECTED_CACHE_LINE_SIZE) == 1, "CMTS_EXPECTED_CACHE_LINE_SIZE MUST BE A POWER OF TWO");
#endif

#ifdef CMTS_DEBUG
#include <assert.h>
#define CMTS_ASSERT(expression) assert((expression))
#define CMTS_ASSERT_SIDE_EFFECTS(expression) assert((expression))
#else
#define CMTS_ASSERT(expression) CMTS_ASSUME((expression))
#define CMTS_ASSERT_SIDE_EFFECTS(expression) expression
#endif