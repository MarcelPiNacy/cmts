#include <cmts.h>
#include <cstdlib>
#include <ctime>
#include <cassert>
#include <cstdio>

struct array_info
{
	int* ptr;
	int size;
};

struct array_view
{
	int* ptr;
	int low;
	int high;
};

void random_init(array_view* view)
{
	for (int i = view->low; i < view->high; ++i)
		view->ptr[i] = rand();
	delete view;
}

int partition(int* array, int low, int high)
{
	const int pivot = (low + high) / 2;
	--low;
	++high;

	while (true)
	{
		do { ++low; } while (array[low] < array[pivot]);
		do { --high; } while (array[high] > array[pivot]);

		if (high < low)
			return high;

		const int tmp = array[low];
		array[low] = array[high];
		array[high] = tmp;
	}
}

void quick_sort(array_view* view)
{
	if (view->low < view->high)
	{
		cmts_dispatch_options_t opt;
		opt.sync_type = CMTS_SYNC_TYPE_COUNTER;
		opt.sync_object = cmts_new_counter(2);
		opt.priority = 0;

		const int p = partition(view->ptr, view->low, view->high);

		opt.parameter = new array_view{ view->ptr, view->low, p };
		cmts_dispatch((cmts_function_pointer_t)quick_sort, &opt);

		opt.parameter = new array_view{ view->ptr, p + 1, view->high };
		cmts_dispatch((cmts_function_pointer_t)quick_sort, &opt);

		cmts_await_counter_and_delete(opt.sync_object);
	}

	delete view;
}

void check_sorted(int* array, int size)
{
	for (int i = 1; i < size; ++i)
	{
		if (array[i - 1] > array[i])
		{
			puts("Failed to sort array!");
			getchar();
			abort();
		}
	}
}

void entry_point(void* unused)
{
	srand(time(nullptr));

	array_info array;
	array.size = 1 << 21;
	array.ptr = new int[array.size];
	
	const int group_size = 64 / sizeof(int);
	const int k = array.size / group_size;

	// Randomly initialize the array, in parallel:

	cmts_dispatch_options_t opt;
	opt.sync_type = CMTS_SYNC_TYPE_COUNTER;
	opt.sync_object = cmts_new_counter(k);
	opt.priority = 0;

	for (int i = 0; i < array.size; i += group_size)
	{
		opt.parameter = new array_view{ array.ptr, i, i + group_size };
		cmts_dispatch((cmts_function_pointer_t)random_init, &opt);
	}

	cmts_await_counter_and_delete(opt.sync_object);

	// Run parallel quicksort:

	opt.sync_type = CMTS_SYNC_TYPE_FENCE;
	opt.sync_object = cmts_new_fence();
	opt.parameter = new array_view{ array.ptr, 0, array.size - 1 };
	cmts_dispatch((cmts_function_pointer_t)quick_sort, &opt);
	cmts_await_fence_and_delete(opt.sync_object);

	// Check if sort succeeded:

	check_sorted(array.ptr, array.size);

	cmts_signal_finalize();
}

int main()
{
	cmts_init(nullptr);
	cmts_dispatch(entry_point, nullptr);
	cmts_finalize(nullptr);
	return 0;
}

// Ideally, this should be in its own .CPP file:
#define CMTS_IMPLEMENTATION
#include <cmts.h>