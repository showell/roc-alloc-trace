app [main!] {}

# Four pairs of loops that write into a list, each pair differing in one
# line: the first writes in place, the second copies the whole list on
# every write (in some builds). They come from a larger set of copy shapes
# in https://github.com/showell/roc-apps, this tool's first user.
#
#   copy-pairs <shape> <size> <steps>
#
# Each shape makes a list of `size` entries and writes into it `steps`
# times. A write in place allocates nothing; a copy allocates the list
# again, so one more step costs 0 allocations or 1. tests/expected-*.check
# hold each shape's count in the release and the dev build.

main! = |args| {
	shape = args.get(0) ?? crash "usage: copy-pairs <shape> <size> <steps>"
	size = count_at(args, 1)
	steps = count_at(args, 2)
	echo!(U64.to_str(run_shape(shape, size, steps)))
	Ok({})
}

count_at : List(Str), U64 -> U64
count_at = |args, k| {
	text = args.get(k) ?? crash "usage: copy-pairs <shape> <size> <steps>"
	U64.from_str(text) ?? crash "copy-pairs: a size or a step count is a number"
}

run_shape : Str, U64, U64 -> U64
run_shape = |shape, size, steps| {
	match shape {
		"set-or-crash" => set_or_crash(0, steps, size, List.repeat(0, size), 0)
		"get-after-set" => get_after_set(0, steps, size, List.repeat(0, size), 0)
		"closure-called-before" => closure_called_before(0, steps, size, List.repeat(0, size), 0)
		"closure-called-after" => closure_called_after(0, steps, size, List.repeat(0, size), 0)
		"helper-length-before-set" => helper_length_before_set(0, steps, size, List.repeat(0, size), 0)
		"helper-length-after-set" => helper_length_after_set(0, steps, size, List.repeat(0, size), 0)
		"str-list-or-crash" => str_list_or_crash(0, steps, size, List.repeat("a", size), 0)
		"str-list-restored" => str_list_restored(0, steps, size, List.repeat("a", size), 0)
		_ => crash "copy-pairs: no such shape"
	}
}

## Writes in place: nothing reads the old list after the write.
set_or_crash : U64, U64, U64, List(U64), U64 -> U64
set_or_crash = |i, steps, size, xs, sum| {
	if i >= steps {
		sum + xs.len()
	} else {
		j = i % size
		ys = xs.set(j, i) ?? crash "set_or_crash: in range"
		set_or_crash(i + 1, steps, size, ys, sum + j)
	}
}

## **COPIES:** the old list read after the write, so the write can't take it.
get_after_set : U64, U64, U64, List(U64), U64 -> U64
get_after_set = |i, steps, size, xs, sum| {
	if i >= steps {
		sum + xs.len()
	} else {
		j = i % size
		ys = xs.set(j, i) ?? xs
		v = xs.get(j) ?? crash "get_after_set: in range"
		get_after_set(i + 1, steps, size, ys, sum + v)
	}
}

## A closure over the list, called inside the write's own arguments.
closure_called_before : U64, U64, U64, List(U64), U64 -> U64
closure_called_before = |i, steps, size, xs, sum| {
	if i >= steps {
		sum + xs.len()
	} else {
		j = i % size
		at = |k| xs.get(k) ?? crash "closure_called_before: in range"
		ys = xs.set(j, at(j) + 1) ?? xs
		closure_called_before(i + 1, steps, size, ys, sum + j)
	}
}

## **COPIES:** the same closure called after the write: it still holds the
## old list.
closure_called_after : U64, U64, U64, List(U64), U64 -> U64
closure_called_after = |i, steps, size, xs, sum| {
	if i >= steps {
		sum + xs.len()
	} else {
		j = i % size
		at = |k| xs.get(k) ?? crash "closure_called_after: in range"
		ys = xs.set(j, i) ?? xs
		closure_called_after(i + 1, steps, size, ys, sum + at(j))
	}
}

bump_length_first : List(U64), U64, U64 -> (List(U64), U64)
bump_length_first = |xs, j, v| {
	length = xs.len()
	(xs.set(j, v) ?? xs, length)
}

## A helper that reads the length, then writes.
helper_length_before_set : U64, U64, U64, List(U64), U64 -> U64
helper_length_before_set = |i, steps, size, xs, sum| {
	if i >= steps {
		sum + xs.len()
	} else {
		j = i % size
		(ys, length) = bump_length_first(xs, j, i)
		helper_length_before_set(i + 1, steps, size, ys, sum + length)
	}
}

bump_length_after : List(U64), U64, U64 -> (List(U64), U64)
bump_length_after = |xs, j, v| (xs.set(j, v) ?? xs, xs.len())

## **COPIES IN THE DEV BUILD ONLY:** a helper that reads the length after
## its write. The release build specializes the helper and writes in place.
helper_length_after_set : U64, U64, U64, List(U64), U64 -> U64
helper_length_after_set = |i, steps, size, xs, sum| {
	if i >= steps {
		sum + xs.len()
	} else {
		j = i % size
		(ys, length) = bump_length_after(xs, j, i)
		helper_length_after_set(i + 1, steps, size, ys, sum + length)
	}
}

## A list of strings written with `?? crash`, which every build writes in
## place.
str_list_or_crash : U64, U64, U64, List(Str), U64 -> U64
str_list_or_crash = |i, steps, size, xs, sum| {
	if i >= steps {
		sum + xs.len()
	} else {
		j = i % size
		ys = xs.set(j, "x") ?? crash "str_list_or_crash: in range"
		str_list_or_crash(i + 1, steps, size, ys, sum + j)
	}
}

## **COPIES IN THE DEV BUILD ONLY:** the same with `?? xs`. The fallback is
## free only where the entries hold no reference count.
str_list_restored : U64, U64, U64, List(Str), U64 -> U64
str_list_restored = |i, steps, size, xs, sum| {
	if i >= steps {
		sum + xs.len()
	} else {
		j = i % size
		ys = xs.set(j, "x") ?? xs
		str_list_restored(i + 1, steps, size, ys, sum + j)
	}
}
