#include "nt_lock_ops.hpp"
#include "../win_kernel.hpp"
#include "../rundown.hpp"
#include "../thread.hpp"
#include "../status.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"

namespace
{

// EX_PUSH_LOCK. Bit 0 says the lock is held whichever way it was taken, and the
// share count sits above the four state bits -- so a shared acquire of a free
// lock leaves 0x11, which is the constant the real fast path exchanges in.
enum ex_push_lock_state : std::uint64_t
{
	push_lock_locked          = 0x1,
	push_lock_waiting         = 0x2,
	push_lock_multiple_shared = 0x8,
	push_lock_share_increment = 0x10,
	push_lock_state_mask      = 0xF,
};

// Which of the Ex forms' flags mean anything. The binary bugchecks on the rest
// rather than ignoring them, so the mask is a validity check and not a state.
constexpr std::uint32_t push_lock_known_flags = 0x7;

enum eresource_flag : std::uint16_t
{
	// ERESOURCE::Flag: the resource is held for writing rather than reading.
	resource_owned_exclusive = 0x80,
};

// An OWNER_ENTRY's second word packs three flag bits under the recursion count,
// which owner_count and set_owner below are the whole of.
constexpr std::uint32_t owner_flag_mask = 0x7;
constexpr std::uint32_t owner_count_shift = 3;

addr_t current_ethread(vcpu& cpu)
{
	const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());
	return (t && t->ethread()) ? t->ethread().address() : 0;
}

// Nothing here can contend a push lock, for the same reason nothing contends a
// spin lock: the acquiring cpu is stopped inside the handler, so whatever the
// guest is locking against is not running. A lock found already held means the
// guest reached it down a path a real wait would have blocked.
void take_push_lock(emu_object<std::uint64_t> push_lock, const std::uint32_t flags,
	const bool shared, const char* who)
{
	if (flags & ~push_lock_known_flags)
		THREAD_LOG_ERR("{}: flags 0x{:X} are not a push lock's", who, flags);

	const auto value = push_lock.read();
	const auto shares = value / push_lock_share_increment;

	if ((value & push_lock_locked) && (shares == 0 || !shared))
	{
		THREAD_LOG_ERR("{}: 0x{:X} is already held and nothing here can wait",
			who, push_lock.address());
		return;
	}

	const auto taken = shared
		? ((value | push_lock_locked) + push_lock_share_increment)
			| (shares ? push_lock_multiple_shared : 0)
		: (value | push_lock_locked);

	push_lock.write(taken);

	THREAD_LOG_INFO("{}(lock=0x{:X}, flags=0x{:X}) -> 0x{:X}",
		who, push_lock.address(), flags, taken);
}

// The release the binary's fast path performs, which is one formula for both
// kinds: a share decrement, collapsing to nothing once the last share -- or the
// single exclusive hold, whose value is below one share -- goes.
void give_push_lock(emu_object<std::uint64_t> push_lock, const std::uint32_t flags,
	const char* who)
{
	if (flags & ~push_lock_known_flags)
		THREAD_LOG_ERR("{}: flags 0x{:X} are not a push lock's", who, flags);

	const auto value = push_lock.read();

	if (!(value & push_lock_locked))
	{
		THREAD_LOG_ERR("{}: 0x{:X} was not held", who, push_lock.address());
		return;
	}

	if (value & push_lock_waiting)
		THREAD_LOG_ERR("{}: 0x{:X} has waiters that nothing will wake", who, push_lock.address());

	const auto released = (value & ~push_lock_state_mask) <= push_lock_share_increment
		? 0
		: value - push_lock_share_increment;

	push_lock.write(released);

	THREAD_LOG_INFO("{}(lock=0x{:X}, flags=0x{:X}) -> 0x{:X}",
		who, push_lock.address(), flags, released);
}

// An ERESOURCE's single owner entry. Windows spills further shared owners into
// an allocated owner table; nothing here has two threads inside a resource at
// once -- the cpu is stopped in the handler -- so recursion by the one owner is
// the whole of what the count has to carry.
std::uint32_t owner_count(const emu_object<_ERESOURCE>& resource)
{
	return resource.field(&_ERESOURCE::OwnerEntry).field(&_OWNER_ENTRY::TableSize).read()
		>> owner_count_shift;
}

void set_owner(const emu_object<_ERESOURCE>& resource, const addr_t owner_thread,
	const std::uint32_t count)
{
	auto entry = resource.field(&_ERESOURCE::OwnerEntry);

	entry.field(&_OWNER_ENTRY::OwnerThread).write(owner_thread);
	entry.field(&_OWNER_ENTRY::TableSize).write(
		(entry.field(&_OWNER_ENTRY::TableSize).read() & owner_flag_mask)
			| (count << owner_count_shift));
}

bool take_resource(const emu_object<_ERESOURCE>& resource, vcpu& cpu,
	const bool exclusive, const std::uint8_t wait, const char* who)
{
	const auto owner = current_ethread(cpu);
	const auto entries = resource.field(&_ERESOURCE::ActiveEntries).read();
	const auto flag = resource.field(&_ERESOURCE::Flag).read();
	const auto held_exclusive = (flag & resource_owned_exclusive) != 0;
	const auto held_by = resource.field(&_ERESOURCE::OwnerEntry)
		.field(&_OWNER_ENTRY::OwnerThread).read();

	// Free: take it, and say which way it is held so a release can tell.
	if (entries == 0)
	{
		resource.field(&_ERESOURCE::Flag).write(static_cast<std::uint16_t>(
			exclusive ? (flag | resource_owned_exclusive) : (flag & ~resource_owned_exclusive)));

		set_owner(resource, owner, 1);
		resource.field(&_ERESOURCE::ActiveEntries).write(1);
		resource.field(&_ERESOURCE::ActiveCount).write(1);

		THREAD_LOG_INFO("{}(resource=0x{:X}, wait={}) -> true", who, resource.address(), wait);

		return true;
	}

	// Recursive, and a shared acquire of a shared resource, are the two the
	// owner entry can carry.
	if (held_by == owner || (!exclusive && !held_exclusive))
	{
		if (held_by != owner)
		{
			resource.field(&_ERESOURCE::ActiveEntries).write(entries + 1);
			resource.field(&_ERESOURCE::ActiveCount).write(
				static_cast<std::int16_t>(resource.field(&_ERESOURCE::ActiveCount).read() + 1));
		}

		set_owner(resource, owner, owner_count(resource) + 1);

		THREAD_LOG_INFO("{}(resource=0x{:X}, wait={}): recursive -> true",
			who, resource.address(), wait);

		return true;
	}

	// A caller that passed Wait is documented never to be refused, so it is the
	// one that has to be told the wait did not happen.
	if (wait)
		THREAD_LOG_ERR("{}: 0x{:X} is held by thread 0x{:X} and nothing here can wait",
			who, resource.address(), held_by);
	else
		THREAD_LOG_INFO("{}(resource=0x{:X}, wait=0) -> false", who, resource.address());

	return false;
}

}

// Push locks, executive resources, and the rundown reference a driver waits on
// before tearing something down. All three are reader/writer locks whose only
// observable state here is what they leave in their own memory: a redirect runs
// with its cpu stopped, so no second party can be holding one, and no wait can
// be satisfied by anything other than the caller giving up.
void modules::register_ntoskrnl_lock_ops(win_kernel_state& state, proc_module& mod)
{
	// One instruction that zeroes eight bytes serves three exports: the linker
	// folds ExInitializeRundownProtection and KeInitializeSpinLock onto this on
	// both architectures, so all three names reach this handler.
	state.redirect(mod, "ExInitializePushLock",
		[](vcpu&, emu_object<std::uint64_t> push_lock)
		{
			if (!push_lock)
				return;

			push_lock.write(0);

			THREAD_LOG_INFO("ExInitializePushLock(lock=0x{:X})", push_lock.address());
		});

	state.redirect(mod, "ExAcquirePushLockExclusiveEx",
		[](vcpu&, emu_object<std::uint64_t> push_lock, const std::uint32_t flags)
		{
			if (push_lock)
				take_push_lock(push_lock, flags, false, "ExAcquirePushLockExclusiveEx");
		});

	state.redirect(mod, "ExAcquirePushLockSharedEx",
		[](vcpu&, emu_object<std::uint64_t> push_lock, const std::uint32_t flags)
		{
			if (push_lock)
				take_push_lock(push_lock, flags, true, "ExAcquirePushLockSharedEx");
		});

	state.redirect(mod, "ExReleasePushLockEx",
		[](vcpu&, emu_object<std::uint64_t> push_lock, const std::uint32_t flags)
		{
			if (push_lock)
				give_push_lock(push_lock, flags, "ExReleasePushLockEx");
		});

	state.redirect(mod, "ExReleasePushLockExclusiveEx",
		[](vcpu&, emu_object<std::uint64_t> push_lock, const std::uint32_t flags)
		{
			if (push_lock)
				give_push_lock(push_lock, flags, "ExReleasePushLockExclusiveEx");
		});

	state.redirect(mod, "ExReleasePushLockSharedEx",
		[](vcpu&, emu_object<std::uint64_t> push_lock, const std::uint32_t flags)
		{
			if (push_lock)
				give_push_lock(push_lock, flags, "ExReleasePushLockSharedEx");
		});

	state.redirect(mod, "ExInitializeResourceLite",
		[](vcpu&, emu_object<_ERESOURCE> resource) -> NTSTATUS
		{
			if (!resource)
				return STATUS_INVALID_PARAMETER;

			resource.write(_ERESOURCE{});

			// The system resource list is circular and anchored in the resource
			// itself; nothing links them together here, so an empty one points
			// at its own head.
			const auto head = resource.field(&_ERESOURCE::SystemResourcesList).address();
			resource.field(&_ERESOURCE::SystemResourcesList).write(guest_links(head, head));

			THREAD_LOG_INFO("ExInitializeResourceLite(resource=0x{:X})", resource.address());

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "ExAcquireResourceExclusiveLite",
		[](vcpu& cpu, emu_object<_ERESOURCE> resource, const std::uint8_t wait) -> bool
		{
			return resource
				&& take_resource(resource, cpu, true, wait, "ExAcquireResourceExclusiveLite");
		});

	state.redirect(mod, "ExAcquireResourceSharedLite",
		[](vcpu& cpu, emu_object<_ERESOURCE> resource, const std::uint8_t wait) -> bool
		{
			return resource
				&& take_resource(resource, cpu, false, wait, "ExAcquireResourceSharedLite");
		});

	state.redirect(mod, "ExReleaseResourceLite",
		[](vcpu&, emu_object<_ERESOURCE> resource)
		{
			if (!resource)
				return;

			const auto count = owner_count(resource);
			const auto entries = resource.field(&_ERESOURCE::ActiveEntries).read();

			if (!count || !entries)
			{
				// Real NT bugchecks with RESOURCE_NOT_OWNED. The guest is left
				// standing instead, because a driver releasing a resource it
				// never took is easier to read about than to find in a crash.
				THREAD_LOG_ERR("ExReleaseResourceLite: 0x{:X} is not held", resource.address());
				return;
			}

			if (count > 1)
			{
				set_owner(resource, resource.field(&_ERESOURCE::OwnerEntry)
					.field(&_OWNER_ENTRY::OwnerThread).read(), count - 1);

				THREAD_LOG_INFO("ExReleaseResourceLite(resource=0x{:X}): {} recursive holds left",
					resource.address(), count - 1);

				return;
			}

			set_owner(resource, 0, 0);
			resource.field(&_ERESOURCE::ActiveEntries).write(entries - 1);
			resource.field(&_ERESOURCE::Flag).write(static_cast<std::uint16_t>(
				resource.field(&_ERESOURCE::Flag).read() & ~resource_owned_exclusive));

			if (entries == 1)
				resource.field(&_ERESOURCE::ActiveCount).write(0);

			THREAD_LOG_INFO("ExReleaseResourceLite(resource=0x{:X}): {} owners left",
				resource.address(), entries - 1);
		});

	state.redirect(mod, "ExDeleteResourceLite",
		[](vcpu&, emu_object<_ERESOURCE> resource) -> NTSTATUS
		{
			if (!resource)
				return STATUS_INVALID_PARAMETER;

			if (resource.field(&_ERESOURCE::ActiveEntries).read())
				THREAD_LOG_ERR("ExDeleteResourceLite: 0x{:X} is still held", resource.address());

			// No owner table was ever allocated, so unlinking the resource from
			// its own list is all the teardown there is.
			resource.write(_ERESOURCE{});

			THREAD_LOG_INFO("ExDeleteResourceLite(resource=0x{:X})", resource.address());

			return STATUS_SUCCESS;
		});

	// Marks a rundown reference closed so no further reference can be taken,
	// and waits for the outstanding ones. Nothing can drop a reference while
	// this cpu is stopped, so an outstanding one is a wait that cannot end.
	state.redirect(mod, "ExWaitForRundownProtectionRelease", [](vcpu&, win::rundown_ref run_ref)
	{
		if (!run_ref)
			return;

		if (const auto held = win::rundown_references(run_ref))
			THREAD_LOG_ERR("ExWaitForRundownProtectionRelease: 0x{:X} has {} references and "
				"nothing here can wait", run_ref.address(), held);

		win::begin_rundown(run_ref);

		THREAD_LOG_INFO("ExWaitForRundownProtectionRelease(0x{:X}): running down",
			run_ref.address());
	});
}
