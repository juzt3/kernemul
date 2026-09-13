#pragma once
#include "../../emu/object.hpp"
#include "defs.hpp"
#include "string.hpp"
#include "types.hpp"

// The guest-side half of a loaded driver. Windows builds one DRIVER_OBJECT per
// driver and hands it to DriverEntry, which is where a driver puts everything
// the system later calls it back through: its unload routine, its dispatch
// table, and the device objects it creates. A driver that is handed nothing
// here faults on its first line, so the object exists whether or not anything
// but the driver ever looks at it.

// What the io manager stamps into the front of the structure, so that code
// handed a bare pointer can tell a driver object from a device object. This is
// the io type, not the object manager's type index -- a driver object has both
// and they are unrelated.
inline constexpr short io_type_driver = 4;

struct driver_object_params
{
	// The driver's name in the object namespace, already built in guest memory.
	_UNICODE_STRING driver_name{};
	// Where the driver was mapped, and how much of it. A driver compares its
	// own addresses against these to decide what belongs to it.
	addr_t driver_start = 0;
	std::uint32_t driver_size = 0;
	// The driver's entry in PsLoadedModuleList. A driver reaches its own
	// KLDR_DATA_TABLE_ENTRY through this and no other way.
	addr_t driver_section = 0;
	addr_t driver_init = 0;
};

inline _DRIVER_OBJECT make_default_driver_object(const driver_object_params& p)
{
	const auto ptr = [](const addr_t a) { return reinterpret_cast<void*>(static_cast<std::uintptr_t>(a)); };

	_DRIVER_OBJECT drv{};

	drv.Type = io_type_driver;
	drv.Size = static_cast<short>(sizeof(_DRIVER_OBJECT));

	// The one field of the object NT fills in that the driver does not.
	drv.DriverName = p.driver_name;

	drv.DriverStart = ptr(p.driver_start);
	drv.DriverSize = p.driver_size;
	drv.DriverSection = ptr(p.driver_section);
	drv.DriverInit = ptr(p.driver_init);

	// DeviceObject, DriverUnload and the MajorFunction table are the driver's
	// to fill in: they are what DriverEntry is for, and NT leaves them empty.

	return drv;
}

// Where a driver object and its registry path live in the guest's namespace.
// Both are strings the driver may read back and print, and a service name is
// the last component of its registry key, so the two are built from one name.
inline constexpr std::wstring_view driver_name_prefix = L"\\Driver\\";
inline constexpr std::wstring_view driver_services_key =
	L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
