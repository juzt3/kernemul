#pragma once
#include "../../emu/object.hpp"
#include "defs.hpp"
#include "string.hpp"
#include "types.hpp"


// The io type, not the object manager's type index -- a driver object has both, unrelated.
inline constexpr short io_type_driver = 4;
inline constexpr short io_type_device = 3;

enum device_flags : std::uint32_t
{
	do_exclusive           = 0x00000008,
	do_device_initializing = 0x00000080,
	do_shutdown_registered = 0x00000800,
};

constexpr device_flags operator|(device_flags a, device_flags b)
{
	return static_cast<device_flags>(static_cast<std::uint32_t>(a) | static_cast<std::uint32_t>(b));
}

struct driver_object_params
{
	_UNICODE_STRING driver_name{};
	addr_t driver_start = 0;
	std::uint32_t driver_size = 0;
	// A driver reaches its own KLDR_DATA_TABLE_ENTRY through this and no other way.
	addr_t driver_section = 0;
	addr_t driver_init = 0;
};

inline _DRIVER_OBJECT make_default_driver_object(const driver_object_params& p)
{
	const auto ptr = [](const addr_t a) { return reinterpret_cast<void*>(static_cast<std::uintptr_t>(a)); };

	_DRIVER_OBJECT drv{};

	drv.Type = io_type_driver;
	drv.Size = static_cast<short>(sizeof(_DRIVER_OBJECT));

	drv.DriverName = p.driver_name;

	drv.DriverStart = ptr(p.driver_start);
	drv.DriverSize = p.driver_size;
	drv.DriverSection = ptr(p.driver_section);
	drv.DriverInit = ptr(p.driver_init);

	// DeviceObject, DriverUnload and MajorFunction are the driver's; NT leaves them empty.

	return drv;
}

// A service name is the last component of its registry key, so the two are built from one name.
inline constexpr std::u16string_view driver_name_prefix = u"\\Driver\\";
inline constexpr std::u16string_view driver_services_key =
	u"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
