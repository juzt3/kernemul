#include "nt_helpers.hpp"

#include <intrin.h>

static constexpr std::uint8_t normal_year_day_to_month[365] = {
	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
	 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
	 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
	 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
	10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,
	11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11
};

static constexpr std::uint8_t leap_year_day_to_month[366] = {
	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
	 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
	 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
	 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
	10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,
	11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11
};

static constexpr std::int16_t normal_year_month_start[12] = {
	0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
};

static constexpr std::int16_t leap_year_month_start[12] = {
	0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335
};

// 64x64->128 multiply, return upper 64 bits >> shift_count
static std::int64_t rtl_extended_magic_divide(const std::int64_t dividend,
	const std::int64_t magic_divisor,
	const int shift_count)
{
	auto abs_dividend = static_cast<std::uint64_t>(dividend < 0 ? -dividend : dividend);

	unsigned __int64 high = 0;

	_umul128(abs_dividend, static_cast<std::uint64_t>(magic_divisor), &high);

	const auto result = static_cast<std::int64_t>(high >> shift_count);

	return dividend < 0 ? -result : result;
}

static constexpr std::int64_t magic_10000 = 0xD1B71758E219652CLL;
static constexpr std::int64_t magic_86400000 = 0xC6D750EBFA67B90ELL;

static void time_to_days_and_fraction(const std::int64_t time, std::int32_t& days, std::uint32_t& fraction)
{
	const auto milliseconds = rtl_extended_magic_divide(time, magic_10000, 13);
	const auto day_count = rtl_extended_magic_divide(milliseconds, magic_86400000, 26);

	days = static_cast<std::int32_t>(day_count);
	fraction = static_cast<std::uint32_t>(milliseconds - 86400000LL * day_count);
}

static bool is_leap_year(const std::uint32_t year)
{
	if (year % 400 == 0) return true;
	if (year % 100 == 0) return false;

	return (year % 4) == 0;
}

static _TIME_FIELDS time_to_time_fields(const std::int64_t time)
{
	std::int32_t days = 0;
	std::uint32_t fraction = 0;

	time_to_days_and_fraction(time, days, fraction);

	_TIME_FIELDS fields = { };

	fields.Weekday = static_cast<SHORT>((days + 1) % 7);

	const auto total_days = static_cast<std::uint32_t>(days);

	const std::uint32_t n400 = total_days / 146097;
	const std::uint32_t d400 = total_days % 146097;

	const std::uint32_t n100 = (100 * d400 + 75) / 3652425;

	const std::uint32_t d100 = d400 - 36524 * n100;

	const std::uint32_t n4 = d100 / 1461;

	const std::uint32_t d4 = d100 % 1461;

	const std::uint32_t n1 = (100 * d4 + 75) / 36525;

	const std::uint32_t year = 4 * (25 * n100 + n4) + n1 + 400 * n400;

	const auto year_plus_one = year + 1;
	const auto day_of_year = static_cast<std::int64_t>(
		days - 365 * year - year / 4 + year / 100 - year / 400);

	std::uint8_t month_index = 0;
	std::int16_t month_start_day = 0;

	if (is_leap_year(year_plus_one))
	{
		month_index = leap_year_day_to_month[day_of_year];
		month_start_day = leap_year_month_start[month_index];
	}
	else
	{
		month_index = normal_year_day_to_month[day_of_year];
		month_start_day = normal_year_month_start[month_index];
	}

	fields.Year = static_cast<SHORT>(year + 1601);
	fields.Month = static_cast<SHORT>(month_index + 1);
	fields.Day = static_cast<SHORT>(day_of_year - month_start_day + 1);

	fields.Milliseconds = static_cast<SHORT>(fraction % 1000);

	const std::uint32_t total_seconds = fraction / 1000;
	const std::uint32_t total_minutes = total_seconds / 60;

	fields.Hour = static_cast<SHORT>(total_minutes / 60);
	fields.Minute = static_cast<SHORT>(total_minutes % 60);
	fields.Second = static_cast<SHORT>(total_seconds % 60);

	return fields;
}

static void handle_system_time_to_local_time(const std::shared_ptr<emulator_t>& emulator,
	emulator_object_t<LARGE_INTEGER> system_time_object,
	emulator_object_t<LARGE_INTEGER> local_time_object)
{
	const auto system_time = system_time_object.read();

	constexpr std::int64_t timezone_bias = 0;

	LARGE_INTEGER local_time;

	local_time.QuadPart = system_time.QuadPart - timezone_bias;

	local_time_object.write(local_time);

	THREAD_LOG("ExSystemTimeToLocalTime called (system_time=0x{:X})", system_time.QuadPart);
}

static void handle_time_to_time_fields(const std::shared_ptr<emulator_t>& emulator,
	emulator_object_t<LARGE_INTEGER> time_object,
	emulator_object_t<_TIME_FIELDS> time_fields_object)
{
	const auto time = time_object.read();
	const auto fields = time_to_time_fields(time.QuadPart);

	time_fields_object.write(fields);

	THREAD_LOG("RtlTimeToTimeFields called (time=0x{:X}, {}-{:02}-{:02} {:02}:{:02}:{:02}.{:03})",
		time.QuadPart, fields.Year, fields.Month, fields.Day,
		fields.Hour, fields.Minute, fields.Second, fields.Milliseconds);
}

static void handle_query_performance_counter(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type frequency_address)
{
	static std::uint64_t counter = 0;
	constexpr std::uint64_t frequency = 10000000;

	counter += 100000;

	if (frequency_address)
	{
		static_cast<void>(emulator->write_virtual_memory(
			frequency_address, &frequency, sizeof(frequency)));
	}

	THREAD_LOG("KeQueryPerformanceCounter called (counter=0x{:X})", counter);

	write_return_value(emulator, counter);
}

static void handle_query_time_increment(const std::shared_ptr<emulator_t>& emulator)
{
	constexpr std::uint32_t time_increment = 156250;

	THREAD_LOG("KeQueryTimeIncrement called -> {}", time_increment);

	write_return_value(emulator, static_cast<std::uint64_t>(time_increment));
}

void redirect_ntoskrnl_time_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image)
{
	redirect_handler<handle_system_time_to_local_time>(emulator, mapped_image, "ExSystemTimeToLocalTime");

	redirect_handler<handle_time_to_time_fields>(emulator, mapped_image, "RtlTimeToTimeFields");

	redirect_handler<handle_query_performance_counter>(emulator, mapped_image, "KeQueryPerformanceCounter");

	redirect_handler<handle_query_time_increment>(emulator, mapped_image, "KeQueryTimeIncrement");
}
