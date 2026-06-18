#pragma once

#include "../emulator/emulator.hpp"
#include "../image/mapped_image.hpp"
#include "../kernel/kernel.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace user
{
	using syscall_id_type = std::uint32_t;

	struct syscall_entry_t
	{
		syscall_id_type number;
		std::string name;
		kernel::function_implementation_t handler;
	};

	class syscall_table_t
	{
	public:
		void parse_from_image(const std::shared_ptr<emulator_t>& emulator,
			const std::shared_ptr<image_t>& image);

		void register_handler(const std::string& name,
			const kernel::function_implementation_t& handler);

		[[nodiscard]] std::optional<syscall_entry_t> find_by_number(syscall_id_type syscall_number) const;
		[[nodiscard]] std::string_view find_name(syscall_id_type syscall_number) const;

		[[nodiscard]] std::size_t size() const { return entries_.size(); }

	private:
		std::unordered_map<syscall_id_type, syscall_entry_t> entries_;
		std::unordered_map<std::string, syscall_id_type> name_to_number_;
	};

	inline syscall_table_t syscall_table;
}
