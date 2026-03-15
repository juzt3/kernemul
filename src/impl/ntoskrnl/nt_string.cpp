#include "nt_helpers.hpp"

void redirect_ntoskrnl_string_functions(const std::shared_ptr<emulator_t>& emulator,
	const mapped_image_t& mapped_image)
{
	redirect_function(
		[emulator]
		{
			const auto rcx = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto rdx = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			auto destination_object = emulator_object_t<UNICODE_STRING>::view_at(emulator, rcx);

			UNICODE_STRING destination = { };

			destination.Buffer = reinterpret_cast<PWSTR>(rdx);

			if (rdx)
			{
				const auto source_string = kernel::read_guest_wstring(*emulator, rdx);
				const auto count = static_cast<std::int64_t>(source_string.size());

				auto byte_length = static_cast<std::uint64_t>(sizeof(wchar_t) * count);

				if (byte_length >= 0xFFFE)
				{
					byte_length = (byte_length & ~static_cast<std::uint64_t>(0xFFFF)) | 0xFFFC;
				}

				destination.Length = static_cast<std::uint16_t>(byte_length);
				destination.MaximumLength = static_cast<std::uint16_t>(byte_length + sizeof(wchar_t));

				spdlog::info("RtlInitUnicodeString called (destination=0x{:X}, source='{}')",
					rcx, util::narrow_wstring(source_string));
			}
			else
			{
				spdlog::info("RtlInitUnicodeString called (destination=0x{:X}, source=null)", rcx);
			}

			destination_object.write(destination);
		},
		mapped_image,
		"RtlInitUnicodeString"
	);

	redirect_function(
		[emulator]
		{
			const auto ecx = emulator->read_register<x86::reg::rcx, std::uint32_t>();
			const auto rdx = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto r8 = emulator->read_register<x86::reg::r8, std::uint64_t>();

			spdlog::info("RtlDuplicateUnicodeString called (string in=0x{:X})", rdx);

			if ((ecx & 0xFFFFFFFC) != 0 ||
				((ecx & 2) != 0 && (ecx & 1) == 0) ||
				!r8)
			{
				write_nt_status(emulator, 0xC000000D);

				return;
			}

			auto destination_string_object = emulator_object_t<UNICODE_STRING>::view_at(emulator, r8);

			std::uint16_t length = 0;
			std::uint16_t max_length = 0;
			emulator_t::address_type source_buffer_address = 0;

			if (rdx)
			{
				const auto source_string_object = emulator_object_t<UNICODE_STRING>::view_at(emulator, rdx);
				const auto source_string = source_string_object.read();

				if ((source_string.Length & 1) != 0 ||
					(source_string.MaximumLength & 1) != 0 ||
					source_string.Length > source_string.MaximumLength ||
					source_string.MaximumLength == 0xFFFF ||
					(!source_string.Buffer && (source_string.Length || source_string.MaximumLength)))
				{
					write_nt_status(emulator, 0xC000000D);

					return;
				}

				length = source_string.Length;
				source_buffer_address = reinterpret_cast<emulator_t::address_type>(source_string.Buffer);
			}

			if (ecx & 1)
			{
				if (length == 0xFFFE)
				{
					write_nt_status(emulator, 0xC0000106);

					return;
				}

				max_length = length + 2;
			}
			else
			{
				max_length = length;
			}

			if ((ecx & 2) == 0 && !length)
			{
				max_length = 0;
			}

			PWSTR guest_buffer = nullptr;

			if (max_length)
			{
				const auto buffer_allocation = emulator->heap_allocate(max_length, prot_read_write);

				emulator_err_t error = buffer_allocation.error_or({});

				error.throw_if("string heap allocation");

				std::vector<std::uint8_t> buffer(max_length, 0);

				if (length)
				{
					error = emulator->read_virtual_memory(source_buffer_address, buffer.data(), length);

					error.throw_if("read source buffer");
				}

				if (ecx & 1)
				{
					*reinterpret_cast<std::uint16_t*>(buffer.data() + length) = 0;
				}

				error = emulator->write_virtual_memory(*buffer_allocation, buffer);

				error.throw_if("write memory");

				guest_buffer = reinterpret_cast<PWSTR>(*buffer_allocation);
			}

			const UNICODE_STRING destination_string = {
				.Length = length,
				.MaximumLength = max_length,
				.Buffer = guest_buffer
			};

			destination_string_object.write(destination_string);

			write_nt_success(emulator);
		},
		mapped_image,
		"RtlDuplicateUnicodeString"
	);

	redirect_function(
		[emulator]
		{
			const auto rcx = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			auto string_object = emulator_object_t<UNICODE_STRING>::view_at(emulator, rcx);
			const auto string_value = string_object.read();

			if (string_value.Buffer)
			{
				spdlog::info("RtlFreeUnicodeString called (buffer=0x{:X})", reinterpret_cast<std::uint64_t>(string_value.Buffer));

				const UNICODE_STRING zeroed = { };

				string_object.write(zeroed);
			}
			else
			{
				spdlog::info("RtlFreeUnicodeString called (buffer=null)");
			}
		},
		mapped_image,
		"RtlFreeUnicodeString"
	);

	redirect_function(
		[emulator]
		{
			const auto rcx = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			if (!rcx)
			{
				spdlog::info("wcslen called (str=null, result=0)");

				write_return_value(emulator, 0);

				return;
			}

			const auto str = kernel::read_guest_wstring(*emulator, rcx);

			spdlog::info("wcslen called (str='{}', result={})", util::narrow_wstring(str), str.size());

			write_return_value(emulator, str.size());
		},
		mapped_image,
		"wcslen"
	);

	redirect_function(
		[emulator]
		{
			const auto dst_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto size_in_words = emulator->read_register<x86::reg::rdx, std::uint64_t>();
			const auto src_address = emulator->read_register<x86::reg::r8, emulator_t::address_type>();

			constexpr std::uint32_t einval = 22;
			constexpr std::uint32_t erange = 34;

			if (!dst_address || !size_in_words)
			{
				spdlog::warn("wcscpy_s called with null dst or zero size (dst=0x{:X}, size={}, src=0x{:X})",
					dst_address, size_in_words, src_address);

				write_return_value(emulator, einval);

				return;
			}

			if (!src_address)
			{
				spdlog::warn("wcscpy_s called with null src (dst=0x{:X}, size={})", dst_address, size_in_words);

				const wchar_t null_term = 0;

				emulator_err_t error = emulator->write_virtual_memory(dst_address, &null_term, sizeof(null_term));

				error.throw_if("wcscpy_s write null terminator");

				write_return_value(emulator, einval);

				return;
			}

			const auto src_string = kernel::read_guest_wstring(*emulator, src_address);

			spdlog::info("wcscpy_s called (dst=0x{:X}, size={}, src='{}')",
				dst_address, size_in_words, util::narrow_wstring(src_string));

			auto remaining = size_in_words;
			emulator_t::address_type write_address = dst_address;

			for (std::size_t i = 0; i < src_string.size(); ++i)
			{
				const wchar_t ch = src_string[i];

				emulator_err_t error = emulator->write_virtual_memory(write_address, &ch, sizeof(ch));

				error.throw_if("wcscpy_s write char");

				write_address += sizeof(wchar_t);
				--remaining;

				if (!remaining)
				{
					spdlog::warn("wcscpy_s: buffer too small (needed {} words, had {})",
						src_string.size() + 1, size_in_words);

					const wchar_t null_term = 0;

					error = emulator->write_virtual_memory(dst_address, &null_term, sizeof(null_term));

					error.throw_if("wcscpy_s write null on truncation");

					write_return_value(emulator, erange);

					return;
				}
			}

			const wchar_t null_term = 0;

			emulator_err_t error = emulator->write_virtual_memory(write_address, &null_term, sizeof(null_term));

			error.throw_if("wcscpy_s write final null");

			write_return_value(emulator, 0);
		},
		mapped_image,
		"wcscpy_s"
	);

	redirect_function(
		[emulator]
		{
			const auto str1_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto str2_address = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			const auto str1 = kernel::read_guest_string(*emulator, str1_address);
			const auto str2 = kernel::read_guest_string(*emulator, str2_address);

			spdlog::info("_stricmp called (str1='{}', str2='{}')", str1, str2);

			auto a1 = reinterpret_cast<const std::uint8_t*>(str1.data());
			auto a2 = reinterpret_cast<const std::uint8_t*>(str2.data());

			std::int32_t v6;
			std::int32_t v7;

			do
			{
				const auto v4 = static_cast<std::int32_t>(*a1++);
				const auto v5 = static_cast<std::int32_t>(*a2++);

				v6 = (static_cast<std::uint32_t>(v4 - 65) <= 0x19) ? v4 + 32 : v4;
				v7 = (static_cast<std::uint32_t>(v5 - 65) <= 0x19) ? v5 + 32 : v5;
			} while (v6 && v6 == v7);

			const auto result = static_cast<std::uint32_t>(v6 - v7);

			spdlog::info("_stricmp returning {}", static_cast<std::int32_t>(result));

			write_return_value(emulator, result);
		},
		mapped_image,
		"_stricmp"
	);

	redirect_function(
		[emulator]
		{
			const auto str1_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto str2_address = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			const auto str1 = kernel::read_guest_string(*emulator, str1_address);
			const auto str2 = kernel::read_guest_string(*emulator, str2_address);

			spdlog::info("strcmp called (str1='{}', str2='{}')", str1, str2);

			const auto* a = reinterpret_cast<const std::uint8_t*>(str1.data());
			const auto* b = reinterpret_cast<const std::uint8_t*>(str2.data());

			std::uint32_t c1;
			std::uint32_t c2;

			do
			{
				c1 = *a++;
				c2 = *b++;
			} while (c1 && c1 == c2);

			std::int32_t result;

			if (c1 < c2)
				result = -1;
			else if (c1 > c2)
				result = 1;
			else
				result = 0;

			write_return_value(emulator, static_cast<std::uint32_t>(result));
		},
		mapped_image,
		"strcmp"
	);

	redirect_function(
		[emulator]
		{
			const auto dst_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto size_in_words = emulator->read_register<x86::reg::rdx, std::uint64_t>();
			const auto src_address = emulator->read_register<x86::reg::r8, emulator_t::address_type>();

			constexpr std::uint32_t einval = 22;
			constexpr std::uint32_t erange = 34;

			if (!dst_address || !size_in_words)
			{
				spdlog::warn("wcscat_s called with null dst or zero size (dst=0x{:X}, size={}, src=0x{:X})",
					dst_address, size_in_words, src_address);

				write_return_value(emulator, einval);

				return;
			}

			if (!src_address)
			{
				spdlog::warn("wcscat_s called with null src (dst=0x{:X}, size={})", dst_address, size_in_words);

				const wchar_t null_term = 0;

				emulator_err_t error = emulator->write_virtual_memory(dst_address, &null_term, sizeof(null_term));

				error.throw_if("wcscat_s write null terminator");

				write_return_value(emulator, einval);

				return;
			}

			const auto dst_string = kernel::read_guest_wstring(*emulator, dst_address);
			const auto src_string = kernel::read_guest_wstring(*emulator, src_address);

			spdlog::info("wcscat_s called (dst=0x{:X}, dst_content='{}', size={}, src='{}')",
				dst_address, util::narrow_wstring(dst_string), size_in_words, util::narrow_wstring(src_string));

			auto remaining = size_in_words;

			if (dst_string.size() >= remaining)
			{
				spdlog::warn("wcscat_s: dst string not null-terminated within size");

				const wchar_t null_term = 0;

				emulator_err_t error = emulator->write_virtual_memory(dst_address, &null_term, sizeof(null_term));

				error.throw_if("wcscat_s write null on invalid dst");

				write_return_value(emulator, einval);

				return;
			}

			remaining -= dst_string.size();
			auto write_address = dst_address + dst_string.size() * sizeof(wchar_t);

			for (std::size_t i = 0; i < src_string.size(); ++i)
			{
				const wchar_t ch = src_string[i];

				emulator_err_t error = emulator->write_virtual_memory(write_address, &ch, sizeof(ch));

				error.throw_if("wcscat_s write char");

				write_address += sizeof(wchar_t);
				--remaining;

				if (!remaining)
				{
					spdlog::warn("wcscat_s: buffer too small");

					const wchar_t null_term = 0;

					error = emulator->write_virtual_memory(dst_address, &null_term, sizeof(null_term));

					error.throw_if("wcscat_s write null on truncation");

					write_return_value(emulator, erange);

					return;
				}
			}

			const wchar_t null_term = 0;

			emulator_err_t error = emulator->write_virtual_memory(write_address, &null_term, sizeof(null_term));

			error.throw_if("wcscat_s write final null");

			write_return_value(emulator, 0);
		},
		mapped_image,
		"wcscat_s"
	);

	redirect_function(
		[emulator]
		{
			const auto c = emulator->read_register<x86::reg::rcx, std::int32_t>();

			const auto result = std::tolower(c);

			spdlog::info("tolower called (c='{}', result='{}')",
				static_cast<char>(c), static_cast<char>(result));

			write_return_value(emulator, static_cast<std::uint32_t>(result));
		},
		mapped_image,
		"tolower"
	);
}
