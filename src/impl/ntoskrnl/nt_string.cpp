#include "nt_helpers.hpp"

void redirect_ntoskrnl_string_functions(const std::shared_ptr<emulator_t>& emulator,
	const kernel_image_t& mapped_image)
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

				THREAD_LOG("RtlInitUnicodeString called (destination=0x{:X}, source='{}')",
					rcx, util::narrow_wstring(source_string));
			}
			else
			{
				THREAD_LOG("RtlInitUnicodeString called (destination=0x{:X}, source=null)", rcx);
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

			THREAD_LOG("RtlDuplicateUnicodeString called (string in=0x{:X})", rdx);

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
				THREAD_LOG("RtlFreeUnicodeString called (buffer=0x{:X})", reinterpret_cast<std::uint64_t>(string_value.Buffer));

				const UNICODE_STRING zeroed = { };

				string_object.write(zeroed);
			}
			else
			{
				THREAD_LOG("RtlFreeUnicodeString called (buffer=null)");
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
				THREAD_LOG("wcslen called (str=null, result=0)");

				write_return_value(emulator, 0);

				return;
			}

			const auto str = kernel::read_guest_wstring(*emulator, rcx);

			THREAD_LOG("wcslen called (str='{}', result={})", util::narrow_wstring(str), str.size());

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
				THREAD_WARN_LOG("wcscpy_s called with null dst or zero size (dst=0x{:X}, size={}, src=0x{:X})",
					dst_address, size_in_words, src_address);

				write_return_value(emulator, einval);

				return;
			}

			if (!src_address)
			{
				THREAD_WARN_LOG("wcscpy_s called with null src (dst=0x{:X}, size={})", dst_address, size_in_words);

				const wchar_t null_term = 0;

				emulator_err_t error = emulator->write_virtual_memory(dst_address, &null_term, sizeof(null_term));

				error.throw_if("wcscpy_s write null terminator");

				write_return_value(emulator, einval);

				return;
			}

			const auto src_string = kernel::read_guest_wstring(*emulator, src_address);

			THREAD_LOG("wcscpy_s called (dst=0x{:X}, size={}, src='{}')",
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
					THREAD_WARN_LOG("wcscpy_s: buffer too small (needed {} words, had {})",
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

			THREAD_LOG("_stricmp called (str1='{}', str2='{}')", str1, str2);

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

			THREAD_LOG("_stricmp returning {}", static_cast<std::int32_t>(result));

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

			THREAD_LOG("strcmp called (str1='{}', str2='{}')", str1, str2);

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
			const auto str1_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto str2_address = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			auto max_count = emulator->read_register<x86::reg::r8, std::uint64_t>();

			if (!max_count)
			{
				write_return_value(emulator, 0);
				return;
			}

			const auto str1 = kernel::read_guest_string(*emulator, str1_address);
			const auto str2 = kernel::read_guest_string(*emulator, str2_address);

			const auto len1 = str1.size();
			const auto len2 = str2.size();
			const auto limit = static_cast<std::size_t>(max_count);

			std::int32_t result = 0;

			for (std::size_t i = 0; i < limit; ++i)
			{
				const auto c1 = i < len1 ? static_cast<unsigned char>(str1[i]) : 0u;
				const auto c2 = i < len2 ? static_cast<unsigned char>(str2[i]) : 0u;

				if (c1 < c2)
				{
					result = -1;
					break;
				}

				if (c1 > c2)
				{
					result = 1;
					break;
				}

				if (c1 == 0)
					break;
			}

			THREAD_LOG("strncmp called (str1='{}', str2='{}', max_count={}, result={})",
				str1, str2, max_count, result);

			write_return_value(emulator, static_cast<std::uint32_t>(result));
		},
		mapped_image,
		"strncmp"
	);

	redirect_function(
		[emulator]
		{
			const auto str1_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto str2_address = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			const auto str1 = kernel::read_guest_string(*emulator, str1_address);
			const auto str2 = kernel::read_guest_string(*emulator, str2_address);

			const char* result = std::strstr(str1.c_str(), str2.c_str());

			emulator_t::address_type guest_result = 0;

			if (result)
			{
				guest_result = str1_address + static_cast<std::uint64_t>(result - str1.c_str());
			}

			THREAD_LOG("strstr called (str1='{}', str2='{}', found={})", str1, str2, guest_result != 0);

			write_return_value(emulator, guest_result);
		},
		mapped_image,
		"strstr"
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
				THREAD_WARN_LOG("wcscat_s called with null dst or zero size (dst=0x{:X}, size={}, src=0x{:X})",
					dst_address, size_in_words, src_address);

				write_return_value(emulator, einval);

				return;
			}

			if (!src_address)
			{
				THREAD_WARN_LOG("wcscat_s called with null src (dst=0x{:X}, size={})", dst_address, size_in_words);

				const wchar_t null_term = 0;

				emulator_err_t error = emulator->write_virtual_memory(dst_address, &null_term, sizeof(null_term));

				error.throw_if("wcscat_s write null terminator");

				write_return_value(emulator, einval);

				return;
			}

			const auto dst_string = kernel::read_guest_wstring(*emulator, dst_address);
			const auto src_string = kernel::read_guest_wstring(*emulator, src_address);

			THREAD_LOG("wcscat_s called (dst=0x{:X}, dst_content='{}', size={}, src='{}')",
				dst_address, util::narrow_wstring(dst_string), size_in_words, util::narrow_wstring(src_string));

			auto remaining = size_in_words;

			if (dst_string.size() >= remaining)
			{
				THREAD_WARN_LOG("wcscat_s: dst string not null-terminated within size");

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
					THREAD_WARN_LOG("wcscat_s: buffer too small");

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

			THREAD_LOG("tolower called (c='{}', result='{}')",
				static_cast<char>(c), static_cast<char>(result));

			write_return_value(emulator, static_cast<std::uint32_t>(result));
		},
		mapped_image,
		"tolower"
	);

	redirect_function(
		[emulator]
		{
			const auto destination_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto source_address = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			_ANSI_STRING destination = { };

			destination.Buffer = reinterpret_cast<PCHAR>(source_address);

			if (source_address)
			{
				const auto source_string = kernel::read_guest_string(*emulator, source_address);
				auto length = static_cast<std::uint64_t>(source_string.size());

				if (length >= 0xFFFF)
				{
					length = (length & ~static_cast<std::uint64_t>(0xFFFF)) | 0xFFFE;
				}

				destination.Length = static_cast<USHORT>(length);
				destination.MaximumLength = static_cast<USHORT>(length + 1);

				THREAD_LOG("RtlInitAnsiString called (destination=0x{:X}, source='{}')",
					destination_address, source_string);
			}
			else
			{
				THREAD_LOG("RtlInitAnsiString called (destination=0x{:X}, source=null)", destination_address);
			}

			emulator_err_t error = emulator->write_virtual_memory(destination_address, &destination, sizeof(destination));
			error.throw_if("RtlInitAnsiString: write destination");
		},
		mapped_image,
		"RtlInitAnsiString"
	);

	redirect_function(
		[emulator]
		{
			const auto destination_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto source_address = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto allocate_destination = emulator->read_register<x86::reg::r8, std::uint8_t>();

			_ANSI_STRING source = { };
			emulator_err_t error = emulator->read_virtual_memory(source_address, &source, sizeof(source));
			error.throw_if("RtlAnsiStringToUnicodeString: read source");

			const auto source_buffer = reinterpret_cast<emulator_t::address_type>(source.Buffer);

			std::string ansi_string;

			if (source_buffer && source.Length)
			{
				ansi_string.resize(source.Length);
				error = emulator->read_virtual_memory(source_buffer, ansi_string.data(), source.Length);
				error.throw_if("RtlAnsiStringToUnicodeString: read source buffer");
			}

			THREAD_LOG("RtlAnsiStringToUnicodeString called (dest=0x{:X}, source='{}', allocate={})",
				destination_address, ansi_string, allocate_destination);

			std::wstring wide_string(ansi_string.begin(), ansi_string.end());

			const auto unicode_byte_length = static_cast<std::uint32_t>(wide_string.size() * sizeof(wchar_t));
			const auto unicode_size_with_null = unicode_byte_length + sizeof(wchar_t);

			if (unicode_size_with_null > 0xFFFF)
			{
				constexpr std::uint32_t status_invalid_parameter_2 = 0xC00000F0;
				write_nt_status(emulator, status_invalid_parameter_2);
				return;
			}

			UNICODE_STRING destination = { };
			destination.Length = static_cast<USHORT>(unicode_byte_length);

			if (allocate_destination)
			{
				destination.MaximumLength = static_cast<USHORT>(unicode_size_with_null);

				const auto allocation = emulator->heap_allocate(unicode_size_with_null, prot_read_write, true);
				error = allocation.error_or({});
				error.throw_if("RtlAnsiStringToUnicodeString: allocate buffer");

				destination.Buffer = reinterpret_cast<PWSTR>(*allocation);
			}
			else
			{
				error = emulator->read_virtual_memory(destination_address, &destination, sizeof(destination));
				error.throw_if("RtlAnsiStringToUnicodeString: read existing destination");

				if (destination.MaximumLength < unicode_size_with_null)
				{
					constexpr std::uint32_t status_buffer_overflow = 0x80000005;
					write_nt_status(emulator, status_buffer_overflow);
					return;
				}

				destination.Length = static_cast<USHORT>(unicode_byte_length);
			}

			const auto buffer_address = reinterpret_cast<emulator_t::address_type>(destination.Buffer);

			error = emulator->write_virtual_memory(buffer_address, wide_string.data(), unicode_byte_length);
			error.throw_if("RtlAnsiStringToUnicodeString: write wide string");

			constexpr wchar_t null_terminator = 0;
			error = emulator->write_virtual_memory(buffer_address + unicode_byte_length, &null_terminator, sizeof(null_terminator));
			error.throw_if("RtlAnsiStringToUnicodeString: write null terminator");

			error = emulator->write_virtual_memory(destination_address, &destination, sizeof(destination));
			error.throw_if("RtlAnsiStringToUnicodeString: write destination");

			write_nt_success(emulator);
		},
		mapped_image,
		"RtlAnsiStringToUnicodeString"
	);

	redirect_function(
		[emulator]
		{
			const auto string1_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto string2_address = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto case_insensitive = emulator->read_register<x86::reg::r8, std::uint8_t>();

			UNICODE_STRING str1_header = {};
			emulator_err_t error = emulator->read_virtual_memory(string1_address, &str1_header, sizeof(str1_header));
			error.throw_if("RtlCompareString: read String1");

			UNICODE_STRING str2_header = {};
			error = emulator->read_virtual_memory(string2_address, &str2_header, sizeof(str2_header));
			error.throw_if("RtlCompareString: read String2");

			const auto len1 = str1_header.Length;
			const auto len2 = str2_header.Length;
			const auto buf1_address = reinterpret_cast<emulator_t::address_type>(str1_header.Buffer);
			const auto buf2_address = reinterpret_cast<emulator_t::address_type>(str2_header.Buffer);

			const auto compare_length = std::min(len1, len2);

			std::string buf1(len1, '\0');
			std::string buf2(len2, '\0');

			if (len1)
			{
				error = emulator->read_virtual_memory(buf1_address, buf1.data(), len1);
				error.throw_if("RtlCompareString: read buffer1");
			}

			if (len2)
			{
				error = emulator->read_virtual_memory(buf2_address, buf2.data(), len2);
				error.throw_if("RtlCompareString: read buffer2");
			}

			std::int32_t result = 0;

			for (std::uint16_t i = 0; i < compare_length; i++)
			{
				auto c1 = static_cast<unsigned char>(buf1[i]);
				auto c2 = static_cast<unsigned char>(buf2[i]);

				if (case_insensitive)
				{
					if (c1 >= 'a' && c1 <= 'z') c1 -= 0x20;
					if (c2 >= 'a' && c2 <= 'z') c2 -= 0x20;
				}

				if (c1 != c2)
				{
					result = static_cast<std::int32_t>(c1) - static_cast<std::int32_t>(c2);
					break;
				}
			}

			if (result == 0)
			{
				result = static_cast<std::int32_t>(len1) - static_cast<std::int32_t>(len2);
			}

			THREAD_LOG("RtlCompareString called (str1=0x{:X}, str2=0x{:X}, case_insensitive={}) -> {}",
				string1_address, string2_address, case_insensitive, result);

			write_return_value(emulator, static_cast<std::uint64_t>(static_cast<std::uint32_t>(result)));
		},
		mapped_image,
		"RtlCompareString"
	);
}
