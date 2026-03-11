#include "nt_helpers.hpp"

void redirect_ntoskrnl_string_functions(const std::shared_ptr<emulator_t>& emulator,
	const mapped_image_t& mapped_image, const portable_executable::image_t* const pe_image)
{
	redirect_image_export(
		[emulator]
		{
			const auto rcx = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto rdx = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			auto destination_object = emulator_object_t<UNICODE_STRING>::view_at(emulator, rcx);

			UNICODE_STRING destination = { };

			destination.Buffer = reinterpret_cast<PWSTR>(rdx);

			if (rdx)
			{
				const auto source_string = read_guest_wstring(*emulator, rdx);
				const auto count = static_cast<std::int64_t>(source_string.size());

				auto byte_length = static_cast<std::uint64_t>(sizeof(wchar_t) * count);

				if (byte_length >= 0xFFFE)
				{
					byte_length = (byte_length & ~static_cast<std::uint64_t>(0xFFFF)) | 0xFFFC;
				}

				destination.Length = static_cast<std::uint16_t>(byte_length);
				destination.MaximumLength = static_cast<std::uint16_t>(byte_length + sizeof(wchar_t));

				spdlog::info("RtlInitUnicodeString called (destination=0x{:X}, source='{}')",
					rcx, std::string(source_string.begin(), source_string.end()));
			}
			else
			{
				spdlog::info("RtlInitUnicodeString called (destination=0x{:X}, source=null)", rcx);
			}

			destination_object.write(destination);
		},
		pe_image,
		mapped_image,
		"RtlInitUnicodeString"
	);

	redirect_image_export(
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
		pe_image,
		mapped_image,
		"RtlDuplicateUnicodeString"
	);

	redirect_image_export(
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
		pe_image,
		mapped_image,
		"RtlFreeUnicodeString"
	);
}
