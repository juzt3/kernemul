#include "ci_sign.hpp"

static std::string read_guest_hash_hex(const emulator_t& emulator,
	const emulator_t::address_type address, const std::uint32_t size)
{
	std::string hex;

	if (!address || size == 0)
	{
		return hex;
	}

	const auto clamped_size = std::min(size, static_cast<std::uint32_t>(64));
	std::vector<std::uint8_t> bytes(clamped_size);
	static_cast<void>(emulator.read_virtual_memory(address, bytes.data(), clamped_size));

	for (const auto byte : bytes)
	{
		hex += std::format("{:02X}", byte);
	}

	return hex;
}

void redirect_ci_sign_functions(const std::shared_ptr<emulator_t>& emulator,
	const kernel_image_t& mapped_image)
{
	redirect_function(
		[emulator]
		{
			const auto digest_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto digest_size = emulator->read_register<x86::reg::rdx, std::int32_t>();

			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			emulator_t::address_type signing_time_address = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x38, &signing_time_address, sizeof(signing_time_address)));

			const auto hash_hex = read_guest_hash_hex(*emulator, digest_address, static_cast<std::uint32_t>(digest_size));

			THREAD_LOG("CiCheckSignedFile called (hash='{}', digest_size={})", hash_hex, digest_size);

			if (signing_time_address)
			{
				constexpr std::int64_t dummy_signing_time = 0x01DA0000'00000000;
				static_cast<void>(emulator->write_virtual_memory(signing_time_address, &dummy_signing_time, sizeof(dummy_signing_time)));
			}

			write_nt_success(emulator);
		},
		mapped_image,
		"CiCheckSignedFile"
	);

	redirect_function(
		[emulator]
		{
			THREAD_LOG("CiFreePolicyInfo called");
		},
		mapped_image,
		"CiFreePolicyInfo"
	);

	redirect_function(
		[emulator]
		{
			const auto hash_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto hash_size = emulator->read_register<x86::reg::rdx, std::uint32_t>();

			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			emulator_t::address_type signing_time_address = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x48, &signing_time_address, sizeof(signing_time_address)));

			const auto hash_hex = read_guest_hash_hex(*emulator, hash_address, hash_size);

			THREAD_LOG("CiVerifyHashInCatalog called (hash='{}', hash_size={})", hash_hex, hash_size);

			if (signing_time_address)
			{
				constexpr std::int64_t dummy_signing_time = 0x01DA0000'00000000;
				static_cast<void>(emulator->write_virtual_memory(signing_time_address, &dummy_signing_time, sizeof(dummy_signing_time)));
			}

			write_nt_success(emulator);
		},
		mapped_image,
		"CiVerifyHashInCatalog"
	);

	redirect_function(
		[emulator]
		{
			const auto file_object_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			emulator_t::address_type signing_time_address = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x30, &signing_time_address, sizeof(signing_time_address)));

			std::string file_path;

			if (file_object_address)
			{
				constexpr std::size_t file_name_offset = 0x58;
				UNICODE_STRING file_name{};
				static_cast<void>(emulator->read_virtual_memory(
					file_object_address + file_name_offset, &file_name, sizeof(file_name)));

				const auto buffer_address = reinterpret_cast<emulator_t::address_type>(file_name.Buffer);

				if (buffer_address && file_name.Length)
				{
					const auto char_count = file_name.Length / sizeof(wchar_t);
					std::wstring wide_path(char_count, L'\0');
					static_cast<void>(emulator->read_virtual_memory(buffer_address, wide_path.data(), file_name.Length));
					file_path = util::narrow_wstring(wide_path);
				}
			}

			THREAD_LOG("CiValidateFileObject called (path='{}')", file_path);

			if (signing_time_address)
			{
				constexpr std::int64_t dummy_signing_time = 0x01DA0000'00000000;
				static_cast<void>(emulator->write_virtual_memory(signing_time_address, &dummy_signing_time, sizeof(dummy_signing_time)));
			}

			write_nt_success(emulator);
		},
		mapped_image,
		"CiValidateFileObject"
	);
}
