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

// CiCheckSignedFile(digest, digest_size, ?, ?, ?, policy_info, signing_time)
static void handle_check_signed_file(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type digest_address, std::int32_t digest_size,
	[[maybe_unused]] std::uint64_t reserved_r8,
	[[maybe_unused]] std::uint64_t reserved_r9,
	[[maybe_unused]] std::uint64_t reserved_5th,
	emulator_t::address_type policy_info_address,
	emulator_t::address_type signing_time_address)
{
	const auto hash_hex = read_guest_hash_hex(*emulator, digest_address, static_cast<std::uint32_t>(digest_size));

	THREAD_LOG("CiCheckSignedFile called (hash='{}', digest_size={}, policy_info=0x{:X})",
		hash_hex, digest_size, policy_info_address);

	// populate MINCRYPT_POLICY_INFO to indicate a valid Microsoft signer
	if (policy_info_address)
	{
		// zero-fill the full struct first, then set key fields
		std::array<std::uint8_t, 0x70> policy_info{};
		auto* p32 = reinterpret_cast<std::uint32_t*>(policy_info.data());

		p32[0] = 0x70;    // Size
		p32[1] = 0;       // VerificationStatus (success)
		p32[2] = 0xFFFFFFFF; // PolicyBits - all signer flags set

		static_cast<void>(emulator->write_virtual_memory(policy_info_address, policy_info.data(), policy_info.size()));
	}

	if (signing_time_address)
	{
		constexpr std::int64_t dummy_signing_time = 0x01DA0000'00000000;
		static_cast<void>(emulator->write_virtual_memory(signing_time_address, &dummy_signing_time, sizeof(dummy_signing_time)));
	}

	write_nt_success(emulator);
}

static void handle_free_policy_info(const std::shared_ptr<emulator_t>& emulator)
{
	THREAD_LOG("CiFreePolicyInfo called");
}

// CiVerifyHashInCatalog(hash, hash_size, ?, ?, ?, ?, ?, ?, signing_time)
static void handle_verify_hash_in_catalog(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type hash_address, std::uint32_t hash_size,
	[[maybe_unused]] std::uint64_t reserved_r8,
	[[maybe_unused]] std::uint64_t reserved_r9,
	[[maybe_unused]] std::uint64_t reserved_5th,
	[[maybe_unused]] std::uint64_t reserved_6th,
	[[maybe_unused]] std::uint64_t reserved_7th,
	[[maybe_unused]] std::uint64_t reserved_8th,
	emulator_t::address_type signing_time_address)
{
	const auto hash_hex = read_guest_hash_hex(*emulator, hash_address, hash_size);

	THREAD_LOG("CiVerifyHashInCatalog called (hash='{}', hash_size={})", hash_hex, hash_size);

	if (signing_time_address)
	{
		constexpr std::int64_t dummy_signing_time = 0x01DA0000'00000000;
		static_cast<void>(emulator->write_virtual_memory(signing_time_address, &dummy_signing_time, sizeof(dummy_signing_time)));
	}

	write_nt_success(emulator);
}

// CiValidateFileObject(file_object, ?, ?, ?, ?, signing_time)
static void handle_validate_file_object(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type file_object_address,
	[[maybe_unused]] std::uint64_t reserved_rdx,
	[[maybe_unused]] std::uint64_t reserved_r8,
	[[maybe_unused]] std::uint64_t reserved_r9,
	[[maybe_unused]] std::uint64_t reserved_5th,
	emulator_t::address_type signing_time_address)
{
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
}

void redirect_ci_sign_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image)
{
	redirect_handler<handle_check_signed_file>(emulator, mapped_image, "CiCheckSignedFile");

	redirect_handler<handle_free_policy_info>(emulator, mapped_image, "CiFreePolicyInfo");

	redirect_handler<handle_verify_hash_in_catalog>(emulator, mapped_image, "CiVerifyHashInCatalog");

	redirect_handler<handle_validate_file_object>(emulator, mapped_image, "CiValidateFileObject");
}
