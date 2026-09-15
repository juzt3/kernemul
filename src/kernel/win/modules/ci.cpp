#include "ci.hpp"
#include "../win_kernel.hpp"
#include "../objects.hpp"
#include "../pool.hpp"
#include "../status.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"
#include <openssl/evp.h>
#include <array>
#include <vector>

namespace
{

// A type the kernel does not store, so the layout is declared here; only its head is filled in.
#pragma pack(push, 8)
struct policy_info_t
{
	std::uint32_t structure_size;
	std::uint32_t verification_status;
	std::uint32_t flags;
	std::uint32_t padding;
	addr_t        authenticode_signing_time;
	std::uint32_t chain_info_size;
	std::uint32_t padding2;
	addr_t        chain_info;
};
#pragma pack(pop)

constexpr std::size_t sha256_size = 32;

std::array<std::uint8_t, sha256_size> sha256(const std::span<const std::uint8_t> data)
{
	std::array<std::uint8_t, sha256_size> digest{};
	unsigned int size = 0;

	EVP_Digest(data.data(), data.size(), digest.data(), &size, EVP_sha256(), nullptr);

	return digest;
}

}

// All of these end in STATUS_INVALID_IMAGE_HASH: no catalogue or certificate store is here.
void modules::register_ci(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	state.redirect(mod, "CiCheckSignedFile",
		[](vcpu& cpu, const addr_t digest, const std::uint32_t digest_size,
			const std::uint32_t digest_identifier, const addr_t win_certificate,
			const std::uint32_t certificate_size, emu_object<policy_info_t> policy_info,
			const addr_t signing_time, emu_object<void> signer_digest,
			emu_object<std::uint32_t> signer_digest_size) -> NTSTATUS
		{
			if (policy_info)
			{
				policy_info_t info{};
				info.structure_size = sizeof(info);
				policy_info.write(info);
			}

			if (signer_digest_size)
				signer_digest_size.write(0);

			THREAD_LOG_WARN("CiCheckSignedFile(digest=0x{:X}/{}, identifier={}, certificate="
				"0x{:X}/{}, signing_time=0x{:X}, signer_digest=0x{:X}): nothing here holds a "
				"certificate to check a chain against",
				digest, digest_size, digest_identifier, win_certificate, certificate_size,
				signing_time, signer_digest.address());

			return STATUS_INVALID_IMAGE_HASH;
		});

	// Nothing is allocated on the failure path above, so there is nothing to give back.
	state.redirect(mod, "CiFreePolicyInfo", [](vcpu&, emu_object<policy_info_t> policy_info)
	{
		if (!policy_info)
			return;

		THREAD_LOG_INFO("CiFreePolicyInfo(0x{:X})", policy_info.address());

		policy_info.write({});
	});

	state.redirect(mod, "CiVerifyHashInCatalog",
		[](vcpu& cpu, const addr_t hash, const std::uint32_t hash_size,
			const std::uint32_t hash_algorithm, const bool is_reload_catalogs,
			const std::uint32_t secure_process, const std::uint32_t acceptable_policy,
			emu_object<addr_t> catalog_handle, emu_object<void> catalog_name,
			const addr_t timestamp, emu_object<policy_info_t> policy_info) -> NTSTATUS
		{
			if (catalog_handle)
				catalog_handle.write(0);

			if (policy_info)
			{
				policy_info_t info{};
				info.structure_size = sizeof(info);
				policy_info.write(info);
			}

			std::string digest;

			if (hash && hash_size)
			{
				std::vector<std::uint8_t> bytes(std::min<std::uint32_t>(hash_size, sha256_size));
				cpu.curr_addr_space()->read_mem(hash, bytes.data(), bytes.size());

				for (const auto b : bytes)
					digest += std::format("{:02x}", b);
			}

			THREAD_LOG_WARN("CiVerifyHashInCatalog({}, algorithm={}, reload={}, secure={}, "
				"policy=0x{:X}, timestamp=0x{:X}, name=0x{:X}): no catalogue is loaded",
				digest, hash_algorithm, is_reload_catalogs, secure_process, acceptable_policy,
				timestamp, catalog_name.address());

			return STATUS_INVALID_IMAGE_HASH;
		});

	state.redirect(mod, "CiValidateFileObject",
		[st](vcpu& cpu, const addr_t file_object, const std::uint32_t unknown1,
			const std::uint32_t unknown2, emu_object<policy_info_t> policy_info,
			emu_object<policy_info_t> timestamp_policy_info, const addr_t signing_time,
			emu_object<void> digest, emu_object<std::uint32_t> digest_size,
			emu_object<std::uint32_t> digest_identifier) -> NTSTATUS
		{
			const auto host = st->objs.get_object<file_host>(file_object);

			if (!host || !host->file)
			{
				THREAD_LOG_WARN("CiValidateFileObject: 0x{:X} is not a file object", file_object);
				return STATUS_INVALID_PARAMETER;
			}

			const auto computed = sha256(host->file->data());

			if (digest && digest_size)
			{
				const auto room = digest_size.read();

				if (room >= computed.size())
					cpu.curr_addr_space()->write_mem(digest.address(), computed.data(),
						computed.size());

				digest_size.write(static_cast<std::uint32_t>(computed.size()));
			}

			if (digest_identifier)
				digest_identifier.write(sha256_size);

			for (auto info : { policy_info, timestamp_policy_info })
			{
				if (!info)
					continue;

				policy_info_t zeroed{};
				zeroed.structure_size = sizeof(zeroed);
				info.write(zeroed);
			}

			std::string text;
			for (const auto b : computed)
				text += std::format("{:02x}", b);

			THREAD_LOG_WARN("CiValidateFileObject('{}', {}, {}, signing_time=0x{:X}): sha256 is "
				"{}, and nothing here can say whether it was signed",
				host->path, unknown1, unknown2, signing_time, text);

			return STATUS_INVALID_IMAGE_HASH;
		});
}
