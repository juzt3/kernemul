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

// MINCRYPT_POLICY_INFO, the structure Ci hands back describing what it decided
// about a file. A WDK-adjacent type the kernel does not store, so the layout is
// declared here; only the head of it is filled in.
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

// The digest a catalogue lookup is keyed by. Everything current signs with
// SHA-256.
constexpr std::size_t sha256_size = 32;

// What Ci says about a file it will not vouch for. A driver that gets this
// takes its unsigned-image path, which is the honest answer here: nothing in
// the guest filesystem carries a signature that was ever checked.
constexpr NTSTATUS status_invalid_image_hash = 0xC0000428;

std::array<std::uint8_t, sha256_size> sha256(const std::span<const std::uint8_t> data)
{
	std::array<std::uint8_t, sha256_size> digest{};
	unsigned int size = 0;

	EVP_Digest(data.data(), data.size(), digest.data(), &size, EVP_sha256(), nullptr);

	return digest;
}

}

// Code integrity. Nothing here holds a certificate store or a catalogue, so no
// file can be vouched for -- and a driver told an image is unsigned takes the
// path it takes on a machine where it is. The hashing is real, so a driver that
// computes a digest and compares it against its own gets the right answer.
void modules::register_ci(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	// The real one parses the image, hashes it and walks its certificate chain.
	// The hash is real here; there is nothing to check the chain against.
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

			return status_invalid_image_hash;
		});

	// The chain info a check would have allocated. Nothing is allocated on the
	// failure path above, so there is nothing to give back -- and a driver that
	// calls this on a policy it never got a chain for is doing the right thing.
	state.redirect(mod, "CiFreePolicyInfo", [](vcpu&, emu_object<policy_info_t> policy_info)
	{
		if (!policy_info)
			return;

		THREAD_LOG_INFO("CiFreePolicyInfo(0x{:X})", policy_info.address());

		policy_info.write({});
	});

	// A catalogue lookup, keyed by the digest of the file. No catalogue is
	// loaded, so no digest is in one.
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

			// The digest the caller is asking about, read back so the log names
			// what was looked up rather than an address.
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

			return status_invalid_image_hash;
		});

	// The same question about a file that is already open. The file is one the
	// io manager here made, so its contents are hashed for real -- and then
	// there is still nothing to check the result against.
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

			// The digest is real and the caller gets it; what it cannot get is
			// a verdict, because nothing here is authorised to give one.
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

			return status_invalid_image_hash;
		});
}
