#include "cng.hpp"
#include "../win_kernel.hpp"
#include "../objects.hpp"
#include "../status.hpp"
#include "../string.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"
#include "../../../util/string.hpp"
#include <openssl/evp.h>
#include <algorithm>
#include <string_view>
#include <vector>

namespace
{

// The algorithm an open provider names, and what it can do. Everything below
// is real: the digests and the ciphers come out of OpenSSL, so a driver that
// hashes a buffer here gets the digest it would get on Windows.
struct algorithm_host final : win_object
{
	std::u16string id;
	std::u16string chaining_mode = u"ChainingModeCBC";
	const EVP_MD* digest = nullptr;
	bool symmetric = false;
	std::size_t key_length = 0;
};

struct hash_host final : win_object
{
	// Owned rather than shared: BCryptDuplicateHash would copy it, and nothing
	// else may touch the context of a hash in progress.
	EVP_MD_CTX* ctx = nullptr;
	const EVP_MD* digest = nullptr;

	~hash_host() override
	{
		if (ctx)
			EVP_MD_CTX_free(ctx);
	}
};

struct key_host final : win_object
{
	std::vector<std::uint8_t> key;
	std::u16string algorithm;
	std::u16string chaining_mode;
};

const EVP_MD* digest_for(const std::u16string_view id)
{
	if (id == u"MD5")    return EVP_md5();
	if (id == u"SHA1")   return EVP_sha1();
	if (id == u"SHA256") return EVP_sha256();
	if (id == u"SHA384") return EVP_sha384();
	if (id == u"SHA512") return EVP_sha512();

	return nullptr;
}

// AES is the only symmetric algorithm a driver here is likely to ask for, and
// the cipher depends on the key length the caller ends up importing.
const EVP_CIPHER* cipher_for(const std::u16string_view chaining_mode, const std::size_t key_bytes)
{
	const bool cbc = chaining_mode != u"ChainingModeECB";

	switch (key_bytes)
	{
	case 16: return cbc ? EVP_aes_128_cbc() : EVP_aes_128_ecb();
	case 24: return cbc ? EVP_aes_192_cbc() : EVP_aes_192_ecb();
	case 32: return cbc ? EVP_aes_256_cbc() : EVP_aes_256_ecb();
	default: return nullptr;
	}
}

// BCRYPT_* property names, read and written as counted wide strings.
constexpr std::u16string_view property_object_length = u"ObjectLength";
constexpr std::u16string_view property_hash_length = u"HashDigestLength";
constexpr std::u16string_view property_chaining_mode = u"ChainingMode";
constexpr std::u16string_view property_block_length = u"BlockLength";

// The opaque object a caller allocates for a hash or a key. Nothing here uses
// it -- the state is host side -- but the caller sizes its allocation from
// ObjectLength, so the number has to be one it can act on.
constexpr std::uint32_t object_length = 0x200;

constexpr std::uint32_t aes_block_length = 16;

std::vector<std::uint8_t> read_bytes(addr_space& space, const addr_t addr, const std::size_t size)
{
	std::vector<std::uint8_t> out(size);

	if (addr && size)
		space.read_mem(addr, out.data(), size);

	return out;
}

}

// CNG, backed by OpenSSL. The hashing and the symmetric ciphers are real -- a
// digest computed here is the digest Windows would have produced -- so a driver
// that hashes its own data and checks the result against a constant works.
//
// Signature verification is the exception: it needs a public key the guest has
// no way to have been given, and saying a signature checked out when nothing
// checked it is the one answer that must not be invented.
void modules::register_cng(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	auto make_object = [st](std::shared_ptr<win_object> host) -> addr_t
	{
		const std::uint8_t body[sizeof(addr_t)] = {};

		return st->objs.create_object(0, body, sizeof(body), std::move(host),
			prot_rw | prot_supervisor);
	};

	state.redirect(mod, "BCryptOpenAlgorithmProvider",
		[st, make_object](vcpu& cpu, emu_object<addr_t> algorithm, const addr_t alg_id,
			const addr_t implementation, const std::uint32_t flags) -> NTSTATUS
		{
			if (!algorithm)
				return STATUS_INVALID_PARAMETER;

			auto& space = *cpu.curr_addr_space();
			const auto id = guest::read_wstring(space, alg_id);

			auto host = std::make_shared<algorithm_host>();
			host->id = id;
			host->digest = digest_for(id);
			host->symmetric = id == u"AES";

			if (!host->digest && !host->symmetric)
			{
				THREAD_LOG_WARN("BCryptOpenAlgorithmProvider('{}'): not one of the algorithms "
					"backed here", narrow_wstring(id));

				return STATUS_NOT_SUPPORTED;
			}

			const auto addr = make_object(std::move(host));

			if (!addr)
				return STATUS_INSUFFICIENT_RESOURCES;

			algorithm.write(addr);

			THREAD_LOG_INFO("BCryptOpenAlgorithmProvider('{}', implementation=0x{:X}, "
				"flags=0x{:X}) -> 0x{:X}",
				narrow_wstring(id), implementation, flags, addr);

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "BCryptCloseAlgorithmProvider",
		[st](vcpu&, const addr_t algorithm, const std::uint32_t flags) -> NTSTATUS
		{
			if (!st->objs.get_object<algorithm_host>(algorithm))
				return STATUS_INVALID_HANDLE;

			THREAD_LOG_INFO("BCryptCloseAlgorithmProvider(0x{:X}, flags=0x{:X})",
				algorithm, flags);

			st->objs.dereference_object(algorithm);

			return STATUS_SUCCESS;
		});

	// The sizes a caller allocates from, and the chaining mode it reads back.
	state.redirect(mod, "BCryptGetProperty",
		[st](vcpu& cpu, const addr_t handle, const addr_t property, const addr_t output,
			const std::uint32_t output_size, emu_object<std::uint32_t> result_size,
			const std::uint32_t flags) -> NTSTATUS
		{
			const auto algorithm = st->objs.get_object<algorithm_host>(handle);

			if (!algorithm)
				return STATUS_INVALID_HANDLE;

			auto& space = *cpu.curr_addr_space();
			const auto name = guest::read_wstring(space, property);

			auto write_dword = [&](const std::uint32_t value) -> NTSTATUS
			{
				if (result_size)
					result_size.write(sizeof(value));

				if (output_size < sizeof(value))
					return STATUS_BUFFER_TOO_SMALL;

				space.write_mem<std::uint32_t>(output, value);

				return STATUS_SUCCESS;
			};

			NTSTATUS status = STATUS_NOT_SUPPORTED;
			std::uint32_t reported = 0;

			if (name == property_object_length)
			{
				reported = object_length;
				status = write_dword(reported);
			}
			else if (name == property_hash_length && algorithm->digest)
			{
				reported = static_cast<std::uint32_t>(EVP_MD_get_size(algorithm->digest));
				status = write_dword(reported);
			}
			else if (name == property_block_length && algorithm->symmetric)
			{
				reported = aes_block_length;
				status = write_dword(reported);
			}
			else if (name == property_chaining_mode)
			{
				const auto bytes = static_cast<std::uint32_t>(
					(algorithm->chaining_mode.size() + 1) * sizeof(char16_t));

				if (result_size)
					result_size.write(bytes);

				if (output_size < bytes)
					return STATUS_BUFFER_TOO_SMALL;

				space.write_mem(output, algorithm->chaining_mode.c_str(), bytes);
				status = STATUS_SUCCESS;
			}

			THREAD_LOG_INFO("BCryptGetProperty('{}', '{}', flags=0x{:X}) -> 0x{:X} ({})",
				narrow_wstring(algorithm->id), narrow_wstring(name), flags, status, reported);

			return status;
		});

	state.redirect(mod, "BCryptSetProperty",
		[st](vcpu& cpu, const addr_t handle, const addr_t property, const addr_t input,
			const std::uint32_t input_size, const std::uint32_t flags) -> NTSTATUS
		{
			const auto algorithm = st->objs.get_object<algorithm_host>(handle);

			if (!algorithm)
				return STATUS_INVALID_HANDLE;

			auto& space = *cpu.curr_addr_space();
			const auto name = guest::read_wstring(space, property);

			if (name != property_chaining_mode)
			{
				THREAD_LOG_WARN("BCryptSetProperty('{}'): only the chaining mode can be set here",
					narrow_wstring(name));
				return STATUS_NOT_SUPPORTED;
			}

			algorithm->chaining_mode = guest::read_wstring(space, input);

			THREAD_LOG_INFO("BCryptSetProperty('{}', ChainingMode = '{}', input=0x{:X}/{}, "
				"flags=0x{:X})",
				narrow_wstring(algorithm->id), narrow_wstring(algorithm->chaining_mode),
				input, input_size, flags);

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "BCryptCreateHash",
		[st, make_object](vcpu&, const addr_t algorithm, emu_object<addr_t> hash,
			const addr_t hash_object, const std::uint32_t hash_object_size,
			const addr_t secret, const std::uint32_t secret_size,
			const std::uint32_t flags) -> NTSTATUS
		{
			const auto provider = st->objs.get_object<algorithm_host>(algorithm);

			if (!provider || !provider->digest)
				return STATUS_INVALID_HANDLE;

			if (!hash)
				return STATUS_INVALID_PARAMETER;

			if (secret && secret_size)
			{
				THREAD_LOG_WARN("BCryptCreateHash: a keyed hash needs HMAC, which is not "
					"backed here");
				return STATUS_NOT_SUPPORTED;
			}

			auto host = std::make_shared<hash_host>();
			host->ctx = EVP_MD_CTX_new();
			host->digest = provider->digest;

			if (!host->ctx || EVP_DigestInit_ex(host->ctx, host->digest, nullptr) != 1)
				return STATUS_INSUFFICIENT_RESOURCES;

			const auto addr = make_object(std::move(host));

			if (!addr)
				return STATUS_INSUFFICIENT_RESOURCES;

			hash.write(addr);

			THREAD_LOG_INFO("BCryptCreateHash('{}', object=0x{:X}/{}, flags=0x{:X}) -> 0x{:X}",
				narrow_wstring(provider->id), hash_object, hash_object_size, flags, addr);

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "BCryptHashData",
		[st](vcpu& cpu, const addr_t hash, const addr_t input, const std::uint32_t input_size,
			const std::uint32_t flags) -> NTSTATUS
		{
			const auto host = st->objs.get_object<hash_host>(hash);

			if (!host || !host->ctx)
				return STATUS_INVALID_HANDLE;

			const auto bytes = read_bytes(*cpu.curr_addr_space(), input, input_size);

			if (!bytes.empty() && EVP_DigestUpdate(host->ctx, bytes.data(), bytes.size()) != 1)
				return STATUS_UNSUCCESSFUL;

			THREAD_LOG_INFO("BCryptHashData(0x{:X}, {} bytes, flags=0x{:X})",
				hash, input_size, flags);

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "BCryptFinishHash",
		[st](vcpu& cpu, const addr_t hash, const addr_t output, const std::uint32_t output_size,
			const std::uint32_t flags) -> NTSTATUS
		{
			const auto host = st->objs.get_object<hash_host>(hash);

			if (!host || !host->ctx)
				return STATUS_INVALID_HANDLE;

			const auto size = static_cast<std::uint32_t>(EVP_MD_get_size(host->digest));

			if (output_size < size)
				return STATUS_BUFFER_TOO_SMALL;

			std::vector<std::uint8_t> digest(size);
			unsigned int written = 0;

			if (EVP_DigestFinal_ex(host->ctx, digest.data(), &written) != 1)
				return STATUS_UNSUCCESSFUL;

			cpu.curr_addr_space()->write_mem(output, digest.data(), written);

			std::string text;
			for (const auto b : digest)
				text += std::format("{:02x}", b);

			THREAD_LOG_INFO("BCryptFinishHash(0x{:X}, flags=0x{:X}) -> {}", hash, flags, text);

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "BCryptDestroyHash", [st](vcpu&, const addr_t hash) -> NTSTATUS
	{
		if (!st->objs.get_object<hash_host>(hash))
			return STATUS_INVALID_HANDLE;

		THREAD_LOG_INFO("BCryptDestroyHash(0x{:X})", hash);

		st->objs.dereference_object(hash);

		return STATUS_SUCCESS;
	});

	state.redirect(mod, "BCryptGenerateSymmetricKey",
		[st, make_object](vcpu& cpu, const addr_t algorithm, emu_object<addr_t> key,
			const addr_t key_object, const std::uint32_t key_object_size,
			const addr_t secret, const std::uint32_t secret_size,
			const std::uint32_t flags) -> NTSTATUS
		{
			const auto provider = st->objs.get_object<algorithm_host>(algorithm);

			if (!provider || !provider->symmetric)
				return STATUS_INVALID_HANDLE;

			if (!key || !secret || !secret_size)
				return STATUS_INVALID_PARAMETER;

			if (!cipher_for(provider->chaining_mode, secret_size))
			{
				THREAD_LOG_WARN("BCryptGenerateSymmetricKey: {} bytes is not an AES key length",
					secret_size);
				return STATUS_INVALID_PARAMETER;
			}

			auto host = std::make_shared<key_host>();
			host->key = read_bytes(*cpu.curr_addr_space(), secret, secret_size);
			host->algorithm = provider->id;
			host->chaining_mode = provider->chaining_mode;

			const auto addr = make_object(std::move(host));

			if (!addr)
				return STATUS_INSUFFICIENT_RESOURCES;

			key.write(addr);

			THREAD_LOG_INFO("BCryptGenerateSymmetricKey('{}', {}-bit, object=0x{:X}/{}, "
				"flags=0x{:X}) -> 0x{:X}",
				narrow_wstring(provider->id), secret_size * 8, key_object, key_object_size,
				flags, addr);

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "BCryptDestroyKey", [st](vcpu&, const addr_t key) -> NTSTATUS
	{
		if (!st->objs.get_object<key_host>(key))
			return STATUS_INVALID_HANDLE;

		THREAD_LOG_INFO("BCryptDestroyKey(0x{:X})", key);

		st->objs.dereference_object(key);

		return STATUS_SUCCESS;
	});

	// One call does the whole transform: there is no chaining state carried
	// between calls, which is what BCRYPT_BLOCK_PADDING in the flags decides.
	auto transform = [st](vcpu& cpu, const addr_t key, const addr_t input,
		const std::uint32_t input_size, const addr_t iv, const std::uint32_t iv_size,
		const addr_t output, const std::uint32_t output_size,
		emu_object<std::uint32_t> result_size, const std::uint32_t flags,
		const bool encrypt, const std::string_view who) -> NTSTATUS
	{
		constexpr std::uint32_t block_padding = 0x1;

		const auto host = st->objs.get_object<key_host>(key);

		if (!host)
			return STATUS_INVALID_HANDLE;

		const auto* cipher = cipher_for(host->chaining_mode, host->key.size());

		if (!cipher)
			return STATUS_NOT_SUPPORTED;

		auto& space = *cpu.curr_addr_space();
		const auto plain = read_bytes(space, input, input_size);
		const auto vector = read_bytes(space, iv, iv_size);

		auto* ctx = EVP_CIPHER_CTX_new();

		if (!ctx)
			return STATUS_INSUFFICIENT_RESOURCES;

		std::vector<std::uint8_t> result(plain.size() + EVP_MAX_BLOCK_LENGTH);
		int produced = 0;
		int finished = 0;
		bool ok = EVP_CipherInit_ex(ctx, cipher, nullptr, host->key.data(),
			vector.empty() ? nullptr : vector.data(), encrypt ? 1 : 0) == 1;

		if (ok)
			ok = EVP_CIPHER_CTX_set_padding(ctx, (flags & block_padding) ? 1 : 0) == 1;

		if (ok)
			ok = EVP_CipherUpdate(ctx, result.data(), &produced, plain.data(),
				static_cast<int>(plain.size())) == 1;

		if (ok)
			ok = EVP_CipherFinal_ex(ctx, result.data() + produced, &finished) == 1;

		EVP_CIPHER_CTX_free(ctx);

		if (!ok)
		{
			THREAD_LOG_WARN("{}: the transform failed", who);
			return STATUS_UNSUCCESSFUL;
		}

		const auto total = static_cast<std::uint32_t>(produced + finished);

		if (result_size)
			result_size.write(total);

		// A null output buffer is how a caller asks how much room it needs.
		if (!output)
			return STATUS_SUCCESS;

		if (output_size < total)
			return STATUS_BUFFER_TOO_SMALL;

		space.write_mem(output, result.data(), total);

		THREAD_LOG_INFO("{}(key=0x{:X}, {} bytes, iv={}, flags=0x{:X}) -> {} bytes",
			who, key, input_size, iv_size ? "yes" : "no", flags, total);

		return STATUS_SUCCESS;
	};

	state.redirect(mod, "BCryptEncrypt",
		[transform](vcpu& cpu, const addr_t key, const addr_t input,
			const std::uint32_t input_size, [[maybe_unused]] const addr_t padding_info,
			const addr_t iv, const std::uint32_t iv_size, const addr_t output,
			const std::uint32_t output_size, emu_object<std::uint32_t> result_size,
			const std::uint32_t flags) -> NTSTATUS
		{
			return transform(cpu, key, input, input_size, iv, iv_size, output, output_size,
				result_size, flags, true, "BCryptEncrypt");
		});

	state.redirect(mod, "BCryptDecrypt",
		[transform](vcpu& cpu, const addr_t key, const addr_t input,
			const std::uint32_t input_size, [[maybe_unused]] const addr_t padding_info,
			const addr_t iv, const std::uint32_t iv_size, const addr_t output,
			const std::uint32_t output_size, emu_object<std::uint32_t> result_size,
			const std::uint32_t flags) -> NTSTATUS
		{
			return transform(cpu, key, input, input_size, iv, iv_size, output, output_size,
				result_size, flags, false, "BCryptDecrypt");
		});

	// An asymmetric key blob. Importing one means parsing a BCRYPT_RSAKEY_BLOB
	// into a key only BCryptVerifySignature would use, and that cannot give an
	// answer -- so the import is refused rather than handing back a key that
	// leads nowhere.
	state.redirect(mod, "BCryptImportKeyPair",
		[](vcpu& cpu, const addr_t algorithm, const addr_t import_key,
			const addr_t blob_type, emu_object<addr_t> key, const addr_t key_object,
			const std::uint32_t key_object_size, const addr_t input,
			const std::uint32_t input_size, const std::uint32_t flags) -> NTSTATUS
		{
			if (key)
				key.write(0);

			THREAD_LOG_WARN("BCryptImportKeyPair(algorithm=0x{:X}, import_key=0x{:X}, '{}', "
				"object=0x{:X}/{}, input=0x{:X}/{}, flags=0x{:X}): asymmetric keys are not "
				"backed here, because nothing could be done with one",
				algorithm, import_key,
				narrow_wstring(guest::read_wstring(*cpu.curr_addr_space(), blob_type)),
				key_object, key_object_size, input, input_size, flags);

			return STATUS_NOT_SUPPORTED;
		});

	// The one answer that must not be invented: a driver told a signature
	// verified acts on data nothing vouched for.
	state.redirect(mod, "BCryptVerifySignature",
		[](vcpu&, const addr_t key, const addr_t padding_info, const addr_t hash,
			const std::uint32_t hash_size, const addr_t signature,
			const std::uint32_t signature_size, const std::uint32_t flags) -> NTSTATUS
		{
			THREAD_LOG_WARN("BCryptVerifySignature(key=0x{:X}, padding=0x{:X}, hash=0x{:X}/{}, "
				"signature=0x{:X}/{}, flags=0x{:X}): nothing here holds a key to verify against",
				key, padding_info, hash, hash_size, signature, signature_size, flags);

			return STATUS_INVALID_SIGNATURE;
		});
}
