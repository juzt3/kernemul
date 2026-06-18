#include "cng_bcrypt.hpp"

#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

// BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE *phAlgorithm, LPCWSTR pszAlgId, LPCWSTR pszImplementation, ULONG dwFlags)
static void handle_open_algorithm_provider(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type handle_out_address, emulator_t::address_type alg_id_address,
	emulator_t::address_type implementation_address, std::uint32_t flags)
{
	const auto alg_id_string = kernel::read_guest_wstring(*emulator, alg_id_address);
	const auto alg_id_narrow = util::narrow_wstring(alg_id_string);

	std::wstring implementation_string;
	std::string implementation_narrow;

	if (implementation_address)
	{
		implementation_string = kernel::read_guest_wstring(*emulator, implementation_address);
		implementation_narrow = util::narrow_wstring(implementation_string);
	}

	THREAD_LOG("BCryptOpenAlgorithmProvider called (handle_out=0x{:X}, alg_id='{}', implementation='{}', flags=0x{:X})",
		handle_out_address, alg_id_narrow,
		implementation_address ? implementation_narrow : "null",
		flags);

	BCRYPT_ALG_HANDLE host_handle = nullptr;

	const auto status = BCryptOpenAlgorithmProvider(
		&host_handle,
		alg_id_string.c_str(),
		implementation_address ? implementation_string.c_str() : nullptr,
		flags & ~BCRYPT_PROV_DISPATCH
	);

	if (status == 0)
	{
		const auto handle_value = reinterpret_cast<emulator_t::address_type>(host_handle);

		static_cast<void>(emulator->write_virtual_memory(
			handle_out_address, &handle_value, sizeof(handle_value)));

		THREAD_LOG("BCryptOpenAlgorithmProvider: success (host_handle=0x{:X})", handle_value);
	}
	else
	{
		THREAD_WARN_LOG("BCryptOpenAlgorithmProvider: host returned 0x{:X}", static_cast<std::uint32_t>(status));
	}

	emulator->write_register<x86::reg::rax>(static_cast<std::uint64_t>(status));
}

// BCryptGetProperty(BCRYPT_HANDLE hObject, LPCWSTR pszProperty, PUCHAR pbOutput, ULONG cbOutput, ULONG *pcbResult, ULONG dwFlags)
static void handle_get_property(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type handle, emulator_t::address_type property_address,
	emulator_t::address_type output_address, std::uint32_t output_size,
	emulator_t::address_type result_address, std::uint32_t flags)
{
	const auto property_string = kernel::read_guest_wstring(*emulator, property_address);
	const auto property_narrow = util::narrow_wstring(property_string);

	THREAD_LOG("BCryptGetProperty called (handle=0x{:X}, property='{}', output=0x{:X}, size=0x{:X}, result=0x{:X}, flags=0x{:X})",
		handle, property_narrow, output_address, output_size, result_address, flags);

	std::vector<std::uint8_t> buffer(output_size);
	ULONG result_size = 0;

	const auto status = BCryptGetProperty(
		reinterpret_cast<BCRYPT_HANDLE>(handle),
		property_string.c_str(),
		output_address ? buffer.data() : nullptr,
		output_size,
		&result_size,
		flags
	);

	if (result_address)
	{
		static_cast<void>(emulator->write_virtual_memory(result_address, &result_size, sizeof(result_size)));
	}

	if (status == 0 && output_address && result_size > 0)
	{
		static_cast<void>(emulator->write_virtual_memory(output_address, buffer.data(), result_size));
	}

	THREAD_LOG("BCryptGetProperty: status=0x{:X}, result_size=0x{:X}", static_cast<std::uint32_t>(status), result_size);

	emulator->write_register<x86::reg::rax>(static_cast<std::uint64_t>(status));
}

// BCryptSetProperty(BCRYPT_HANDLE hObject, LPCWSTR pszProperty, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags)
static void handle_set_property(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type handle, emulator_t::address_type property_address,
	emulator_t::address_type value_address, std::uint32_t value_size,
	std::uint32_t flags)
{
	std::wstring property_name;
	if (property_address)
	{
		property_name = kernel::read_guest_wstring(*emulator, property_address);
	}

	THREAD_LOG("BCryptSetProperty called (handle=0x{:X}, property='{}', value=0x{:X}, size={}, flags=0x{:X})",
		handle, util::narrow_wstring(property_name), value_address, value_size, flags);

	std::vector<std::uint8_t> value_buffer(value_size);
	if (value_size > 0 && value_address)
	{
		emulator->read_virtual_memory(value_address, value_buffer.data(), value_size)
			.throw_if("BCryptSetProperty: read value");
	}

	if (property_name == L"ChainingMode" && value_size >= 2)
	{
		const auto mode = std::wstring(reinterpret_cast<const wchar_t*>(value_buffer.data()));
		THREAD_LOG("BCryptSetProperty: ChainingMode = '{}'", util::narrow_wstring(mode));
	}

	const auto status = ::BCryptSetProperty(
		reinterpret_cast<BCRYPT_HANDLE>(handle),
		property_name.c_str(),
		value_buffer.data(),
		value_size,
		flags);

	THREAD_LOG("BCryptSetProperty: status=0x{:X}", static_cast<std::uint32_t>(status));
	write_return_value(emulator, static_cast<std::uint64_t>(status));
}

// BCryptCreateHash(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_HASH_HANDLE *phHash, PUCHAR pbHashObject, ULONG cbHashObject, PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags)
static void handle_create_hash(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type algorithm_handle, emulator_t::address_type hash_handle_out,
	emulator_t::address_type hash_object_address, std::uint32_t hash_object_size,
	emulator_t::address_type secret_address, std::uint32_t secret_size, std::uint32_t flags)
{
	THREAD_LOG("BCryptCreateHash called (algorithm=0x{:X}, hash_out=0x{:X}, hash_object=0x{:X}, hash_object_size=0x{:X}, secret=0x{:X}, secret_size=0x{:X}, flags=0x{:X})",
		algorithm_handle, hash_handle_out, hash_object_address, hash_object_size, secret_address, secret_size, flags);

	std::vector<std::uint8_t> secret_buffer;

	if (secret_address && secret_size)
	{
		secret_buffer.resize(secret_size);

		emulator_err_t error = emulator->read_virtual_memory(secret_address, secret_buffer.data(), secret_size);
		error.throw_if("BCryptCreateHash: read secret");
	}

	BCRYPT_HASH_HANDLE host_hash_handle = nullptr;

	const auto status = BCryptCreateHash(
		reinterpret_cast<BCRYPT_ALG_HANDLE>(algorithm_handle),
		&host_hash_handle,
		nullptr,
		0,
		secret_buffer.empty() ? nullptr : secret_buffer.data(),
		static_cast<ULONG>(secret_buffer.size()),
		flags & ~BCRYPT_HASH_REUSABLE_FLAG
	);

	if (status == 0)
	{
		const auto handle_value = reinterpret_cast<emulator_t::address_type>(host_hash_handle);

		static_cast<void>(emulator->write_virtual_memory(hash_handle_out, &handle_value, sizeof(handle_value)));

		THREAD_LOG("BCryptCreateHash: success (host_handle=0x{:X})", handle_value);
	}
	else
	{
		THREAD_WARN_LOG("BCryptCreateHash: host returned 0x{:X}", static_cast<std::uint32_t>(status));
	}

	emulator->write_register<x86::reg::rax>(static_cast<std::uint64_t>(status));
}

// BCryptHashData(BCRYPT_HASH_HANDLE hHash, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags)
static void handle_hash_data(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type hash_handle, emulator_t::address_type input_address,
	std::uint32_t input_size, std::uint32_t flags)
{
	THREAD_LOG("BCryptHashData called (handle=0x{:X}, input=0x{:X}, size=0x{:X}, flags=0x{:X})",
		hash_handle, input_address, input_size, flags);

	std::vector<std::uint8_t> input_buffer(input_size);

	if (input_size)
	{
		emulator_err_t error = emulator->read_virtual_memory(input_address, input_buffer.data(), input_size);
		error.throw_if("BCryptHashData: read input");
	}

	const auto status = BCryptHashData(
		reinterpret_cast<BCRYPT_HASH_HANDLE>(hash_handle),
		input_buffer.data(),
		input_size,
		flags
	);

	THREAD_LOG("BCryptHashData: status=0x{:X}", static_cast<std::uint32_t>(status));

	emulator->write_register<x86::reg::rax>(static_cast<std::uint64_t>(status));
}

// BCryptFinishHash(BCRYPT_HASH_HANDLE hHash, PUCHAR pbOutput, ULONG cbOutput, ULONG dwFlags)
static void handle_finish_hash(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type hash_handle, emulator_t::address_type output_address,
	std::uint32_t output_size, std::uint32_t flags)
{
	THREAD_LOG("BCryptFinishHash called (handle=0x{:X}, output=0x{:X}, size=0x{:X}, flags=0x{:X})",
		hash_handle, output_address, output_size, flags);

	std::vector<std::uint8_t> output_buffer(output_size);

	const auto status = BCryptFinishHash(
		reinterpret_cast<BCRYPT_HASH_HANDLE>(hash_handle),
		output_buffer.data(),
		output_size,
		flags
	);

	if (status == 0 && output_address && output_size)
	{
		static_cast<void>(emulator->write_virtual_memory(output_address, output_buffer.data(), output_size));
	}

	THREAD_LOG("BCryptFinishHash: status=0x{:X}", static_cast<std::uint32_t>(status));

	emulator->write_register<x86::reg::rax>(static_cast<std::uint64_t>(status));
}

// BCryptDestroyHash(BCRYPT_HASH_HANDLE hHash)
static void handle_destroy_hash(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type hash_handle)
{
	THREAD_LOG("BCryptDestroyHash called (handle=0x{:X})", hash_handle);

	const auto status = BCryptDestroyHash(reinterpret_cast<BCRYPT_HASH_HANDLE>(hash_handle));

	THREAD_LOG("BCryptDestroyHash: status=0x{:X}", static_cast<std::uint32_t>(status));

	emulator->write_register<x86::reg::rax>(static_cast<std::uint64_t>(status));
}

// BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE hAlgorithm, ULONG dwFlags)
static void handle_close_algorithm_provider(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type algorithm_handle, std::uint32_t flags)
{
	THREAD_LOG("BCryptCloseAlgorithmProvider called (handle=0x{:X}, flags=0x{:X})", algorithm_handle, flags);

	const auto status = BCryptCloseAlgorithmProvider(
		reinterpret_cast<BCRYPT_ALG_HANDLE>(algorithm_handle),
		flags
	);

	THREAD_LOG("BCryptCloseAlgorithmProvider: status=0x{:X}", static_cast<std::uint32_t>(status));

	emulator->write_register<x86::reg::rax>(static_cast<std::uint64_t>(status));
}

// BCryptGenerateSymmetricKey(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE *phKey, PUCHAR pbKeyObject, ULONG cbKeyObject, PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags)
static void handle_generate_symmetric_key(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type algorithm_handle, emulator_t::address_type key_handle_out,
	emulator_t::address_type key_object_address, std::uint32_t key_object_size,
	emulator_t::address_type secret_address, std::uint32_t secret_size, std::uint32_t flags)
{
	THREAD_LOG("BCryptGenerateSymmetricKey called (algorithm=0x{:X}, key_out=0x{:X}, secret=0x{:X}, secret_size=0x{:X}, flags=0x{:X})",
		algorithm_handle, key_handle_out, secret_address, secret_size, flags);

	std::vector<std::uint8_t> secret(secret_size);
	if (secret_size > 0)
	{
		emulator->read_virtual_memory(secret_address, secret.data(), secret_size)
			.throw_if("BCryptGenerateSymmetricKey: read secret");
	}

	BCRYPT_KEY_HANDLE host_key = nullptr;
	const auto status = ::BCryptGenerateSymmetricKey(
		reinterpret_cast<BCRYPT_ALG_HANDLE>(algorithm_handle),
		&host_key, nullptr, 0,
		secret.data(), static_cast<ULONG>(secret_size), flags);

	if (BCRYPT_SUCCESS(status) && key_handle_out)
	{
		const auto handle_value = reinterpret_cast<std::uint64_t>(host_key);
		emulator->write_virtual_memory(key_handle_out, &handle_value, sizeof(handle_value))
			.throw_if("BCryptGenerateSymmetricKey: write key handle");

		THREAD_LOG("BCryptGenerateSymmetricKey: success (host_handle=0x{:X})", handle_value);
	}
	else
	{
		THREAD_WARN_LOG("BCryptGenerateSymmetricKey: host returned 0x{:X}", static_cast<std::uint32_t>(status));
	}

	emulator->write_register<x86::reg::rax>(static_cast<std::uint64_t>(status));
}

// BCryptDestroyKey(BCRYPT_KEY_HANDLE hKey)
static void handle_destroy_key(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type key_handle)
{
	THREAD_LOG("BCryptDestroyKey called (handle=0x{:X})", key_handle);

	const auto status = ::BCryptDestroyKey(reinterpret_cast<BCRYPT_KEY_HANDLE>(key_handle));

	THREAD_LOG("BCryptDestroyKey: status=0x{:X}", static_cast<std::uint32_t>(status));

	emulator->write_register<x86::reg::rax>(static_cast<std::uint64_t>(status));
}

// BCryptEncrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, VOID *pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG *pcbResult, ULONG dwFlags)
static void handle_encrypt(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type key_handle, emulator_t::address_type input_address,
	std::uint32_t input_size, emulator_t::address_type padding_info,
	emulator_t::address_type iv_address, std::uint32_t iv_size,
	emulator_t::address_type output_address, std::uint32_t output_size,
	emulator_t::address_type result_size_address, std::uint32_t flags)
{
	THREAD_LOG("BCryptEncrypt called (key=0x{:X}, input=0x{:X}, input_size=0x{:X}, iv=0x{:X}, iv_size=0x{:X}, output=0x{:X}, output_size=0x{:X}, flags=0x{:X})",
		key_handle, input_address, input_size, iv_address, iv_size, output_address, output_size, flags);

	std::vector<std::uint8_t> input(input_size);
	if (input_size > 0)
	{
		emulator->read_virtual_memory(input_address, input.data(), input_size)
			.throw_if("BCryptEncrypt: read input");
	}

	std::vector<std::uint8_t> iv(iv_size);
	if (iv_size > 0)
	{
		emulator->read_virtual_memory(iv_address, iv.data(), iv_size)
			.throw_if("BCryptEncrypt: read IV");
	}

	std::vector<std::uint8_t> output(output_size);
	ULONG result_size = 0;

	// handle padding/auth info
	BCRYPT_PKCS1_PADDING_INFO pkcs1_info = {};
	BCRYPT_OAEP_PADDING_INFO oaep_info = {};
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info = {};
	std::vector<std::uint8_t> nonce_buffer;
	std::vector<std::uint8_t> auth_data_buffer;
	std::vector<std::uint8_t> tag_buffer;
	std::vector<std::uint8_t> mac_context_buffer;
	void* host_padding_info = nullptr;

	constexpr std::uint32_t bcrypt_pad_pkcs1 = 0x2;
	constexpr std::uint32_t bcrypt_pad_oaep = 0x4;

	// check for authenticated cipher mode info (GCM/CCM) - flags=0 but padding_info is set
	if (padding_info && flags == 0)
	{
		// read the guest BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
		struct guest_auth_info
		{
			std::uint32_t cb_size;
			std::uint32_t dw_info_version;
			std::uint64_t pb_nonce;
			std::uint32_t cb_nonce;
			std::uint32_t pad1;
			std::uint64_t pb_auth_data;
			std::uint32_t cb_auth_data;
			std::uint32_t pad2;
			std::uint64_t pb_tag;
			std::uint32_t cb_tag;
			std::uint32_t pad3;
			std::uint64_t pb_mac_context;
			std::uint32_t cb_mac_context;
			std::uint32_t cb_aad;
			std::uint64_t cb_data;
			std::uint32_t dw_flags;
		} guest = {};

		static_cast<void>(emulator->read_virtual_memory(padding_info, &guest, sizeof(guest)));

		BCRYPT_INIT_AUTH_MODE_INFO(auth_info);

		if (guest.cb_nonce > 0 && guest.pb_nonce)
		{
			nonce_buffer.resize(guest.cb_nonce);
			static_cast<void>(emulator->read_virtual_memory(guest.pb_nonce, nonce_buffer.data(), guest.cb_nonce));
			auth_info.pbNonce = nonce_buffer.data();
			auth_info.cbNonce = guest.cb_nonce;
		}

		if (guest.cb_auth_data > 0 && guest.pb_auth_data)
		{
			auth_data_buffer.resize(guest.cb_auth_data);
			static_cast<void>(emulator->read_virtual_memory(guest.pb_auth_data, auth_data_buffer.data(), guest.cb_auth_data));
			auth_info.pbAuthData = auth_data_buffer.data();
			auth_info.cbAuthData = guest.cb_auth_data;
		}

		if (guest.cb_tag > 0 && guest.pb_tag)
		{
			tag_buffer.resize(guest.cb_tag);
			static_cast<void>(emulator->read_virtual_memory(guest.pb_tag, tag_buffer.data(), guest.cb_tag));
			auth_info.pbTag = tag_buffer.data();
			auth_info.cbTag = guest.cb_tag;
		}

		if (guest.cb_mac_context > 0 && guest.pb_mac_context)
		{
			mac_context_buffer.resize(guest.cb_mac_context);
			static_cast<void>(emulator->read_virtual_memory(guest.pb_mac_context, mac_context_buffer.data(), guest.cb_mac_context));
			auth_info.pbMacContext = mac_context_buffer.data();
			auth_info.cbMacContext = guest.cb_mac_context;
		}

		auth_info.dwFlags = guest.dw_flags;

		host_padding_info = &auth_info;

		THREAD_LOG("BCryptEncrypt: GCM auth info (nonce_size={}, auth_data_size={}, tag_size={}, flags=0x{:X})",
			guest.cb_nonce, guest.cb_auth_data, guest.cb_tag, guest.dw_flags);
	}
	else if ((flags & bcrypt_pad_pkcs1) && padding_info)
	{
		// BCRYPT_PKCS1_PADDING_INFO { LPCWSTR pszAlgId; }
		// pszAlgId is NULL for encryption
		host_padding_info = &pkcs1_info;
	}
	else if ((flags & bcrypt_pad_oaep) && padding_info)
	{
		// BCRYPT_OAEP_PADDING_INFO { LPCWSTR pszAlgId; PUCHAR pbLabel; ULONG cbLabel; }
		// read the algorithm string pointer from the guest struct
		emulator_t::address_type alg_id_ptr = 0;
		static_cast<void>(emulator->read_virtual_memory(padding_info, &alg_id_ptr, sizeof(alg_id_ptr)));

		std::wstring alg_name;
		if (alg_id_ptr)
		{
			alg_name = kernel::read_guest_wstring(*emulator, alg_id_ptr);
		}

		// default to SHA256 if we can't read the algorithm name
		if (alg_name.empty() || alg_name == L"SHA256")
		{
			oaep_info.pszAlgId = BCRYPT_SHA256_ALGORITHM;
		}
		else if (alg_name == L"SHA1")
		{
			oaep_info.pszAlgId = BCRYPT_SHA1_ALGORITHM;
		}
		else if (alg_name == L"SHA384")
		{
			oaep_info.pszAlgId = BCRYPT_SHA384_ALGORITHM;
		}
		else if (alg_name == L"SHA512")
		{
			oaep_info.pszAlgId = BCRYPT_SHA512_ALGORITHM;
		}
		else
		{
			oaep_info.pszAlgId = BCRYPT_SHA256_ALGORITHM;
		}

		// read pbLabel and cbLabel
		emulator_t::address_type label_ptr = 0;
		std::uint32_t label_size = 0;
		static_cast<void>(emulator->read_virtual_memory(padding_info + 8, &label_ptr, sizeof(label_ptr)));
		static_cast<void>(emulator->read_virtual_memory(padding_info + 16, &label_size, sizeof(label_size)));

		oaep_info.pbLabel = nullptr;
		oaep_info.cbLabel = 0;

		host_padding_info = &oaep_info;

		THREAD_LOG("BCryptEncrypt: OAEP padding (alg='{}', label=0x{:X}, label_size={})",
			util::narrow_wstring(alg_name), label_ptr, label_size);
	}

	const auto status = ::BCryptEncrypt(
		reinterpret_cast<BCRYPT_KEY_HANDLE>(key_handle),
		input.data(), input_size, host_padding_info,
		iv_size > 0 ? iv.data() : nullptr, iv_size,
		output_size > 0 ? output.data() : nullptr, output_size,
		&result_size, flags);

	if (BCRYPT_SUCCESS(status))
	{
		if (output_address && output_size > 0)
		{
			emulator->write_virtual_memory(output_address, output.data(), result_size)
				.throw_if("BCryptEncrypt: write output");
		}
		if (iv_size > 0 && iv_address)
		{
			emulator->write_virtual_memory(iv_address, iv.data(), iv_size)
				.throw_if("BCryptEncrypt: write updated IV");
		}

		// write back GCM tag and mac context to guest
		if (host_padding_info == &auth_info)
		{
			if (auth_info.cbTag > 0 && auth_info.pbTag)
			{
				// read guest auth info to get the tag pointer
				emulator_t::address_type guest_tag_ptr = 0;
				static_cast<void>(emulator->read_virtual_memory(padding_info + 0x28, &guest_tag_ptr, sizeof(guest_tag_ptr)));
				if (guest_tag_ptr)
				{
					static_cast<void>(emulator->write_virtual_memory(guest_tag_ptr, auth_info.pbTag, auth_info.cbTag));
				}
			}
			if (auth_info.cbMacContext > 0 && auth_info.pbMacContext)
			{
				emulator_t::address_type guest_mac_ptr = 0;
				static_cast<void>(emulator->read_virtual_memory(padding_info + 0x38, &guest_mac_ptr, sizeof(guest_mac_ptr)));
				if (guest_mac_ptr)
				{
					static_cast<void>(emulator->write_virtual_memory(guest_mac_ptr, auth_info.pbMacContext, auth_info.cbMacContext));
				}
			}
		}
	}

	if (result_size_address)
	{
		emulator->write_virtual_memory(result_size_address, &result_size, sizeof(result_size))
			.throw_if("BCryptEncrypt: write result size");
	}

	THREAD_LOG("BCryptEncrypt: status=0x{:X}, result_size=0x{:X}", static_cast<std::uint32_t>(status), result_size);

	emulator->write_register<x86::reg::rax>(static_cast<std::uint64_t>(status));
}

// BCryptDecrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, VOID *pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG *pcbResult, ULONG dwFlags)
static void handle_decrypt(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type key_handle, emulator_t::address_type input_address,
	std::uint32_t input_size, emulator_t::address_type padding_info,
	emulator_t::address_type iv_address, std::uint32_t iv_size,
	emulator_t::address_type output_address, std::uint32_t output_size,
	emulator_t::address_type result_size_address, std::uint32_t flags)
{
	THREAD_LOG("BCryptDecrypt called (key=0x{:X}, input=0x{:X}, input_size=0x{:X}, iv=0x{:X}, iv_size=0x{:X}, output=0x{:X}, output_size=0x{:X}, flags=0x{:X})",
		key_handle, input_address, input_size, iv_address, iv_size, output_address, output_size, flags);

	std::vector<std::uint8_t> input(input_size);
	if (input_size > 0)
	{
		emulator->read_virtual_memory(input_address, input.data(), input_size)
			.throw_if("BCryptDecrypt: read input");
	}

	std::vector<std::uint8_t> iv(iv_size);
	if (iv_size > 0)
	{
		emulator->read_virtual_memory(iv_address, iv.data(), iv_size)
			.throw_if("BCryptDecrypt: read IV");
	}

	std::vector<std::uint8_t> output(output_size);
	ULONG result_size = 0;

	const auto status = ::BCryptDecrypt(
		reinterpret_cast<BCRYPT_KEY_HANDLE>(key_handle),
		input.data(), input_size, nullptr,
		iv_size > 0 ? iv.data() : nullptr, iv_size,
		output_size > 0 ? output.data() : nullptr, output_size,
		&result_size, flags);

	if (BCRYPT_SUCCESS(status))
	{
		if (output_address && output_size > 0)
		{
			emulator->write_virtual_memory(output_address, output.data(), result_size)
				.throw_if("BCryptDecrypt: write output");
		}
		if (iv_size > 0 && iv_address)
		{
			emulator->write_virtual_memory(iv_address, iv.data(), iv_size)
				.throw_if("BCryptDecrypt: write updated IV");
		}
	}

	if (result_size_address)
	{
		emulator->write_virtual_memory(result_size_address, &result_size, sizeof(result_size))
			.throw_if("BCryptDecrypt: write result size");
	}

	THREAD_LOG("BCryptDecrypt: status=0x{:X}, result_size=0x{:X}", static_cast<std::uint32_t>(status), result_size);

	emulator->write_register<x86::reg::rax>(static_cast<std::uint64_t>(status));
}

// BCryptImportKeyPair(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE hImportKey, LPCWSTR pszBlobType, BCRYPT_KEY_HANDLE *phKey, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags)
static void handle_import_key_pair(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type algorithm_handle, emulator_t::address_type import_key,
	emulator_t::address_type blob_type_address, emulator_t::address_type key_handle_out,
	emulator_t::address_type input_address, std::uint32_t input_size, std::uint32_t flags)
{
	std::wstring blob_type;
	if (blob_type_address)
	{
		blob_type = kernel::read_guest_wstring(*emulator, blob_type_address);
	}

	THREAD_LOG("BCryptImportKeyPair called (algorithm=0x{:X}, blob_type='{}', key_out=0x{:X}, input=0x{:X}, input_size=0x{:X}, flags=0x{:X})",
		algorithm_handle, util::narrow_wstring(blob_type), key_handle_out, input_address, input_size, flags);

	std::vector<std::uint8_t> input(input_size);
	if (input_size > 0)
	{
		emulator->read_virtual_memory(input_address, input.data(), input_size)
			.throw_if("BCryptImportKeyPair: read input");
	}

	BCRYPT_KEY_HANDLE host_key = nullptr;
	const auto status = ::BCryptImportKeyPair(
		reinterpret_cast<BCRYPT_ALG_HANDLE>(algorithm_handle),
		nullptr, blob_type.c_str(),
		&host_key, input.data(), input_size, flags);

	if (BCRYPT_SUCCESS(status) && key_handle_out)
	{
		const auto handle_value = reinterpret_cast<std::uint64_t>(host_key);
		emulator->write_virtual_memory(key_handle_out, &handle_value, sizeof(handle_value))
			.throw_if("BCryptImportKeyPair: write key handle");

		THREAD_LOG("BCryptImportKeyPair: success (host_handle=0x{:X})", handle_value);
	}
	else
	{
		THREAD_WARN_LOG("BCryptImportKeyPair: host returned 0x{:X}", static_cast<std::uint32_t>(status));
	}

	emulator->write_register<x86::reg::rax>(static_cast<std::uint64_t>(status));
}

// BCryptVerifySignature(BCRYPT_KEY_HANDLE hKey, VOID *pPaddingInfo, PUCHAR pbHash, ULONG cbHash, PUCHAR pbSignature, ULONG cbSignature, ULONG dwFlags)
static void handle_verify_signature(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type key_handle, emulator_t::address_type padding_info,
	emulator_t::address_type input_address, std::uint32_t input_size,
	emulator_t::address_type output_address, std::uint32_t output_size,
	emulator_t::address_type result_size_address, std::uint32_t flags)
{
	THREAD_LOG("BCryptVerifySignature called (key=0x{:X}, padding=0x{:X}, input=0x{:X}, input_size=0x{:X}, output=0x{:X}, output_size=0x{:X}, flags=0x{:X})",
		key_handle, padding_info, input_address, input_size, output_address, output_size, flags);

	std::vector<std::uint8_t> hash_data(input_size);
	if (input_size > 0)
	{
		emulator->read_virtual_memory(input_address, hash_data.data(), input_size)
			.throw_if("BCryptVerifySignature: read hash");
	}

	std::vector<std::uint8_t> signature(output_size);
	if (output_size > 0)
	{
		emulator->read_virtual_memory(output_address, signature.data(), output_size)
			.throw_if("BCryptVerifySignature: read signature");
	}

	const auto status = ::BCryptVerifySignature(
		reinterpret_cast<BCRYPT_KEY_HANDLE>(key_handle),
		nullptr, hash_data.data(), input_size,
		signature.data(), output_size, flags);

	THREAD_LOG("BCryptVerifySignature: status=0x{:X}", static_cast<std::uint32_t>(status));

	emulator->write_register<x86::reg::rax>(static_cast<std::uint64_t>(status));
}

void redirect_cng_bcrypt_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image)
{
	redirect_handler<handle_open_algorithm_provider>(emulator, mapped_image, "BCryptOpenAlgorithmProvider");
	redirect_handler<handle_get_property>(emulator, mapped_image, "BCryptGetProperty");
	redirect_handler<handle_set_property>(emulator, mapped_image, "BCryptSetProperty");
	redirect_handler<handle_create_hash>(emulator, mapped_image, "BCryptCreateHash");
	redirect_handler<handle_hash_data>(emulator, mapped_image, "BCryptHashData");
	redirect_handler<handle_finish_hash>(emulator, mapped_image, "BCryptFinishHash");
	redirect_handler<handle_destroy_hash>(emulator, mapped_image, "BCryptDestroyHash");
	redirect_handler<handle_close_algorithm_provider>(emulator, mapped_image, "BCryptCloseAlgorithmProvider");
	redirect_handler<handle_generate_symmetric_key>(emulator, mapped_image, "BCryptGenerateSymmetricKey");
	redirect_handler<handle_destroy_key>(emulator, mapped_image, "BCryptDestroyKey");
	redirect_handler<handle_encrypt>(emulator, mapped_image, "BCryptEncrypt");
	redirect_handler<handle_decrypt>(emulator, mapped_image, "BCryptDecrypt");
	redirect_handler<handle_import_key_pair>(emulator, mapped_image, "BCryptImportKeyPair");
	redirect_handler<handle_verify_signature>(emulator, mapped_image, "BCryptVerifySignature");
}
