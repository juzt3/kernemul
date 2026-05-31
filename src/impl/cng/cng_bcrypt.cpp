#include "cng_bcrypt.hpp"

#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

void redirect_cng_bcrypt_functions(const std::shared_ptr<emulator_t>& emulator,
	const kernel_image_t& mapped_image)
{
	redirect_function(
		[emulator]
		{
			const auto handle_out_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto alg_id_address = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto implementation_address = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
			const auto flags = emulator->read_register<x86::reg::r9, std::uint32_t>();

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
		},
		mapped_image,
		"BCryptOpenAlgorithmProvider"
	);

	redirect_function(
		[emulator]
		{
			const auto handle = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto property_address = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto output_address = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
			const auto output_size = emulator->read_register<x86::reg::r9, std::uint32_t>();

			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			emulator_t::address_type result_address = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x28, &result_address, sizeof(result_address)));

			std::uint32_t flags = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x30, &flags, sizeof(flags)));

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
		},
		mapped_image,
		"BCryptGetProperty"
	);

	redirect_function(
		[emulator]
		{
			const auto handle = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto property_address = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto value_address = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
			const auto value_size = emulator->read_register<x86::reg::r9, std::uint32_t>();

			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();
			std::uint32_t flags = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x28, &flags, sizeof(flags)));

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
		},
		mapped_image,
		"BCryptSetProperty"
	);

	redirect_function(
		[emulator]
		{
			const auto algorithm_handle = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto hash_handle_out = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto hash_object_address = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
			const auto hash_object_size = emulator->read_register<x86::reg::r9, std::uint32_t>();

			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			emulator_t::address_type secret_address = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x28, &secret_address, sizeof(secret_address)));

			std::uint32_t secret_size = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x30, &secret_size, sizeof(secret_size)));

			std::uint32_t flags = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x38, &flags, sizeof(flags)));

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
		},
		mapped_image,
		"BCryptCreateHash"
	);

	redirect_function(
		[emulator]
		{
			const auto hash_handle = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto input_address = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto input_size = emulator->read_register<x86::reg::r8, std::uint32_t>();
			const auto flags = emulator->read_register<x86::reg::r9, std::uint32_t>();

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
		},
		mapped_image,
		"BCryptHashData"
	);

	redirect_function(
		[emulator]
		{
			const auto hash_handle = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto output_address = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto output_size = emulator->read_register<x86::reg::r8, std::uint32_t>();
			const auto flags = emulator->read_register<x86::reg::r9, std::uint32_t>();

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
		},
		mapped_image,
		"BCryptFinishHash"
	);

	redirect_function(
		[emulator]
		{
			const auto hash_handle = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("BCryptDestroyHash called (handle=0x{:X})", hash_handle);

			const auto status = BCryptDestroyHash(reinterpret_cast<BCRYPT_HASH_HANDLE>(hash_handle));

			THREAD_LOG("BCryptDestroyHash: status=0x{:X}", static_cast<std::uint32_t>(status));

			emulator->write_register<x86::reg::rax>(static_cast<std::uint64_t>(status));
		},
		mapped_image,
		"BCryptDestroyHash"
	);

	redirect_function(
		[emulator]
		{
			const auto algorithm_handle = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto flags = emulator->read_register<x86::reg::rdx, std::uint32_t>();

			THREAD_LOG("BCryptCloseAlgorithmProvider called (handle=0x{:X}, flags=0x{:X})", algorithm_handle, flags);

			const auto status = BCryptCloseAlgorithmProvider(
				reinterpret_cast<BCRYPT_ALG_HANDLE>(algorithm_handle),
				flags
			);

			THREAD_LOG("BCryptCloseAlgorithmProvider: status=0x{:X}", static_cast<std::uint32_t>(status));

			emulator->write_register<x86::reg::rax>(static_cast<std::uint64_t>(status));
		},
		mapped_image,
		"BCryptCloseAlgorithmProvider"
	);

	redirect_function(
		[emulator]
		{
			const auto algorithm_handle = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto key_handle_out = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto key_object_address = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
			const auto key_object_size = emulator->read_register<x86::reg::r9, std::uint32_t>();

			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			emulator_t::address_type secret_address = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x28, &secret_address, sizeof(secret_address)));

			std::uint32_t secret_size = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x30, &secret_size, sizeof(secret_size)));

			std::uint32_t flags = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x38, &flags, sizeof(flags)));

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
		},
		mapped_image,
		"BCryptGenerateSymmetricKey"
	);

	redirect_function(
		[emulator]
		{
			const auto key_handle = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("BCryptDestroyKey called (handle=0x{:X})", key_handle);

			const auto status = ::BCryptDestroyKey(reinterpret_cast<BCRYPT_KEY_HANDLE>(key_handle));

			THREAD_LOG("BCryptDestroyKey: status=0x{:X}", static_cast<std::uint32_t>(status));

			emulator->write_register<x86::reg::rax>(static_cast<std::uint64_t>(status));
		},
		mapped_image,
		"BCryptDestroyKey"
	);

	redirect_function(
		[emulator]
		{
			const auto key_handle = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto input_address = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto input_size = emulator->read_register<x86::reg::r8, std::uint32_t>();
			const auto padding_info = emulator->read_register<x86::reg::r9, emulator_t::address_type>();

			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			emulator_t::address_type iv_address = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x28, &iv_address, sizeof(iv_address)));

			std::uint32_t iv_size = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x30, &iv_size, sizeof(iv_size)));

			emulator_t::address_type output_address = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x38, &output_address, sizeof(output_address)));

			std::uint32_t output_size = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x40, &output_size, sizeof(output_size)));

			emulator_t::address_type result_size_address = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x48, &result_size_address, sizeof(result_size_address)));

			std::uint32_t flags = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x50, &flags, sizeof(flags)));

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
		},
		mapped_image,
		"BCryptEncrypt"
	);

	redirect_function(
		[emulator]
		{
			const auto key_handle = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto input_address = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto input_size = emulator->read_register<x86::reg::r8, std::uint32_t>();
			const auto padding_info = emulator->read_register<x86::reg::r9, emulator_t::address_type>();

			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			emulator_t::address_type iv_address = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x28, &iv_address, sizeof(iv_address)));

			std::uint32_t iv_size = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x30, &iv_size, sizeof(iv_size)));

			emulator_t::address_type output_address = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x38, &output_address, sizeof(output_address)));

			std::uint32_t output_size = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x40, &output_size, sizeof(output_size)));

			emulator_t::address_type result_size_address = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x48, &result_size_address, sizeof(result_size_address)));

			std::uint32_t flags = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x50, &flags, sizeof(flags)));

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
		},
		mapped_image,
		"BCryptDecrypt"
	);

	redirect_function(
		[emulator]
		{
			const auto algorithm_handle = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto import_key = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto blob_type_address = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
			const auto key_handle_out = emulator->read_register<x86::reg::r9, emulator_t::address_type>();

			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			emulator_t::address_type input_address = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x28, &input_address, sizeof(input_address)));

			std::uint32_t input_size = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x30, &input_size, sizeof(input_size)));

			std::uint32_t flags = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x38, &flags, sizeof(flags)));

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
		},
		mapped_image,
		"BCryptImportKeyPair"
	);

	redirect_function(
		[emulator]
		{
			const auto key_handle = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto padding_info = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto input_address = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
			const auto input_size = emulator->read_register<x86::reg::r9, std::uint32_t>();

			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			emulator_t::address_type output_address = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x28, &output_address, sizeof(output_address)));

			std::uint32_t output_size = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x30, &output_size, sizeof(output_size)));

			emulator_t::address_type result_size_address = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x38, &result_size_address, sizeof(result_size_address)));

			std::uint32_t flags = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x40, &flags, sizeof(flags)));

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
		},
		mapped_image,
		"BCryptVerifySignature"
	);
}
