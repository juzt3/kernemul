#pragma once
#include "../util/log.hpp"

#include <pe.hpp>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>

#include <filesystem>
#include <format>
#include <fstream>
#include <limits>
#include <string>

namespace pdb_server
{

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = net::ssl;
using tcp = net::ip::tcp;

inline std::string format_guid(const pe::guid& g)
{
	return std::format("{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
		g.data1, g.data2, g.data3,
		g.data4[0], g.data4[1], g.data4[2], g.data4[3],
		g.data4[4], g.data4[5], g.data4[6], g.data4[7]);
}

inline std::string build_key(const pe::codeview_rsds& cv)
{
	return std::format("{}{:X}", format_guid(cv.guid), cv.age);
}

// The name the symbol server knows the PDB by. What the PE carries is the path
// it was built at -- always a Windows one, "d:\build\ntkrnlmp.pdb"
// -- so the split is on both separators by hand. std::filesystem would do it
// on Windows and hand back the whole string anywhere else, where a backslash
// is an ordinary character.
inline std::string pdb_file_name(const pe::codeview_rsds& cv)
{
	const std::string_view path = cv.pdb_path();
	const auto slash = path.find_last_of("\\/");

	return std::string(slash == std::string_view::npos ? path : path.substr(slash + 1));
}

inline std::filesystem::path cached_path(const pe::codeview_rsds& cv)
{
	const auto name = pdb_file_name(cv);
	return std::filesystem::path("symbols") / name / build_key(cv) / name;
}

inline void close_stream(beast::ssl_stream<beast::tcp_stream>& stream)
{
	beast::error_code ec;
	beast::get_lowest_layer(stream).socket().shutdown(tcp::socket::shutdown_both, ec);
	beast::get_lowest_layer(stream).close();
}

inline void parse_redirect_url(
	const std::string_view location,
	std::string& host,
	std::string& target)
{
	const auto scheme_end = location.find("://");

	if (scheme_end == std::string_view::npos)
	{
		target = location;
		return;
	}

	const auto host_start = scheme_end + 3;
	const auto path_start = location.find('/', host_start);

	if (path_start == std::string_view::npos)
	{
		host = location.substr(host_start);
		target = "/";
	}
	else
	{
		host = location.substr(host_start, path_start - host_start);
		target = location.substr(path_start);
	}
}

inline std::vector<std::uint8_t> https_get(
	const std::string_view host,
	const std::string_view target,
	const std::uint32_t max_redirects = 5)
{
	net::io_context ioc;

	ssl::context ctx(ssl::context::tlsv12_client);
	ctx.set_default_verify_paths();
	ctx.set_verify_mode(ssl::verify_none);

	std::string current_host(host);
	std::string current_target(target);

	for (std::uint32_t redirect = 0; redirect <= max_redirects; ++redirect)
	{
		tcp::resolver resolver(ioc);
		beast::ssl_stream<beast::tcp_stream> stream(ioc, ctx);

		SSL_set_tlsext_host_name(stream.native_handle(), current_host.c_str());

		beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));
		beast::get_lowest_layer(stream).connect(resolver.resolve(current_host, "443"));
		stream.handshake(ssl::stream_base::client);

		beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(120));

		http::request<http::empty_body> req(http::verb::get, current_target, 11);
		req.set(http::field::host, current_host);
		req.set(http::field::user_agent, "Microsoft-Symbol-Server/10.0.0.0");
		http::write(stream, req);

		beast::flat_buffer buffer;
		http::response_parser<http::dynamic_body> parser;
		parser.body_limit(std::numeric_limits<std::uint64_t>::max());
		http::read(stream, buffer, parser);

		auto response = parser.release();
		const auto status = response.result_int();

		if (status >= 300 && status < 400)
		{
			const auto location = response[http::field::location];

			if (location.empty())
				return {};

			parse_redirect_url(std::string_view(location), current_host, current_target);
			close_stream(stream);
			continue;
		}

		if (response.result() != http::status::ok)
		{
			close_stream(stream);
			return {};
		}

		const auto body_str = beast::buffers_to_string(response.body().data());
		close_stream(stream);

		return { body_str.begin(), body_str.end() };
	}

	return {};
}

inline std::filesystem::path download(const pe::codeview_rsds& cv)
{
	auto dest = cached_path(cv);

	if (std::filesystem::exists(dest))
		return dest;

	auto name = pdb_file_name(cv);
	auto key = build_key(cv);
	auto target = std::format("/download/symbols/{}/{}/{}", name, key, name);

	LOG_INFO("downloading {} from symbol server...", name);

	try
	{
		auto data = https_get("msdl.microsoft.com", target);
		if (data.empty())
		{
			LOG_WARN("failed to download {}", name);
			return {};
		}

		std::filesystem::create_directories(dest.parent_path());

		std::ofstream file(dest, std::ios::binary);
		file.write(reinterpret_cast<const char*>(data.data()), data.size());

		if (!file.good())
		{
			std::filesystem::remove(dest);
			return {};
		}
	}
	catch (const std::exception& e)
	{
		LOG_WARN("download failed: {}", e.what());
		std::filesystem::remove(dest);
		return {};
	}

	LOG_INFO("cached {} -> {}", name, dest.string());
	return dest;
}

} // namespace pdb_server
