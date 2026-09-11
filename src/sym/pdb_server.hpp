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

inline std::filesystem::path cached_path(const pe::codeview_rsds& cv)
{
	auto name = std::filesystem::path(cv.pdb_path()).filename();
	return std::filesystem::path("symbols") / name / build_key(cv) / name;
}

inline bool download_file(const std::string& host, const std::string& target,
	const std::filesystem::path& dest)
{
	std::filesystem::create_directories(dest.parent_path());

	try
	{
		net::io_context ioc;

		ssl::context ctx(ssl::context::tlsv12_client);
		ctx.set_default_verify_paths();

		tcp::resolver resolver(ioc);
		beast::ssl_stream<beast::tcp_stream> stream(ioc, ctx);

		SSL_set_tlsext_host_name(stream.native_handle(), host.c_str());

		auto results = resolver.resolve(host, "443");
		beast::get_lowest_layer(stream).connect(results);
		stream.handshake(ssl::stream_base::client);

		http::request<http::empty_body> req(http::verb::get, target, 11);
		req.set(http::field::host, host);
		req.set(http::field::user_agent, "Microsoft-Symbol-Server/10.0.0.0");

		http::write(stream, req);

		beast::flat_buffer buffer;
		http::response<http::dynamic_body> res;
		http::read(stream, buffer, res);

		beast::error_code ec;
		stream.shutdown(ec);

		if (res.result() != http::status::ok)
			return false;

		std::ofstream file(dest, std::ios::binary);
		if (!file.is_open())
			return false;

		for (const auto& buf : res.body().data())
			file.write(static_cast<const char*>(buf.data()), buf.size());

		return file.good();
	}
	catch (const std::exception& e)
	{
		LOG_WARN("download failed: {}", e.what());
		return false;
	}
}

inline std::filesystem::path download(const pe::codeview_rsds& cv)
{
	auto dest = cached_path(cv);

	if (std::filesystem::exists(dest))
		return dest;

	auto name = std::filesystem::path(cv.pdb_path()).filename().string();
	auto key = build_key(cv);
	auto target = std::format("/download/symbols/{}/{}/{}", name, key, name);

	LOG_INFO("downloading {} from symbol server...", name);

	if (!download_file("msdl.microsoft.com", target, dest))
	{
		LOG_WARN("failed to download {}", name);
		std::filesystem::remove(dest);
		return {};
	}

	LOG_INFO("cached {} -> {}", name, dest.string());
	return dest;
}

} // namespace pdb_server
