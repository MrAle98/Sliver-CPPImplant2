#include "filesystem.h"
#include "sliver.pb.h"
#include <string>
#include <ctime>
#include <iostream>
#include <fstream>

namespace FS {
	mutex m;
	static constexpr time_t const NULL_TIME = -1;

	long tz_offset(time_t when = NULL_TIME)
	{
		if (when == NULL_TIME)
			when = std::time(nullptr);
		auto const tm = *std::localtime(&when);
		std::ostringstream os;
		os << std::put_time(&tm, "%z");
		std::string s = os.str();
		// s is in ISO 8601 format: "±HHMM"
		int h = std::stoi(s.substr(0, 3), nullptr, 10);
		int m = std::stoi(s[0] + s.substr(3), nullptr, 10);

		return h * 3600 + m * 60;
	}
	string perms_tostring(filesystem::perms p) {
		string out;
		auto show = [&](char op, filesystem::perms perm)
		{
			auto c = filesystem::perms::none == (perm & p) ? '-' : op;
			out.push_back(c);
		};
		show('r', filesystem::perms::owner_read);
		show('w', filesystem::perms::owner_write);
		show('x', filesystem::perms::owner_exec);
		show('r', filesystem::perms::group_read);
		show('w', filesystem::perms::group_write);
		show('x', filesystem::perms::group_exec);
		show('r', filesystem::perms::others_read);
		show('w', filesystem::perms::others_write);
		show('x', filesystem::perms::others_exec);
		return out;
	}
	string pwd() {
		unique_lock lk{ m };
		return std::filesystem::current_path().string();
	}
	string cd(const string& path_string) {
		unique_lock lk{ m };
		auto path = filesystem::path{ path_string };
		if (!filesystem::exists(path)) {
			return filesystem::current_path().string();
		}
		filesystem::current_path(filesystem::path{ path });
		return filesystem::current_path().string();
	}
	sliverpb::Ls ls(const string& path_string,bool recursive) {
		unique_lock lk{ m };
		sliverpb::Ls ls_resp;
		auto path = filesystem::path{ path_string };
		time_t rawtime;
		time(&rawtime);
		ls_resp.set_path(filesystem::absolute(path).string());
		ls_resp.set_timezoneoffset(tz_offset());
		char buf[1024] = { 0 };
		size_t size;
		_get_tzname(
			&size,
			buf,
			1024,
			1
		);
		string timezone{ buf };
		ls_resp.set_timezone(buf);
		if (!filesystem::exists(path)) {
			ls_resp.set_exists(false);
		}
		else if(filesystem::exists(path) && filesystem::is_directory(path)){
			ls_resp.set_exists(true);
			vector<sliverpb::FileInfo> list;
			if (recursive) {
				for (const auto& entry : filesystem::recursive_directory_iterator(path)) {
					auto f = ls_resp.add_files();
					string mode;
					f->set_name(filesystem::absolute(entry.path()).string());
					f->set_isdir(entry.is_directory());
					if (entry.is_directory())
						mode.push_back('d');
					mode.append(perms_tostring(entry.status().permissions()));
					f->set_mode(mode);
					f->set_size(entry.file_size());
					if (entry.is_symlink()) {
						f->set_link(filesystem::read_symlink(entry).string());
					}
					else {
						f->set_link(string{ "" });
					}
					f->set_modtime(std::chrono::duration_cast<std::chrono::seconds>(entry.last_write_time().time_since_epoch()).count());
				}
			}
			else {
				for (const auto& entry : filesystem::directory_iterator(path)) {
					auto f = ls_resp.add_files();
					string mode;
					f->set_name(filesystem::absolute(entry.path()).string());
					f->set_isdir(entry.is_directory());
					if (entry.is_directory())
						mode.push_back('d');
					mode.append(perms_tostring(entry.status().permissions()));
					f->set_mode(mode);
					f->set_size(entry.file_size());
					if (entry.is_symlink()) {
						f->set_link(filesystem::read_symlink(entry).string());
					}
					else {
						f->set_link(string{ "" });
					}
					f->set_modtime(std::chrono::duration_cast<std::chrono::seconds>(entry.last_write_time().time_since_epoch()).count());
				}
			}
			return ls_resp;
		}
		else if (filesystem::exists(path) &&
			(filesystem::is_regular_file(path)
				|| filesystem::is_block_file(path)
				|| filesystem::is_character_file(path))) {
			ls_resp.set_exists(true);
			vector<sliverpb::FileInfo> list;
			filesystem::directory_entry entry{ path };
			auto f = ls_resp.add_files();
			string mode;
			f->set_name(filesystem::absolute(entry.path()).string());
			mode.append(perms_tostring(entry.status().permissions()));
			f->set_mode(mode);
			f->set_size(entry.file_size());
			if (entry.is_symlink()) {
				f->set_link(filesystem::read_symlink(entry).string());
			}
			else {
				f->set_link(string{ "" });
			}
			f->set_modtime(std::chrono::duration_cast<std::chrono::minutes>(entry.last_write_time().time_since_epoch()).count());
			return ls_resp;
		}
		return ls_resp;
	}
	bool write(const string& path, const string& data) {
		unique_lock lk{ m };
		filesystem::path fpath{ path };
		std::ofstream ofs{ fpath, ios::binary };
		if (!ofs)
			return false;
		ofs.write(data.c_str(), data.size());
		ofs.close();
		if (!ofs.good())
			return false;
		else
			return true;
	}
	string read(const string& path) {
		unique_lock lk{ m };
		filesystem::path fpath{ path };
		if (!filesystem::exists(fpath)) {
			throw exception("file not found");
		}
		std::ifstream t(path, ios::binary);
		std::stringstream buffer;
		buffer << t.rdbuf();
		return buffer.str();
	}
	bool mkdir(const string& path, error_code& err) {
		unique_lock{ m };
		return filesystem::create_directories(path, err);
	}
	bool remove(const string& path, error_code& err,bool recursive) {
		unique_lock{ m };
		if (recursive)
			return filesystem::remove_all(path, err);
		else
			return filesystem::remove(path, err);
	}
}