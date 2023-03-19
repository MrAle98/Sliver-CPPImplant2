#pragma once
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <curl/curl.h>
using namespace std::chrono;

system_clock::time_point toUTC(system_clock::time_point tp) {
	auto time_t = std::chrono::system_clock::to_time_t(tp);
	auto ptm = gmtime(&time_t);
	auto utc_time_t = _mkgmtime(ptm);
	auto time_point_utc = std::chrono::system_clock::from_time_t(utc_time_t);
	return time_point_utc;
}

system_clock::time_point toUTC(time_t* tt) {
	auto ptm = gmtime(tt);
	auto utc_time_t = _mkgmtime(ptm);
	auto time_point_utc = std::chrono::system_clock::from_time_t(utc_time_t);
	return time_point_utc;
}

time_t fromHTTPDate(const char* dateString) {
	return curl_getdate(dateString, NULL);
}

