#include <blepp/lescan.h>
#include <blepp/blestatemachine.h>
#include <blepp/lescan.h>
#include <blepp/pretty_printers.h>

#include <boost/program_options.hpp>

#include <iostream>
#include <string>
#include <cstdlib>
#include <csignal>
#include <vector>

#include <sys/select.h>

namespace po = boost::program_options;

volatile
bool terminate = false;

void _on_sigint(int)
{
    terminate = true;
}

void get_nokelock_keys(std::string const &lock_mac)
{

}

void connect_nokelock(std::string const& lock_mac)
{
    bool done = false;

    // Set up the Nokelock known GATT services of interest
    BLEPP::UUID notification("36f5");
    BLEPP::UUID command("fee7");
    BLEPP::UUID name("2a00");

    BLEPP::BLEGATTStateMachine gatt;

    // Callback that's hit when the device is found, along with its details
    std::function<void()> on_found_service = [&gatt, &notification, &command, &name, &done]() {
        for (auto& service: gatt.primary_services) {
            std::cout << "Service UUID: " << to_str(service.uuid) << " (Handle " << service.start_handle << " to " << service.end_handle << ")" << std::endl;

            for (auto& characteristic: service.characteristics) {
                if (characteristic.uuid == notification) {
                    std::cout << "  I have Nokelock Notification capabilities" << std::endl;
                } else if (characteristic.uuid == command) {
                    std::cout << "  I have Nokelock Command capabilities" << std::endl;
                } else if (characteristic.uuid == name) {
                    characteristic.cb_read = [&](const BLEPP::PDUReadResponse& resp) {
                        auto val = resp.value();
                        std::cout << "  My name is " << std::string(val.first, val.second) << std::endl;
                    };
                }
            }
        }
        done = true;
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
    }

    // No need to remain connected
    gatt.close();

    std::cout << "DEBUG: now you know what I know about " << lock_mac << std::endl;
}

void find_nokelocks()
{
    fd_set fd_scan;
    FD_ZERO(&fd_scan);

    struct timeval fd_scan_timeout = {
        .tv_sec = 0,
        .tv_usec = 500000
    };

    BLEPP::UUID notification("fee7");

    BLEPP::HCIScanner scanner(true, BLEPP::HCIScanner::FilterDuplicates::Software,
            BLEPP::HCIScanner::ScanType::Active);

    std::signal(SIGINT, _on_sigint);

    while (false == terminate) {
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
                        std::cout << "  Service: " << to_str(uuid) << std::endl;

                        // TODO: connect, grab keys, profit
                        connect_nokelock(resp.address);
                        break;
                    }
                }
            }
        }
    }

    std::cout << "Scan terminated." << std::endl;
}

int main(int const argc, char const* const argv[])
{
    po::options_description desc("Main Options");

    desc.add_options()
        ("help,h",          "Get some help (this screen)")
        ("mac-address,m",   po::value<std::string>()->default_value(""), "HCI device MAC address")
        ("hci-device,H",    po::value<std::string>()->default_value(""), "HCI device name")
        ("search,S",        po::value<bool>()->default_value(true), "Search for Nokelocks (default)")
        ;

    po::variables_map args;
    po::store(po::command_line_parser(argc, argv)
            .options(desc)
            .run(), args);
    po::notify(args);

    auto hci_mac = args["mac-address"].as<std::string>();
    auto hci_dev = args["hci-device"].as<std::string>();
    bool search = args["search"].as<bool>();

    find_nokelocks();

    return EXIT_SUCCESS;
}
