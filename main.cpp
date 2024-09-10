#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <utility>

#include "algcv_misc.h"
#include "httplib.h"

static const int PORT = 10001;                         // 端口号
static const std::string URL_PATH = "/sim_info";       // URL 路径
static const std::string SERIALPORT = "/dev/ttyUSB2";  // 串口
static const speed_t BAUDRATE = B115200;               // 波特率

static int SIM_STATUS = 0;  // SIM卡状态
static int TYPE = 0;        // SIM卡类型
static int STRENGTH = 0;    // SIM卡信号强度
static int INTERNET = 0;    // SIM卡上网状态

struct APNConfig {
  std::string apn;
  std::string user;
  std::string password;
  int auth = 0;
};

static APNConfig apnConfig;

void InitLog(const std::string& logName, const std::string& logPath) {
  LogInit(logName.c_str(), logPath.c_str());
  SetPrintLevel(0);
  SetLogFileFlushInterval(5);
  SetLogModule(AIRIA_PRINT_ALL_MODULE);
}

/* Ping网络 */
class NetworkUtils {
 public:
  /* 解析域名并进行 ping 测试 */
  static bool pingDomain(const std::string& domain, const std::string& iface) {
    // 解析域名获取 IP 地址
    std::string ipAddresses = resolveDomain(domain);
    if (ipAddresses.empty()) {
      return "Failed to resolve domain.";
    }

    // 打印解析得到的 IP 地址
    //    std::ostringstream result;
    //    result << "Resolved IP addresses for " << domain << ":\n" <<
    //    ipAddresses;

    // 逐个 ping 解析出的 IP 地址
    bool success = false;
    std::istringstream stream(ipAddresses);
    std::string ip;
    while (std::getline(stream, ip)) {
      if (pingIPAddress(ip, iface)) {
        //        result << "Ping successful for IP: " << ip << "\n";
        success = true;
        break;
      } else {
        //        result << "Ping failed for IP: " << ip << "\n";
      }
    }

    //    if (!success) {
    //      result << "Ping failed for all IP addresses.\n";
    //    }

    return success;
  }

 private:
  /* 解析域名，获取 IP 地址 */
  static std::string resolveDomain(const std::string& domain) {
    struct addrinfo hints {
    }, *res, *p;
    int status;
    char ipstr[INET6_ADDRSTRLEN];
    std::string ipAddresses;

    // 初始化 hints 结构
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    // 获取地址信息
    if ((status = getaddrinfo(domain.c_str(), nullptr, &hints, &res)) != 0) {
      return "getaddrinfo error: " + std::string(gai_strerror(status));
    }

    // 遍历所有的地址信息
    for (p = res; p != nullptr; p = p->ai_next) {
      void* addr;
      if (p->ai_family == AF_INET) {
        auto* ipv4 = (struct sockaddr_in*)p->ai_addr;
        addr = &(ipv4->sin_addr);
      } else {
        auto* ipv6 = (struct sockaddr_in6*)p->ai_addr;
        addr = &(ipv6->sin6_addr);
      }
      // 将地址转换为字符串
      inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
      ipAddresses += ipstr;
      ipAddresses += "\n";
    }

    freeaddrinfo(res);  // 释放地址信息链表
    return ipAddresses;
  }

  /* 执行 ping 命令并返回结果 */
  static bool pingIPAddress(const std::string& ip, const std::string& iface) {
    std::string command =
        "ping -I " + iface + " -c 2 " + ip + " > /dev/null 2>&1";
    int result = system(command.c_str());
    return (result == 0);
  }
};

/* 串口 */
class Serial {
 public:
  static Serial* GetInstance(const std::string& serialPort,
                             const speed_t& baudRate) {
    static Serial v(serialPort, baudRate);
    return &v;
  }

  int getSerialFd() const { return m_fd; }

  bool reset() {
    if (m_fd) {
      close(m_fd);
    }

    if (!init()) {
      ALGCV_TRACE_ERR("Failed to reset serial port");
      exit(0);
    }
    return true;
  }

 private:
  Serial(std::string serialPort, const speed_t& baudRate)
      : m_serialPort(std::move(serialPort)), m_baudRate(baudRate) {
    if (!init()) {
      ALGCV_TRACE_ERR("Error init Serial!");
      exit(0);
    }
  }

  ~Serial() {
    if (m_fd) {
      close(m_fd);
    }
  }

  bool init() {
    // 打开串口
    m_fd = open(m_serialPort.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (m_fd == -1) {
      ALGCV_TRACE_ERR("Error opening serial port: %s\n",
                      std::string(strerror(errno)).c_str());
      return false;
    }

    // 清除输入缓冲区
    tcflush(m_fd, TCIOFLUSH);

    // 配置串口设置
    struct termios tty {};
    memset(&tty, 0, sizeof(tty));
    if (tcgetattr(m_fd, &tty) != 0) {
      ALGCV_TRACE_ERR("Error getting serial port attributes: %s\n",
                      std::string(strerror(errno)).c_str());
      close(m_fd);
      return false;
    }

    // 设置波特率
    cfsetospeed(&tty, m_baudRate);
    cfsetispeed(&tty, m_baudRate);

    // 设置字符大小
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= CS8;

    // 设置停止位
    tty.c_cflag &= ~CSTOPB;

    // 设置无校验
    tty.c_cflag &= ~PARENB;

    // 禁用流控制
    tty.c_cflag &= ~CRTSCTS;

    // 设置本地模式和启用接收器
    tty.c_cflag |= (CLOCAL | CREAD);

    // 设置非规范模式
    tty.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
    tty.c_iflag &= ~(IXON | IXOFF | IXANY);
    tty.c_oflag &= ~OPOST;

    // 设置超时
    tty.c_cc[VMIN] = 0;
    tty.c_cc[VTIME] = 1;

    // 应用设置
    if (tcsetattr(m_fd, TCSANOW, &tty) != 0) {
      ALGCV_TRACE_ERR("Error setting serial port attributes: %s\n",
                      std::string(strerror(errno)).c_str());
      close(m_fd);
      return false;
    }

    return true;
  }

 private:
  std::string m_serialPort;
  speed_t m_baudRate;
  int m_fd{0};
};

/* SIM卡状态 */
class SIM_INFO {
 public:
  /* 获得实例 */
  static SIM_INFO* GetInstance(const std::string& serialPort,
                               const speed_t& baudRate) {
    static SIM_INFO v(serialPort, baudRate);
    return &v;
  }

  /* SIM卡状态 */
  bool checkSIMStatus(bool printResponse = true) {
    std::string response = sendATCommand("AT+CPIN?\r\n", printResponse);
    return (response.find("+CPIN: READY") != std::string::npos);
  }

  /* 获取(4G or 5G)类型 */
  std::string getNetworkType(bool printResponse = true) {
    std::string response = sendATCommand("AT+QNWINFO\r\n", printResponse);

    // 解析响应以提取网络类型信息
    if (response.find("LTE") != std::string::npos ||
        response.find("WCDMA") != std::string::npos) {
      return "4G";
    } else if (response.find("NR") != std::string::npos) {
      return "5G";
    } else {
      return "Unknown";
    }
  }

  /*
   * 提取信号强度
   * 0 格： 0 到 4
   * 1 格： 5 到 9
   * 2 格： 10 到 14
   * 3 格： 15 到 19
   * 4 格： 20 到 31
   */
  int getSignalStrength(bool printResponse = true) {
    std::string command = "AT+CSQ\r\n";
    std::string response = sendATCommand(command, printResponse);

    int signalStrength = 0;
    // 解析响应以提取信号强度
    char* signalStart = const_cast<char*>(strstr(response.c_str(), "+CSQ: "));
    if (signalStart != nullptr) {
      signalStrength = std::stoi(signalStart + 6);  // 跳过 "+CSQ: "
    } else {
      ALGCV_TRACE_INFO("Failed to parse signal strength from response: %s\n",
                       response.c_str());
    }
    if (signalStrength >= 5 && signalStrength <= 9) {
      return 1;
    } else if (signalStrength >= 10 && signalStrength <= 14) {
      return 2;
    } else if (signalStrength >= 15 && signalStrength <= 19) {
      return 3;
    } else if (signalStrength >= 20 && signalStrength <= 31) {
      return 4;
    } else {
      return 0;
    }
  }

  /* 查看网络状态 */
  bool checkRegistrationStatus() {
    return NetworkUtils::pingDomain(m_domain, m_iface);
  }

 private:
  /* 私有构造函数 提供单例 */
  SIM_INFO(const std::string& serialPort, const speed_t& baudRate)
      : m_serial(Serial::GetInstance(serialPort, baudRate)) {
    bool ret = init();
    if (!ret) {
      ALGCV_TRACE_ERR("SIM_INFO init failed!\n");
      exit(0);
    }
  }

  /* 析构 */
  ~SIM_INFO() = default;

  /* 初始化SIM卡 */
  bool init() {
    int nums = 3;
    bool check_flag = false;
    // 检查SIM状态
    while (nums--) {
      check_flag = checkSIMStatus();
      if (check_flag) {
        break;
      }
    }

    if (check_flag) {
      // 初始化拨号
      // 取消回显
      sendATCommand("ATE0\r\n");

      // 完全功能模式
      sendATCommand("AT+CFUN=1\r\n");

      // 配置USB网络模式
      sendATCommand("AT+QCFG=\"usbnet\"\r\n");

      // 配置网络地址转换（NAT）设置
      sendATCommand("AT+QCFG=\"NAT\"\r\n");

      // 查询模块固件版本号
      sendATCommand("AT+CGMR\r\n");

      // 查询SIM卡ICCID（集成电路卡识别码）
      sendATCommand("AT+QCCID\r\n");

      // 查询国际移动用户识别码（IMSI）
      sendATCommand("AT+CIMI\r\n");

      // 配置GSM网络注册状态
      sendATCommand("AT+CGREG=2\r\n");

      // 配置EPS网络注册状态
      sendATCommand("AT+CEREG=2\r\n");

      // 配置5G网络注册状态
      sendATCommand("AT+C5GREG=2\r\n");

      // 配置PDP（分组数据协议）上下文参数 APN
      if (apnConfig.apn.empty()) {
        sendATCommand("AT+QICSGP=1\r\n");
      } else {
        sendATCommand(
            "AT+QICSGP=1,"
            "\"" +
            apnConfig.apn +
            "\","
            "\"" +
            apnConfig.user +
            "\","
            "\"" +
            apnConfig.password + "\"," + std::to_string(apnConfig.auth) +
            "\r\n");

        sendATCommand("AT+CGDCONT=1,\"IPV4\",\"" + apnConfig.apn + "\" \r\n");
      }

      // 设置自动运营商选择（Automatic Mode）
      sendATCommand("AT+COPS=3,0\r\n");

      // 查询当前运营商
      sendATCommand("AT+COPS?\r\n");

      // 设置手动运营商选择（Manual Mode）
      sendATCommand("AT+COPS=3,1\r\n");

      // 设置手动/自动运营商选择（Manual/Automatic Mode）
      sendATCommand("AT+COPS=3,2\r\n");

      // 查询当前服务小区信息
      sendATCommand("AT+QENG=\"servingcell\"\r\n");

      // 控制网络设备
      sendATCommand("AT+QNETDEVCTL=1,1,1\r\n");

      // 查询网络设备状态
      sendATCommand("AT+QNETDEVSTATUS=1\r\n");

      // 拉起usb0
      if (system("ifconfig usb0 up") != 0) {
        ALGCV_TRACE_ERR("Failed to bring network interface up\n");
        return false;
      }

      // DHCP获取IP地址
      if (system("busybox udhcpc -f -n -q -t 5 -i usb0") != 0) {
        ALGCV_TRACE_ERR("Failed to obtain IP address via udhcpc\n");
        return false;
      }

      return true;
    } else {
      ALGCV_TRACE_INFO("SIM Card not ready or missing\n");
      return false;
    }
  }

  /* 发送AT命令和读取响应的功能 */
  std::string sendATCommand(const std::string& command,
                            bool printResponse = true) {
    std::string response;

    int fd = m_serial->getSerialFd();
    // 清除输入缓冲区
    tcflush(fd, TCIFLUSH);

    // 尝试将命令写入串口（带重试机制）
    const int max_write_attempts = 5;
    const int write_retry_delay_ms = 100;  // 重试间隔
    ssize_t bytes_written = -1;
    for (int attempt = 0; attempt < max_write_attempts; ++attempt) {
      bytes_written = write(fd, command.c_str(), command.size());
      if (bytes_written != -1 || errno != EAGAIN) {
        break;
      }
      std::this_thread::sleep_for(
          std::chrono::milliseconds(write_retry_delay_ms));
    }

    if (bytes_written == -1) {
      ALGCV_TRACE_ERR("Error writing to serial port: %s\n",
                      std::string(strerror(errno)).c_str());
      close(fd);
      return response;
    }

    // 等待响应（超时）
    const int max_attempts = 10;
    const int timeout_ms = 100;  // ms
    int attempts = 0;
    char buf[256];
    ssize_t bytes_read;

    while (attempts < max_attempts) {
      bytes_read = read(fd, buf, sizeof(buf) - 1);
      if (bytes_read > 0) {
        buf[bytes_read] = '\0';  // Null 终止缓冲区
        response += buf;
      } else if (bytes_read == -1 && errno != EAGAIN) {
        ALGCV_TRACE_ERR("Error reading from serial port: %s\n",
                        strerror(errno));

        // 重启串口
        m_serial->reset();

        // 重启后重新尝试读取响应
        fd = m_serial->getSerialFd();
        bytes_read = read(fd, buf, sizeof(buf) - 1);
        if (bytes_read > 0) {
          buf[bytes_read] = '\0';
          response += buf;
        } else {
          return response;
        }
      } else {
        std::this_thread::sleep_for(
            std::chrono::milliseconds(timeout_ms));  // 睡眠超时期
        attempts++;
      }
    }

    if (printResponse) {
      std::string cmd = command;
      cmd = cmd.erase(cmd.length() - 2);
      ALGCV_TRACE_INFO("%s%s", cmd.c_str(), response.c_str());
    }

    return response;
  }

 private:
  std::string m_iface = "usb0";
  std::string m_domain = "www.baidu.com";
  Serial* m_serial;
};

/* Http服务接口 */
class HTTPServer {
 public:
  HTTPServer(const std::string& serialPort, const speed_t& baudRate)
      : m_sim_info(SIM_INFO::GetInstance(serialPort, baudRate)) {}

  void start() {
    m_svr.Get(URL_PATH,
              [&](const httplib::Request& req, httplib::Response& res) {
                std::lock_guard<std::mutex> lock(m_mutex);
                std::string json =
                    "{"
                    "\"status\":" +
                    std::to_string(SIM_STATUS) +
                    ","
                    "\"type\":" +
                    std::to_string(TYPE) +
                    ","
                    "\"strength\":" +
                    std::to_string(STRENGTH) +
                    ","
                    "\"internet\":" +
                    std::to_string(INTERNET) + "}";
                res.set_content(json, "application/json");
              });

    std::thread(&HTTPServer::updateStatusVariables, this).detach();
    std::thread(&HTTPServer::printStatus, this).detach();
    ALGCV_TRACE_INFO("Server listening on port %d\n", PORT);
    bool success = m_svr.listen("0.0.0.0", PORT);
    if (!success) {
      ALGCV_TRACE_ERR("Error: Failed to start server on port %d\n", PORT);
    }
    ALGCV_TRACE_ERR("Server Stop\n");
  }

 private:
  [[noreturn]] void updateStatusVariables() {
    while (true) {
      int sim_status_tmp = m_sim_info->checkSIMStatus(false) ? 1 : 0;
      std::string type = m_sim_info->getNetworkType(false);
      int type_tmp = type == "4G" ? 1 : (type == "5G" ? 2 : 0);
      int strength_tmp = m_sim_info->getSignalStrength(false);
      int internet_tmp = m_sim_info->checkRegistrationStatus() ? 1 : 0;

      m_mutex.lock();
      SIM_STATUS = sim_status_tmp;
      TYPE = type_tmp;
      STRENGTH = strength_tmp;
      INTERNET = internet_tmp;
      m_mutex.unlock();

      std::this_thread::sleep_for(std::chrono::seconds(10));
    }
  }

  void printStatus() {
    m_mutex.lock();
    ALGCV_TRACE_INFO("STATUS = %d, TYPE = %d, STRENGTH = %d, INTERNET = %d\n",
                     SIM_STATUS, TYPE, STRENGTH, INTERNET);
    m_mutex.unlock();
    std::this_thread::sleep_for(std::chrono::minutes(10));
  }

 private:
  SIM_INFO* m_sim_info;
  httplib::Server m_svr;
  std::mutex m_mutex;
};

void help() {
  std::cout
      << "SIM_Manager_Linux_V1.0\n"
      << ":Usage: sim_manager [options]\n"
      << "-s [apn [user password auth]]       Set apn/user/password/auth get "
         "from your network provider. auth: 1~pap, 2~chap, 3~MsChapV2\n"
      << "-f log dir path                     Save log message of this program "
         "to file. The default dir path is /maicro/sim_manager/logs\n"
      << "[Examples]\n"
      << "Example 1: sim_manager\n"
      << "Example 2: sim_manager -s 3gnet\n"
      << "Example 3: sim_manager -s 3gnet carl 1234 1 -f "
         "/tmp/sim_manager_log\n";
}

int main(int argc, char* argv[]) {
  std::string logName = argv[0];
  // 默认日志文件路径
  std::string logFilePath = "/maicro/log";

  if (argc > 1 &&
      (std::string(argv[1]) == "-h" || std::string(argv[1]) == "-help")) {
    help();
    return 0;
  }

  // 处理命令行参数
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "-f" && i + 1 < argc) {
      logFilePath = argv[++i];
    } else if (arg == "-s") {
      // 检查是否有足够的参数
      if (i + 3 < argc) {
        // 有四个参数
        apnConfig.apn = argv[++i];
        apnConfig.user = argv[++i];
        apnConfig.password = argv[++i];
        apnConfig.auth = std::stoi(argv[++i]);
      } else if (i + 1 < argc) {
        // 只有一个参数
        apnConfig.apn = argv[++i];
      }
    }
  }
  // 设置日志文件路径
  InitLog(logName, logFilePath);
  ALGCV_TRACE_INFO("SIM Manager Run!\n");

  HTTPServer server(SERIALPORT, BAUDRATE);
  server.start();

  return 0;
}