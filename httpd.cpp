#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <map>
#include <vector>
#include <thread>
#include <algorithm>
#include <system_error>

// 平台特定的头文件
#ifdef __APPLE__
#include <sys/uio.h>
#else
#include <sys/sendfile.h>
#endif

#include "httpd.h"

using namespace std;

// HTTP请求结构体
struct HTTPRequest {
    string method;
    string url;
    string version;
    map<string, string> headers;
    string body;
};

// HTTP响应结构体
struct HTTPResponse {
    int status_code;
    string status_message;
    map<string, string> headers;
    string body;
    string file_path;
    bool send_file;
};

class HTTPServer {
private:
    unsigned short port;
    string doc_root;
    int server_fd;

    // HTTP状态码映射
    map<int, string> status_messages = {
        {200, "OK"},
        {400, "Bad Request"},
        {403, "Forbidden"},
        {404, "Not Found"},
        {500, "Internal Server Error"}
    };

    // 文件类型映射
    map<string, string> content_types = {
        {".html", "text/html"},
        {".htm", "text/html"},
        {".jpg", "image/jpeg"},
        {".jpeg", "image/jpeg"},
        {".png", "image/png"},
        {".txt", "text/plain"},
        {".css", "text/css"},
        {".js", "application/javascript"},
        {".ico", "image/x-icon"}
    };

public:
    HTTPServer(unsigned short p, const string& root) : port(p), doc_root(root) {}

    bool initialize() {
        // 创建socket
        server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd < 0) {
            cerr << "Failed to create socket: " << strerror(errno) << endl;
            return false;
        }

        // 设置socket选项
        int opt = 1;
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
            cerr << "Failed to set socket options: " << strerror(errno) << endl;
            close(server_fd);
            return false;
        }

        // 绑定地址
        struct sockaddr_in address;
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port);

        if (::bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
            cerr << "Failed to bind socket: " << strerror(errno) << endl;
            close(server_fd);
            return false;
        }

        // 开始监听
        if (listen(server_fd, 10) < 0) {
            cerr << "Failed to listen on socket: " << strerror(errno) << endl;
            close(server_fd);
            return false;
        }

        cout << "Server listening on port " << port << endl;
        cout << "Document root: " << doc_root << endl;
        return true;
    }

    void run() {
        while (true) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            
            int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
            if (client_fd < 0) {
                cerr << "Failed to accept connection: " << strerror(errno) << endl;
                continue;
            }

            // 为每个连接创建新线程
            thread client_thread(&HTTPServer::handle_client, this, client_fd);
            client_thread.detach();
        }
    }

    ~HTTPServer() {
        if (server_fd >= 0) {
            close(server_fd);
        }
    }

private:
    void handle_client(int client_fd) {
        char buffer[8192] = {0};
        
        // 读取请求（组帧阶段）
        ssize_t bytes_read = read(client_fd, buffer, sizeof(buffer) - 1);
        if (bytes_read <= 0) {
            close(client_fd);
            return;
        }

        try {
            // 解析请求
            HTTPRequest request = parse_request(string(buffer, bytes_read));
            
            // 处理请求并生成响应
            HTTPResponse response = process_request(request);
            
            // 发送响应（组帧阶段）
            send_response(client_fd, response);
        } catch (const exception& e) {
            cerr << "Error handling client request: " << e.what() << endl;
            // 发送500错误响应
            HTTPResponse error_response = create_error_response(500, "Internal Server Error");
            send_response(client_fd, error_response);
        }
        
        close(client_fd);
    }

    // 解析HTTP请求（解析阶段）
    HTTPRequest parse_request(const string& request_data) {
        HTTPRequest request;
        istringstream stream(request_data);
        string line;
        
        // 解析请求行
        if (getline(stream, line)) {
            istringstream line_stream(line);
            line_stream >> request.method >> request.url >> request.version;
            
            // 移除可能的CR字符
            if (!request.version.empty() && request.version.back() == '\r') {
                request.version.pop_back();
            }
        }

        // 解析头部
        while (getline(stream, line) && line != "\r" && !line.empty()) {
            size_t colon_pos = line.find(':');
            if (colon_pos != string::npos) {
                string key = line.substr(0, colon_pos);
                string value = line.substr(colon_pos + 1);
                
                // 移除首尾空白字符和CR
                key.erase(0, key.find_first_not_of(" \t"));
                key.erase(key.find_last_not_of(" \t\r") + 1);
                value.erase(0, value.find_first_not_of(" \t"));
                value.erase(value.find_last_not_of(" \t\r") + 1);
                
                request.headers[key] = value;
            }
        }

        return request;
    }

    // 处理HTTP请求
    HTTPResponse process_request(const HTTPRequest& request) {
        HTTPResponse response;
        
        // 检查方法
        if (request.method != "GET") {
            return create_error_response(400, "Only GET method is supported");
        }

        // 检查Host头部
        if (request.headers.find("Host") == request.headers.end()) {
            return create_error_response(400, "Host header is required");
        }

        // 处理url
        string url = request.url;
        if (url == "/") {
            url = "/index.html";
        }

        // 构建文件路径并检查安全性
        string file_path = map_url_to_path(url);
        if (file_path.empty()) {
            return create_error_response(404, "File not found or path traversal attempt detected");
        }

        // 检查文件是否存在和权限
        struct stat file_stat;
        if (stat(file_path.c_str(), &file_stat) < 0) {
            if (errno == ENOENT) {
                return create_error_response(404, "File not found");
            } else {
                return create_error_response(500, "Internal server error while accessing file");
            }
        }

        if (S_ISDIR(file_stat.st_mode)) {
            // 如果是目录，尝试查找index.html
            string index_path = file_path;
            if (index_path.back() != '/') {
                index_path += "/";
            }
            index_path += "index.html";
            
            if (stat(index_path.c_str(), &file_stat) == 0 && !S_ISDIR(file_stat.st_mode)) {
                file_path = index_path;
            } else {
                return create_error_response(404, "Directory index not found");
            }
        }

        if (!S_ISREG(file_stat.st_mode)) {
            return create_error_response(404, "Requested path is not a file");
        }

        if (access(file_path.c_str(), R_OK) < 0) {
            return create_error_response(403, "Permission denied");
        }

        // 成功找到文件
        response.status_code = 200;
        response.status_message = status_messages[200];
        response.file_path = file_path;
        response.send_file = true;
        
        // 设置响应头部
        response.headers["Server"] = "TritonHTTP/1.0";
        response.headers["Last-Modified"] = format_time(file_stat.st_mtime);
        
        // 设置Content-Type
        string content_type = get_content_type(file_path);
        if (!content_type.empty()) {
            response.headers["Content-Type"] = content_type;
        }
        
        response.headers["Content-Length"] = to_string(file_stat.st_size);

        return response;
    }

    // 创建错误响应
    HTTPResponse create_error_response(int status_code, const string& message) {
        HTTPResponse response;
        response.status_code = status_code;
        response.status_message = status_messages[status_code];
        response.body = "<html><body><h1>" + to_string(status_code) + " " + 
                       status_messages[status_code] + "</h1><p>" + message + "</p></body></html>";
        response.send_file = false;
        
        response.headers["Server"] = "TritonHTTP/1.0";
        response.headers["Content-Type"] = "text/html";
        response.headers["Content-Length"] = to_string(response.body.length());
        
        return response;
    }

    // 发送HTTP响应
    void send_response(int client_fd, const HTTPResponse& response) {
        string response_str;
        
        // 构建状态行
        response_str = "HTTP/1.1 " + to_string(response.status_code) + " " +
                      response.status_message + "\r\n";
        
        // 添加头部
        for (const auto& header : response.headers) {
            response_str += header.first + ": " + header.second + "\r\n";
        }
        
        // 空行分隔头部和正文
        response_str += "\r\n";
        
        // 发送头部
        ssize_t sent = send(client_fd, response_str.c_str(), response_str.length(), 0);
        if (sent < 0) {
            cerr << "Failed to send response headers: " << strerror(errno) << endl;
            return;
        }
        
        // 如果是200响应且需要发送文件，发送文件内容
        if (response.send_file && response.status_code == 200 && !response.file_path.empty()) {
            send_file(client_fd, response.file_path);
        } else if (!response.body.empty()) {
            // 发送错误消息正文
            sent = send(client_fd, response.body.c_str(), response.body.length(), 0);
            if (sent < 0) {
                cerr << "Failed to send response body: " << strerror(errno) << endl;
            }
        }
    }

    // 将相对url映射到绝对文件路径
    string map_url_to_path(const string& url) {
        // 安全检查：防止路径遍历攻击
        size_t pos = 0;
        string normalized_url = url;
        
        // 移除所有的 "../"
        while ((pos = normalized_url.find("/../")) != string::npos) {
            if (pos == 0) {
                // 试图跳出根目录
                return "";
            }
            // 找到前一个斜杠
            size_t prev_slash = normalized_url.rfind('/', pos - 1);
            if (prev_slash == string::npos) {
                return "";
            }
            normalized_url.erase(prev_slash, pos - prev_slash + 3);
        }
        
        // 检查开头的 ".."
        if (normalized_url.find("../") == 0) {
            return "";
        }
        
        string path = doc_root + normalized_url;
        return path;
    }

    // 获取文件的内容类型
    string get_content_type(const string& file_path) {
        size_t dot_pos = file_path.find_last_of('.');
        if (dot_pos == string::npos) {
            return "application/octet-stream";
        }
        
        string extension = file_path.substr(dot_pos);
        // 转换为小写进行比较
        string extension_lower = extension;
        transform(extension_lower.begin(), extension_lower.end(), extension_lower.begin(), ::tolower);
        
        auto it = content_types.find(extension_lower);
        if (it != content_types.end()) {
            return it->second;
        }
        
        return "application/octet-stream";
    }

    // 跨平台文件发送函数
    void send_file(int client_fd, const string& file_path) {
        int file_fd = open(file_path.c_str(), O_RDONLY);
        if (file_fd < 0) {
            cerr << "Failed to open file: " << strerror(errno) << endl;
            return;
        }
        
        // 使用通用的read/write方法发送文件，确保跨平台兼容性
        char buffer[8192];
        ssize_t bytes_read;
        
        while ((bytes_read = read(file_fd, buffer, sizeof(buffer))) > 0) {
            ssize_t bytes_written = write(client_fd, buffer, bytes_read);
            if (bytes_written < 0) {
                cerr << "Failed to write to socket: " << strerror(errno) << endl;
                break;
            }
        }
        
        close(file_fd);
    }

    // 格式化时间（用于Last-Modified头部）
    string format_time(time_t time_val) {
        struct tm* tm_info = gmtime(&time_val);
        if (!tm_info) {
            return "";
        }
        
        char buffer[30];
        strftime(buffer, sizeof(buffer), "%a, %d %b %Y %H:%M:%S GMT", tm_info);
        return string(buffer);
    }
};

void start_httpd(unsigned short port, string doc_root)
{
    cerr << "Starting server (port: " << port <<
        ", doc_root: " << doc_root << ")" << endl;

    // 检查文档根目录是否存在且可访问
    struct stat stat_buf;
    if (stat(doc_root.c_str(), &stat_buf) != 0 || !S_ISDIR(stat_buf.st_mode)) {
        cerr << "Document root does not exist or is not a directory: " << doc_root << endl;
        return;
    }

    HTTPServer server(port, doc_root);
    
    if (!server.initialize()) {
        cerr << "Failed to initialize server" << endl;
        return;
    }

    server.run();
}