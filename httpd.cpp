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
#include <queue>
#include <memory>
#include <sys/select.h>
#include <errno.h>
#include <mutex>
#include <netdb.h>

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
    string client_ip;
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

// 访问规则结构体
struct AccessRule {
    bool allow;
    string target;
};

struct ConnectionState{
	int fd;
	string read_buffer;
	queue<HTTPRequest> request_queue;
	bool keep_alive;
	time_t last_activity;
    string client_ip;

	ConnectionState(int socketfd, string ip):fd(socketfd),keep_alive(true),last_activity(time(nullptr)),client_ip(ip){}
};

class HTTPServer {
private:
    unsigned short port;
    string doc_root;
    int server_fd;

	const int CONNECTION_TIMEOUT = 5;

    map<int, string> status_messages = {
        {200, "OK"},
        {400, "Bad Request"},
        {403, "Forbidden"},
        {404, "Not Found"},
        {500, "Internal Server Error"}
    };

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

	map<int,shared_ptr<ConnectionState>> connections;
	mutex Connections_mutex;

public:
    HTTPServer(unsigned short p, const string& root) : port(p), doc_root(root) {}

    bool initialize() {
        server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd < 0) {
            cerr << "Failed to create socket: " << strerror(errno) << endl;
            return false;
        }

        int opt = 1;
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
            cerr << "Failed to set socket options: " << strerror(errno) << endl;
            close(server_fd);
            return false;
        }

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

        if (listen(server_fd, 10) < 0) {
            cerr << "Failed to listen on socket: " << strerror(errno) << endl;
            close(server_fd);
            return false;
        }

        cout << "Server listening on port " << port << endl;
        cout << "Document root: " << doc_root << endl;
        cout << "HTTP/1.1 Pipelining: ENABLED" << endl;
        cout << "IP-based Access Control: ENABLED" << endl;
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

            string client_ip = inet_ntoa(client_addr.sin_addr);

            thread client_thread(&HTTPServer::handle_pipelined_client, this, client_fd, client_ip);
            client_thread.detach();
        }
    }

    ~HTTPServer() {
        if (server_fd >= 0) {
            close(server_fd);
        }
    }

private:
    void handle_pipelined_client(int client_fd, string client_ip) {
        auto conn_state = make_shared<ConnectionState> (client_fd, client_ip);

        {
            lock_guard<mutex> lock(Connections_mutex);
            connections[client_fd] = conn_state;
        }

        char buffer[8192] = {0};
        bool connection_alive = true;

        while(connection_alive){
            struct timeval timeout;
            timeout.tv_sec = CONNECTION_TIMEOUT;
            timeout.tv_usec = 0;

            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(client_fd,&read_fds);

            int activity = select(client_fd+1,&read_fds,NULL,NULL,&timeout);

            if(activity<0&&errno != EINTR){
                cerr<<"Select error:"<<strerror(errno)<<endl;
                break;
            }

            if(activity==0){
                cout<<"Connection timeout: "<<client_fd<<endl;
                break;
            }

            if(FD_ISSET(client_fd,&read_fds)){
                ssize_t bytes_read = read(client_fd,buffer,sizeof(buffer)-1);
                if(bytes_read<=0){
                    connection_alive = false;
                    break;
                }

                buffer[bytes_read] = '\0';
                conn_state -> read_buffer.append(buffer,bytes_read);
                conn_state -> last_activity = time(nullptr);

                parse_requests(conn_state);

                while(!conn_state->request_queue.empty()){
                    HTTPRequest request = conn_state ->request_queue.front();
                    conn_state -> request_queue.pop();

                    request.client_ip = conn_state->client_ip;

                    if(request.headers.find("Connection")!=request.headers.end()){
                        string connection_value = request.headers["Connection"];

                        for (char& c : connection_value){
                            c = tolower(c);
                        }
                        if(connection_value == "close"){
                            conn_state ->keep_alive = false;
                        }
                    }

                    HTTPResponse response = process_request(request);

                    if (conn_state->keep_alive){
                        response.headers["Connection"] = "keep-alive";
                    }else{
                        response.headers["Connection"] = "close";
                    }

                    send_response(client_fd,response);
                }

                if (!conn_state->keep_alive){
                    connection_alive = false;
                }
            }
        }
        
        {
            lock_guard<mutex> lock(Connections_mutex);
            connections.erase(client_fd);
        }
        close(client_fd);
        cout<<"Connection closed: "<<client_fd<<endl;
    }

    void parse_requests(shared_ptr<ConnectionState> conn_state){
        size_t pos = 0;

        while(pos <conn_state->read_buffer.length()){
            size_t header_end = conn_state->read_buffer.find("\r\n\r\n",pos);
            if(header_end == string::npos){
                break;
            }

            size_t request_end = header_end + 4;
            string request_str = conn_state->read_buffer.substr(pos,request_end - pos);
            HTTPRequest request = parse_request(request_str);

            conn_state->request_queue.push(request);
            pos = request_end;
        }

        if(pos > 0){
            conn_state ->read_buffer.erase(0,pos);
        }
    }

    HTTPRequest parse_request(const string& request_data) {
        HTTPRequest request;
        istringstream stream(request_data);
        string line;
        
        if (getline(stream, line)) {
            istringstream line_stream(line);
            line_stream >> request.method >> request.url >> request.version;
            
            if (!request.version.empty() && request.version.back() == '\r') {
                request.version.pop_back();
            }
        }

        while (getline(stream, line) && line != "\r" && !line.empty()) {
            size_t colon_pos = line.find(':');
            if (colon_pos != string::npos) {
                string key = line.substr(0, colon_pos);
                string value = line.substr(colon_pos + 1);
                
                key.erase(0, key.find_first_not_of(" \t"));
                key.erase(key.find_last_not_of(" \t\r") + 1);
                value.erase(0, value.find_first_not_of(" \t"));
                value.erase(value.find_last_not_of(" \t\r") + 1);
                
                request.headers[key] = value;
            }
        }

        return request;
    }

    // 修复的访问控制检查函数
    bool check_access_control(const string& file_path, const string& client_ip) {
        cout << "Checking access control for: " << file_path << " from IP: " << client_ip << endl;
        
        // 获取文件所在目录
        string dir_path = get_directory_path(file_path);
        string htaccess_path = dir_path + "/.htaccess";
        
        cout << "Looking for .htaccess at: " << htaccess_path << endl;
        
        // 检查.htaccess文件是否存在
        struct stat st;
        if (stat(htaccess_path.c_str(), &st) != 0) {
            // 文件不存在，默认允许访问
            cout << "No .htaccess file found, allowing access" << endl;
            return true;
        }
        
        if (!S_ISREG(st.st_mode)) {
            // 不是常规文件，默认允许
            cout << ".htaccess is not a regular file, allowing access" << endl;
            return true;
        }
        
        // 读取.htaccess文件
        ifstream htaccess_file(htaccess_path);
        if (!htaccess_file.is_open()) {
            cerr << "Failed to open .htaccess file: " << htaccess_path << " (error: " << strerror(errno) << ")" << endl;
            return true; // 如果无法读取，默认允许
        }
        
        vector<AccessRule> rules;
        string line;
        
        // 解析规则
        while (getline(htaccess_file, line)) {
            // 跳过空行和注释
            if (line.empty() || line[0] == '#') {
                continue;
            }
            
            istringstream line_stream(line);
            string action, from, target;
            line_stream >> action >> from >> target;
            
            if (from != "from" || (action != "allow" && action != "deny")) {
                cerr << "Invalid rule in .htaccess: " << line << endl;
                continue;
            }
            
            AccessRule rule;
            rule.allow = (action == "allow");
            rule.target = target;
            rules.push_back(rule);
            cout << "Loaded rule: " << (rule.allow ? "allow" : "deny") << " from " << rule.target << endl;
        }
        
        htaccess_file.close();
        
        // 如果没有规则，默认允许
        if (rules.empty()) {
            cout << "No rules in .htaccess, allowing access" << endl;
            return true;
        }
        
        // 按顺序应用规则
        for (const auto& rule : rules) {
            if (match_ip_rule(client_ip, rule.target)) {
                cout << "Rule matched: " << (rule.allow ? "ALLOW" : "DENY") << " from " << rule.target << endl;
                return rule.allow;
            }
        }
        
        // 如果没有匹配的规则，默认拒绝
        cout << "No rules matched, default DENY" << endl;
        return false;
    }
    
    // 获取目录路径的辅助函数
    string get_directory_path(const string& file_path) {
        size_t last_slash = file_path.find_last_of('/');
        if (last_slash == string::npos) {
            return doc_root;
        }
        return file_path.substr(0, last_slash);
    }
    
    bool match_ip_rule(const string& client_ip, const string& rule_target) {
        // 特殊处理：0.0.0.0/0 匹配所有
        if (rule_target == "0.0.0.0/0") {
            return true;
        }
        
        // 检查是否是CIDR格式
        size_t slash_pos = rule_target.find('/');
        if (slash_pos != string::npos) {
            // CIDR格式
            string network_str = rule_target.substr(0, slash_pos);
            string prefix_len_str = rule_target.substr(slash_pos + 1);
            
            int prefix_len;
            try {
                prefix_len = stoi(prefix_len_str);
            } catch (const exception& e) {
                cerr << "Invalid prefix length in CIDR: " << rule_target << endl;
                return false;
            }
            
            if (prefix_len < 0 || prefix_len > 32) {
                cerr << "Invalid prefix length: " << prefix_len << endl;
                return false;
            }
            
            // 转换IP地址为整数
            struct in_addr client_addr, network_addr;
            if (inet_pton(AF_INET, client_ip.c_str(), &client_addr) != 1 ||
                inet_pton(AF_INET, network_str.c_str(), &network_addr) != 1) {
                return false;
            }
            
            // 计算掩码
            uint32_t mask = (prefix_len == 0) ? 0 : ~((1U << (32 - prefix_len)) - 1);
            mask = htonl(mask);
            
            // 比较网络地址
            return (client_addr.s_addr & mask) == (network_addr.s_addr & mask);
        } else {
            // 具体IP或主机名
            struct in_addr ip_addr;
            if (inet_pton(AF_INET, rule_target.c_str(), &ip_addr) == 1) {
                // 具体IP
                return client_ip == rule_target;
            } else {
                // 尝试解析主机名
                struct hostent* host = gethostbyname(rule_target.c_str());
                if (host == nullptr) {
                    return false;
                }
                
                for (int i = 0; host->h_addr_list[i] != nullptr; i++) {
                    char* ip_str = inet_ntoa(*(struct in_addr*)host->h_addr_list[i]);
                    if (client_ip == string(ip_str)) {
                        return true;
                    }
                }
                
                return false;
            }
        }
    }

    HTTPResponse process_request(const HTTPRequest& request) {
        HTTPResponse response;
        
        if (request.method != "GET") {
            return create_error_response(400, "Only GET method is supported");
        }

        if (request.headers.find("Host") == request.headers.end()) {
            return create_error_response(400, "Host header is required");
        }

        string url = request.url;
        if (url == "/") {
            url = "/index.html";
        }

        string file_path = map_url_to_path(url);
        if (file_path.empty()) {
            return create_error_response(404, "File not found or path traversal attempt detected");
        }

        cout << "Processing request for: " << file_path << endl;

        // 检查访问控制
        bool access_allowed = check_access_control(file_path, request.client_ip);
        if (!access_allowed) {
            cerr << "Access denied for IP " << request.client_ip << " to " << file_path << endl;
            return create_error_response(403, "Access denied by .htaccess rules");
        }

        struct stat file_stat;
        if (stat(file_path.c_str(), &file_stat) < 0) {
            if (errno == ENOENT) {
                return create_error_response(404, "File not found");
            } else {
                return create_error_response(500, "Internal server error while accessing file");
            }
        }

        if (S_ISDIR(file_stat.st_mode)) {
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

        response.status_code = 200;
        response.status_message = status_messages[200];
        response.file_path = file_path;
        response.send_file = true;
        
        response.headers["Server"] = "TritonHTTP/1.0";
        response.headers["Last-Modified"] = format_time(file_stat.st_mtime);
        
        string content_type = get_content_type(file_path);
        if (!content_type.empty()) {
            response.headers["Content-Type"] = content_type;
        }
        
        response.headers["Content-Length"] = to_string(file_stat.st_size);

        return response;
    }

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

    void send_response(int client_fd, const HTTPResponse& response) {
        string response_str;
        
        response_str = "HTTP/1.1 " + to_string(response.status_code) + " " +
                      response.status_message + "\r\n";
        
        for (const auto& header : response.headers) {
            response_str += header.first + ": " + header.second + "\r\n";
        }
        
        response_str += "\r\n";
        
        ssize_t sent = send(client_fd, response_str.c_str(), response_str.length(), 0);
        if (sent < 0) {
            cerr << "Failed to send response headers: " << strerror(errno) << endl;
            return;
        }
        
        if (response.send_file && response.status_code == 200 && !response.file_path.empty()) {
            send_file(client_fd, response.file_path);
        } else if (!response.body.empty()) {
            sent = send(client_fd, response.body.c_str(), response.body.length(), 0);
            if (sent < 0) {
                cerr << "Failed to send response body: " << strerror(errno) << endl;
            }
        }
    }

    string map_url_to_path(const string& url) {
        size_t pos = 0;
        string normalized_url = url;
        
        while ((pos = normalized_url.find("/../")) != string::npos) {
            if (pos == 0) {
                return "";
            }
            size_t prev_slash = normalized_url.rfind('/', pos - 1);
            if (prev_slash == string::npos) {
                return "";
            }
            normalized_url.erase(prev_slash, pos - prev_slash + 3);
        }
        
        if (normalized_url.find("../") == 0) {
            return "";
        }
        
        string path = doc_root + normalized_url;
        return path;
    }

    string get_content_type(const string& file_path) {
        size_t dot_pos = file_path.find_last_of('.');
        if (dot_pos == string::npos) {
            return "application/octet-stream";
        }
        
        string extension = file_path.substr(dot_pos);
        string extension_lower = extension;
        transform(extension_lower.begin(), extension_lower.end(), extension_lower.begin(), ::tolower);
        
        auto it = content_types.find(extension_lower);
        if (it != content_types.end()) {
            return it->second;
        }
        
        return "application/octet-stream";
    }

    void send_file(int client_fd, const string& file_path) {
        int file_fd = open(file_path.c_str(), O_RDONLY);
        if (file_fd < 0) {
            cerr << "Failed to open file: " << strerror(errno) << endl;
            return;
        }
        
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