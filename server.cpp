#include <iostream>
#include <WINSOCK2.h>
#include <time.h>
#include <fstream>
#pragma warning(disable:4996)
#pragma comment(lib, "ws2_32.lib")
using namespace std;

#define PORT 1234
#define ADDRSRV "127.0.0.1"
const int MAXSIZE = 2048;//传输缓冲区最大长度
const u_short SYN = 0x1; //SYN = 1 ACK = 0
const u_short ACK = 0x2;//SYN = 0, ACK = 1
const u_short ACK_SYN = 0x3;//SYN = 1, ACK = 1
const u_short FIN = 0x4;//FIN = 1 ACK = 0
const u_short FIN_ACK = 0x5;//FIN = 1 ACK = 0
const u_short END = 0x7;//结束标志
double MAX_TIME = CLOCKS_PER_SEC;



u_short cksum(u_short* mes, int size) {
    int count = (size + 1) / 2;
    u_short* buf = (u_short*)malloc(size + 1);
    memset(buf, 0, size + 1);
    memcpy(buf, mes, size);
    u_long sum = 0;
    while (count--) {
        sum += *buf++;
        if (sum & 0xffff0000) {
            sum &= 0xffff;
            sum++;
        }
    }
    return ~(sum & 0xffff);
}

struct UDPhead
{
    u_short sum = 0;//校验和
    u_short datalen = 0;//数据长度
    u_short flag = 0;//标志位 
    u_short SEQ = 0;//序列号
};

char* pack(UDPhead updhead, u_short datalen, u_short flag, u_short SEQ) {
    char* Buffer = new char[sizeof(updhead)];
    updhead.flag = flag;
    updhead.datalen = datalen;
    updhead.SEQ = SEQ;
    updhead.sum = 0;
    u_short Sum = cksum((u_short*)&updhead, sizeof(updhead));
    updhead.sum = Sum;
    memcpy(Buffer, &updhead, sizeof(updhead));
    return Buffer;
}

bool handshake(SOCKET& server, SOCKADDR_IN& server_addr)
{ 
    UDPhead updhead;
    int ClientAddrLen = sizeof(server_addr);
    char* Buffer = new char[sizeof(updhead)];

    //接收第一次握手信息
    while (1)
    {
        if (recvfrom(server, Buffer, sizeof(updhead), 0, (sockaddr*)&server_addr, &ClientAddrLen) != -1)
        {
            memcpy(&updhead, Buffer, sizeof(updhead));
            if (updhead.flag == SYN && cksum((u_short*)&updhead, sizeof(updhead)) == 0)
            {
                cout << "---***------  服务器接收到第一次握手请求  ------***---" << endl;
                break;
            }
        }
    }

    //发送第二次握手信息
    Buffer = pack(updhead, 0, ACK, 0);
    sendto(server, Buffer, sizeof(updhead), 0, (sockaddr*)&server_addr, ClientAddrLen);
    cout << "---***------      服务器已发送确认包      ------***---" << endl;
    clock_t time1 = clock();//记录第二次握手发送时间

    //接收第三次握手
    while (1)
    {
        clock_t time2 = clock();
        if (time2 - time1 > MAX_TIME)
        {
            Buffer = pack(updhead, 0, ACK, 0);
            sendto(server, Buffer, sizeof(updhead), 0, (sockaddr*)&server_addr, ClientAddrLen);
            cout << "---***------        超时重传确认包        ------***---" << endl;
        }
        if (recvfrom(server, Buffer, sizeof(updhead), 0, (sockaddr*)&server_addr, &ClientAddrLen) > 0)
        {
            UDPhead temp1;
            memcpy(&temp1, Buffer, sizeof(updhead));
            if (temp1.flag == ACK_SYN && cksum((u_short*)&temp1, sizeof(temp1) == 0))
            {
                cout << "---***------  服务器接收到第三次握手请求  ------***---" << endl;
                cout << "---***------  连接已建立可以进行文件传输  ------***---" << endl;
            }
            break;
        }
    }
    return true;
}

int Accept(SOCKET& sockServ, SOCKADDR_IN& ClientAddr, int& ClientAddrLen, char* message)
{
    long int len = 0;//文件长度
    UDPhead updhead;
    char* Buffer = new char[MAXSIZE + sizeof(updhead)];
    int seq = 0;
    int index = 0;

    while (1)
    {
        int length = recvfrom(sockServ, Buffer, sizeof(updhead) + MAXSIZE, 0, (sockaddr*)&ClientAddr, &ClientAddrLen);//接收报文长度
        memcpy(&updhead, Buffer, sizeof(updhead));
        
        //判断结尾
        if (updhead.flag == END && cksum((u_short*)&updhead, sizeof(updhead)) == 0)
        {
            cout << "---***------ 已收到最后一个数据包 ------***---" << endl;
            break;
        }

        //差错检测
        if (cksum((u_short*)Buffer, length) != 0)
        {
            cout << "---***------校验和异常进行错误重传------***---" << endl;
            while (1) {
                if (seq == int(updhead.SEQ) && cksum((u_short*)Buffer, length - sizeof(updhead))==0)
                {
                    break;
                }
            }
        }

        //确认重传
        if (updhead.flag == u_short(0) && cksum((u_short*)Buffer, length)==0)
        {
            //判断序列号是否正确
            if (seq != int(updhead.SEQ))
            {
                Buffer = pack(updhead, 0, ACK, (u_short)seq);
                //重发该包的ACK
                sendto(sockServ, Buffer, sizeof(updhead), 0, (sockaddr*)&ClientAddr, ClientAddrLen);
                cout << "重发ACK:" << (int)updhead.SEQ << " SEQ:" << (int)updhead.SEQ << endl;
                continue;//丢弃该数据包
            }
            seq = int(updhead.SEQ);
            if (seq > 255)
                seq = seq % 256;

            //输出日志记录
            cout << "->收到数据包,大小为" << length - sizeof(updhead) << " bytes! 标识:" << int(updhead.flag) << " 序列号 : " << int(updhead.SEQ) << " 校验和计算结果:" << cksum((u_short*)Buffer, length) << endl;
            
            //拼接数据包
            char* temp = new char[length - sizeof(updhead)];
            memcpy(temp, Buffer + sizeof(updhead), length - sizeof(updhead));
            memcpy(message + len, temp, length - sizeof(updhead));
            len = len + int(updhead.datalen);

            //返回ACK
            updhead.flag = ACK;
            updhead.datalen = 0;
            updhead.SEQ = (u_short)seq;
            updhead.sum = 0;
            u_short temp1 = cksum((u_short*)&updhead, sizeof(updhead));
            updhead.sum = temp1;
            memcpy(Buffer, &updhead, sizeof(updhead));

            //重发该包的ACK
            sendto(sockServ, Buffer, sizeof(updhead), 0, (sockaddr*)&ClientAddr, ClientAddrLen);
            cout << "->发送回应的 ACK:" << (int)updhead.SEQ << "  序列号:" << (int)updhead.SEQ << endl << endl;
            seq++;
            if (seq > 255)
                seq = seq % 256;
        }
    }
    //发送END信息
    Buffer = pack(updhead, 0, END, 0);
    sendto(sockServ, Buffer, sizeof(updhead), 0, (sockaddr*)&ClientAddr, ClientAddrLen);
    return len;
}

int dishandshake(SOCKET& sockServ, SOCKADDR_IN& ClientAddr, int& ClientAddrLen)
{
    UDPhead updhead;
    char* Buffer = new char[sizeof(updhead)];
    while (1)
    {
        int length = recvfrom(sockServ, Buffer, sizeof(updhead) + MAXSIZE, 0, (sockaddr*)&ClientAddr, &ClientAddrLen);//接收报文长度
        memcpy(&updhead, Buffer, sizeof(updhead));
        if (updhead.flag == FIN && cksum((u_short*)&updhead, sizeof(updhead)) == 0)
        {
            cout << "---***------  服务器接收到第一次挥手请求  ------***---" << endl;
            break;
        }
    }

    //发送第二次挥手信息
    Buffer = pack(updhead, 0, ACK, 0);
    sendto(sockServ, Buffer, sizeof(updhead), 0, (sockaddr*)&ClientAddr, ClientAddrLen);
    cout << "---***------  服务器发送到第二次挥手请求  ------***---" << endl;
    clock_t time1 = clock();//记录第二次挥手发送时间

    //接收第三次挥手
    while (recvfrom(sockServ, Buffer, sizeof(updhead), 0, (sockaddr*)&ClientAddr, &ClientAddrLen) <= 0)
    {
        if (clock() - time1 > MAX_TIME)
        {
            Buffer = pack(updhead, 0, ACK, 0);
            sendto(sockServ, Buffer, sizeof(updhead), 0, (sockaddr*)&ClientAddr, ClientAddrLen);
            cout << "---***------  服务器已发送第二次挥手请求  ------***---" << endl;
            cout << "第二次挥手超时，正在进行重传" << endl;
        }
    }

    UDPhead temp1;
    memcpy(&temp1, Buffer, sizeof(updhead));
    if (temp1.flag == FIN_ACK && cksum((u_short*)&temp1, sizeof(temp1) == 0))
    {
        cout << "---***------  服务器接收到第三次挥手请求  ------***---" << endl;
    }
    else
        return -1;

    //发送第四次挥手信息
    Buffer = pack(updhead, 0, FIN_ACK, 0);
    sendto(sockServ, Buffer, sizeof(updhead), 0, (sockaddr*)&ClientAddr, ClientAddrLen);
    cout << "---***------  服务器已发送第四次挥手请求  ------***---" << endl;
    return 1;
}


int main()
{
    WSADATA wsadata;
    WSAStartup(MAKEWORD(2, 2), &wsadata);

    SOCKADDR_IN server_addr;
    SOCKET server;

    server_addr.sin_family = AF_INET;//使用IPV4
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr(ADDRSRV);


    server = socket(AF_INET, SOCK_DGRAM, 0);
    bind(server, (SOCKADDR*)&server_addr, sizeof(server_addr));//绑定套接字，进入监听状态
    cout << "服务器启动成功！！！" << endl;


    int len = sizeof(server_addr);
    //建立连接
    if(handshake(server, server_addr)==true);
    {
        cout << "连接成功" << endl;
    }


    char* name = new char[20];
    char* data = new char[1000000000];
    int namelen = Accept(server, server_addr, len, name);
    int datalen = Accept(server, server_addr, len, data);


    string file;
    for (int i = 0; i < namelen; i++)
    {
        file = file + name[i];
    }
    cout << "收到的文件名称为： " << file << endl;
    dishandshake(server, server_addr, len);
    ofstream fout;
    fout.open(file.c_str(), ofstream::binary);
    for (int i = 0; i < datalen; i++)
    {
        fout << data[i];
    }
    fout.close();
    cout << "已成功接收文件" << endl;
}
