#include <iostream>
#include <WINSOCK2.h>
#include <time.h>
#include <fstream>
#pragma comment(lib, "ws2_32.lib")
using namespace std;

#pragma warning(disable:4996)
#define PORT 1234
#define ADDRSRV "127.0.0.1"
const int MAXSIZE = 2048;//传输缓冲区最大长度
const u_short SYN = 0x1; // ACK、SYN = 01
const u_short ACK = 0x2;//ACK、SYN = 10
const u_short ACK_SYN = 0x3;//ACK、SYN = 11
const u_short FIN = 0x4;//FIN、ACK、SYN = 100
const u_short FIN_ACK = 0x5;//FIN = 1 ACK = 0
const u_short END = 0x7;//结束
double MAX_TIME = CLOCKS_PER_SEC;

u_short cksum(u_short* data, int size) {
    int count = (size + 1) / 2;
    u_short* buf = (u_short*)malloc(size + 1);
    memset(buf, 0, size + 1);
    memcpy(buf, data, size);
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

bool handshake(SOCKET& server, SOCKADDR_IN& server_addr)//三次握手建立连接
{
    int adlen = sizeof(server_addr);
    UDPhead updhead;
    char* Buffer = new char[sizeof(updhead)];
    u_short sum;

    
    //第一次握手
    Buffer = pack(updhead, 0, SYN, 0);
    sendto(server, Buffer, sizeof(updhead), 0, (sockaddr*)&server_addr, adlen);
    cout << "---***------    客户端第一次握手已发送    ------***---" << endl;
    clock_t time1 = clock(); //记录发送第一次握手时间

    //设置非阻塞模式
    u_long mode = 1;
    ioctlsocket(server, FIONBIO, &mode);

    //接收第二次握手
    while (recvfrom(server, Buffer, sizeof(updhead), 0, (sockaddr*)&server_addr, &adlen) <= 0)
    {
        if (clock() - time1 > MAX_TIME)//超时，重新传输第一次握手
        {
            Buffer = pack(updhead, 0, SYN, 0);
            sendto(server, Buffer, sizeof(updhead), 0, (sockaddr*)&server_addr, adlen);
            time1 = clock();
            cout << "---***------    第一次握手超时需要重传    ------***---" << endl;
        }
    }


    //进行校验和检验
    memcpy(&updhead, Buffer, sizeof(updhead));
    if (updhead.flag == ACK && cksum((u_short*)&updhead, sizeof(updhead) == 0))
    {
        cout << "---***------    成功收到服务器第二次握手  ------***---" << endl;
    }
    else
    {
        cout << "连接错误" << endl;
        return -1;
    }

    //进行第三次握手
    Buffer = pack(updhead, 0, ACK_SYN, 0);
    sendto(server, (char*)&updhead, sizeof(updhead), 0, (sockaddr*)&server_addr, adlen);
    cout << "---***------    客户端第三次握手已发送    ------***---" << endl;
    return true;
}


void send_package(SOCKET& server, SOCKADDR_IN& server_addr, int& adlen, char* data, int len, int& order)
{
    //打包数据包
    UDPhead updhead;
    char* buffer = new char[MAXSIZE + sizeof(updhead)];
    updhead.datalen = len;
    updhead.SEQ = unsigned char(order);//序列号
    memcpy(buffer, &updhead, sizeof(updhead));
    memcpy(buffer + sizeof(updhead), data, sizeof(updhead) + len);

    //计算校验和
    u_short check = cksum((u_short*)buffer, sizeof(updhead) + len);
    updhead.sum = check;
    memcpy(buffer, &updhead, sizeof(updhead));

    
    //发送给服务器端
    sendto(server, buffer, len + sizeof(updhead), 0, (sockaddr*)&server_addr, adlen);

    //日志信息输出
    cout << "->发送数据大小为： " << len << " bytes " << " 标志位：" << int(updhead.flag) << " 序列号:" << int(updhead.SEQ) << " 校验和:" << int(updhead.sum) << endl;
    clock_t time = clock();//记录发送时间
    //接收ack等信息
   
    while (1)
    {
        u_long mode = 1;
        //非阻塞模式
        ioctlsocket(server, FIONBIO, &mode);


        while (recvfrom(server, buffer, MAXSIZE, 0, (sockaddr*)&server_addr, &adlen) <= 0)
        {
            if (clock() - time > MAX_TIME)
            {
                updhead.datalen = len;
                updhead.SEQ = u_short(order);//序列号
                updhead.flag = u_short(0x0);
                memcpy(buffer, &updhead, sizeof(updhead));
                memcpy(buffer + sizeof(updhead), data, sizeof(updhead) + len);
                u_short check = cksum((u_short*)buffer, sizeof(updhead) + len);//计算校验和
                updhead.sum = check;
                memcpy(buffer, &updhead, sizeof(updhead));
                sendto(server, buffer, len + sizeof(updhead), 0, (sockaddr*)&server_addr, adlen);//发送
                cout << "超时重传数据： " << len << " bytes! 标志位:" << int(updhead.flag) << " 序列号:" << int(updhead.SEQ) << endl;
                clock_t start = clock();//记录发送时间
            }
        }
        memcpy(&updhead, buffer, sizeof(updhead));//缓冲区接收到信息，读取
        u_short check = cksum((u_short*)&updhead, sizeof(updhead));
        if (updhead.SEQ == u_short(order) && updhead.flag == ACK)
        {
            cout << "->收到服务器端确认  标志位:" << int(updhead.flag) << " 序列号:" << int(updhead.SEQ) << endl << endl;
            break;
        }
        else
            continue;
    }
    //阻塞模式
    u_long mode = 0;
    ioctlsocket(server, FIONBIO, &mode);
}

void upload(SOCKET& server, SOCKADDR_IN& server_addr, int& adlen, char* data, int len)
{
    int packagenum = len / MAXSIZE + (len % MAXSIZE != 0);
    int seqnum = 0;
    for (int i = 0; i < packagenum; i++)
    {
        send_package(server, server_addr, adlen, data + i * MAXSIZE, i == packagenum - 1 ? len - (packagenum - 1) * MAXSIZE : MAXSIZE, seqnum);
        seqnum++;
        if (seqnum > 255)
        {
            seqnum = seqnum - 256;
        }
    }
    //发送结束信息
    UDPhead updhead;
    char* Buffer = new char[sizeof(updhead)];
    updhead.flag = END;
    updhead.sum = 0;
    u_short temp = cksum((u_short*)&updhead, sizeof(updhead));
    updhead.sum = temp;
    memcpy(Buffer, &updhead, sizeof(updhead));
    sendto(server, Buffer, sizeof(updhead), 0, (sockaddr*)&server_addr, adlen);
    cout << "---***------       文件传输已结束       ------***---" << endl;
    clock_t start = clock();
    while (1)
    {
        u_long mode = 1;
        ioctlsocket(server, FIONBIO, &mode);
        memcpy(&updhead, Buffer, sizeof(updhead));//缓冲区接收到信息，读取
        u_short check = cksum((u_short*)&updhead, sizeof(updhead));
        if (updhead.flag == END)
        {
            cout << "---***------     文件成功发送给服务器     ------***---" << endl << endl;
            break;
        }
        else
        {
            continue;
        }
    }
    u_long mode = 0;
    ioctlsocket(server, FIONBIO, &mode);//改回阻塞模式
}



int dishandshake(SOCKET& server, SOCKADDR_IN& server_addr, int& adlen)
{
    UDPhead updhead;
    char* Buffer = new char[sizeof(updhead)];

    u_short sum;

    //进行第一次握手
    updhead.flag = FIN;
    updhead.sum = 0;//校验和置0
    u_short temp = cksum((u_short*)&updhead, sizeof(updhead));
    updhead.sum = temp;//计算校验和
    memcpy(Buffer, &updhead, sizeof(updhead));//将首部放入缓冲区
    if (sendto(server, Buffer, sizeof(updhead), 0, (sockaddr*)&server_addr, adlen) == -1)
    {
        return -1;
    }
    clock_t start = clock(); //记录发送第一次挥手时间

    u_long mode = 1;
    ioctlsocket(server, FIONBIO, &mode);

    //接收第二次挥手
    while (recvfrom(server, Buffer, sizeof(updhead), 0, (sockaddr*)&server_addr, &adlen) <= 0)
    {
        if (clock() - start > MAX_TIME)//超时，重新传输第一次挥手
        {
            updhead.flag = FIN;
            updhead.sum = 0;//校验和置0
            updhead.sum = cksum((u_short*)&updhead, sizeof(updhead));//计算校验和
            memcpy(Buffer, &updhead, sizeof(updhead));//将首部放入缓冲区
            sendto(server, Buffer, sizeof(updhead), 0, (sockaddr*)&server_addr, adlen);
            start = clock();
            cout << "第一次挥手超时，正在进行重传" << endl;
        }
    }


    //进行校验和检验
    memcpy(&updhead, Buffer, sizeof(updhead));
    if (cksum((u_short*)&updhead, sizeof(updhead) == 0))
    {
        cout << "收到第二次挥手信息" << endl;
    }
    else
    {
        cout << "连接发生错误，程序直接退出！" << endl;
        return -1;
    }

    //进行第三次挥手
    updhead.flag = FIN_ACK;
    updhead.sum = 0;
    updhead.sum = cksum((u_short*)&updhead, sizeof(updhead));//计算校验和
    if (sendto(server, (char*)&updhead, sizeof(updhead), 0, (sockaddr*)&server_addr, adlen) == -1)
    {
        return -1;
    }

    start = clock();
    //接收第四次挥手
    while (recvfrom(server, Buffer, sizeof(updhead), 0, (sockaddr*)&server_addr, &adlen) <= 0)
    {
        if (clock() - start > MAX_TIME)//超时，重新传输第三次挥手
        {
            updhead.flag = FIN;
            updhead.sum = 0;//校验和置0
            updhead.sum = cksum((u_short*)&updhead, sizeof(updhead));//计算校验和
            memcpy(Buffer, &updhead, sizeof(updhead));//将首部放入缓冲区
            sendto(server, Buffer, sizeof(updhead), 0, (sockaddr*)&server_addr, adlen);
            start = clock();
            cout << "第四次握手超时，正在进行重传" << endl;
        }
    }
    cout << "---***------  四次挥手结束，连接断开  ------***---" << endl;
    return 1;
}


int main()
{
    WSADATA wsadata;
    WSAStartup(MAKEWORD(2, 2), &wsadata);

    SOCKADDR_IN server_addr;
    SOCKET server;

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr(ADDRSRV);

    server = socket(AF_INET, SOCK_DGRAM, 0);
    int len = sizeof(server_addr);

    //建立连接
    handshake(server, server_addr);

    const char* file1= "1.jpg";
    const char* file2 = "2.jpg";
    const char* file3 = "3.jpg";
    const char* file4 = "helloworld.txt";
    string file;
    file = file1;
    int select = 0;
    cout << "---***------       请选择要发送的文件     ------***---" << endl;
    cin >> select;
    switch (select)
    {
    case(1):
        file = file1;
        break;
    case(2):
        file = file2;
        break;
    case(3):
        file = file3;
        break;
    case(4):
        file = file4;
        break;
    default:
        break;
    }

    //以二进制方式打开文件，利用ifstream类的构造函数创建一个文件输入流对象，c_str()把string类型变量转换成char*变量
    ifstream fin;
    fin.open(file.c_str(), ifstream::binary);
    
    //缓冲区
    char* buffer = new char[1000000000];
    int seq = 0;

    //从文件中读取一个字符，并把读取的字符保存在temp中
    unsigned char temp = fin.get();
    while (fin)
    {
        buffer[seq++] = temp;
        temp = fin.get();
    }
    fin.close();
    upload(server, server_addr, len, (char*)(file.c_str()), file.length());
    clock_t start = clock();
    upload(server, server_addr, len, buffer, seq);
    clock_t end = clock();
    cout << "传输时间为:" << (end - start) / CLOCKS_PER_SEC << "s" << endl;
    dishandshake(server, server_addr, len);
}
