#include <iostream>
#include <WINSOCK2.h>
#include <time.h>
#include <fstream>
#pragma warning(disable:4996)
#pragma comment(lib, "ws2_32.lib")
using namespace std;

#define PORT 1234
#define ADDRSRV "127.0.0.1"
const int MAXSIZE = 2048;//���仺������󳤶�
const u_short SYN = 0x1; //SYN = 1 ACK = 0
const u_short ACK = 0x2;//SYN = 0, ACK = 1
const u_short ACK_SYN = 0x3;//SYN = 1, ACK = 1
const u_short FIN = 0x4;//FIN = 1 ACK = 0
const u_short FIN_ACK = 0x5;//FIN = 1 ACK = 0
const u_short END = 0x7;//������־
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
    u_short sum = 0;//У���
    u_short datalen = 0;//���ݳ���
    u_short flag = 0;//��־λ 
    u_short SEQ = 0;//���к�
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

    //���յ�һ��������Ϣ
    while (1)
    {
        if (recvfrom(server, Buffer, sizeof(updhead), 0, (sockaddr*)&server_addr, &ClientAddrLen) != -1)
        {
            memcpy(&updhead, Buffer, sizeof(updhead));
            if (updhead.flag == SYN && cksum((u_short*)&updhead, sizeof(updhead)) == 0)
            {
                cout << "---***------  ���������յ���һ����������  ------***---" << endl;
                break;
            }
        }
    }

    //���͵ڶ���������Ϣ
    Buffer = pack(updhead, 0, ACK, 0);
    sendto(server, Buffer, sizeof(updhead), 0, (sockaddr*)&server_addr, ClientAddrLen);
    cout << "---***------      �������ѷ���ȷ�ϰ�      ------***---" << endl;
    clock_t time1 = clock();//��¼�ڶ������ַ���ʱ��

    //���յ���������
    while (1)
    {
        clock_t time2 = clock();
        if (time2 - time1 > MAX_TIME)
        {
            Buffer = pack(updhead, 0, ACK, 0);
            sendto(server, Buffer, sizeof(updhead), 0, (sockaddr*)&server_addr, ClientAddrLen);
            cout << "---***------        ��ʱ�ش�ȷ�ϰ�        ------***---" << endl;
        }
        if (recvfrom(server, Buffer, sizeof(updhead), 0, (sockaddr*)&server_addr, &ClientAddrLen) > 0)
        {
            UDPhead temp1;
            memcpy(&temp1, Buffer, sizeof(updhead));
            if (temp1.flag == ACK_SYN && cksum((u_short*)&temp1, sizeof(temp1) == 0))
            {
                cout << "---***------  ���������յ���������������  ------***---" << endl;
                cout << "---***------  �����ѽ������Խ����ļ�����  ------***---" << endl;
            }
            break;
        }
    }
    return true;
}

int Accept(SOCKET& sockServ, SOCKADDR_IN& ClientAddr, int& ClientAddrLen, char* message)
{
    long int len = 0;//�ļ�����
    UDPhead updhead;
    char* Buffer = new char[MAXSIZE + sizeof(updhead)];
    int seq = 0;
    int index = 0;

    while (1)
    {
        int length = recvfrom(sockServ, Buffer, sizeof(updhead) + MAXSIZE, 0, (sockaddr*)&ClientAddr, &ClientAddrLen);//���ձ��ĳ���
        memcpy(&updhead, Buffer, sizeof(updhead));
        
        //�жϽ�β
        if (updhead.flag == END && cksum((u_short*)&updhead, sizeof(updhead)) == 0)
        {
            cout << "---***------ ���յ����һ�����ݰ� ------***---" << endl;
            break;
        }

        //�����
        if (cksum((u_short*)Buffer, length) != 0)
        {
            cout << "---***------У����쳣���д����ش�------***---" << endl;
            while (1) {
                if (seq == int(updhead.SEQ) && cksum((u_short*)Buffer, length - sizeof(updhead))==0)
                {
                    break;
                }
            }
        }

        //ȷ���ش�
        if (updhead.flag == u_short(0) && cksum((u_short*)Buffer, length)==0)
        {
            //�ж����к��Ƿ���ȷ
            if (seq != int(updhead.SEQ))
            {
                Buffer = pack(updhead, 0, ACK, (u_short)seq);
                //�ط��ð���ACK
                sendto(sockServ, Buffer, sizeof(updhead), 0, (sockaddr*)&ClientAddr, ClientAddrLen);
                cout << "�ط�ACK:" << (int)updhead.SEQ << " SEQ:" << (int)updhead.SEQ << endl;
                continue;//���������ݰ�
            }
            seq = int(updhead.SEQ);
            if (seq > 255)
                seq = seq % 256;

            //�����־��¼
            cout << "->�յ����ݰ�,��СΪ" << length - sizeof(updhead) << " bytes! ��ʶ:" << int(updhead.flag) << " ���к� : " << int(updhead.SEQ) << " У��ͼ�����:" << cksum((u_short*)Buffer, length) << endl;
            
            //ƴ�����ݰ�
            char* temp = new char[length - sizeof(updhead)];
            memcpy(temp, Buffer + sizeof(updhead), length - sizeof(updhead));
            memcpy(message + len, temp, length - sizeof(updhead));
            len = len + int(updhead.datalen);

            //����ACK
            updhead.flag = ACK;
            updhead.datalen = 0;
            updhead.SEQ = (u_short)seq;
            updhead.sum = 0;
            u_short temp1 = cksum((u_short*)&updhead, sizeof(updhead));
            updhead.sum = temp1;
            memcpy(Buffer, &updhead, sizeof(updhead));

            //�ط��ð���ACK
            sendto(sockServ, Buffer, sizeof(updhead), 0, (sockaddr*)&ClientAddr, ClientAddrLen);
            cout << "->���ͻ�Ӧ�� ACK:" << (int)updhead.SEQ << "  ���к�:" << (int)updhead.SEQ << endl << endl;
            seq++;
            if (seq > 255)
                seq = seq % 256;
        }
    }
    //����END��Ϣ
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
        int length = recvfrom(sockServ, Buffer, sizeof(updhead) + MAXSIZE, 0, (sockaddr*)&ClientAddr, &ClientAddrLen);//���ձ��ĳ���
        memcpy(&updhead, Buffer, sizeof(updhead));
        if (updhead.flag == FIN && cksum((u_short*)&updhead, sizeof(updhead)) == 0)
        {
            cout << "---***------  ���������յ���һ�λ�������  ------***---" << endl;
            break;
        }
    }

    //���͵ڶ��λ�����Ϣ
    Buffer = pack(updhead, 0, ACK, 0);
    sendto(sockServ, Buffer, sizeof(updhead), 0, (sockaddr*)&ClientAddr, ClientAddrLen);
    cout << "---***------  ���������͵��ڶ��λ�������  ------***---" << endl;
    clock_t time1 = clock();//��¼�ڶ��λ��ַ���ʱ��

    //���յ����λ���
    while (recvfrom(sockServ, Buffer, sizeof(updhead), 0, (sockaddr*)&ClientAddr, &ClientAddrLen) <= 0)
    {
        if (clock() - time1 > MAX_TIME)
        {
            Buffer = pack(updhead, 0, ACK, 0);
            sendto(sockServ, Buffer, sizeof(updhead), 0, (sockaddr*)&ClientAddr, ClientAddrLen);
            cout << "---***------  �������ѷ��͵ڶ��λ�������  ------***---" << endl;
            cout << "�ڶ��λ��ֳ�ʱ�����ڽ����ش�" << endl;
        }
    }

    UDPhead temp1;
    memcpy(&temp1, Buffer, sizeof(updhead));
    if (temp1.flag == FIN_ACK && cksum((u_short*)&temp1, sizeof(temp1) == 0))
    {
        cout << "---***------  ���������յ������λ�������  ------***---" << endl;
    }
    else
        return -1;

    //���͵��Ĵλ�����Ϣ
    Buffer = pack(updhead, 0, FIN_ACK, 0);
    sendto(sockServ, Buffer, sizeof(updhead), 0, (sockaddr*)&ClientAddr, ClientAddrLen);
    cout << "---***------  �������ѷ��͵��Ĵλ�������  ------***---" << endl;
    return 1;
}


int main()
{
    WSADATA wsadata;
    WSAStartup(MAKEWORD(2, 2), &wsadata);

    SOCKADDR_IN server_addr;
    SOCKET server;

    server_addr.sin_family = AF_INET;//ʹ��IPV4
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr(ADDRSRV);


    server = socket(AF_INET, SOCK_DGRAM, 0);
    bind(server, (SOCKADDR*)&server_addr, sizeof(server_addr));//���׽��֣��������״̬
    cout << "�����������ɹ�������" << endl;


    int len = sizeof(server_addr);
    //��������
    if(handshake(server, server_addr)==true);
    {
        cout << "���ӳɹ�" << endl;
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
    cout << "�յ����ļ�����Ϊ�� " << file << endl;
    dishandshake(server, server_addr, len);
    ofstream fout;
    fout.open(file.c_str(), ofstream::binary);
    for (int i = 0; i < datalen; i++)
    {
        fout << data[i];
    }
    fout.close();
    cout << "�ѳɹ������ļ�" << endl;
}