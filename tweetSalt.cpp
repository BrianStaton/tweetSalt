extern "C"
{
#include "tweetnacl.h"
#include "naclSupport.h"
}

#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <getopt.h>
#include <pthread.h>
#include <libgen.h>
#include <set>

#include <errno.h>
#include <netdb.h>
#include <ifaddrs.h>

#include <sys/ioctl.h>
#include <net/if.h>

const char *VERSION_STRING="1.0.2";
const char *DATE_STRING="03-SEP-2019";

#define MAX_MSG_LEN (512)

uint8_t serverPublickey[crypto_box_PUBLICKEYBYTES];
uint8_t serverSecretkey[crypto_box_SECRETKEYBYTES];
uint8_t clientPublickey[crypto_box_PUBLICKEYBYTES];
uint8_t clientSecretkey[crypto_box_SECRETKEYBYTES];

bool serverKeyRxFlag = false;
bool clientKeyRxFlag = false;

typedef enum
{
    NA_MSG_CODE             =   0
    , KEY_EXCHANGE_MSG_CODE =   1
    , DATA_MSG_CODE         =   2
    , CLEAR_TEXT_MSG_CODE   =   3
    , CYPHER_TEXT_MSG_CODE  =   4
}   msgCode_t;

#pragma pack(push, 1)
typedef struct
{
    uint8_t     msgCode;
    uint8_t     pk[crypto_box_PUBLICKEYBYTES];
}   keyExchangeMsg_t;

typedef struct
{
    uint8_t     msgCode;
    uint32_t    x;
}   dataMsg_t;

typedef struct
{
    uint8_t     msgCode;
    uint32_t    dateLen;
    uint8_t     nonce[crypto_box_NONCEBYTES];
    char        s[MAX_MSG_LEN];
}   textMsg_t;
#pragma pack(pop)

typedef struct
{
    uint16_t rxPort;
    uint16_t txPort;
    bool verboseFlag;
    bool serverMode;
}   RxArgs_t;

int doTx(in_addr_t ipAddr, uint16_t txPort, const void *msg, size_t msgLen)
{
    struct sockaddr_in addr;
    int addrlen, cnt;
    static int sock = -1;

    /* set up socket */
    if (sock < 0)
    {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
    }
    if (sock < 0)
    {
        perror("socket");
        return 1;
    }
    bzero((char *)&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addrlen = sizeof(addr);

    addr.sin_port = htons(txPort);
    addr.sin_addr.s_addr = ipAddr;

    printf("sending: %d bytes msgCode=%d\n", (int)msgLen, ((dataMsg_t *)(msg))->msgCode);
    cnt = sendto(sock, msg, msgLen, 0,
                 (struct sockaddr *) &addr, addrlen);
    if (cnt < 0)
    {
        perror("sendto");
        return 1;
    }
    return 0;
}

void processServerModeRxMsg(RxArgs_t *theArgs, in_addr_t ipAddr, char *msg)
{
    dataMsg_t *pDataMsg = (dataMsg_t *)msg;
    keyExchangeMsg_t *pKeyExchangeMsg = (keyExchangeMsg_t *)msg;
    textMsg_t *pTextMsg = (textMsg_t *)msg;
    char* decryptedMsg;

    msgCode_t rxCode = (msgCode_t)(pDataMsg->msgCode);

    switch (rxCode)
    {
        case KEY_EXCHANGE_MSG_CODE:
            memcpy(clientPublickey, pKeyExchangeMsg->pk, sizeof(clientPublickey));
            crypto_box_keypair(serverPublickey, serverSecretkey);
            keyExchangeMsg_t serverKeyMsg;
            serverKeyMsg.msgCode = KEY_EXCHANGE_MSG_CODE;
            memcpy(&serverKeyMsg.pk, serverPublickey, sizeof(serverKeyMsg.pk));
            doTx(ipAddr, theArgs->txPort, &serverKeyMsg, sizeof(serverKeyMsg));
            break;

        case DATA_MSG_CODE:
            if (theArgs->verboseFlag)
            {
                printf("rx data %d\n", pDataMsg->x);
            }
            dataMsg_t serverDataMsg;
            serverDataMsg.msgCode = DATA_MSG_CODE;
            serverDataMsg.x = pDataMsg->x + 1;
            doTx(ipAddr, theArgs->txPort, &serverDataMsg, sizeof(serverDataMsg));
            break;

        case CLEAR_TEXT_MSG_CODE:
            printf("rx: %s\n", &(pTextMsg->s[crypto_box_ZEROBYTES]));
            break;

        case CYPHER_TEXT_MSG_CODE:
            decryptedMsg = (char *)malloc(pTextMsg->dateLen);
            if  (0 ==   crypto_box_open    (   (uint8_t *)decryptedMsg
                                                    , (const uint8_t *)(pTextMsg->s)
                                                    , pTextMsg->dateLen
                                                    , (const uint8_t *)(pTextMsg->nonce)
                                                    , clientPublickey
                                                    , serverSecretkey
                                                )
                )
            {
                printf("rx: %s\n", (char *)(&decryptedMsg[crypto_box_ZEROBYTES]));
            }
            else
            {
                fprintf(stderr, "forgery\n");
            }
            free(decryptedMsg);
            break;

        default:
            break;
    }
}

void processClientModeRxMsg(RxArgs_t *theArgs, in_addr_t ipAddr, char *msg)
{
    dataMsg_t *pDataMsg = (dataMsg_t *)msg;
    keyExchangeMsg_t *pKeyExchangeMsg = (keyExchangeMsg_t *)msg;
    msgCode_t rxCode = (msgCode_t)(pDataMsg->msgCode);

    switch (rxCode)
    {
        case KEY_EXCHANGE_MSG_CODE:
            memcpy(serverPublickey, pKeyExchangeMsg->pk, sizeof(serverPublickey));
            serverKeyRxFlag = true;
            break;

        case DATA_MSG_CODE:
            if (theArgs->verboseFlag)
            {
                printf("rx data %d\n", pDataMsg->x);
            }
            break;
        default:
            break;
    }
}

int doRx(RxArgs_t *theArgs)
{
    struct sockaddr_in addr;
    int addrlen, sock, cnt;
    uint32_t val = 1;
    char message[2048];
    dataMsg_t *pDataMsg = (dataMsg_t *)message;

    /* set up socket */
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("socket");
        return 1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                   &val, sizeof(val)) < 0)
    {
        perror("setsockopt reuse");
        return 1;
    }

    bzero((char *)&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addrlen = sizeof(addr);

    /* receive */
    addr.sin_port = htons(theArgs->rxPort);

    if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0)
    {
        perror("bind");
        return 1;
    }

    while (1)
    {
        memset(message, 0, sizeof(message));
        cnt = recvfrom(sock, message, sizeof(message), 0,
                       (struct sockaddr *) &addr, (socklen_t *) &addrlen);
        if (cnt < 0)
        {
            perror("recvfrom");
            return 1;
        }
        else if (cnt == 0)
        {
            break;
        }

        msgCode_t rxCode = (msgCode_t)(pDataMsg->msgCode);

        if (theArgs->verboseFlag)
        {
            printf("received %s:%d(%d): msgCode = %d\n", inet_ntoa(addr.sin_addr), theArgs->rxPort, cnt, (int)rxCode);
        }

        fflush(stdout);

        if (theArgs->serverMode)
        {
            processServerModeRxMsg(theArgs, addr.sin_addr.s_addr, message);
        }
        else
        {
            processClientModeRxMsg(theArgs, addr.sin_addr.s_addr, message);
        }
    }
    return 0;
}

void *rxHandler(void *arg)
{
    RxArgs_t *pTheArgs = (RxArgs_t *)(arg);
    doRx(pTheArgs);
    return NULL;
}

void sendClientKeys(in_addr_t serverAddr, uint16_t txPort, bool verboseFlag)
{
    keyExchangeMsg_t clientKeyMsg;
    clientKeyMsg.msgCode = KEY_EXCHANGE_MSG_CODE;
    crypto_box_keypair(clientPublickey, clientSecretkey);
    memcpy(&clientKeyMsg.pk, clientPublickey, sizeof(clientKeyMsg.pk));

    if (verboseFlag)
    {
        printf("Sending client keys\n");
    }
    doTx(serverAddr, txPort, &clientKeyMsg, sizeof(clientKeyMsg));
}

void sendTOD(in_addr_t ipAddr, uint16_t txPort, bool encryptFlag, bool verboseFlag)
{
    char clearText[128];
    time_t t = time(0);
    struct tm *pTm = gmtime(&t);
    textMsg_t textMsg;

    memset(clearText, 0, sizeof(clearText));
    strftime(&(clearText[crypto_box_ZEROBYTES]), sizeof(clearText), "%F %T", pTm);
    size_t msgLen = strlen((char *)(&clearText[crypto_box_ZEROBYTES])) + 1;
    size_t paddedMsgLen = msgLen + crypto_box_ZEROBYTES;

    textMsg.dateLen = paddedMsgLen;

    if (verboseFlag)
    {
        printf("Sending: \"%s\"%sEncrypted\n"
               ,&(clearText[crypto_box_ZEROBYTES])
               ,(encryptFlag) ? " " : " NOT "
              );
    }

    if (encryptFlag)
    {
        textMsg.msgCode = CYPHER_TEXT_MSG_CODE;
        randombytes_buf(textMsg.nonce, crypto_box_NONCEBYTES);
        if  (0 != crypto_box   (   (uint8_t *)(textMsg.s)
                                        , (const uint8_t *)clearText
                                        , paddedMsgLen
                                        , textMsg.nonce
                                        , serverPublickey
                                        , clientSecretkey
                                    )
            )
        {
            /* error */
            fprintf(stderr, "encrypt error\n");
            return;
        }
    }
    else
    {
        textMsg.msgCode = CLEAR_TEXT_MSG_CODE;
        memcpy(textMsg.s, clearText, textMsg.dateLen);
        strcpy(textMsg.s, clearText);
    }

    doTx(ipAddr, txPort, &textMsg, sizeof(textMsg) - sizeof(textMsg.s) + textMsg.dateLen);
}

void myIp(const char *intf, char *ipAddr)
{
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, intf, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    /* display result */
    sprintf(ipAddr, "%s", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
}
void usage(const char *prog, const char *extraLine = (const char *)(NULL));

void usage(const char *prog, const char *extraLine)
{
    fprintf(stderr, "usage: %s <options>\n", prog);
    fprintf(stderr, "-c --client serveraddr:port   Client mode talking to server:port\n");
    fprintf(stderr, "-r --rxport receivePort       Client mode receive port\n");
    fprintf(stderr, "-s --server receivePort       Server mode and port on which to receive\n");
    fprintf(stderr, "-t --txport transmitPort      Port for transmit. Usually used for server reply\n");
    fprintf(stderr, "-e --encrypt                  Client only sends encrypted messages\n");
    fprintf(stderr, "-i --interface ethernetIntf   Local ethernet interface in use\n");
    fprintf(stderr, "--verbose                     Verbose printout\n");
    if (extraLine) fprintf(stderr, "\n%s\n", extraLine);
}

int main(int argc, char *argv[])
{
    int opt;
    bool usageError = false;
    bool clientMode = false;
    bool serverMode = false;
    bool encryptOnly = false;
    char ipAddr[16];
    in_addr_t serverAddr;
    uint16_t rxPort = 0;
    uint16_t txPort = 0;
    char *cp;
    RxArgs_t rxArgs;
    pthread_t rxThread;
    struct in_addr addr;
    char selfIpAddr[16];
    char ethernetInterface[16];

    strcpy(ethernetInterface, "eth0");

    printf("%s v%s %s\n", basename(argv[0]), VERSION_STRING, DATE_STRING);

    rxArgs.verboseFlag = true;
    ipAddr[0] = '\0';

    struct option longOptions[] =
    {
//        {"rx",          no_argument,        0,      'r'}
//        ,{"receive",    no_argument,        0,      'r'}
//        ,{"tx",         required_argument,  0,      't'}
//        ,{"transmit",   required_argument,  0,      't'}
//        ,{"multicast",  no_argument,        0,      'm'}
//        ,{"timeOffset", required_argument,  0,      'o'}
        {"client",      required_argument,  0,      'c'}
        ,{"server",     required_argument,  0,      's'}
        ,{"rxport",     required_argument,  0,      'r'}
        ,{"txport",     required_argument,  0,      't'}
        ,{"encrypt",    no_argument,        0,      'e'}
        ,{"interface",  required_argument,  0,      'i'}
        ,{"help",       no_argument,        0,      'h'}
        ,{"version",    no_argument,        0,      129}
        ,{"verbose",    no_argument,        0,      130}
        ,{0,0,0,0}
    };

    while (1)
    {
        int optionIndex = 0;

        opt = getopt_long(argc, argv, "c:r:t:s:i:eh?", longOptions, &optionIndex);

        if (-1 == opt) break;

        switch (opt)
        {
            case 'c':
                cp = strchr(optarg, ':');
                if (cp)
                {
                    *cp = '\0';
                    strcpy(ipAddr, optarg);
                    txPort = (uint16_t)(strtoul(cp+1, NULL, 10));
                    clientMode = true;
                    serverMode = false;
                }
                else
                {
                    strcpy(ipAddr, optarg);
                }
                break;
            case 's':
                serverMode = true;
                clientMode = false;
                rxPort = (uint16_t)strtoul(optarg, NULL, 10);
                break;
            case 'r':
                rxPort = (uint16_t)strtoul(optarg, NULL, 10);
                break;
            case 't':
                txPort = (uint16_t)strtoul(optarg, NULL, 10);
                break;
            case 'e':
                encryptOnly = true;
                break;
            case 'i':
                strcpy(ethernetInterface, optarg);
                break;
            case 129:
                // Just print version string
                return 0;
                break;
            case 130:
                rxArgs.verboseFlag = true;
                break;
            case 'h':
            case '?':
            default:
                usageError = true;
                break;
        }
    }

    #if 0
    clientMode = true;
    strcpy(ipAddr, "192.168.50.125");
    rxPort = 50002;
    txPort = 50001;
    encryptOnly = true;
    #elif 0
    serverMode = true;
    strcpy(ethernetInterface, "wlan0");
    rxPort = 50001;
    txPort = 50002;
    #endif // 0

    if  (   (usageError)
            || (   (clientMode)
                   && ('\0' == ipAddr[0])
               )
            || (0 == rxPort)
            || (0 == txPort)
            || (   (!clientMode)
                   && (!serverMode)
               )
        )
    {
        usage(basename(argv[0]));
        return -1;
    }

    printf("Creating RX thread on port %d\n",  rxPort);
    rxArgs.rxPort = rxPort;
    rxArgs.txPort = txPort;
    rxArgs.serverMode = serverMode;
    rxThread = pthread_create(&rxThread, NULL, rxHandler, (void *)(&(rxArgs)));

    serverAddr = inet_addr(ipAddr);
    if (clientMode)
    {
        addr.s_addr = serverAddr;
        printf("Client mode: Talking to %s:%d\n", inet_ntoa(addr),  txPort);
    }
    else
    {
        myIp(ethernetInterface, selfIpAddr);
        printf("Server mode: %s:%d\n", selfIpAddr, rxPort);
    }

    while (true)
    {
        //pthread_join(rxThread[numThreads], &res);
        sleep(1);
        if (clientMode)
        {
            if (serverKeyRxFlag)
            {
                if (!encryptOnly)
                {
                    sendTOD(serverAddr, txPort, false, rxArgs.verboseFlag);
                }
                sendTOD(serverAddr, txPort, true, rxArgs.verboseFlag);
            }
            else
            {
                sendClientKeys(serverAddr, txPort, rxArgs.verboseFlag);
            }

        }
    }

    return 0;
}

