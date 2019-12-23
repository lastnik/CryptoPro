#include "mainwindow.h"
#include <QApplication>
#include <cpcsp/CSP_WinCrypt.h>
#include <cpcsp/WinCryptEx.h>
#include <pki/cades.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <wincspc.h>
#include <wincsp.h>
#include <WinCryptEx.h>
#include <CSP_WinCrypt.h>
#include <CSP_WinDef.h>
#include <CSP_WinBase.h>
#include <QtGlobal>
/*
static void HandleError(char *s)
{
    qWarning(s);
}
static void CleanUp(void);

static HCRYPTPROV  hProv = 0;         // Дескриптор CSP
static LPTSTR      pszName = NULL;
static LPTSTR      pbProvName = NULL;

int main(void)
{

    //--------------------------------------------------------------------
    //  Объявление и инициализация переменных.


    DWORD       dwType;
    DWORD       cbName;
    DWORD       dwIndex = 0;
    BYTE        *ptr = NULL;
    ALG_ID      aiAlgid;
    DWORD       dwBits;
    DWORD       dwNameLen;
    CHAR        szName[1000000]; // Распределены динамически
    BYTE        pbData[1024];// Распределены динамически
    DWORD       cbData=1024;
    DWORD       dwIncrement = sizeof(DWORD);
    DWORD       dwFlags = CRYPT_FIRST;
    CHAR        *pszAlgType = NULL;
    BOOL        fMore = TRUE;
    DWORD       cbProvName;

    //   Печать заголовка перечисления типов провайдеров.
    printf("\n          Listing Available Provider Types.\n");
    printf("Provider type      Provider Type Name\n");
    printf("_____________    _____________________________________\n");

    // Цикл по перечисляемым типам провайдеров.
    dwIndex = 0;
    while(CryptEnumProviderTypes(
        dwIndex,     // in -- dwIndex
        NULL,        // in -- pdwReserved- устанавливается в NULL
        0,           // in -- dwFlags -- устанавливается в ноль
        &dwType,     // out -- pdwProvType
        NULL,        // out -- pszProvName -- NULL при первом вызове
        &cbName      // in, out -- pcbProvName
        ))
    {
        //  cbName - длина имени следующего типа провайдера.
        //  Распределение памяти в буфере для восстановления этого имени.
        pszName = (LPTSTR)malloc(cbName);
        if(!pszName)
            HandleError("ERROR - malloc failed!");

        memset(pszName, 0, cbName);

        //--------------------------------------------------------------------
        //  Получение имени типа провайдера.

        if(CryptEnumProviderTypes(
            dwIndex++,
            NULL,
            0,
            &dwType,
            pszName,
            &cbName))
        {
            printf ("     %4.0d        %s\n",dwType, pszName);
        }
        else
        {
            HandleError("ERROR - CryptEnumProviders");
        }
    }

    //   Печать заголовка перечисления провайдеров.
    printf("\n\n          Listing Available Providers.\n");
    printf("Provider type      Provider Name\n");
    printf("_____________    _____________________________________\n");

    // Цикл по перечисляемым провайдерам.
    dwIndex = 0;
    while(CryptEnumProviders(
        dwIndex,     // in -- dwIndex
        NULL,        // in -- pdwReserved- устанавливается в NULL
        0,           // in -- dwFlags -- устанавливается в ноль
        &dwType,     // out -- pdwProvType
        NULL,        // out -- pszProvName -- NULL при первом вызове
        &cbName      // in, out -- pcbProvName
        ))
    {
        //  cbName - длина имени следующего провайдера.
        //  Распределение памяти в буфере для восстановления этого имени.
        pszName = (LPTSTR)malloc(cbName);
        if(!pszName)
            HandleError("ERROR - malloc failed!");

        memset(pszName, 0, cbName);

        //  Получение имени провайдера.
        if(CryptEnumProviders(
            dwIndex++,
            NULL,
            0,
            &dwType,
            pszName,
            &cbName     // pcbProvName -- длина pszName
            ))
        {
            printf ("     %4.0d        %s\n",dwType, pszName);
        }
        else
        {
            HandleError("ERROR - CryptEnumProviders");
        }

    } // Конец цикла while

    printf("\n\nProvider types and provider names have been listed.\n");

    // Получение имени CSP, определенного для компьютера по умолчанию.

    // Получение длины имени провайдера по умолчанию.
    if(!CryptGetDefaultProvider(
        PROV_GOST_2012_256,
        NULL,
        CRYPT_MACHINE_DEFAULT,
        NULL,
        &cbProvName))
    {
        HandleError("Error getting the length of the default provider name.");
    }

    // Распределение локальной памяти под имя провайдера по умолчанию.

    pbProvName = (LPTSTR)malloc(cbProvName);
    if(!pbProvName)
        HandleError("Error during memory allocation for provider name.");

    memset(pbProvName, 0, cbProvName);

    // Получение имени провайдера по умолчанию.
    if(CryptGetDefaultProvider(
        PROV_GOST_2012_256,
        NULL,
        CRYPT_MACHINE_DEFAULT,
        pbProvName,
        &cbProvName))
    {
        printf("The default provider name is %s\n\n",pbProvName);
    }
    else
    {
        HandleError("Getting the name of the provider failed.");
    }

    //-----------------------------------------------------
    //  Получение криптографического контекста.

    if(!CryptAcquireContext(
        &hProv,
        NULL,
        NULL,
        PROV_GOST_2012_256,
        CRYPT_VERIFYCONTEXT))
    {
        HandleError("Error during CryptAcquireContext!");
    }

    //------------------------------------------------------
    // Перечисление поддерживаемых алгоритмов.

    //------------------------------------------------------
    // Печать заголовка таблицы, содержащей информацию об алгоритмах
    printf("\n               Enumerating the supported algorithms\n\n");
    printf("     Algid      Bits      Type        Name         Algorithm\n");
    printf("                                     Length          Name\n");
    printf("    ________________________________________________________\n");

    while(fMore)
    {
        //------------------------------------------------------
        // Извлечение информации об алгоритме.

        if(CryptGetProvParam(hProv, PP_ENUMALGS, pbData, &cbData, dwFlags))
        {
            //-----------------------------------------------------------
            // Извлечение информации об алгоритме из буфера 'pbData'.

            dwFlags=0;
            ptr = pbData;
            aiAlgid = *(ALG_ID *)ptr;
            ptr += sizeof(ALG_ID);
            dwBits = *(DWORD *)ptr;
            ptr += dwIncrement;
            dwNameLen = *(DWORD *)ptr;
            ptr += dwIncrement;
            //strncpy_s(szName, NAME_LENGTH, (char *) ptr, dwNameLen);
            strncpy(szName, (char *) ptr, dwNameLen);
            // Определение типа алгоритма.

            switch(GET_ALG_CLASS(aiAlgid)) {
                case ALG_CLASS_DATA_ENCRYPT: pszAlgType = "Encrypt  ";
                    break;
                case ALG_CLASS_HASH:         pszAlgType = "Hash     ";
                    break;
                case ALG_CLASS_KEY_EXCHANGE: pszAlgType = "Exchange ";
                    break;
                case ALG_CLASS_SIGNATURE:    pszAlgType = "Signature";
                    break;
                default:                     pszAlgType = "Unknown  ";
            }

            // Печать информации об алгоритме.
            printf("    %8.8xh    %-4d    %s     %-2d          %s\n",
                aiAlgid, dwBits, pszAlgType, dwNameLen, szName);
        }
        else
            fMore = FALSE;
    }

    if(GetLastError() == ERROR_NO_MORE_ITEMS)
    {
        printf("\nThe program completed without error.\n");
    }
    else
    {
        HandleError("Error reading algorithm!");
    }

    CleanUp();
    return 0;
}

void CleanUp(void)
{
    // Освобождение дескриптора провайдера.
    if(hProv)
        CryptReleaseContext(hProv, 0);
    if(pszName)
        free(pszName);
    if(pbProvName)
        free(pbProvName);
}
*/
int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();

    return a.exec();
}

