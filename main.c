#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/cmac.h>

#define NEXT_BYTE char2hex(fgetc(fp))
#define START_BYTE fgetc(fp)
#define NEW_LINE    printf("\n")

typedef struct{

    uint8_t size;
    uint16_t address;
    uint8_t type;
    uint8_t data[32];
    uint8_t checksum;

}Line;

void print_hex(uint8_t *data,uint16_t len){
    for(uint16_t i=0;i<len;i++)
        printf("%x",data[i]);
    printf("\n");
}

uint8_t char2hex(char c){

    if(c >= '0' && c <= '9')
        return c - '0';

    if(c >= 'A' && c <= 'F')
        return (c - 'A') + 10;
    

    return 0;   
}

bool getLine(FILE *fp,Line *line){
    char c;
    uint8_t buffer[256]={0};
    uint8_t i=0;
    uint8_t counter=0;

    if(START_BYTE != ':')
        return false;

    line->size = (NEXT_BYTE << 4) | NEXT_BYTE;
    line->address =  (NEXT_BYTE << 12) | (NEXT_BYTE << 8) | (NEXT_BYTE << 4) | NEXT_BYTE;
    line->type = (NEXT_BYTE << 4) | NEXT_BYTE;

    for(uint8_t i=0;i<line->size;i++){
        line->data[i] = (NEXT_BYTE << 4) | NEXT_BYTE;
    }

    line->checksum = (NEXT_BYTE << 4) | NEXT_BYTE;

    NEXT_BYTE;

    return true;

}

bool save_binary_file(const char *filename,uint8_t *buffer,uint32_t buffer_len){
    FILE *binFile = fopen(filename,"wb");
    if(binFile == NULL)
        return false;
    fwrite(buffer,1,buffer_len,binFile);
    fclose(binFile);
    return true;
}

bool load_hex_file(const char *filename,uint8_t *buffer,uint16_t *size,uint16_t startAddr,uint16_t endAddr){
    uint16_t disk_size = endAddr - startAddr;
    uint8_t disk[disk_size];
    memset(disk,0xFF,disk_size);

    FILE *fp = fopen(filename,"r");

    if(fp == NULL)
        return false;

    Line line;

    while (!feof(fp))
    {
        if(getLine(fp,&line)){
            printf("0x%08x  ",line.address);
            for(uint8_t i=0;i<line.size;i++)
                printf("0x%02x ",line.data[i]);

            printf("\n");

            if(line.type == 0 && line.address >= startAddr && line.address <= endAddr){
                uint16_t offset = line.address - startAddr;
                memcpy(&disk[offset],line.data,line.size);
            }

        }

    }    

    memcpy(buffer,disk,disk_size);
    *size =disk_size;
}

bool load_key_file(const char *filename,uint8_t *buffer){

    FILE *fp = fopen(filename,"rb");
    if(fp == NULL)
        return false;

    for(uint8_t i=0;i<16;i++){
        buffer[i] = (NEXT_BYTE << 4) | NEXT_BYTE;
    }

    //fread(buffer,1,16,fp);
    fclose(fp);

    printf("Loaded key : ");
    print_hex(buffer,16);
}

bool generate_cmac(uint8_t *data,uint16_t data_len,uint8_t *key,uint8_t *cmac){

    uint16_t cmac_size;

    CMAC_CTX *verifyCMAC = CMAC_CTX_new();

    CMAC_Init(verifyCMAC, key,16, EVP_aes_128_cbc(), NULL);

    CMAC_Update(verifyCMAC,data,data_len);
    CMAC_Final(verifyCMAC, cmac,(size_t*)&cmac_size);

    CMAC_CTX_free(verifyCMAC);

}

int main(int argc,char *argv[]){

    if(argc < 5 ){
        printf("hexCMAC <aesKeyFile> <hexFile> <startAddress> <endAddress>\n");
        return 1;
    }

    uint16_t startAddr = strtol(argv[3], NULL, 16); 
    uint16_t endAddr = strtol(argv[4], NULL, 16); 
    uint16_t size = endAddr - startAddr;
    uint8_t disk[size];
    uint8_t cmac[16];
    uint8_t key[16];

    load_key_file(argv[1],key);

    load_hex_file(argv[2],disk,&size,startAddr,endAddr);

    save_binary_file("./binary.bin",disk,size);

    printf("Disk : ");
    print_hex(disk,size);

    generate_cmac(disk,size,key,cmac);

    printf("Signature : ");
    print_hex(cmac,16);

    return 0;
}