#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define NEXT_BYTE char2hex(fgetc(fp))
#define START_BYTE fgetc(fp)

typedef struct{

    uint8_t size;
    uint16_t address;
    uint8_t type;
    uint8_t data[32];
    uint8_t checksum;

}Line;


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


int main(int argc,char *argv[]){

    uint16_t startAddr = strtol(argv[2], NULL, 16); 
    uint16_t endAddr = strtol(argv[3], NULL, 16); 
    uint16_t size = endAddr - startAddr;

    uint8_t image[size];
    memset(image,0xFF,size);

    FILE *fp;

    fp = fopen(argv[1],"r");

    if(fp == NULL)
        return 1;

    Line line;

    while (!feof(fp))
    {
        if(getLine(fp,&line)){
            printf("%x | %d | ",line.address,line.size);
            for(uint8_t i=0;i<line.size;i++)
                printf("0x%x ",line.data[i]);

            printf("\n");


            if(line.type == 0 && line.address >= startAddr && line.address <= endAddr){
                uint16_t offset = line.address - startAddr;
                memcpy(&image[offset],line.data,line.size);
            }

        }

    }
    
    printf("Image :\n");
    for(uint8_t i=0;i<size;i++)
        printf("0x%x ",image[i]);

    printf("\n");
    return 0;
}