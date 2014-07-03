#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>

const uint32_t TEAKey[4] = {0x95a8882c, 0x9d2cc113, 0x815aa0cd, 0xa1c489f7};

void encriptar(uint32_t* v, const uint32_t* k);
void desencriptar(uint32_t* v, const uint32_t* k);
void ficheroArray(unsigned char * buffer);
void ficheroArrayDesencriptar(unsigned char * buffer);

/*
Parametro entrada:
	FicheroOut: Fichero donde se almacenara la salida del cifrador 
	FicheroIn: Fichero a cifrar
*/
int main(int argc, char* argv[]){
	int d=0,e=0;
	int ficheroIn, ficheroOut;
	unsigned char buff[8];

	if(argc>=5 || argc==1){
		printf("Error de sintaxis: tea (e)ncriptar/(d)esencriptar FicheroIn FicheroOut\n");
		return 0;
	}
	
	if(strcmp(argv[1],"d")==0){
		d=1;
		printf("Modo desencriptar\n");
	}else if(strcmp(argv[1],"e")==0){
		e=1;
		printf("Modo encriptar\n");
	}else{
		printf("Error de sintaxis: tea (e)ncriptar/(d)esencriptar FicheroOut Clave FicheroIn\n");
		printf("El primer argumento solo puede ser una d o una e\n");
		return 1;
	}	
	
	ficheroIn=open(argv[2],O_RDONLY);
	if(ficheroIn==-1){
		printf("Error de fichero: FicheroIn no existe o no puede ser leido\n");
		return 1;
	}
	
	printf("Abriendo In: %s\n",argv[2]);
	
	ficheroOut=open(argv[3],O_WRONLY | O_CREAT | O_TRUNC, 0600 );
	if(ficheroOut==-1){
		printf("Error de fichero: FicheroOut no existe o no puede ser leido\n");
		return 1;
	}
	
	printf("Abriendo Out: %s\n",argv[3]);
	
	while(read(ficheroIn,buff,8) == 8){
		if(e==1){
			ficheroArray(buff);
		}else if(d==1){
			ficheroArrayDesencriptar(buff);
		}else{
			printf("ERROR e:%i, d:%i\n",e,d);
		}
		write(ficheroOut,buff,8);
	}
	
	close(ficheroIn);
	close(ficheroOut);
	printf("%s terminado, %s es el fichero de salida\n",((e==1) ? "Encriptar" : "Desencriptar" ), argv[3]);
}

void encriptar(uint32_t* v, const uint32_t* k){
	uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
	
    for (i=0; i < 32; i++) {                       /* basic cycle start */
        sum += delta;
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);  
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}
 
void ficheroArray(unsigned char * buffer){
    uint32_t datablock[2];

    datablock[0] = (buffer[0] << 24) | (buffer[1] << 16)  | (buffer[2] << 8) | (buffer[3]);
    datablock[1] = (buffer[4] << 24) | (buffer[5] << 16)  | (buffer[6] << 8) | (buffer[7]);

    encriptar(datablock, TEAKey);

    buffer[0] = (char) ((datablock[0] >> 24) & 0xFF);
    buffer[1] = (char) ((datablock[0] >> 16) & 0xFF);
    buffer[2] = (char) ((datablock[0] >> 8) & 0xFF);
    buffer[3] = (char) ((datablock[0]) & 0xFF);
    buffer[4] = (char) ((datablock[1] >> 24) & 0xFF);
    buffer[5] = (char) ((datablock[1] >> 16) & 0xFF);
    buffer[6] = (char) ((datablock[1] >> 8) & 0xFF);
    buffer[7] = (char) ((datablock[1]) & 0xFF);
}

void desencriptar(uint32_t* v, const uint32_t* k){
	uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;  /* set up */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
	
    for (i=0; i<32; i++) {                         /* basic cycle start */
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;                                   
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}

void ficheroArrayDesencriptar(unsigned char * buffer){
    uint32_t datablock[2];

    datablock[0] = (buffer[0] << 24) | (buffer[1] << 16)  | (buffer[2] << 8) | (buffer[3]);
    datablock[1] = (buffer[4] << 24) | (buffer[5] << 16)  | (buffer[6] << 8) | (buffer[7]);

    desencriptar(datablock, TEAKey);

    buffer[0] = (char) ((datablock[0] >> 24) & 0xFF);
    buffer[1] = (char) ((datablock[0] >> 16) & 0xFF);
    buffer[2] = (char) ((datablock[0] >> 8) & 0xFF);
    buffer[3] = (char) ((datablock[0]) & 0xFF);
    buffer[4] = (char) ((datablock[1] >> 24) & 0xFF);
    buffer[5] = (char) ((datablock[1] >> 16) & 0xFF);
    buffer[6] = (char) ((datablock[1] >> 8) & 0xFF);
    buffer[7] = (char) ((datablock[1]) & 0xFF);
}
