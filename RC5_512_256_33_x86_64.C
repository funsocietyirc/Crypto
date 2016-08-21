// #fsociety @ freenode
// RC5 (64bit, 33 Rounds, 512bit key, 256bit block)
// -Based on RC5REF.C - Inspired by Equation Group

/* RC5REF.C -- Reference implementation of RC5-32/12/16 in C.        */
/* Copyright (C) 1995 RSA Data Security, Inc.                        */
#include <stdio.h>
#include <time.h>
typedef unsigned long long int WORD; /* Should be 64-bit = 8 bytes   */
#define w        64             /* word size in bits                 */
#define r        33             /* number of rounds                  */
#define b        64             /* number of bytes in key            */
#define c        8              /* number  words in key = ceil(8*b/w)*/
#define t        136            /* size of table S = 4*(r+1) words   */
WORD S[t];                      /* expanded key table                */
//WORD P = 0xb7e15163, Q = 0x9e3779b9;  /* magic constants           */
WORD P = 0xb7e15163, Q = 0x61C88647;  /* Equation Group constants    */
/* Rotation operators. x must be unsigned, to get logical right shift*/
#define ROTL(x,y) (((x)<<(y&(w-1))) | ((x)>>(w-(y&(w-1)))))
#define ROTR(x,y) (((x)>>(y&(w-1))) | ((x)<<(w-(y&(w-1)))))

/* 4 WORD input pt/output ct    */
void RC5_ENCRYPT(WORD *pt, WORD *ct) {
  WORD i, A=pt[0]+S[0], B=pt[1]+S[1], C=pt[2]+S[2], D=pt[3]+S[3];
  for (i=1; i<=r; i++) {
    A = ROTL(A^B,B)+S[2*i];
    B = ROTL(B^A,A)+S[2*i+1];
    C = ROTL(C^D,D)+S[2*i+2];
    D = ROTL(D^C,C)+S[2*i+3];    
  }
  ct[0] = A; ct[1] = B; ct[2] = C; ct[3] = D;
}

/* 4 WORD input ct/output pt    */
void RC5_DECRYPT(WORD *ct, WORD *pt) {
  WORD i, D=ct[3], C=ct[2], B=ct[1], A=ct[0];
  for (i=r; i>0; i--) {
    D = ROTR(D-S[2*i+3],C)^C;		
    C = ROTR(C-S[2*i+2],D)^D;		
    B = ROTR(B-S[2*i+1],A)^A;
    A = ROTR(A-S[2*i],B)^B;
  }
  pt[3] = D-S[3]; pt[2] = C-S[2]; pt[1] = B-S[1]; pt[0] = A-S[0];
}

/* secret input key K[0...b-1]      */
void RC5_SETUP(unsigned char *K) {
  WORD i, j, k, u=w/8, A, B, L[c];
  /* Initialize L, then S, then mix key into S */
  for (i=b-1,L[c-1]=0; i!=-1; i--) L[i/u] = (L[i/u]<<8)+K[i];
  //for (S[0]=P,i=1; i<t; i++) S[i] = S[i-1]+Q;
  for (S[0]=P,i=1; i<t; i++) S[i] = S[i-1]-Q;
  /* 3*t > 3*c */
  for (A=B=i=j=k=0; k<3*t; k++,i=(i+1)%t,j=(j+1)%c) {
    A = S[i] = ROTL(S[i]+(A+B),3);
    B = L[j] = ROTL(L[j]+(A+B),(A+B));
  }
}

int main() {
  WORD i, j, pt1[4], pt2[4], ct[4] = {0,0};
  unsigned char key[b];
  //time_t t0, t1;
  if (sizeof(WORD)!=8) {
    printf("RC5 error: WORD has %ld bytes.\n",sizeof(WORD));
  }
  printf("RC5 (64bit, 33 Rounds, 512bit key, 256bit block):\n");
  for (i=1;i<6;i++) {
    /* Initialize pt1 and key pseudorandomly based on previous ct */
    pt1[0]=ct[0]; pt1[1]=ct[1]; pt1[2]=ct[2]; pt1[3]=ct[3];
    for (j=0;j<b;j++) { key[j] = ct[0]%(255-j); }
    /* Setup, encrypt, and decrypt */
    RC5_SETUP(key);
    RC5_ENCRYPT(pt1,ct);
    RC5_DECRYPT(ct,pt2);
    /* Print out results, checking for decryption failure */
    printf("\n%lld. key = ",i);
    for (j=0; j<b; j++) { printf("%.2X",key[j]); }
    printf("\n   P: %016llX %016llX %016llX %016llX =>  C: %016llX %016llX %016llX %016llX => dP: %016llX %016llX %016llX %016llX\n", 
    pt1[0], pt1[1], pt1[2], pt1[3],
    ct[0], ct[1], ct[2], ct[3], 
    pt2[0], pt2[1], pt2[2], pt2[3]);
    if (pt1[0] != pt2[0] || pt1[1] != pt2[1] || pt1[2] != pt2[2] || pt1[3] != pt2[3]) {
      printf("\n DECRYPT ERROR: %016llX %016llX %016llX %016llX != %016llX %016llX %016llX %016llX \n", pt1[0], pt1[1], pt2[0], pt2[1]);
    }
  }
  /*
  time (&t0);
  for (i=1;i<33000000;i++) { RC5_ENCRYPT(ct,ct); }
  time (&t1);
  printf ("\n   Time_t for 33 mil blocks:  %ld \n", t1-t0);
  */
  return 0;
}
// EOF
