#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "gmp.h"
#include <time.h>
#include <stdbool.h>

int mpzSgn(mpz_t ptr) {
    int result = mpz_cmp_si(ptr, 0);
    if (result < 0) {
      return -1;
    } else if (result > 0) {
      return 1;
    }
    return 0;
  }

void gcd(int* ret,int* got_countp,char* got_data,int* got_datalen,char* value1,int* value1len,char* value2,int* value2len)
{
    mpz_t rp, value1p,value2p;
    mpz_init (rp);
    mpz_init (value1p);
    mpz_init (value2p);

    size_t got_count;
    mpz_import(value1p,(*value1len)-1,1,1,1,0,value1);
    memset(got_data, '\0',(*got_datalen)-1);
    mpz_export (got_data, &got_count,1,1,1,0,value1p);
    mpz_import(value2p,(*value2len)-1,1,1,1,0,value2);
    memset(got_data, '\0',(*got_datalen)-1);
    mpz_export (got_data, &got_count,1,1,1,0,value2p);

    mpz_gcd(rp, value1p, value2p);
    
    int res = mpzSgn(rp);
    *ret = res;
    
    int requiredSize = (*got_datalen)-1;
    memset(got_data, '\0',requiredSize);
    mpz_export (got_data, &got_count,1,1,1,0,rp);
    *got_countp = got_count;
}

void modInverse(int* ret,int* got_countp,char* got_data,char* val,int* vallen,char* modulus,int* modlen)
{
    mpz_t rp, valp,modulusp;
    mpz_init (rp);
    mpz_init (valp);
    mpz_init (modulusp);

    size_t got_count;
    mpz_import(valp,(*vallen)-1,1,1,1,0,val);
    memset(got_data, '\0',(*modlen)-1);
    mpz_export (got_data, &got_count,1,1,1,0,valp);
    mpz_import(modulusp,(*modlen)-1,1,1,1,0,modulus);
    memset(got_data, '\0',(*modlen)-1);
    mpz_export (got_data, &got_count,1,1,1,0,modulusp);

    int res = mpz_invert(rp, valp, modulusp);
    if (res == 0) 
    {
	return;
    }

    res = mpzSgn(rp);
    *ret = res;

    int requiredSize = (*modlen)-1;
    memset(got_data, '\0',requiredSize);
    mpz_export (got_data, &got_count,1,1,1,0,rp);
    *got_countp = got_count;
}

void modPowSecure(int* ret,int* got_countp,char* got_data,char* base,int* baselen,char* exponent,int* explen,char* modulus,int* modlen)
{
    mpz_t rp, basep,exponentp,modulusp;
    mpz_init (rp);
    mpz_init (exponentp);
    mpz_init (basep);
    mpz_init (modulusp);

    size_t got_count;
    mpz_import(basep,(*baselen)-1,1,1,1,0,base);
    memset(got_data, '\0',(*modlen)-1);
    mpz_export (got_data, &got_count,1,1,1,0,basep);
    mpz_import(exponentp,(*explen)-1,1,1,1,0,exponent);
    memset(got_data, '\0',(*modlen)-1);
    mpz_export (got_data, &got_count,1,1,1,0,exponentp);
    mpz_import(modulusp,(*modlen)-1,1,1,1,0,modulus);
    memset(got_data, '\0',(*modlen)-1);
    mpz_export (got_data, &got_count,1,1,1,0,modulusp);

    bool sig = (mpz_sgn(exponentp) < 0);
    if(sig)
    {
	mpz_neg (exponentp, exponentp);
    }

    if(sig) 
    {
      int res = mpz_invert(basep, basep, modulusp);
      if (res == 0) 
      {
	  return;
      }
    }

    //mpz_powm (rp, basep, exponentp, modulusp);
    mpz_powm_sec(rp, basep, exponentp, modulusp);
    int res = mpzSgn(rp);
    *ret = res;

    int requiredSize = (*modlen)-1;
    memset(got_data, '\0',requiredSize);
    mpz_export (got_data, &got_count,1,1,1,0,rp);
    *got_countp = got_count;
}

void modPowInsecure(int* ret,int* got_countp,char* got_data,char* base,int* baselen,char* exponent,int* explen,char* modulus,int* modlen)
{
    mpz_t rp, basep,exponentp,modulusp;
    mpz_init (rp);
    mpz_init (exponentp);
    mpz_init (basep);
    mpz_init (modulusp);

    size_t got_count;
    mpz_import(basep,(*baselen)-1,1,1,1,0,base);
    memset(got_data, '\0',(*modlen)-1);
    mpz_export (got_data, &got_count,1,1,1,0,basep);
    mpz_import(exponentp,(*explen)-1,1,1,1,0,exponent);
    memset(got_data, '\0',(*modlen)-1);
    mpz_export (got_data, &got_count,1,1,1,0,exponentp);
    mpz_import(modulusp,(*modlen)-1,1,1,1,0,modulus);
    memset(got_data, '\0',(*modlen)-1);
    mpz_export (got_data, &got_count,1,1,1,0,modulusp);

    bool sig = (mpz_sgn(exponentp) < 0);
    if(sig)
    {
	mpz_neg (exponentp, exponentp);
    }

    if(sig) 
    {
      //int res = mpz_invert(basep, exponentp, modulusp);
      int res = mpz_invert(basep, basep, modulusp);
      if (res == 0) 
      {
	  return;
      }
    }

    mpz_powm (rp, basep, exponentp, modulusp);
    int res = mpzSgn(rp);
    *ret = res;

    int requiredSize = (*modlen)-1;
    memset(got_data, '\0',requiredSize);
    mpz_export (got_data, &got_count,1,1,1,0,rp);
    *got_countp = got_count;
}

void isProbablePrime(int* ret,char* num,int* numlen) 
{
    mpz_t rp;
    mpz_init (rp);

    size_t got_count;
    char got_data[*numlen];
    mpz_import(rp,*numlen,1,1,1,0,num);
    memset(got_data, '\0',*numlen);
    mpz_export (got_data, &got_count,1,1,1,0,rp);

    if(mpz_probab_prime_p(rp,10) != 0)
	*ret = 1;
    else
	*ret = 0;
}

void get_rand_int(int* got_countp,char* got_data,int*bitlen) 
{
    mpz_t rp;
    mpz_init (rp);
    //mpz_t nxtp;
    //mpz_init (nxtp);
    
    gmp_randstate_t rs;
    gmp_randinit_default (rs);
    gmp_randseed_ui (rs, 11);
    //gmp_randseed (rs,1111);
    mpz_rrandomb (rp,rs,256);
    //mpz_nextprime (nxtp, rp);

    int bytenum = 1000;//((*bitlen)+7)/8;
    size_t got_count;
    char got_data2[bytenum];
    memset(got_data2, '\0',bytenum);
    mpz_export (got_data2, &got_count,1,1,1,0,rp);
    *got_countp = got_count;
    printf("gmp rand num is:%s\n",got_data2);
    gmp_randclear (rs);

}
