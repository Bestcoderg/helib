/* Copyright (C) 2012-2017 IBM Corp.
 * This program is Licensed under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. See accompanying LICENSE file.
 */
#include <iostream>
#include <fstream>
#include <vector>
#include <cmath>
#include <algorithm>
#include <NTL/BasicThreadPool.h>
NTL_CLIENT

#include "EncryptedArray.h"
#include "FHE.h"

#include "intraSlot.h"
#include "binaryArith.h"
#include "binaryCompare.h"
int N,T,S;
int a[10]; // 明文数组

Ctxt Equal(std::vector<Ctxt> m1, std::vector<Ctxt> m2);
Ctxt Equal2(std::vector<Ctxt> m1, std::vector<Ctxt> m2);
Ctxt mulOrdiVector(vector<Ctxt>& vArray,EncryptedArray& ea,long nslots);
Ctxt divOrMul(std::vector<Ctxt> array);
Ctxt Less(std::vector<Ctxt> m1, std::vector<Ctxt> m2);
Ctxt divOrAdd(std::vector<Ctxt> array);

int main(int argc, char *argv[])
{
    long m = 0;                   // Specific modulus
	long p = 2;                   // Plaintext base [default=2], should be a prime number
	long r = 1;                   // Lifting [default=1]
	long L = 16;                  // Number of levels in the modulus chain [default=heuristic]
	long c = 2;                   // Number of columns in key-switching matrix [default=2]
	long w = 64;                  // Hamming weight of secret key
	long d = 0;                   // Degree of the field extension [default=1]
	long k = 80;                 // Security parameter [default=80] 
    long s = 0;                   // Minimum number of slots [default=0]

	std::cout << "Finding m... " << std::flush;
	m = FindM(k, L, c, p, d, s, 0);                            // Find a value for m given the specified values
	std::cout << "m = " << m << std::endl;
	
	std::cout << "Initializing context... " << std::flush;
	FHEcontext context(m, p, r); 	                        // Initialize context
	buildModChain(context, L, c);                           // Modify the context, adding primes to the modulus chain
	std::cout << "OK!" << std::endl;

	std::cout << "Creating polynomial... " << std::flush;
	ZZX G =  context.alMod.getFactorsOverZZ()[0];                // Creates the polynomial used to encrypt the data
	std::cout << "OK!" << std::endl;

	std::cout << "Generating keys... " << std::flush;
	FHESecKey secretKey(context);                           // Construct a secret key structure
	const FHEPubKey& publicKey = secretKey;                 // An "upcast": FHESecKey is a subclass of FHEPubKey
	secretKey.GenSecKey(w);                                 // Actually generate a secret key with Hamming weight w
    //add1DMatrices(secretKey);
	std::cout << "OK!" << std::endl;
	/*** END INITIALIZATION ***/  

    /*printf("please input the number of your vec:");
    scanf("%d",&N);
    for(int i=0;i<N;i++){
        scanf("%d",&a[i]);
    }*/
    /*** END INPUT ***/
    /*NTL::Vec<Ctxt> enca[10],Y[10]; // 加密后的数组
    for(int i=0;i<N;i++){
        for(int j =0;j<32 ;j++){
            publicKey.Encrypt(enca[i][j] , ZZX(0));
            publicKey.Encrypt(Y[i][j] , ZZX(0));
            enca[i][j].modDownToLevel(5);
            Y[i][j].modDownToLevel(5);
        }
    }*/
    //EncryptedArray ea(context, G);
    //long nSlots = ea.size();

    Ctxt result(publicKey);
    std::vector<Ctxt> enca, encb;
    for(int i=0;i<8;i++){
        Ctxt c1(publicKey), c2(publicKey);
        publicKey.Encrypt(c1, ZZX((20>>i)&1));
        publicKey.Encrypt(c2, ZZX((23>>i)&1));
        enca.push_back(c1);
        encb.push_back(c2);
    }
    result = Less(enca, encb);
    ZZX ptResult;
    secretKey.Decrypt(ptResult, result);
    cout<<ptResult[0]<<endl;
    /*** END ENCRYPT ***/
    /*NTL::Vec<Ctxt> M[5],S;
    Ctxt zeroCtxt(publicKey);
    publicKey.Encrypt(zeroCtxt,ZZX(0));
    for(int i=0;i<5;i++)
        resize(M[i], 5 , zeroCtxt);
    resize(S,5,zeroCtxt);*/

    /*Ctxt e(publicKey),g(publicKey);
    for(int i=0;i<5;i++){
    for(int j=i+1;j<5;j++){
        compEqGt(CtPtrs_VecCt(e),CtPtrs_VecCt(g),CtPtrs_VecCt(enca[i]),CtPtrs_VecCt(enca[j]));
        M[j][i] = g;
        g.addConst(to_ZZX(1));
        M[i][j] = g;
    }
    for(int i=0;i<5;i++){
      for(int j=0;j<5;j++){
        S[i].addCtxt(M[j][i]);
      }
    }
    Ctxt tmp(publicKey);
    publicKey.Encrypt(tmp,ZZX(0));
    */

    /*for(int i=0;i<5;i++,tmp.addConst(to_ZZX(1))){
      for(int j=0;j<5;j++){
        compEqGt(CtPtrs_VecCt(e),CtPtrs_VecCt(g),CtPtrs_VecCt(tmp),CtPtrs_VecCt(S[j]);
        Y[i] += e.multiply(enca[j]);      
      }
    }*/

    /*for(int i=0;i<5;i++){
      for(int j=0;j<32;j++){
        ZZX ptSum;
        publicKey.decrypt(ptSsum,Y[i][j]);
        cout<<ptSum[0];
      }
      cout<<"....."<<endl;
    }
  }*/

}

Ctxt Equal(std::vector<Ctxt> m1, std::vector<Ctxt> m2) {
    Ctxt cOne(m1[0].getPubKey());
    std::vector<Ctxt> cSum;
    m1[0].getPubKey().Encrypt(cOne, to_ZZX(1));
    long length = m1.size();
    for(long i = 0; i < length; i++) {
        Ctxt result(m1[0].getPubKey());
        result = m1[i];            //result=A
        result.addCtxt(cOne);      //result=A+1
        m1[i].multiplyBy(m2[i]);   //A=AB
        m2[i].addCtxt(cOne);       //B=B+1
        result.multiplyBy(m2[i]);  //result=(A+1)(B+1)
        result.addCtxt(m1[i]);     //result=(A+1)(B+1)+AB
        cSum.push_back(result);
    }
    return divOrMul(cSum);
}

Ctxt Equal2(std::vector<Ctxt> m1, std::vector<Ctxt> m2) {
    Ctxt cOne(m1[0].getPubKey());
    std::vector<Ctxt> cSum;
    m1[0].getPubKey().Encrypt(cOne, to_ZZX(1));
    long length = m1.size();
    for(long i = 0; i < length; i++) {
        Ctxt result(m1[0].getPubKey());
        result = m1[i];            //result=A
        result.addCtxt(cOne);      //result=A+1
        result.addCtxt(m2[i]);     //result=A+1+B
        cSum.push_back(result);
    }
    return divOrMul(cSum);
}

Ctxt divOrMul(std::vector<Ctxt> array) {  //连续乘
    Ctxt result(array[0].getPubKey());
    if(array.size() == 1) {
        return array[0];
    } else {
        long iter;
        long size = array.size();
        long mid = size/2;
        std::vector<Ctxt> leftArray;
        std::vector<Ctxt> rightArray;
        for(iter = 0 ; iter < mid ; iter++){
            leftArray.push_back(array[iter]);
        }
        for(iter = mid ; iter < size ; iter++){
            rightArray.push_back(array[iter]);
        }
        Ctxt resultLeft = divOrMul(leftArray);
        Ctxt resultRight = divOrMul(rightArray);
        result = resultLeft;
        result.multiplyBy(resultRight);
        return result;
    }
}

Ctxt Less(std::vector<Ctxt> m1, std::vector<Ctxt> m2) {
    Ctxt cOne(m1[0].getPubKey());
    std::vector<Ctxt> cSum;
    std::vector<Ctxt> cEqual;
    m1[0].getPubKey().Encrypt(cOne, to_ZZX(1));
    long length = m1.size();
    for(long i = 0; i < length; i++) {
        Ctxt cLess(m1[0].getPubKey());
        cLess = m2[i];             //cLess = B
        cLess.addCtxt(cOne);       //cLess = B+1
        cLess.multiplyBy(m1[i]);   //CLess = A(B+1)
        for(long j = i + 1; j < length; j++) {
            std::vector<Ctxt> sub_m1, sub_m2;
            for(long k = j; k < length; k++) {
                sub_m1.push_back(m1[k]);
                sub_m2.push_back(m2[k]);
            }
            cEqual.push_back(Equal2(sub_m1, sub_m2));
        }
        if(i != length -1) cLess.multiplyBy(divOrAdd(cEqual));
        cSum.push_back(cLess);
    }
    return divOrAdd(cSum);
}

Ctxt divOrAdd(std::vector<Ctxt> array) {  //连续加
    Ctxt result(array[0].getPubKey());
    if(array.size() == 1) {
        return array[0];
    } else {
        long iter;
        long size = array.size();
        long mid = size/2;
        std::vector<Ctxt> leftArray;
        std::vector<Ctxt> rightArray;
        for(iter = 0 ; iter < mid ; iter++){
            leftArray.push_back(array[iter]);
        }
        for(iter = mid ; iter < size ; iter++){
            rightArray.push_back(array[iter]);
        }
        Ctxt resultLeft = divOrAdd(leftArray);
        Ctxt resultRight = divOrAdd(rightArray);
        result = resultLeft;
        result.addCtxt(resultRight);
        return result;
    }
}