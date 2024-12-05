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
#include <time.h>
NTL_CLIENT

#include "EncryptedArray.h"
#include "FHE.h"

#include "intraSlot.h"
#include "binaryArith.h"
#include "binaryCompare.h"

#include "GreaterThan.hpp"
#include "Timer.hpp"
#include<bits/stdc++.h>

const int MAX_N = 33;
int N,T,S;
long a[MAX_N]; // 明文数组

Ctxt Equal(std::vector<Ctxt> m1, std::vector<Ctxt> m2);
Ctxt Equal2(std::vector<Ctxt> m1, std::vector<Ctxt> m2);
Ctxt mulOrdiVector(vector<Ctxt>& vArray,EncryptedArray& ea,long nslots);
Ctxt divOrMul(std::vector<Ctxt> array);
Ctxt Less(std::vector<Ctxt> m1, std::vector<Ctxt> m2);
Ctxt divOrAdd(std::vector<Ctxt> array);
void full_adder(std::vector<Ctxt>& val , Ctxt x);

int main(int argc, char *argv[])
{
    //freopen("in.txt" , "r" , stdin);
    //freopen("out.txt" , "w" , stdout);

    ArgMapping amap;
	long m = 8192;
	long p = 113; // small domain
    long L = 4;
    amap.arg("m", m, "m");
    amap.arg("p", p, "p");
    amap.arg("L", L, "L");
    amap.parse(argc, argv);


    /*long m = 8192;                   // Specific modulus
	long p = 113;                   // Plaintext base [default=2], should be a prime number
	long r = 1;                   // Lifting [default=1]
	long L = 16;                  // Number of levels in the modulus chain [default=heuristic]
	long c = 2;                   // Number of columns in key-switching matrix [default=2]
	long w = 64;                  // Hamming weight of secret key
	long d = 0;                   // Degree of the field extension [default=1]
	long k = 80;                 // Security parameter [default=80] 
    long s = 0;                   // Minimum number of slots [default=0]*/

	//std::cout << "Finding m... " << std::flush;
	//m = FindM(k, L, c, p, d, s, 0);                            // Find a value for m given the specified values
	std::cout << "m = " << m << std::endl;
	
	std::cout << "Initializing context... " << std::flush;
	FHEcontext context(m, p, 1); 	                        // Initialize context
	buildModChain(context, L);                           // Modify the context, adding primes to the modulus chain
	std::cout << "OK!" << std::endl;

	std::cout << "Creating polynomial... " << std::flush;
	ZZX G =  context.alMod.getFactorsOverZZ()[0];                // Creates the polynomial used to encrypt the data
	std::cout << "OK!" << std::endl;

	std::cout << "Generating keys... " << std::flush;
	FHESecKey secretKey(context);                           // Construct a secret key structure
	const FHEPubKey& publicKey = secretKey;                 // An "upcast": FHESecKey is a subclass of FHEPubKey
	secretKey.GenSecKey(64);                                 // Actually generate a secret key with Hamming weight w
    
	setup_auxiliary_for_greater_than(&secretKey);
    auto gt_args = create_greater_than_args(0, 1, context);

    //add1DMatrices(secretKey);
	std::cout << "OK!" << std::endl;
	/*** END INITIALIZATION ***/  

    
    printf("please input the number of your vec:");
    scanf("%d",&N);
    for(int i=0;i<N;i++){
        scanf("%ld",&a[i]);
    }


    /*************** time **********************/
    clock_t start, finish;
    start = clock();
    NTL::Vec<Ctxt> enc;
    
    //std::vector<Ctxt> enc;
    //std::vector<Ctxt> M[MAX_N];
    NTL::Vec<Ctxt> M[MAX_N];
   
    Ctxt my_one(publicKey);
    publicKey.Encrypt(my_one,ZZX(1));
    Ctxt my_zero(publicKey);
    publicKey.Encrypt(my_zero,ZZX(0));

    resize(enc, N, my_zero);
    for(int i = 0; i< N; i++) {
        resize(M[i], N, my_zero);
    }
    

    for(int i=0;i<N;i++){
        for(int j=0;j<N;j++){
            //M[i].push_back(my_zero);
            M[i][j] = my_zero;
        }
    }
    finish = clock();
    std::cout<<"初始化M完成:"<<(double)(finish-start)/CLOCKS_PER_SEC<<endl;
    start = clock();
    for(int i=0;i<N;i++){
        Ctxt t = encrypt_in_degree(a[i], publicKey);
        //enc.push_back(t);
        enc[i] = t;
    }
    finish = clock();
    std::cout<<"加密完成："<<(double)(finish-start)/CLOCKS_PER_SEC<<endl;
    cout << "___________________加密完成________________" << endl;

    for(int i=0;i<N;i++){

        ZZX ptResult;
        secretKey.Decrypt(ptResult, enc[i]);
        std::cout<<"!!!!!!!!!!!!!!!!!!!!!"<<ptResult[0];
        std::cout << std::endl;
    }






    start = clock();
    for(int i=0;i<N;i++){
        for(int j=i+1;j<N;j++){
            auto tmp = greater_than(enc[i], enc[j], context);
            M[i][j] += tmp;
            auto tmpp = greater_than(enc[j], enc[i], context);
            M[j][i] =tmpp;




            // M[j][i] += tmp;
            // M[j][i].addCtxt(my_one);
            
        }
    }

    for(int i=0;i<N;i++){

        ZZX ptResult;
        secretKey.Decrypt(ptResult, enc[i]);
        std::cout<<"!!!!!!!!!!!!!!!!!!!!!"<<ptResult[0];
        std::cout << std::endl;
    }

























    finish = clock();
    std::cout<<"M赋值："<<(double)(finish-start)/CLOCKS_PER_SEC<<std::endl;
     for(int i=0;i<N;i++){
        for(int j=0;j<N;j++){
            
            ZZX ptResult;
            secretKey.Decrypt(ptResult, M[i][j]);
            std::cout<<ptResult[0];
        }
        cout<<endl;
    }
     cout << "___________________M完成________________" << endl;

    /***********sort***************/
    
    //std::vector<Ctxt> val; //val[i]-第i个元素在排序后序列的位置,一共分为4位。
    NTL::Vec<Ctxt> val;
    resize(val ,N, my_zero);
    // for(int i=0;i<N;i++){
    //     val.push_back(my_zero);
        
    // }
    start = clock();
    for(int i=0;i<N;i++){
        Ctxt tmp(publicKey);
        tmp = my_zero;
        for(int j =0;j<N;j++){
            tmp += M[j][i];
            //full_adder(val[i] , M[j][i]);
        }
        //val.push_back(tmp);
        val[i] = tmp;
    }
    finish = clock();
    std::cout<<"汉明权重："<<(double)(finish-start)/CLOCKS_PER_SEC<<std::endl;
    cout << "___________________汉明权重完成________________" << endl;
    
    for(int i=0;i<N;i++){

        ZZX ptResult;
        secretKey.Decrypt(ptResult, val[i]);
        std::cout<<ptResult[0];
        std::cout << std::endl;
    }
    start = clock();
    cout << "___________________输出完成________________" << endl;







    //std::vector<Ctxt> tta;
    NTL::Vec<Ctxt> tta;
    resize(tta, N, my_zero);
    for(long i=0;i<N;i++){
        Ctxt t(publicKey);
        t = encrypt_in_degree(i, publicKey);
        //tta.push_back(t);
        tta[i] = t;

        Ctxt ans(publicKey);
        ans = my_zero;
        for(int j=0;j<N;j++){

            // Ctxt tmp = greater_than(tta[i], val[j], context);
            // Ctxt tmpp = greater_than(val[j], tta[i], context);
            // tmp.multiplyBy(tmpp);
            // tmp.multiplyBy(enc[j]);
            // ans += tmp;

            ZZX ptResult,abccd;
            secretKey.Decrypt(ptResult,tta[i]);
            secretKey.Decrypt(abccd,val[j]);
            std::cout<<ptResult[0] << "......"<<abccd[0]<<endl;

        }
        cout << "______________________"<<endl;
        // ZZX ptResult;
        // secretKey.Decrypt(ptResult,ans);
        // std::cout<<ptResult[0] << endl;

    }
    finish = clock();
    std::cout<<"排序:"<<(double)(finish-start)/CLOCKS_PER_SEC<<std::endl;
    cout << "___________________排序完成________________" << endl;
    
    //EncryptedArray ea(context, G);
    //long nSlots = ea.size();
    /*
    Ctxt result(publicKey);
    std::vector<Ctxt> enca, encb;
    for(int i=7;i>=0;i--){
        Ctxt c1(publicKey), c2(publicKey);
        publicKey.Encrypt(c1, ZZX((120>>i)&1));
        publicKey.Encrypt(c2, ZZX((123>>i)&1));
        enca.push_back(c1);
        encb.push_back(c2);
    }
    result = Less(enca, encb);
    ZZX ptResult;
    secretKey.Decrypt(ptResult, result);
    cout<<ptResult[0]<<endl;
    */
    /*** END ENCRYPT ***/
   

}

// 四位全加器
void full_adder(std::vector<Ctxt>& val , Ctxt x){
    
    for(int i=0;i<4;i++){
        Ctxt t = x;
        x.multiplyBy(val[i]);
        val[i] += t;

    }


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
        cLess = m1[i];             //cLess = B
        cLess.addCtxt(cOne);       //cLess = B+1
        cLess.multiplyBy(m2[i]);   //CLess = A(B+1)
        std::vector<Ctxt> sub_m1, sub_m2;
        sub_m1.clear();
        sub_m2.clear();
        for(long j = 0;j<i;j++){
            sub_m1.push_back(m1[j]);
            sub_m2.push_back(m2[j]);
        }
        if(i != 0)cLess.multiplyBy(Equal2(sub_m1,sub_m2));
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
