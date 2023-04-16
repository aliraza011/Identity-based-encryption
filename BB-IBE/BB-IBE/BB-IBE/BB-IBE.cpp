/*
   *******************************
	Author: Ali Raza
	Date: 01/08/2019.
    Crypto Scheme:Boneh-Boyen IBE
   *******************************
   Compile with modules as specified below

	For MR_PAIRING_SSP curves
	 ssp_pair.cpp ecn.cpp zzn2.cpp zzn.cpp big.cpp miracl.lib
  
	For MR_PAIRING_SS2 curves
   ss2_pair.cpp ec2.cpp gf2m4x.cpp gf2m.cpp big.cpp miracl.lib
    
	or of course

    ss2_pair.cpp ec2.cpp gf2m4x.cpp gf2m.cpp big.cpp miracl.a -o bgw


   Test program 
*/

#include <iostream> //library for input and output from and to hardware devices.
#include <ctime>    // library for  system clock.



//********* CHOOSE JUST ONE OF THESE **********
#define MR_PAIRING_SS2    // AES-80 or AES-128 security GF(2^m) curve
//#define AES_SECURITY 80   // OR
#define AES_SECURITY 128

//#define MR_PAIRING_SSP    // AES-80 or AES-128 security GF(p) curve
//#define AES_SECURITY 80   // OR
//#define AES_SECURITY 128
//*********************************************
// library for type one pariring.
#include "pairing_1.h"  

//main program from where the compiler starts execution.
int main()   
{   
	// initialise pairing-friendly curve
	PFC pfc(AES_SECURITY);  

	// get handle on mip (Miracl Instance Pointer)
    miracl* mip=get_mip();   

	// get pairing-friendly group order
	Big order=pfc.order();  

	//initialize elements of type big( Setup parameters and Message)
	Big alpha,ID,r1,s,M,A;       
	int i;
	 //initialize Group G1 elements 
	G1 g,h1,g2,g1,msk,d0,d1,B,C1; 

	/*Initialize  time seed. The time_t datatype is a data type in the ISO C library defined for storing
	system time values. Such values are returned from the standard time() library function.
	*/
	time_t seed;         

	 // initialise (insecure!) random numbers                 
	time(&seed);          

	 //creat random number of long type from the seed value.
    irand((long)seed);       

	cout << "************************ Boneh-Boyen IBE ********************* " << endl;
	/////////////////////
	// setup
	////////////////////
	cout << "Starting Setup" << endl;
	//random alpha
	pfc.random(alpha);   
	//randomly generate g
	pfc.random(g); 
	// randomly generate g2
	pfc.random(g2);    
	// randomly generate h1
	pfc.random(h1);		  
	// g1=g^alpha
	g1=pfc.mult(g,alpha);   
	//precomute g1
	pfc.precomp_for_mult(g1); 
	// msk=g2^aplha
	msk=pfc.mult(g2,alpha);
	//precomute msk
	pfc.precomp_for_mult(msk);	
	
	//Note: we precompute the values for efficiency of program.
	
	cout << "Setup Completed" << endl;
	cout << "**************************************************************" << endl;
	
	//////////////////////////
	//Extraction
	//////////////////////////////

	cout << "Starting Extraction" << endl;

	//Get char ID and convert to type big.
	ID=pfc.hash_to_group((char *)"Alice");   
	
	// generate random r1
	pfc.random(r1);							
	
	/* d0=(g2^alpha)*F1(ID)^r1. We actually calculate g2^alpha as
	g2*alpha and g1^ID as g1*ID. We changed multiplicative group operations
	into additive group operations becasue there is no function in miracl to calculate 
	G1^Big. We calculate F1(ID)=(g1^ID)*h1 as ((g1*ID)^r)+h1
	because there is no function to calculate G1*G1. Here G1 and 
	Big are elements of data type G1 and Big respectively.
	*/
	d0=pfc.mult(g2,alpha)+pfc.mult((h1+pfc.mult(g1,ID)),r1); 
	
	/*We calculate d1=g^r1 as d1=g*r1. We changed multiplicative group operations
	into additive group operations, becasue there is no function to calculate G1^Big.
	Here G1 and Big are elements of data type G1 and Big respectively.
	*/
	d1=pfc.mult(g,r1);						
	
	cout << "Extraction Completed" << endl;

	cout << "**************************************************************" << endl;
	
	
	////////////////////////////
	//Encryption
	///////////////////////////


	cout << "Starting Encryption" << endl;
	/*mip is the Miracl Instance Pointer. mip->IOBASE=256 simply changes the base to 256.
	We take input in base 256 to componsate all the real world letters and special characters.
	Which are easy to represented in base 256 system of numbers.
	*/
	mip->IOBASE=256;  
	//Message to be encrypted to Alice
	M=(char *)"Test message"; 
	 //print "Message to be encrypted"
	cout << "Message to be encrypted=" << M << endl; 

	/*mip is the Miracl Instance Pointer. mip->IOBASE=16 simply changes the base to 16(Hexadecimal).
	we use the hexadecimal numbers to make coding for microprocessor. But it converts that to binary
	for computation. After the computation the result will be in hexadecimal format by inverse conversion.
	*/
	mip->IOBASE=16; 

	//generate random s
	pfc.random(s);            

	/*This code is for A=M.(e(g1,g2)^s). First we calculated e(g1,g2)^s. We hashed (e(g1,g2)^s) to covert
	it into Big data type. Because xor operation takes both input of big data type. We xor M with hash of
	(e(g1,g2)^s), instead of M.(e(g1,g2)^s). Because there is no function to map a Big datatype in to a GT
	data type. Then xor it with M.
	*/																
	A=lxor(M,pfc.hash_to_aes_key(pfc.power(pfc.pairing(g1,g2),s))); //

	/*Calculate B=g^s as B=g*s. We changed multiplicative group operations
	into additive group operations, becasue there is no function to calculate G1^Big.
	Here G1 and Big are elements of data type G1 and Big respectively.
	*/
	B=pfc.mult(g,s); 

	/*Calculate C1=F1(ID)^s as C1=F1(ID)*s. We changed multiplicative group operations
	into additive group operations becasue there is no function to calculate G1^Big.
	Where G1 and Big are elements of data type G1 and Big respectively.
	We calculate F1(ID)=(g1^ID)*h1 as ((g1*ID)^r)+h1. We changed multiplicative group operations
	into additive group operations because there is no function to calculate G1*G1. Where G1 and 
	Big are elements of data type G1 and Big respectively.
	*/
	C1=pfc.mult((h1+pfc.mult(g1,ID)),s);    
											 
	cout << "Encryption Completed" << endl;

	cout << "**************************************************************" << endl;
	//////////////////////////
	//Decryption
	/////////////////////////
	cout << "Starting Decryption" << endl;

	/* M= A.(e(B,d0)/e(C1,d1)), Please see Note below to know why we changed the numerator and denominator. First we 
	calculated e(B,d0)/e(C1,d1), and then hashed it. We hashed e(B,d0)/e(C1,d1) to covert it into Big data type. 
	Because xor operation takes both input of big data type. We xor A and hash of (e(B,d0)/e(C1,d1)).  Because there
	is no function to map a Big datatype in to a GT data type.
	
	*/
	M=lxor(A,pfc.hash_to_aes_key(pfc.pairing(B,d0)/(pfc.pairing(C1,d1))));

	/*mip is the Miracl Instance Pointer mip->IOBASE=256. It simply changes the base to work with, we will converted
	the result back to base 256 from base 16, because if we output the result in base 16 it will not be same as 
	the ipnut. Becuase the input was in base 256. So we need to change back the base of number system to 256. So that
	we can get the same output and input display.
	*/
	mip->IOBASE=256; 

	// Print the decrypted message.
	cout << "Decrypted message=" << M << endl;
	cout << "**************************************************************" << endl;
	 
	
	system("pause");
	 return 0;
}
