// ---------------------------------------------------------------------------
// Project: Simplified DES
// Description: Implementation and testing of Simplified Data Encryption Standard
// Author: Piriate3King
// Date: 2023-02-11
// ---------------------------------------------------------------------------

#include <iostream>
#include <array>
#include <string>
#include <math.h>

using namespace std;

// ---------------------------------------------------------------------------
// Permutation Tables
// ---------------------------------------------------------------------------
const array<int, 10> P10 = { 3,5,2,7,4,10,1,9,8,6 };
const array<int, 8> P8 = { 6,3,7,4,8,5,10,9 };
const array<int, 4> P4 = { 2,4,3,1 };
const array<int, 8> IP = { 2,6,3,1,4,8,5,7 };
const array<int, 8> INVIP = { 4,1,3,5,7,2,8,6 };
const array<int, 8> EP = { 4,1,2,3,2,3,4,1 };

// ---------------------------------------------------------------------------
// S-Boxes
// ---------------------------------------------------------------------------
const int S0[4][4] = { {1,0,3,2},
                      {3,2,1,0},
                      {0,2,1,3},
                      {3,1,3,2} };
const int S1[4][4] = { {0,1,2,3},
                      {2,0,1,3},
                      {3,0,1,0},
                      {2,1,0,3} };
const int S1MOD[4][4] = { {2,1,0,3},
                         {2,0,1,3},
                         {3,0,1,0},
                         {0,1,2,3} };

// ---------------------------------------------------------------------------
// Function Prototypes
// ---------------------------------------------------------------------------
void readInput(array<int, 8>& pText, array<int, 10>& key, char& s1Sel);
array<int, 8> encrypt(array<int, 8>& pText, array<int, 10>& key, char s1Sel);
void decrypt(array<int, 8>& cText, array<int, 10>& key, char s1Sel);
void subKeyGen(array<int, 10>& key, array<int, 8>& subKey1, array<int, 8>& subKey2);
array<int, 4> fk(array<int, 4>& left, array<int, 4>& right, array<int, 8>& subKey, char s1Sel);
array<int, 4> sbox(array<int, 8>& input, char s1Sel);

//Template functions
template<size_t SIZE1, size_t SIZE2>
array<int, SIZE2> perm(array<int, SIZE1>& input, const array<int, SIZE2>& permTable);

template<size_t SIZE>
void split(array<int, SIZE>& input, array<int, SIZE / 2>& out1, array<int, SIZE / 2>& out2);

template<size_t SIZE>
array<int, SIZE> cshift(array<int, SIZE>& arr, int times);

template<size_t SIZE>
array<int, (SIZE * 2)> combine(array<int, SIZE>& in1, array<int, SIZE>& in2);

template<size_t SIZE>
array<int, SIZE> arrayXOR(array<int, SIZE>& arr1, array<int, SIZE>& arr2);

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
int main()
{
    array<int, 8> pText, cText;
    array<int, 10> key;
    char s1Sel = 'N';

    readInput(pText, key, s1Sel);
    cText = encrypt(pText, key, s1Sel);
    decrypt(cText, key, s1Sel);

    return 0;
}

// ---------------------------------------------------------------------------
// Function Definitions
// ---------------------------------------------------------------------------

//Prompt and read user input for plaintext and key
void readInput(array<int, 8>& pText, array<int, 10>& key, char& s1Sel)
{
    int temp;

    cout << "Enter the 8-bit plaintext: ";
    cin >> temp;

    for (int i = 7; i >= 0; --i)
    {
        pText[i] = temp % 10;
        temp /= 10;
    }

    cout << "Enter the 10-bit key: ";
    cin >> temp;

    for (int i = 9; i >= 0; --i)
    {
        key[i] = temp % 10;
        temp /= 10;
    }

    //Prompt for which S1 box to use
    cout << "Use modified S1 box? (y/n) ";
    cin >> s1Sel;
}

//Encrypt pText with key, return ciphertext array
array<int, 8> encrypt(array<int, 8>& pText, array<int, 10>& key, char s1Sel)
{
    array<int, 8> subKey1, subKey2, cText;
    array<int, 8> temp;
    array<int, 4> left, right;

    subKeyGen(key, subKey1, subKey2);

    //IP
    temp = perm(pText, IP);

    //fk1
    split(temp, left, right);
    left = fk(left, right, subKey1, s1Sel);

    //SW
    left.swap(right);
    temp = combine(left, right);

    //Print result after swap
    cout << "\nAfter swap: \t";
    for (int i = 0; i < 8; ++i)
        cout << temp[i];

    //fk2
    left = fk(left, right, subKey2, s1Sel);
    temp = combine(left, right);

    //IP-1
    cText = perm(temp, INVIP);

    //Print ciphertext
    cout << "\nCiphertext: \t";
    for (int i = 0; i < 8; ++i)
        cout << cText[i];

    return cText;
}

//Decrypt cText with key; returns plaintext array
void decrypt(array<int, 8>& cText, array<int, 10>& key, char s1Sel)
{
    array<int, 8> subKey1, subKey2, pText;
    array<int, 8> temp;
    array<int, 4> left, right;

    subKeyGen(key, subKey1, subKey2);

    //IP
    temp = perm(cText, IP);

    //fk2
    split(temp, left, right);
    left = fk(left, right, subKey2, s1Sel);

    //SW
    left.swap(right);
    temp = combine(left, right);

    //Print result after swap
    cout << "\nAfter swap: \t";
    for (int i = 0; i < 8; ++i)
        cout << temp[i];

    //fk1
    left = fk(left, right, subKey1, s1Sel);
    temp = combine(left, right);

    //IP-1
    pText = perm(temp, INVIP);

    //Print decrypted plaintext
    cout << "\nPlaintext: \t";
    for (int i = 0; i < 8; ++i)
        cout << pText[i];
}

//Generate subkeys k1 and k2; return by reference
void subKeyGen(array<int, 10>& key, array<int, 8>& subKey1, array<int, 8>& subKey2)
{
    array<int, 10> p10Key;
    array<int, 5> left, right;
    array<int, 10> ls1, ls2;

    //P10
    p10Key = perm(key, P10);

    //LS-1
        //split left/right 5 elements of p10Key,
        //perform circular left shift of 1 on each, then combine again into ls1
    split(p10Key, left, right);
    left = cshift(left, 1);
    right = cshift(right, 1);
    ls1 = combine(left, right);

    //LS-2
        //split left/right 5 elements of ls1,
        //perform circular left shift of 2 on each, then combine again into ls2
    split(ls1, left, right);
    left = cshift(left, 2);
    right = cshift(right, 2);
    ls2 = combine(left, right);

    //P8 for K1
    subKey1 = perm(ls1, P8);

    //P8 for K2
    subKey2 = perm(ls2, P8);
}

//Perform standard permutations; return permutated array
template<size_t SIZE_IN, size_t SIZE_OUT>
array<int, SIZE_OUT> perm(array<int, SIZE_IN>& input, const array<int, SIZE_OUT>& permTable)
{
    array<int, SIZE_OUT> out;

    for (size_t i = 0; i < SIZE_OUT; ++i)
        out[i] = input[permTable[i] - 1];

    return out;
}

//Split input of size SIZE into two equal sized outputs; return halves by reference
template<size_t SIZE>
void split(array<int, SIZE>& input, array<int, SIZE / 2>& out1, array<int, SIZE / 2>& out2)
{
    size_t halfSize = SIZE / 2;

    for (size_t i = 0; i < halfSize; ++i)
    {
        out1[i] = input[i];
        out2[i] = input[i + halfSize];
    }
}

//Perform circular left shift on array arr of size SIZE; returns shifted array
template<size_t SIZE>
array<int, SIZE> cshift(array<int, SIZE>& arr, int times)
{
    array<int, SIZE> temp;

    for (size_t i = 0; i < SIZE; ++i)
    {
        if ((i + times) >= SIZE)
            temp[i] = arr[i + times - SIZE];
        else
            temp[i] = arr[i + times];
    }

    return temp;
}

//Combine two arrays of equal size; returns combined array
template<size_t SIZE>
array<int, (SIZE * 2)> combine(array<int, SIZE>& in1, array<int, SIZE>& in2)
{
    array<int, (SIZE * 2)> out;

    copy(in1.begin(), in1.end(), out.begin());

    copy(in2.begin(), in2.end(), out.begin() + SIZE);

    return out;
}

//Perform fk function on two arrays representing 4 bits each; returns array of the modified L
array<int, 4> fk(array<int, 4>& left, array<int, 4>& right, array<int, 8>& subKey, char s1Sel)
{
    array<int, 4> postSBox, f;
    array<int, 8> ep, xorKey;

    //EP
    ep = perm(right, EP);

    //EP XOR K
    xorKey = arrayXOR(ep, subKey);

    //S-Box functions
    postSBox = sbox(xorKey, s1Sel);

    //P4
    f = perm(postSBox, P4);

    //L XOR F()
    return arrayXOR(left, f);
}

//Perform XOR operation on values of 2 arrays of size SIZE; returns XOR'd array
template<size_t SIZE>
array<int, SIZE> arrayXOR(array<int, SIZE>& arr1, array<int, SIZE>& arr2)
{
    array<int, SIZE> out;

    for (size_t i = 0; i < SIZE; ++i)
        out[i] = arr1[i] ^ arr2[i];

    return out;
}

//Perform S-Box functions; returns array representing 4 bit value
array<int, 4> sbox(array<int, 8>& input, char s1Sel)
{
    array<int, 4> left, right, finalNib;
    array<int, 2> rowS0, colS0, rowS1, colS1;
    int r0 = 0, c0 = 0, r1 = 0, c1 = 0;
    int s0, s1;

    //split in half
    split(input, left, right);

    //assign lookup values
    rowS0[0] = left[0];
    rowS0[1] = left[3];
    colS0[0] = left[1];
    colS0[1] = left[2];

    rowS1[0] = right[0];
    rowS1[1] = right[3];
    colS1[0] = right[1];
    colS1[1] = right[2];

    //convert array values to binary and calculate decimal
    //values for s-box rows and columns
    for (int i = 1, exp = 0; i >= 0; --i, ++exp)
    {
        r0 += (pow(2, exp) * rowS0[i]);
        c0 += (pow(2, exp) * colS0[i]);
        r1 += (pow(2, exp) * rowS1[i]);
        c1 += (pow(2, exp) * colS1[i]);
    }

    //perform s-box lookups
    s0 = S0[r0][c0];

    if (toupper(s1Sel) == 'Y')
        s1 = S1MOD[r1][c1];
    else
        s1 = S1[r1][c1];

    //convert decimal values back to binary and build 4 'bit' array
    for (int i = 3, cnt = 0; i >= 0; --i, ++cnt)
    {
        if (i > 1)
            finalNib[cnt] = (s0 >> (i - 2)) & 1;
        else
            finalNib[cnt] = (s1 >> i) & 1;
    }

    return finalNib;
}
