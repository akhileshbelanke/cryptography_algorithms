#include "stdio.h"
#include "math.h"
#include "prime_numbers_list.h"

#define ENABLE_RSA        1
#define MAX_LIMIT_COPRIME 10000
#define NUM_BITS_IN_A_KEY 32
#define MSG_PACKET_SIZE   129

unsigned long int prime_1 = 1451;//38201 ;//3167;//1301;//151;//59;//13;//113;//3167;
unsigned long int prime_2 = 2011;//38201 ;//7547;//2143;//101;//103;//29;//127;//7547;

unsigned long long int public_key_n  = 0;
unsigned long long int public_key_e  = 0;
unsigned long long int private_key   = 0;
unsigned long long int private_phi   = 0;
unsigned long long int co_prime_indx = 0;
unsigned long long int coprime_list[MAX_LIMIT_COPRIME]   = {0};
unsigned long long int residue_list[NUM_BITS_IN_A_KEY+1] = {0};

unsigned int calculate_gcd(unsigned int a, unsigned int b)
{
    if (a > b)
    {
        if(b == 0)
        {
            return a;
        }
        else
        {
            return calculate_gcd(b, a%b);
        }
    }
    else
    {
        if(a==0)
        {
            return b;
        }
        else
        {
            return calculate_gcd(a, b%a);
        }
    }
}

unsigned long long int calculate_phi(unsigned int p_num, unsigned int q_num)
{
    // This function assumes that p_num and q_num both are prime are numbers
    return ((p_num - 1) * (q_num - 1));
}

unsigned int check_if_coprime(unsigned int num1, unsigned int num2)
{
    if(calculate_gcd(num1, num2) == 1)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

unsigned int update_co_prime_list_of_number(unsigned long int number)
{
    int i = 0;
    for(i = 0; i < number; i++)
    {
        if(check_if_coprime(number, i) == 1)
        {
            coprime_list[co_prime_indx] = i;
            if(co_prime_indx == MAX_LIMIT_COPRIME)
            {
                break;
            }
            else
            {
                co_prime_indx++;
            }
        }
    }

    return co_prime_indx;
}

unsigned long int calculatePublicKey_e(int random_number)
{
    return coprime_list[random_number];
}

unsigned long int calculatePublicKey_n(unsigned int p_num, unsigned int q_num)
{
    unsigned long int n_value = (p_num * q_num);
    return n_value;
}

unsigned long int calculatePrivateKey(unsigned long int pub_key, unsigned long int p_val, unsigned long int q_val)
{
    unsigned long int phi = (p_val - 1) * (q_val - 1);
    unsigned int iterator = 1;
    while(iterator < phi)
    {
        if(((pub_key * iterator) % phi) == 1) 
        {
            return iterator;
        }
        iterator++;
    }
}

unsigned long long int calculate_modular_exponent(unsigned int number, unsigned long long int exponent, unsigned long long int modulus)
{
    // number ^ 1, number ^ 1*2, number ^ 1*2*2, .... , 
    unsigned int temp_exponent = 1, residue_list_pointer = 1;
    residue_list[residue_list_pointer] = number%modulus;
    unsigned long int mask = 0x1;
    unsigned long long int new_base = 0x1;
    unsigned long long int product = 1;
    while(temp_exponent < exponent)
    {   
        residue_list_pointer++;
        product = (residue_list[residue_list_pointer - 1] * residue_list[residue_list_pointer - 1]);
        residue_list[residue_list_pointer] = product % modulus;
        temp_exponent = temp_exponent * 2;
    }
    int i=1;
    for(i=1; i <= residue_list_pointer; i++)
    {
        if((exponent&mask) != 0)
        {
            new_base = new_base * residue_list[i];
            new_base = new_base % modulus;
        }
        mask = mask << 1;
    }
    return (new_base%modulus);
}

unsigned long long int encrypt_message(unsigned int msg, unsigned long long int pub_e, unsigned long long int pub_n)
{
    unsigned long long int enc_msg = calculate_modular_exponent(msg, pub_e, pub_n);
    return enc_msg;
}

unsigned long int decrypt_message(unsigned int msg, unsigned long int priv, unsigned long int pub_n)
{
    unsigned long long int dec_msg = calculate_modular_exponent(msg, priv, pub_n);
    return dec_msg;
}

int main()
{
    unsigned int message         = 0;
    unsigned int message_end     = message + MSG_PACKET_SIZE;
    int random                   = 10;
    int total_correct_decrytions = 0;
    unsigned int phi_of_phi      = 0;

    private_phi  = calculate_phi(prime_1, prime_2);
    phi_of_phi   = update_co_prime_list_of_number(private_phi);
    public_key_n = calculatePublicKey_n(prime_1, prime_2);

    printf("start p = %lu, q = %lu \n", prime_1, prime_2);
    printf("private phi = %llu \n", private_phi);
    printf("phi(phi)=%u \n", phi_of_phi);
    printf("1st public key done n = %llu \n", public_key_n); 

    for(random = 0; random < phi_of_phi; random++)
    {
        public_key_e = calculatePublicKey_e(random);
        private_key  = calculatePrivateKey(public_key_e, prime_1, prime_2);

        unsigned long long int decrypt_array[MSG_PACKET_SIZE+1] = {0}; 
        unsigned long long int input_array[MSG_PACKET_SIZE+1] = {0}; 
        int count_num_matches = 0;
        int i=0, i_msg;
        for(i_msg = message; i_msg <= message_end; i_msg++)
        {
            unsigned long long int encrypted_msg = encrypt_message(i_msg, public_key_e, public_key_n);
            unsigned long long int decrypted_msg = decrypt_message(encrypted_msg, private_key, public_key_n);
            
            decrypt_array[i] = decrypted_msg; 
            input_array[i] = i_msg; 
            i++;
        }

        for(i=0; i <= MSG_PACKET_SIZE; i++)
        {
            if(input_array[i] == decrypt_array[i])
            {
                count_num_matches++;
            }
        }

        if(count_num_matches == (MSG_PACKET_SIZE+1))
        {
            printf("All %d msg decrypted successfully for %d and e=%llu \n", MSG_PACKET_SIZE, random, public_key_e);
            total_correct_decrytions++;
        }
        
    }

    if(total_correct_decrytions == (phi_of_phi))
    {
        printf("Successfully Decrypted All Input messages.");
    }

    printf("\n total_correct_decrytions = (%d / %d) \n", total_correct_decrytions, phi_of_phi);

    return 0;
}
