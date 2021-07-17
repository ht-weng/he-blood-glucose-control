#include <cstddef>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <string>
#include <chrono>
#include <random>
#include <thread>
#include <mutex>
#include <memory>
#include <limits>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <stdio.h>
#include <assert.h>
#include <sstream>
#include <stdlib.h>
#include <chrono>
#include <tuple>
#include "seal/seal.h"

using namespace std;
using namespace seal;
using namespace std::chrono;

/*
Helper function: Prints the parameters in a SEALContext.
*/
inline void print_parameters(const seal::SEALContext &context)
{
    auto &context_data = *context.key_context_data();

    /*
    Which scheme are we using?
    */
    std::string scheme_name;
    switch (context_data.parms().scheme())
    {
    case seal::scheme_type::bfv:
        scheme_name = "BFV";
        break;
    case seal::scheme_type::ckks:
        scheme_name = "CKKS";
        break;
    default:
        throw std::invalid_argument("unsupported scheme");
    }
    std::cout << "/" << std::endl;
    std::cout << "| Encryption parameters :" << std::endl;
    std::cout << "|   scheme: " << scheme_name << std::endl;
    std::cout << "|   poly_modulus_degree: " <<
        context_data.parms().poly_modulus_degree() << std::endl;

    /*
    Print the size of the true (product) coefficient modulus.
    */
    std::cout << "|   coeff_modulus size: ";
    std::cout << context_data.total_coeff_modulus_bit_count() << " (";
    auto coeff_modulus = context_data.parms().coeff_modulus();
    std::size_t coeff_mod_count = coeff_modulus.size();
    for (std::size_t i = 0; i < coeff_mod_count - 1; i++)
    {
        std::cout << coeff_modulus[i].bit_count() << " + ";
    }
    std::cout << coeff_modulus.back().bit_count();
    std::cout << ") bits" << std::endl;

    /*
    For the BFV scheme print the plain_modulus parameter.
    */
    if (context_data.parms().scheme() == seal::scheme_type::bfv)
    {
        std::cout << "|   plain_modulus: " << context_data.
            parms().plain_modulus().value() << std::endl;
    }

    std::cout << "\\" << std::endl;
}

/*
Helper function: Prints the `parms_id' to std::ostream.
*/
inline std::ostream &operator <<(std::ostream &stream, seal::parms_id_type parms_id)
{
    std::ios old_fmt(nullptr);
    old_fmt.copyfmt(std::cout);

    stream << std::hex << std::setfill('0')
        << std::setw(16) << parms_id[0] << " "
        << std::setw(16) << parms_id[1] << " "
        << std::setw(16) << parms_id[2] << " "
        << std::setw(16) << parms_id[3] << " ";

    std::cout.copyfmt(old_fmt);

    return stream;
}

/*
Helper function: Prints a vector of floating-point values.
*/
template<typename T>
inline void print_vector(std::vector<T> vec, std::size_t print_size = 4, int prec = 3)
{
    /*
    Save the formatting information for std::cout.
    */
    std::ios old_fmt(nullptr);
    old_fmt.copyfmt(std::cout);

    std::size_t slot_count = vec.size();

    std::cout << std::fixed << std::setprecision(prec);
    std::cout << std::endl;
    if(slot_count <= 2 * print_size)
    {
        std::cout << "    [";
        for (std::size_t i = 0; i < slot_count; i++)
        {
            std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    else
    {
        vec.resize(std::max(vec.size(), 2 * print_size));
        std::cout << "    [";
        for (std::size_t i = 0; i < print_size; i++)
        {
            std::cout << " " << vec[i] << ",";
        }
        if(vec.size() > 2 * print_size)
        {
            std::cout << " ...,";
        }
        for (std::size_t i = slot_count - print_size; i < slot_count; i++)
        {
            std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    std::cout << std::endl;

    std::cout.copyfmt(old_fmt);
}

// Return the sum of all the Ciphertexts in a vector
inline Ciphertext sum(vector<Ciphertext>& vec, Evaluator &evaluator, double scale) {
    Ciphertext result_encrypted = vec[0];

    for(int i = 1; i < vec.size(); i++) {
        Ciphertext val = vec[i];
        evaluator.add_inplace(result_encrypted, val);
    }
    return result_encrypted;
}

// Return a subset of the vector of Ciphertexts
inline vector<Ciphertext> slice(vector<Ciphertext>& vec, int start=0, int end=-1) {
    int oldlen = vec.size();
    int newlen;

    if (end == -1 or end >= oldlen){
        newlen = oldlen-start;
    } else {
        newlen = end-start;
    }
    vector<Ciphertext> res;

    for (int i = 0; i < newlen; i++) {
        res.push_back(vec[start+i]);
    }
    return res;
}

// Import data in csv file into a vector of doubles
inline vector<double> csv2vec(string file) {
    vector<double> data;
    ifstream inputFile(file);
    int l = 0;

    // Iteratively read lines and push them into the vector
    while (inputFile) {
        l++;
        string line;
        if (!getline(inputFile, line)) {
            break;
        }
        try {
            data.push_back(stof(line));
        }
        catch (const std::invalid_argument e) {
            cout << "NaN found in file " << file << " line " << l
                 << endl;
            e.what();
        }
    }
    if (!inputFile.eof()) {
        cerr << "Could not read file " << file << "\n";
        __throw_invalid_argument("File not found.");
    }
    return data;
}

// Decrytp a vector of Ciphertexts into a vector of doubles
inline vector<double> decryptVec(vector<Ciphertext>& ct, Decryptor &decryptor, CKKSEncoder &encoder) {
    vector<double> res;
    for (int i = 0; i < ct.size(); i++) {
        vector<double> result;
        Plaintext result_plain; 
        decryptor.decrypt(ct[i], result_plain);
        encoder.decode(result_plain, result);
        res.push_back(result[0]);
    }
    return res;
}

// Write data to csv files for plotting
inline void exportData(vector<double> vec, string file) {
    ofstream output_file(file);
    ostream_iterator<double> output_iterator(output_file, "\n");
    copy(vec.begin(), vec.end(), output_iterator);
}

// Calculate the percentage error between two lists of data
inline double pe(vector<double> ls1, vector<double> ls2) {
    if (ls1.size() != ls2.size()) {
        cout << "Error: the input lists are of different length!" << endl;
        return 0.0;
    } else {
        int n = ls1.size();
        double sm = 0.0;
        for (int i = 0; i < n; i++) {
            sm += abs((ls1[i]-ls2[i])/ls2[i])*100;
        }
        return sm/n;
    }
}

// Get the i-th column of a matrix
inline vector<double> get_column(vector<vector<double>> matrix, int index) {
    vector<double> col;
    for (int i = 0; i < matrix.size(); i++) {
        col.push_back(matrix[i][index]);
    }
    return col;
}


// Recursive PID controller
// g only contains the G(t) and G(t-1)
inline tuple<Ciphertext, Ciphertext> pid_controller_recursive(vector<Ciphertext>& Gs, Ciphertext I_t_1, bool day_flag, CKKSEncoder &encoder,
        Evaluator &evaluator, Decryptor &decryptor, RelinKeys &relin_keys, double scale) {

    // Encrypt parameters
    Plaintext K_P, K_P_T_I, K_P_T_D, G_target, neg_one;
    encoder.encode((0.28518519), scale, K_P);
    encoder.encode((-1), scale, neg_one);
    if (day_flag == true) {
        encoder.encode((0.00063374), scale, K_P_T_I);
        encoder.encode((0.00316872), scale, K_P_T_D);
        encoder.encode((5.0), scale, G_target);
    } else {
        encoder.encode((0.00190123), scale, K_P_T_I);
        encoder.encode((0.00475309), scale, K_P_T_D);
        encoder.encode((6.11), scale, G_target);
    }

    Ciphertext U_t, error_1, error_2, P_term, I_term, D_term;

    // e(t) = G(t) - G_target
    // e(t-1) = G(t-1) - G_target
    evaluator.sub_plain(Gs[1], G_target, error_1);
    evaluator.sub_plain(Gs[0], G_target, error_2);

    // K_P * e(t)
    evaluator.multiply_plain(error_1, K_P, P_term);
    evaluator.rescale_to_next_inplace(P_term);
    P_term.scale() = scale;

    // I_t = (K_P / T_I) * error_1 + I_t_1
    evaluator.multiply_plain(error_1, K_P_T_I, I_term);
    evaluator.rescale_to_next_inplace(I_term);
    I_term.scale() = scale;
    evaluator.mod_switch_to_inplace(I_t_1, I_term.parms_id());
    evaluator.add_inplace(I_term, I_t_1);

    // (K_P / T_D) * (error_1 - error_2)
    evaluator.sub(error_1, error_2, D_term);
    evaluator.multiply_plain_inplace(D_term, K_P_T_D);
    evaluator.rescale_to_next_inplace(D_term);
    D_term.scale() = scale;

    // Add all
    evaluator.add(P_term, I_term, U_t);
    evaluator.add_inplace(U_t, D_term);

    // Return PID signal and I(t)
    return make_tuple(U_t, I_term);
}


// Recursive PID controller
// Gs only contains the G(t) and G(t-1)
inline tuple<double, double> pid_controller_recursive_plain(vector<double>& Gs, double I_t_1, bool day_flag) {

    // Parameters
    double K_P, K_P_T_I, K_P_T_D, G_target, U_t, I_t, error_1, error_2;
    K_P = 0.28518519;
    if (day_flag == true) {
        K_P_T_I = 0.00063374;
        K_P_T_D = 0.00316872;
        G_target = 5.0;
    } else {
        K_P_T_I = 0.00190123;
        K_P_T_D = 0.00475309;
        G_target = 6.11;
    }

    // e(t) = G(t) - g_target
    // e(t-1) = G(t-1) - g_target
    error_1 = Gs[1] - G_target;
    error_2 = Gs[0] - G_target;

    I_t = K_P_T_I * error_1 + I_t_1;

    U_t = K_P * error_1 + I_t + K_P_T_D * (error_1 - error_2);

    // if (U_t < 0) {
    //     U_t = 0;
    // } else {
    //     U_t = 16.67 * U_t;
    // }

    // Return ut and current sum of errors
    return make_tuple(U_t, I_t);
}

// Bergman Minimal Model
inline vector<double> bergman(vector<vector<double>>& y, double U, double D) {
    // The last glucose signal G
    double G = y[y.size()-1][0];
    // The last insulin remote compartmen signal X
    double X = y[y.size()-1][1];
    // The last insulin signal I
    double I = y[y.size()-1][2];

    // Parameters
    double G_b = 4.5;
    double X_b = 15.0;
    double I_b = 15.0;
    double P_1 = -0.028;
    double P_2 = -0.025;
    double P_3 = 0.000005;
    double V_I = 12.0;
    double n = 0.09;
    // Minimal Model
    double Gdt = P_1 * (G - G_b) - (X - X_b) * G + D;
    double Xdt = P_2 * (X - X_b) + P_3 * (I - I_b);
    double Idt = -n * I + U/V_I;

    vector<double> dy_dt{Gdt, Xdt, Idt};
    return dy_dt;
}

int main() {
    // SEAL settings
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 50, 30, 30, 30, 50 }));
    double scale = pow(2.0, 30);
    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    // Generate public and private keys
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;
    cout << endl;

    string meal_profile_suffix = "testProfile";

    cout << "Reading meal profile" << endl;
    // vector<double> meal_profile = csv2vec("../data/meal_profile_"+meal_profile_suffix+".csv");
    vector<double> meal_profile = csv2vec("../data/testProfile.csv");
    cout << "Meal profile imported" << endl;

    // Total time (mins) is defined by the length of meal profile
    int time_limit = meal_profile.size();


    cout << "Plaintext simulation starts" << endl;
    // Set up initial conditions
    vector<double> y0_plaintext{4.5, 15.0, 15.0};
    vector<double> y1_plaintext{4.5, 15.0, 15.0};
    vector<vector<double>> y_plaintext{y0_plaintext, y1_plaintext};
    vector<double> U_plaintext;

    double I_t_1_plaintext = 0.0;
    // Simulation
    for (int t = 0; t < time_limit; t++) {
        // Determine whether it is day or night
        // Day is from 6:00-22:00
        // One day has 1440 mins. Day is from 360 min to 1320 min
        bool day_flag;
        if (t % 1440 >= 360 and t % 1440 < 1320) {
            day_flag = true;
        } else {
            day_flag = false;
        }

        vector<double> dy_dt_plaintext;
        tuple<double, double> res_tup_plaintext;
        double U_t_plaintext;
        
        // Get G(t) and G(t-1)
        double G_t_1_plaintext = y_plaintext[y_plaintext.size()-1][0];
        double G_t_2_plaintext = y_plaintext[y_plaintext.size()-2][0];
        vector<double> Gs_plaintext{G_t_2_plaintext, G_t_1_plaintext};

        cout << "Time point (min): " << t << endl;
        cout << "Current glucose level: " << G_t_1_plaintext << endl;


        // Apply PID
        res_tup_plaintext = pid_controller_recursive_plain(Gs_plaintext, I_t_1_plaintext, day_flag);
        
        // Get the insulin infusion signal
        U_t_plaintext = get<0>(res_tup_plaintext);

        // Normalise insulin infusion signals
        if (U_t_plaintext < 0) {
            U_t_plaintext = 0;
        } else {
            U_t_plaintext = 16.67 * U_t_plaintext;
        }

        U_plaintext.push_back(U_t_plaintext);
        // Get I(t) for the recursive sum of the integral term
        I_t_1_plaintext = get<1>(res_tup_plaintext);

        // Bergman Minimal Model simulation
        dy_dt_plaintext = bergman(y_plaintext, U_t_plaintext, meal_profile[t]);
        
        // y(t) = y(t-1) + dy/dt
        vector<double> yt_plaintext;
        for (int i = 0; i < 3; i++) {
            yt_plaintext.push_back(y_plaintext[y_plaintext.size()-1][i]+dy_dt_plaintext[i]);
        }
        
        // Append yt to y
        y_plaintext.push_back(yt_plaintext);
    }

    cout << "Plaintext simulation ends" << endl;

    // Apply recursive PID on Bergman Minimal Model
    // Only the last two errors and the previous sum are passed into the algorithm
    cout << "Encrypted simulation starts" << endl;
    auto recpid_start = high_resolution_clock::now();

    // Set up initial conditions
    vector<double> y0{4.5, 15.0, 15.0};
    vector<double> y1{4.5, 15.0, 15.0};
    vector<vector<double>> y{y0, y1};
    vector<double> U;

    // Initialise I(t-1)
    double zero = 0.0;
    Plaintext zero_plain;
    Ciphertext zero_encrypted;
    encoder.encode(zero, scale, zero_plain);
    encryptor.encrypt(zero_plain, zero_encrypted);
    Ciphertext I_t_1_encrypted;
    I_t_1_encrypted = zero_encrypted;


    // Simulation
    for (int t = 0; t < time_limit; t++) {
        // Determine whether it is day or night
        // Day is from 6:00-22:00
        // One day has 1440 mins. Day is from 360 min to 1320 min
        bool day_flag;
        if (t % 1440 >= 360 and t % 1440 < 1320) {
            day_flag = true;
        } else {
            day_flag = false;
        }

        vector<double> dy_dt;
        tuple<Ciphertext, Ciphertext> res_tup;
        Ciphertext U_t_encrypted;
        Plaintext U_t_plain;
        vector<double> U_t;
        
        // Get G(t) and G(t-1)
        double G_t_1 = y[y.size()-1][0];
        double G_t_2 = y[y.size()-2][0];

        cout << "Time point (min): " << t << endl;
        cout << "Current glucose level: " << G_t_1 << endl;

        // Encrypt G(t) and G(t-1) and store them into a vector
        Plaintext G_t_1_plain, G_t_2_plain;
        encoder.encode(G_t_1, scale, G_t_1_plain);
        encoder.encode(G_t_2, scale, G_t_2_plain);
        Ciphertext G_t_1_encrypted, G_t_2_encrypted;
        encryptor.encrypt(G_t_1_plain, G_t_1_encrypted);
        encryptor.encrypt(G_t_2_plain, G_t_2_encrypted);
        vector<Ciphertext> Gs_encrypted{G_t_2_encrypted, G_t_1_encrypted};

        // Apply PID on encrypted blood glucose level
        res_tup = pid_controller_recursive(Gs_encrypted, I_t_1_encrypted, day_flag, encoder, evaluator, decryptor, 
            relin_keys, scale);
        
        // Decrypt and scale U_t
        U_t_encrypted = get<0>(res_tup);
        decryptor.decrypt(U_t_encrypted, U_t_plain);
        encoder.decode(U_t_plain, U_t);
        // Normalise insulin infusion signals
        if (U_t[0] < 0) {
            U_t[0] = 0;
        } else {
            U_t[0] = 16.67 * U_t[0];
        }
        U.push_back(U_t[0]);

        // Update I(t-1)
        I_t_1_encrypted = get<1>(res_tup);

        // Bergman Minimal Model simulation
        dy_dt = bergman(y, U_t[0], meal_profile[t]);
        
        // y(t) = y(t-1) + dy/dt
        vector<double> yt;
        for (int i = 0; i < 3; i++) {
            yt.push_back(y[y.size()-1][i]+dy_dt[i]);
        }
        
        // Append yt to y
        y.push_back(yt);
    }

    cout << "Encrypted simulation ends" << endl;
    auto recpid_stop = high_resolution_clock::now();
    auto recpid_duration = duration_cast<seconds>(recpid_stop - recpid_start);
    cout << "Encrypted simulation Duration:  " << recpid_duration.count() << " seconds" << endl;
    cout << endl;

    cout << "Output data" << endl;
    cout << endl;

    vector<double> G, X, I, G_plaintext, X_plaintext, I_plaintext;
    G = get_column(y, 0);
    X = get_column(y, 1);
    I = get_column(y, 2);
    G_plaintext = get_column(y_plaintext, 0);
    X_plaintext = get_column(y_plaintext, 1);
    I_plaintext = get_column(y_plaintext, 2);
    exportData(G, "../data/pid_bergman_SEAL_G_"+meal_profile_suffix+".csv");
    exportData(X, "../data/pid_bergman_SEAL_X_"+meal_profile_suffix+".csv");
    exportData(I, "../data/pid_bergman_SEAL_I_"+meal_profile_suffix+".csv");
    exportData(U, "../data/pid_bergman_SEAL_U_"+meal_profile_suffix+".csv");
    exportData(G_plaintext, "../data/pid_bergman_plaintext_G_"+meal_profile_suffix+".csv");
    exportData(X_plaintext, "../data/pid_bergman_plaintext_X_"+meal_profile_suffix+".csv");
    exportData(I_plaintext, "../data/pid_bergman_plaintext_I_"+meal_profile_suffix+".csv");
    exportData(U_plaintext, "../data/pid_bergman_plaintext_U_"+meal_profile_suffix+".csv");
    cout << endl;
}
