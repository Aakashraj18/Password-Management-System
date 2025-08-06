// Design a password management system using C++ that allows users to create an account with a username and password, login with their credentials, change their password, validate the password, save password and view their password in encrypted form.
// Users can create an account by providing a username and password. The system should enforce the following password criteria:
// At least 8 characters long
// Contains at least one letter
// Contains at least one digit
// Contains at least one of these special characters: <, >, @, !
// The system encrypts passwords using a custom XOR-based encryption algorithm.
// For encryption: char ^ '2'
// For decryption: char ^ '2'



#include <iostream>
#include<limits>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <limits> // Required for numeric_limits
#include <cctype> // Required for isalpha, isdigit, isalnum, isupper
#include <cstdio> // Required for remove and rename
#ifdef _WIN32
#include <conio.h> // Windows for getch
#else
#include <termios.h>
#include <unistd.h>
char getch() {
    char buf = 0;
    struct termios old = {0};
    fflush(stdout);
    if (tcgetattr(STDIN_FILENO, &old) < 0)
        perror("tcgetattr()");
    old.c_lflag &= ~ICANON;
    old.c_lflag &= ~ECHO;
    old.c_cc[VMIN] = 1;
    old.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &old) < 0)
        perror("tcsetattr ICANON");
    if (read(STDIN_FILENO, &buf, 1) < 0)
        perror ("read()");
    old.c_lflag |= ICANON;
    old.c_lflag |= ECHO;
    if (tcsetattr(STDIN_FILENO, TCSADRAIN, &old) < 0)
        perror ("tcsetattr ~ICANON");
    return buf;
}
#endif
using namespace std;

// Base class User
class User {
public:
    string username;
    User(const string& name) : username(name) {}
    virtual bool login() = 0; // Pure virtual function
    virtual ~User() {}
};

// Function to input password masked as '*'
string inputPassword() {
    string password;
    char ch;
    while ((ch =
#ifdef _WIN32
        _getch()
#else
        getch()
#endif
    ) != '\r' && ch != '\n') { // Handle both Enter types
        if (ch == 8 || ch == 127) { // Backspace
            if (!password.empty()) {
                password.pop_back();
                cout << "\b \b";
            }
        } else {
            password += ch;
            cout << '*';
        }
    }
    cout << endl;
    return password;
}


string checkPasswordStrength(const string& password) {
    int score = 0;
    bool hasLetter = false, hasDigit = false, hasSpecial = false;

    if (password.length() >= 8) score++;
    if (password.length() >= 12) score++;

    for (char ch : password) {
        if (isalpha(ch)) hasLetter = true;
        if (isdigit(ch)) hasDigit = true;
        if (!isalnum(ch)) hasSpecial = true;
    }
    if (hasLetter) score++;
    if (hasDigit) score++;
    if (hasSpecial) score++;
    if (isupper(password.front()) || isupper(password.back())) score++;

    if (score <= 2) return "Weak";
    else if (score <= 4) return "Moderate";
    else return "Strong";
}

// PasswordManager class, derived from User
class PasswordManager : public User {
public:
    string filename;
private:
    string password; // Always stored ENCRYPTED

    string encrypt(const string& text) {
        string encrypted_text;
        for (char c : text) {
            encrypted_text.push_back(c ^ '2');
        }
        return encrypted_text;
    }

    string decrypt(const string& text) {
        string decrypted_text;
        for (char c : text) {
            decrypted_text.push_back(c ^ '2');
        }
        return decrypted_text;
    }

    bool verifyPassword(const string& text) {
        if (text.length() < 8) {
            cout << "Password must contain at least 8 characters\n";
            return false;
        }
        bool hasLetter = false, hasDigit = false, hasSpecial = false;
        for (char ch : text) {
            if (isalpha(ch)) hasLetter = true;
            if (isdigit(ch)) hasDigit = true;
            if (ch == '<' || ch == '>' || ch == '@' || ch == '!') hasSpecial = true;
        }
        if (!hasLetter) cout << "Password must contain a letter\n";
        if (!hasDigit) cout << "Password must contain a digit\n";
        if (!hasSpecial) cout << "Password must contain one of these special characters: <, >, @, !\n";

        return hasLetter && hasDigit && hasSpecial;
    }

public:
    PasswordManager(const string& file, const string& name, const string& passwd = "")
        : User(name), filename(file) {
        if (!passwd.empty()) {
            if (verifyPassword(passwd))
                password = encrypt(passwd);
            else {
                password = encrypt("user@1234");
                cout << "Default password \"user@1234\" set because your password was invalid.\n";
            }
        }
    }

    ~PasswordManager() override {
        cout << "\n Account with Username \"" << username << "\" logged out.\nThank you!\n";
    }

    void setEncryptedPassword(string text) { password = text; }
    string getPassword() { return password; }
    string getDecryptedPassword() { return decrypt(password); }

    bool setNewPassword(string text) {
        if (verifyPassword(text)) {
            password = encrypt(text);
            cout << "Password changed successfully.\n";
            updatePasswordInFile();
            return true;
        } else {
            cout << "Password not changed.\n";
            return false;
        }
    }

    bool validatePassword(string text) {
        cout << "Password Strength: " << checkPasswordStrength(text) << endl;
        return encrypt(text) == password;
    }

    // Override the login function from the User base class
    bool login() override {
        int attempts = 3;
        while (attempts--) {
            cout << "Password - ";
            string enteredPassword = inputPassword();
            if (validatePassword(enteredPassword)) {
                cout << "\nLogin Successful!\n";
                return true;
            } else {
                cout << "Incorrect Password. " << attempts << " attempts left.\n";
            }
        }
        cout << "Too many failed attempts. Exiting.\n";
        return false;
    }

    static string getExistingUserPassword(const string& filename, const string& uname) {
        ifstream inFile(filename);
        if (!inFile) return "";
        string line;
        while (getline(inFile, line)) {
            stringstream ss(line);
            string stored_user, stored_pass;
            getline(ss, stored_user, ',');
            getline(ss, stored_pass, ',');
            if (stored_user == uname) return stored_pass;
        }
        return "";
    }

    static bool userExists(const string& filename, const string& uname) {
        return !getExistingUserPassword(filename, uname).empty();
    }

    static bool passwordExists(const string& filename, const string& encpwd) {
        ifstream inFile(filename);
        if (!inFile) return false;
        string line;
        while (getline(inFile, line)) {
            stringstream ss(line);
            string stored_user, stored_pass;
            getline(ss, stored_user, ',');
            getline(ss, stored_pass, ',');
            if (stored_pass == encpwd) return true;
        }
        return false;
    }

    void saveToFile() {
        ofstream outFile(filename, ios::app);
        outFile << username << "," << password << ",\n";
        outFile.close();
        cout << "Data saved to file successfully.\n";
    }

    void updatePasswordInFile() {
        ifstream inFile(filename);
        if (!inFile) {
            cout << "Failed to open file for reading.\n";
            return;
        }
        ofstream tempFile("temp.txt");
        string line;
        bool updated = false;

        while (getline(inFile, line)) {
            stringstream ss(line);
            string stored_user, stored_pass;
            getline(ss, stored_user, ',');
            getline(ss, stored_pass, ',');

            if (stored_user == username) {
                tempFile << username << "," << password << ",\n";
                updated = true;
            } else {
                tempFile << line << "\n";
            }
        }
        inFile.close();
        tempFile.close();

        remove(filename.c_str());
        rename("temp.txt", filename.c_str());

        if (updated)
            cout << "Password updated in file successfully.\n";
        else
            cout << "Username not found while updating.\n";
    }
};


// Main function
int main() {
    int userChoice;
    cout << "Welcome to Password Manager\n";
    cout << "----------------------------\n";
    cout << "1. Existing User\n2. New User\n";
    cout << "Enter your choice: ";
    cin >> userChoice;
    cin.ignore(numeric_limits<streamsize>::max(), '\n');

    User* userPtr = nullptr; // Use a pointer to the base class

    if (userChoice == 1) {
        string username;
        cout << "Username - ";
        getline(cin, username);
        string storedPassword = PasswordManager::getExistingUserPassword("password.txt", username);

        if (!storedPassword.empty()) {
            PasswordManager* pwd = new PasswordManager("password.txt", username);
            pwd->setEncryptedPassword(storedPassword);
            userPtr = pwd; // Assign the derived class object to the base class pointer
            if (!userPtr->login()) {
                delete userPtr;
                return 1;
            }
        } else {
            cout << "Username not found.\n";
            return 1;
        }
    }
    else if (userChoice == 2) {
        string username, password, encryptedPassword;
        while (true) {
            cout << "Choose a Username - ";
            getline(cin, username);

            if (PasswordManager::userExists("password.txt", username)) {
                cout << "Username already exists. Try another.\n";
            } else {
                break;
            }
        }

        while (true) {
            cout << "\nPassword must satisfy:\n- At least 8 characters\n- A letter\n- A digit\n- One of these: <, >, @, !\n";
            cout << "Create Password - ";
            password = inputPassword();

            PasswordManager temp("password.txt", username, password);
            string decrypted = temp.getDecryptedPassword();

            if (decrypted == "user@1234" && password != "user@1234") {
                encryptedPassword = temp.getPassword();
                break;
            }
            if (PasswordManager::passwordExists("password.txt", temp.getPassword())) {
                cout << "Password already in use. Try another.\n";
            } else {
                encryptedPassword = temp.getPassword();
                break;
            }
        }

        PasswordManager* pwd = new PasswordManager("password.txt", username, "user@1234");
        pwd->setEncryptedPassword(encryptedPassword);
        pwd->saveToFile();
        userPtr = pwd; // Assign the derived class object to the base class pointer

        cout << "\nAccount created successfully!\n";
    }
    else {
        cout << "Invalid choice.\n";
        return 1;
    }

    if (userPtr) {
        cout << "\nPassword Manager - Welcome " << userPtr->username << "!\n";
        int choice;
        PasswordManager* pwd = dynamic_cast<PasswordManager*>(userPtr); // Downcast to access PasswordManager specific methods
        if (pwd) {
            do {
                cout << "\n1. Change Password\n2. Validate Password\n3. View Password\n4. Save to File\n5. Exit\n";
                cout << "--------------------------------------------------\n";
                cout << "Enter your choice: ";
                cin >> choice;
                cin.ignore(numeric_limits<streamsize>::max(), '\n');

                switch (choice) {
                    case 1: {
                        cout << "Enter new password - ";
                        string newpwd = inputPassword();
                        pwd->setNewPassword(newpwd);
                    } break;

                    case 2: {
                        cout << "Enter password to validate - ";
                        string demopwd = inputPassword();
                        if (pwd->validatePassword(demopwd)) {
                            cout << "Correct Password\n";
                        } else {
                            cout << "Incorrect Password\n";
                        }
                    } break;

                    case 3: {
                        cout << "Encrypted Password: " << pwd->getPassword() << endl;
                        cout << "Decrypted Password: " << pwd->getDecryptedPassword() << endl;
                    } break;

                    case 4: {
                        pwd->saveToFile();
                    } break;

                    case 5: {
                        cout << "Logging out...\n";
                    } break;

                    default:
                        cout << "Invalid choice. Try again.\n";
                }
            } while (choice != 5);
        }
        delete userPtr;
    }

    return 0;
}