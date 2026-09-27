// ByteArray.h

#ifndef BYTEARRAY_H

#include <string>
#include <vector>
#include <iterator>
#include <algorithm>
#include <ctime>
#include <cctype>

class ByteArray
{
protected:
    std::vector<unsigned char> _v;

    friend std::ostream & operator << (std::ostream &out, ByteArray &ba)
    {
        std::copy(ba._v.begin(), ba._v.end(), std::ostream_iterator<unsigned char>(out, ""));
        return out;
    }

public:
    ByteArray()
    {
        std::srand((unsigned int)std::time(nullptr));
    }

    ByteArray& padding(size_t const len_padding_byte, unsigned char const padding_char)
    {
        if (len_padding_byte > 0)
            _v.insert(_v.end(), len_padding_byte, padding_char);
        
        return *this;
    }
    ByteArray& padding(size_t const len_padding_byte)
    {
        for (size_t i = 0; i < len_padding_byte; ++i)
            _v.push_back(std::rand() % 26 + (std::rand() % 2 ? 'A' : 'a'));
        
        return *this;
    }
    ByteArray& pack_addr_32(unsigned int addr, size_t const len_padding_byte = 0)
    {
        unsigned char *b = (unsigned char *)&addr;
        for (size_t i = 0; i < 4; ++i)
            _v.push_back(b[i]);

        return padding(len_padding_byte);
    }
    ByteArray& pack_opcode(std::string const &code)
    {
        unsigned char byte(0);
        for (size_t i = 0; i < code.size(); i += 2)
        {
            if (std::isdigit(code[i]))
                byte = (code[i] - '0') << 4;
            else if (std::isalpha(code[i]))
                byte = ((std::toupper(code[i] - 'A') + 10) << 4);
            
            if (std::isdigit(code[i + 1]))
                byte += (code[i + 1] - '0');
            else if (std::isalpha(code[i + 1]))
                byte += ((std::toupper(code[i + 1]) - 'A') + 10);

            _v.push_back(byte);
        }

        return *this;
    }

    size_t size() const
    {
        return _v.size();
    }

    // Operator
    ByteArray &operator += (unsigned int addr)
    {
        return pack_addr_32(addr);
    }
    ByteArray &operator += (std::string const &s)
    {
        for (size_t i = 0; i < s.size(); ++i)
            _v.push_back(s[i]);

        return *this;
    }
    ByteArray &operator += (ByteArray const &ba)
    {
        _v.insert(_v.end(), ba._v.begin(), ba._v.end());
        return *this;
    }

    ByteArray operator + (unsigned int addr)
    {
        return *this += addr;
    }

    ByteArray operator + (std::string const &s)
    {
        return *this += s;
    }

    ByteArray operator + (ByteArray const &ba)
    {
        return *this += ba;
    }

    ByteArray(std::string const &s)
    {
        *this += s;
        std::srand((unsigned int)std::time(nullptr));
    }
};

#endif