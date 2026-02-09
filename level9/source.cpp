// Compile : g++ source.cpp -fno-stack-protector -std=c++98 -m32 -z execstack -z norelro -no-pie
#include <string.h>
#include <stdlib.h>

class N
{
    public:
        N(int value) { this->ptr = &N::operator+; this->_v = value; };
        ~N(void) {};

        // Overloads operators
        int operator+(N *n) { return (this->_v + n->_v); }
        int operator-(N *n) { return (this->_v - n->_v); }

        // Methods
        static void setAnnotation(N* n, char *str)
        {
            memcpy((char *)(n->_buf - 0x4), str, strlen(str));
        }

        int (N::*ptr)(N *n);
        volatile char _buf[0x60];
        int _v;
};


int main(int ac, char **av)
{
  N *a = NULL, *b = NULL;
  
  if (ac < 2) exit(1);

  a = (N *) new N(5);
  b = (N *) new N(6);

  N::setAnnotation(a,av[1]);

  (b->*(b->ptr))(a);
  return (0);
}
