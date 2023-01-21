#include <iostream>
#include <vector>
#include <string>

class CParam
{
public:

	std::vector<std::string> params;

    bool parse(int argc, char* argv[]);
    void usage();
};

