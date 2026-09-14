#include "cmap.hpp"
#include <cassert>
#include <string>

int main() {
    clibs::Map<std::string, int> ages;

    auto inserted = ages.insert({"alice", 30});
    assert(inserted.second == true);

    auto existing = ages.insert({"alice", 99});
    assert(existing.second == false);

    auto found = ages.find("alice");
    assert(found != ages.end());
    assert(found->second == 30);

    ages["bob"] = 40;
    assert(ages["bob"] == 40);

    ages.erase("alice");
    assert(ages.find("alice") == ages.end());

    assert(ages.size() == 1);
    assert(!ages.empty());

    return 0;
}
