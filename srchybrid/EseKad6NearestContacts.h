#pragma once
#include <array>
#include <cstddef>
namespace ese { namespace discovery {
// Orders caller-validated discovery hints only; never grants a session.
template<std::size_t Capacity> class NearestContacts {
public:
    struct Hint { std::array<unsigned char,16> id{}; std::array<unsigned char,32> node{}; unsigned ordinal=0; };
    explicit NearestContacts(const std::array<unsigned char,16>& target) : target_(target) {}
    bool Add(const std::array<unsigned char,16>& id,const std::array<unsigned char,32>& node,unsigned ordinal) noexcept {
        static_assert(Capacity>0 && Capacity<=64,"bounded hints");
        if(id==std::array<unsigned char,16>{} || node==std::array<unsigned char,32>{}) return false;
        for(unsigned i=0;i<count_;++i) if(hints_[i].id==id || hints_[i].node==node) return false;
        Hint item{id,node,ordinal}; unsigned position=0;
        while(position<count_ && !Before(item,hints_[position])) ++position;
        if(position==Capacity) return false;
        if(count_<Capacity) ++count_;
        for(unsigned i=count_-1;i>position;--i) hints_[i]=hints_[i-1];
        hints_[position]=item; return true;
    }
    unsigned Count() const noexcept { return count_; }
    const Hint& operator[](unsigned i) const noexcept { return hints_[i]; }
private:
    bool Before(const Hint& a,const Hint& b) const noexcept {
        for(unsigned i=0;i<16;++i) {
            const unsigned x=a.id[i]^target_[i],y=b.id[i]^target_[i];
            if(x!=y) return x<y;
        }
        return a.node<b.node;
    }
    std::array<unsigned char,16> target_{};
    std::array<Hint,Capacity> hints_{}; unsigned count_=0;
};
}}
