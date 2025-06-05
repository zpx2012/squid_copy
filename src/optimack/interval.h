#ifndef INTERVAL_H
#define INTERVAL_H

#include <vector>
#include <string>
#include <pthread.h>
#include <chrono>

// Define the structure of interval
struct Interval
{
    unsigned int start;
    unsigned int end;
    // bool sent;
    unsigned int last_recved;
    double sent_epoch_time, recved_epoch_time;//std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count()

    Interval()
        : start(0), end(0), last_recved(0), sent_epoch_time(0), recved_epoch_time(0)
    {
        // sent = false;
    }
    Interval(unsigned int s, unsigned int e)
        : start(s), end(e), last_recved(0), sent_epoch_time(0), recved_epoch_time(0)
    {
        // sent = false;
    }
    Interval(unsigned int s, unsigned int e, double sent_time)
        : start(s), end(e), last_recved(0), sent_epoch_time(sent_time), recved_epoch_time(0)
    {
    }// A subroutine to check if intervals overlap or not.
    
    bool overlaps(Interval b)
    {
        return (std::min(end, b.end) >= std::max(start, b.start));
    }

    bool contains(Interval b){
        return start <= b.start && end >= b.end;
    }

    Interval intersect(Interval that) {
        if (!overlaps(that)) {
            return Interval();
        }
        return Interval{std::max(start, that.start), std::min(end, that.end)};
    }    
    int length(){
        if(start < end)
            return end - start;
        else
            return 0;
    }
};



#endif