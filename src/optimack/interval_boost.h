#ifndef INTERVAL_BOOST_H
#define INTERVAL_BOOST_H

#include <vector>
#include <string>
#include <pthread.h>
#include <chrono>
#include <shared_mutex>
#include <mutex>
#include <boost/icl/interval.hpp>
#include <boost/icl/interval_map.hpp>
// #include "interval.h"

typedef enum
{
    OUT_OF_ORDER = 0,
    IN_ORDER_NEWEST = 1,
    IN_ORDER_FILL = 2,
    REQUEST_NEW = 3,
    REQUEST_TIMEOUT = 4
} ORDER_TYPE;

typedef boost::icl::interval_set<uint> interval_set;
typedef boost::icl::interval_map<uint, double> interval_map;
typedef boost::icl::interval<uint> interval_type;


class IntervalList {
public:
    IntervalList() {
    }

    ~IntervalList() {
        clear();
    }

    void read_lock() { smtx.lock_shared(); }
    void read_unlock() { smtx.unlock_shared(); }

    void write_lock() { smtx.lock(); }
    void write_unlock() { smtx.unlock(); }


    unsigned int size();
    unsigned int total_bytes();

    void clear();

    interval_map::iterator begin();
    interval_map::iterator end(); 

    unsigned int getFirstStart();
    unsigned int getFirstEnd();
    unsigned int getLastEnd();
    // unsigned int getElem(unsigned int index, bool is_start);
    interval_map& getIntervalList() { return Intervals; } //?
    
    void insertNewInterval(unsigned int start, unsigned int end);
    // bool checkAndinsertNewInterval(unsigned int start, unsigned int end, int &order_flag);

    interval_map removeInterval(unsigned int start, unsigned int end);
    interval_map getGapsAndUpdateTimer(uint min_seq, int num, int timeout);
    // void removeInterval_updateTimer(unsigned int start, unsigned int end);

    void substract(IntervalList* other);
    bool contains(unsigned int start, unsigned int end);
    
    void printIntervals();
    std::string Intervals2str();

private:
    interval_map Intervals;
    std::shared_mutex smtx;

};

// struct Interval
// {
//     unsigned int start;
//     unsigned int end;
//     std::string timestamp;
//     Interval()
//         : start(0), end(0)
//     {
//     }
//     Interval(unsigned int s, unsigned int e, char* ts)
//         : start(s), end(e), timestamp(ts)
//     {
//     }
//     Interval(unsigned int s, unsigned int e, std::string ts)
//         : start(s), end(e), timestamp(ts)
//     {
//     }
// };

#endif