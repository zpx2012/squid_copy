#ifndef INTERVAL_BOOST_H
#define INTERVAL_BOOST_H

#include <vector>
#include <string>
#include <pthread.h>
#include <chrono>
#include <boost/icl/interval_set.hpp>
#include "interval.h"

typedef boost::icl::interval_set<unsigned int> interval_set;
typedef interval_set::interval_type interval_type;


class IntervalList {
public:
    IntervalList() {
        // Intervals.clear();
        pthread_mutex_init(&mutex_intervals, NULL);
    }

    ~IntervalList() {
        Intervals.clear();
        pthread_mutex_destroy(&mutex_intervals);
    }
    unsigned int size() { return boost::icl::interval_count(Intervals); }
    unsigned int total_bytes();

    void clear();
    void clear_withLock();

    interval_set::iterator begin() { return Intervals.begin(); }
    interval_set::iterator end() { return Intervals.end(); }

    unsigned int getFirstEnd();
    // unsigned int getFirstEnd_withLock();
    unsigned int getLastEnd();
    // unsigned int getLastEnd_withLock();
    unsigned int getElem_withLock(unsigned int index, bool is_start);
    interval_set& getIntervalList() { return Intervals; }
    pthread_mutex_t* getMutex() { return &mutex_intervals; }

    // Function to insert new interval and merge overlapping intervals
    void insert(Interval newInterval);
    void insert_withLock(Interval newInterval);
    void insertNewInterval(unsigned int start, unsigned int end);
    void insertNewInterval(Interval newInterval);
    void insertNewInterval_withLock(Interval newInterval);
    void insertNewInterval_withLock(unsigned int start, unsigned int end);
    // unsigned int insertNewInterval_getLastEnd_withLock(unsigned int start, unsigned int end);
    bool checkAndinsertNewInterval(unsigned int start, unsigned int end, int &order_flag);
    bool checkAndinsertNewInterval_withLock(unsigned int start, unsigned int end, int &order_flag);
    bool checkAndinsertNewInterval_withLock(unsigned int start, unsigned int end);

    // Function to insert new interval and merge overlapping intervals
    void removeInterval(unsigned int start, unsigned int end);
    void removeInterval_withLock(unsigned int start, unsigned int end);
    // void removeInterval_updateTimer(unsigned int start, unsigned int end);

    void substract(IntervalList* other);
    bool contains(unsigned int start, unsigned int end);
    
    void printIntervals();
    void printIntervals_withLock();

    std::string Intervals2str();
    std::string Intervals2str_withLock();

private:
    interval_set Intervals;
    // std::vector<Interval> Intervals;
    pthread_mutex_t mutex_intervals;
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