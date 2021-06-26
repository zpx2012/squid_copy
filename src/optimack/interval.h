#ifndef INTERVAL_H
#define INTERVAL_H

#include <vector>
#include <string>
#include <pthread.h>

// Define the structure of interval
struct Interval
{
    unsigned int start;
    unsigned int end;

    Interval()
        : start(0), end(0)
    {
    }
    Interval(unsigned int s, unsigned int e)
        : start(s), end(e)
    {
    }
};



class IntervalList {
public:
    IntervalList() {
        Intervals.clear();
        pthread_mutex_init(&mutex_intervals, NULL);
    }

    ~IntervalList() {
        Intervals.clear();
        pthread_mutex_destroy(&mutex_intervals);
    }
    unsigned int size() { return Intervals.size(); }
    unsigned int total_bytes();

    unsigned int getFirstEnd();
    unsigned int getFirstEnd_withLock();
    unsigned int getLastEnd();
    unsigned int getLastEnd_withLock();
    unsigned int getElem_withLock(unsigned int index, bool is_start);
    std::vector<Interval>& getIntervalList() { return Intervals; }

    // Function to insert new interval and merge overlapping intervals
    void insertNewInterval(unsigned int start, unsigned int end);
    void insertNewInterval_withLock(unsigned int start, unsigned int end);
    unsigned int insertNewInterval_getLastEnd_withLock(unsigned int start, unsigned int end);
    bool checkAndinsertNewInterval_withLock(unsigned int start, unsigned int end);

    // Function to insert new interval and merge overlapping intervals
    void removeInterval(unsigned int start, unsigned int end);
    void removeInterval_withLock(unsigned int start, unsigned int end);

    void substract(IntervalList* other);
    bool contains(unsigned int start, unsigned int end);
    
    void printIntervals();
    void printIntervals_withLock();

    std::string Intervals2str();
    std::string Intervals2str_withLock();

private:
    // A subroutine to check if intervals overlap or not.
    bool doesOverlap(Interval a, Interval b);
    bool does_a_contains_b(Interval a, Interval b);
    
    std::vector<Interval> Intervals;
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