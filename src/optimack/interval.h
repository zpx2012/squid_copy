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

typedef enum
{
    OUT_OF_ORDER = 0,
    IN_ORDER_NEWEST = 1,
    IN_ORDER_FILL = 2
} ORDER_TYPE;

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

    void clear();
    void clear_withLock();

    unsigned int getFirstEnd();
    unsigned int getFirstEnd_withLock();
    unsigned int getLastEnd();
    unsigned int getLastEnd_withLock();
    unsigned int getElem_withLock(unsigned int index, bool is_start);
    std::vector<Interval>& getIntervalList() { return Intervals; }
    pthread_mutex_t* getMutex() { return &mutex_intervals; }

    // Function to insert new interval and merge overlapping intervals
    void insert(Interval newInterval);
    void insert_withLock(Interval newInterval);
    void insertNewInterval(unsigned int start, unsigned int end);
    void insertNewInterval(Interval newInterval);
    void insertNewInterval_withLock(Interval newInterval);
    void insertNewInterval_withLock(unsigned int start, unsigned int end);
    unsigned int insertNewInterval_getLastEnd_withLock(unsigned int start, unsigned int end);
    bool checkAndinsertNewInterval(unsigned int start, unsigned int end, int &order_flag);
    bool checkAndinsertNewInterval_withLock(unsigned int start, unsigned int end, int &order_flag);
    bool checkAndinsertNewInterval_withLock(unsigned int start, unsigned int end);

    // Function to insert new interval and merge overlapping intervals
    void removeInterval(unsigned int start, unsigned int end);
    void removeInterval_withLock(unsigned int start, unsigned int end);
    void removeInterval_updateTimer(unsigned int start, unsigned int end);

    void substract(IntervalList* other);
    bool contains(unsigned int start, unsigned int end);
    
    void printIntervals();
    void printIntervals_withLock();

    std::string Intervals2str();
    std::string Intervals2str_withLock();

private:
    
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