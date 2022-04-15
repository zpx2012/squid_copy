#include "interval_boost.h"
#include <boost/range/adaptor/strided.hpp>
#include <stdio.h>
#include "logging.h"
#include <string.h>
#include <iostream>

void IntervalList::clear(){
    Intervals.clear();
}

void IntervalList::clear_withLock(){
    pthread_mutex_lock(&mutex_intervals);
    Intervals.clear();
    pthread_mutex_unlock(&mutex_intervals);
}


unsigned int IntervalList::total_bytes()
{
    return Intervals.size();
}

void IntervalList::insertNewInterval_withLock(unsigned int start, unsigned int end)
{
    pthread_mutex_lock(&mutex_intervals);
    std::string before = Intervals2str();
    insertNewInterval(start, end);
    log_debug("[interval]: before-%s insert[%u,%u], after-%s", before.substr(0,490).c_str(), start, end, Intervals2str().substr(0,490).c_str());
    pthread_mutex_unlock(&mutex_intervals);
}

void IntervalList::insertNewInterval_withLock(Interval newInterval)
{
    pthread_mutex_lock(&mutex_intervals);
    insertNewInterval(newInterval.start, newInterval.end);
    pthread_mutex_unlock(&mutex_intervals);
}

void IntervalList::insert_withLock(Interval newInterval)
{
    pthread_mutex_lock(&mutex_intervals);
    insert(newInterval);
    pthread_mutex_unlock(&mutex_intervals);
}

bool IntervalList::checkAndinsertNewInterval_withLock(unsigned int start, unsigned int end)
{
    pthread_mutex_lock(&mutex_intervals);
    if(contains(start,end)){
        pthread_mutex_unlock(&mutex_intervals);
        return false;
    }
    unsigned int last_first_end = getFirstEnd();
    insertNewInterval(start, end);
    pthread_mutex_unlock(&mutex_intervals);
    return true;
}


bool IntervalList::checkAndinsertNewInterval(unsigned int start, unsigned int end, int& order_flag)
{
    if(contains(start,end)){
        return false;
    }
    char log[10000]={0};
    std::string before = Intervals2str();
    insertNewInterval(start, end);
    unsigned int last_first_end = getFirstEnd();
    // snprintf(log, 10000, "[interval]: before-%s insert[%u,%u], after-%s", before.substr(0,4900).c_str(), start, end, Intervals2str().c_str());
    if(last_first_end < end){
        order_flag = OUT_OF_ORDER;
        log_debug("%s out-of-order", log);
    }
    else if (last_first_end == end){
        order_flag = IN_ORDER_NEWEST;
        log_debug("%s in order newest", log);
    }
    else{
        order_flag = IN_ORDER_FILL;
        log_debug("%s in order fill", log);
    }
    return true;
}

bool IntervalList::checkAndinsertNewInterval_withLock(unsigned int start, unsigned int end, int& order_flag)
{
    bool ret;
    pthread_mutex_lock(&mutex_intervals);
    ret = checkAndinsertNewInterval(start, end, order_flag);
    pthread_mutex_unlock(&mutex_intervals);
    return ret;
}

// unsigned int IntervalList::insertNewInterval_getLastEnd_withLock(unsigned int start, unsigned int end)
// {
//     unsigned lastend = 0;
//     pthread_mutex_lock(&mutex_intervals);
//     insertNewInterval(start, end);
//     lastend = getLastEnd();
//     pthread_mutex_unlock(&mutex_intervals);
//     return lastend;
// }

void IntervalList::removeInterval_withLock(unsigned int start, unsigned int end)
{
    pthread_mutex_lock(&mutex_intervals);
    removeInterval(start, end);
    pthread_mutex_unlock(&mutex_intervals);
}

void IntervalList::printIntervals_withLock()
{
    pthread_mutex_lock(&mutex_intervals);
    printIntervals();
    pthread_mutex_unlock(&mutex_intervals);
}


std::string IntervalList::Intervals2str_withLock()
{
    pthread_mutex_lock(&mutex_intervals);
    std::string str = Intervals2str();
    pthread_mutex_unlock(&mutex_intervals);
    return str;
}

// unsigned int IntervalList::getFirstEnd_withLock()
// {
//     unsigned start = 0;
//     pthread_mutex_lock(&mutex_intervals);
//     if(!Intervals.empty())
//         start = Intervals.begin()->end;
//     pthread_mutex_unlock(&mutex_intervals);    
//     return start;
// }

// unsigned int IntervalList::getLastEnd_withLock()
// {
//     unsigned end = 0;
//     pthread_mutex_lock(&mutex_intervals);
//     if(!Intervals.empty())
//         end = (Intervals.end()-1)->end;
//     pthread_mutex_unlock(&mutex_intervals);
//     return end;
// }

unsigned int IntervalList::getFirstEnd()
{
    if (!Intervals.empty())
        return Intervals.begin()->upper();
    else
        return 0;
}

unsigned int IntervalList::getLastEnd()
{
    if (!Intervals.empty())
        return prev(Intervals.end())->upper();
    else
        return 0;
}

unsigned int IntervalList::getElem_withLock(unsigned int index, bool is_start)
{
    if(index < 0)
        return 0;

    unsigned ret = 0;
    pthread_mutex_lock(&mutex_intervals);
    if(boost::icl::interval_count(Intervals) > index){
        auto strided = Intervals | boost::adaptors::strided(index);
        auto elem = next(strided.begin());
        if(is_start)
            ret = elem->lower();
        else
            ret = elem->upper();
    }
    pthread_mutex_unlock(&mutex_intervals);
    return ret;
}

bool IntervalList::contains(unsigned int start, unsigned int end){
    return boost::icl::contains(Intervals, interval_type::right_open(start, end));
}

// Function to insert new interval and
// merge overlapping intervals
void IntervalList::insert(Interval newInterval)
{
    // Interval newInterval = Interval(start, end);
    unsigned int start = newInterval.start;
    unsigned int end = newInterval.end;
    Intervals.insert(interval_type::right_open(start, end));
}

void IntervalList::insertNewInterval(Interval newInterval)
{
    insertNewInterval(newInterval.start, newInterval.end);
}

// Function to insert new interval and
// merge overlapping intervals
void IntervalList::insertNewInterval(unsigned int start, unsigned int end)
{
    Intervals.insert(interval_type::right_open(start, end));
}


// Function to insert new interval and
// merge overlapping intervals
void IntervalList::removeInterval(unsigned int start, unsigned int end)
{
    Intervals.erase(interval_type::right_open(start, end));
}

void IntervalList::substract(IntervalList* other){
    // std::vector<Interval> other_intervals = other->getIntervalList();
    for(auto& intvl: other->Intervals){
        Intervals.subtract(interval_type::right_open(intvl.lower(), intvl.upper()));
        if(Intervals.empty())
            return;
    }
}



void IntervalList::printIntervals(){
    std::cout << Intervals << std::endl;
    // for(auto it = Intervals.begin(); it != Intervals.end(); it++)
    //     printf("[%u, %u), ", it->lower(), it->upper());
    // printf("\n");
}

std::string IntervalList::Intervals2str(){
    if(!size())
        return "";

    std::string result = "";
    char temp[100] = {0};
    for(auto it = Intervals.begin(); it != Intervals.end(); it++){
        memset(temp, 0, 100);
        sprintf(temp, "[%u, %u), ", it->lower(), it->upper());
        result += temp;
    }
        // result += "[" + std::to_string(Intervals[i].start) + ", " + std::to_string(Intervals[i].end) + "], ";
    return result;
}