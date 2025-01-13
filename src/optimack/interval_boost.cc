#include "interval_boost.h"
#include <boost/range/adaptor/strided.hpp>
#include <stdio.h>
#include "logging.h"
#include <string.h>
#include <iostream>
#include <sstream>
#include <chrono>

bool debug = false;

unsigned int IntervalList::size()
{
    std::shared_lock lock(smtx); 
    return boost::icl::interval_count(Intervals);
}


void IntervalList::clear()
{
    std::unique_lock lock(smtx);
    Intervals.clear();
}


interval_map::iterator IntervalList::begin() 
{ 
    std::shared_lock lock(smtx); 
    return Intervals.begin(); 
}


interval_map::iterator IntervalList::end() 
{ 
    std::shared_lock lock(smtx);
    return Intervals.end(); 
}


unsigned int IntervalList::total_bytes()
{
    std::shared_lock lock(smtx);
    return Intervals.size();
}

// bool IntervalList::checkAndinsertNewInterval(unsigned int start, unsigned int end, int& order_flag)
// {
//     if(contains(start,end)){
//         return false;
//     }
//     char log[10000]={0};
//     std::string before = Intervals2str();
//     insertNewInterval(start, end);
//     unsigned int last_first_end = getFirstEnd();
//     if(debug)
//         printf("[interval]: before-%s insert[%u,%u], after-%s,", before.substr(0,4900).c_str(), start, end, Intervals2str().c_str());

//     // snprintf(log, 10000, "[interval]: before-%s insert[%u,%u], after-%s", before.substr(0,4900).c_str(), start, end, Intervals2str().c_str());
//     if(last_first_end < end){
//         order_flag = OUT_OF_ORDER;
//         if(debug){
//             printf(" out-of-order\n");
//             log_debug("%s out-of-order", log);
//         }
//     }
//     else if (last_first_end == end){
//         order_flag = IN_ORDER_NEWEST;
//         if(debug){
//             printf(" in order newest\n");
//             log_debug("%s in order newest", log);
//         }
//     }
//     else{
//         order_flag = IN_ORDER_FILL;
//         if(debug){
//             printf(" in order fill\n");
//             log_debug("%s in order fill", log);
//         }
//     }
//     return true;
// }

unsigned int IntervalList::getFirstStart()
{
    std::shared_lock lock(smtx);
    if (!Intervals.empty()){
        return Intervals.begin()->first.lower();
    }
    else
        return 0;
}
unsigned int IntervalList::getFirstEnd()
{
    std::shared_lock lock(smtx);
    if (!Intervals.empty())
        return Intervals.begin()->first.upper();
    else
        return 0;
}

unsigned int IntervalList::getLastEnd()
{
    std::shared_lock lock(smtx);
    if (!Intervals.empty())
        return prev(Intervals.end())->first.upper();
    else
        return 0;
}

// unsigned int IntervalList::getElem(unsigned int index, bool is_start)
// {
//     if(index < 0)
//         return 0;

//     unsigned ret = 0;
//     std::shared_lock lock(smtx);
//     if(boost::icl::interval_count(Intervals) > index){
//         auto strided = Intervals | boost::adaptors::strided(index);
//         auto elem = next(strided.begin());
//         if(is_start)
//             ret = elem->lower();
//         else
//             ret = elem->upper();
//     }
//     return ret;
// }

bool IntervalList::contains(unsigned int start, unsigned int end)
{
    std::shared_lock lock(smtx);
    return boost::icl::contains(Intervals, interval_type::right_open(start, end));
}



// Function to insert new interval and
void IntervalList::insertNewInterval(unsigned int start, unsigned int end)
{
    std::unique_lock lock(smtx);
    Intervals += std::make_pair(interval_type::right_open(start, end), 0.01);
}


interval_map IntervalList::removeInterval(unsigned int start, unsigned int end)
{
    interval_map overlaps;
    overlaps += std::make_pair(interval_type::right_open(start, end), 0.01);
    std::unique_lock lock(smtx);
    overlaps &= Intervals;
    for(auto it = overlaps.begin(); it != overlaps.end(); it++){
        Intervals -= it->first;
        uint first_start = Intervals.begin()->first.lower();
        if(first_start == end)
            it->second = IN_ORDER_NEWEST;
        else if(first_start > end)
            it->second = IN_ORDER_FILL;
        else
            it->second = OUT_OF_ORDER;
    }
    return overlaps;
}

double now_ns(){
    return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count()/1000000000.0;
}

interval_map IntervalList::getGapsAndUpdateTimer(uint min_seq, int num, int timeout){
    int cnt = 0;
    double time_now = now_ns();
    interval_map result;
    std::unique_lock lock(smtx);
    // read_lock();
    for(auto it = Intervals.begin(); it != Intervals.end(); it++){
        if(it->first.upper()-1 >= min_seq)
            continue;
        if(it->second == 0.01)
            result += std::make_pair(it->first, double(REQUEST_NEW));
        else if(time_now - it->second >= timeout)
            result += std::make_pair(it->first, double(REQUEST_TIMEOUT));
        else
            continue;
        // read_unlock();
        // write_lock();
        it->second = time_now;
        // write_unlock();
        // read_lock();
        if(++cnt == num)
            break;
    }
    // read_unlock();
    return result;
}


void IntervalList::substract(IntervalList* other)
{
    std::unique_lock lock(smtx);
    Intervals -= other->Intervals;
}



void IntervalList::printIntervals(){

    std::shared_lock lock(smtx);
    std::stringstream ss;
    ss << Intervals;
    std::cout << ss.str().substr(0,100) << std::endl;
    // for(auto it = Intervals.begin(); it != Intervals.end(); it++)
    //     printf("[%u, %u), ", it->lower(), it->upper());
    // printf("\n");
}

std::string IntervalList::Intervals2str(){

    std::shared_lock lock(smtx);
    if(!size())
        return "";

    std::string result = "";
    char temp[100] = {0};
    for(auto it = Intervals.begin(); it != Intervals.end(); it++){
        memset(temp, 0, 100);
        sprintf(temp, "[%u, %u), ", it->first.lower(), it->first.upper());
        result += temp;
    }
        // result += "[" + std::to_string(Intervals[i].start) + ", " + std::to_string(Intervals[i].end) + "], ";
    return result;
}