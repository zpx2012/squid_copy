#include "interval.h"
#include <stdio.h>

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
    unsigned int sum_bytes = 0;
    for (size_t i = 0; i < Intervals.size(); i++)
       sum_bytes += Intervals[i].end - Intervals[i].start + 1;
    return sum_bytes;
}

void IntervalList::insertNewInterval_withLock(unsigned int start, unsigned int end)
{
    pthread_mutex_lock(&mutex_intervals);
    insertNewInterval(start, end);
    pthread_mutex_unlock(&mutex_intervals);
}

void IntervalList::insertNewInterval_withLock(Interval newInterval)
{
    pthread_mutex_lock(&mutex_intervals);
    insertNewInterval(newInterval.start, newInterval.end);
    pthread_mutex_unlock(&mutex_intervals);
}

bool IntervalList::checkAndinsertNewInterval_withLock(unsigned int start, unsigned int end)
{
    pthread_mutex_lock(&mutex_intervals);
    if(contains(start,end)){
        pthread_mutex_unlock(&mutex_intervals);
        return false;
    }
    insertNewInterval(start, end);
    pthread_mutex_unlock(&mutex_intervals);
    return true;
}

unsigned int IntervalList::insertNewInterval_getLastEnd_withLock(unsigned int start, unsigned int end)
{
    unsigned lastend = 0;
    pthread_mutex_lock(&mutex_intervals);
    insertNewInterval(start, end);
    lastend = getLastEnd();
    pthread_mutex_unlock(&mutex_intervals);
    return lastend;
}

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
    Intervals2str();
    pthread_mutex_unlock(&mutex_intervals);
}

unsigned int IntervalList::getFirstEnd_withLock()
{
    unsigned start = 0;
    pthread_mutex_lock(&mutex_intervals);
    if(!Intervals.empty())
        start = Intervals.begin()->end;
    pthread_mutex_unlock(&mutex_intervals);    
    return start;
}

unsigned int IntervalList::getLastEnd_withLock()
{
    unsigned end = 0;
    pthread_mutex_lock(&mutex_intervals);
    if(!Intervals.empty())
        end = (Intervals.end()-1)->end;
    pthread_mutex_unlock(&mutex_intervals);
    return end;
}

unsigned int IntervalList::getFirstEnd()
{
    if (!Intervals.empty())
        return Intervals.begin()->end;
    else
        return 0;
}

unsigned int IntervalList::getLastEnd()
{
    if (!Intervals.empty())
        return (Intervals.end()-1)->end;
    else
        return 0;
}

unsigned int IntervalList::getElem_withLock(unsigned int index, bool is_start)
{
    if(index < 0)
        return 0;

    unsigned ret = 0;
    pthread_mutex_lock(&mutex_intervals);
    if(Intervals.size() > index)
        if(is_start)
            ret = Intervals.at(index).start;
        else
            ret = Intervals.at(index).end;
    pthread_mutex_unlock(&mutex_intervals);
    return ret;
}

// A subroutine to check if intervals overlap or not.
bool IntervalList::doesOverlap(Interval a, Interval b)
{
    return (std::min(a.end, b.end) >= std::max(a.start, b.start));
}

bool IntervalList::does_a_contains_b(Interval a, Interval b){
    return a.start <= b.start && a.end >= b.end;
}

bool IntervalList::contains(unsigned int start, unsigned int end){
    Interval newInterval = Interval(start, end);
    int n = Intervals.size();
    
    if(n == 0)
        return false;

    if (end < Intervals[0].start || newInterval.start > Intervals[n - 1].end)
        return false;
    
    for(int i = 0; i < n; i++)
        if(does_a_contains_b(Intervals[i], newInterval))
            return true;
    return false;
}

// Function to insert new interval and
// merge overlapping intervals
void IntervalList::insert(Interval newInterval)
{
    // Interval newInterval = Interval(start, end);
    unsigned int start = newInterval.start;
    unsigned int end = newInterval.end;
    std::vector<Interval> ans;
    int n = Intervals.size();

    if(start >= end)
        return;
 
    // If set is empty then simply insert
    // newInterval and return.
    if (n == 0)
    {
        Intervals.push_back(newInterval);
        return;
    }
 
 
    // Case 1 and Case 2 (new interval to be
    // inserted at corners)
    if (end < Intervals[0].start || newInterval.start > Intervals[n - 1].end)
    {
        if (newInterval.end < Intervals[0].start)
            Intervals.insert(Intervals.begin(), newInterval);
 
        if (newInterval.start > Intervals[n - 1].end)
            Intervals.insert(Intervals.end(), newInterval);
 
        return;
    }
 
    // Case 3 (New interval covers all existing)
    if (newInterval.start <= Intervals[0].start && newInterval.end >= Intervals[n - 1].end)
    {
        Intervals.clear();
        Intervals.push_back(newInterval);
        return;
    }
 
    // Case 4 and Case 5
    // These two cases need to check whether
    // intervals overlap or not. For this we
    // can use a subroutine that will perform
    // this function.
    bool overlap = true;
    for (int i = 0; i < n; i++)
    {
        overlap = doesOverlap(Intervals[i], newInterval);
        if (!overlap)
        {
            ans.push_back(Intervals[i]);
 
            // Case 4 : To check if given interval
            // lies between two intervals.
            if (i < n &&
                newInterval.start > Intervals[i].end &&
                newInterval.end < Intervals[i + 1].start)
                ans.push_back(newInterval);
 
            continue;
        }
        else{
            if (start < Intervals[i].start){
                Interval left = newInterval;
                left.end = Intervals[i].start;
                ans.push_back(left);
            }
            
            ans.push_back(Intervals[i]);

            if (end > Intervals[i].end){
                Interval right = newInterval;
                right.start = Intervals[i].end;
                ans.push_back(right);
            }
        }
    }
}

void IntervalList::insertNewInterval(Interval newInterval)
{
    insertNewInterval(newInterval.start, newInterval.end);
}

// Function to insert new interval and
// merge overlapping intervals
void IntervalList::insertNewInterval(unsigned int start, unsigned int end)
{
    Interval newInterval = Interval(start, end);
    std::vector<Interval> ans;
    int n = Intervals.size();

    if(start >= end)
        return;
 
    // If set is empty then simply insert
    // newInterval and return.
    if (n == 0)
    {
        Intervals.push_back(newInterval);
        return;
    }
 
 
    // Case 1 and Case 2 (new interval to be
    // inserted at corners)
    if (end < Intervals[0].start || newInterval.start > Intervals[n - 1].end)
    {
        if (newInterval.end < Intervals[0].start)
            Intervals.insert(Intervals.begin(), newInterval);
 
        if (newInterval.start > Intervals[n - 1].end)
            Intervals.insert(Intervals.end(), newInterval);
 
        return;
    }
 
    // Case 3 (New interval covers all existing)
    if (newInterval.start <= Intervals[0].start && newInterval.end >= Intervals[n - 1].end)
    {
        Intervals.clear();
        Intervals.push_back(newInterval);
        return;
    }
 
    // Case 4 and Case 5
    // These two cases need to check whether
    // intervals overlap or not. For this we
    // can use a subroutine that will perform
    // this function.
    bool overlap = true;
    for (int i = 0; i < n; i++)
    {
        overlap = doesOverlap(Intervals[i], newInterval);
        if (!overlap)
        {
            ans.push_back(Intervals[i]);
 
            // Case 4 : To check if given interval
            // lies between two intervals.
            if (i < n &&
                newInterval.start > Intervals[i].end &&
                newInterval.end < Intervals[i + 1].start)
                ans.push_back(newInterval);
 
            continue;
        }
 
        // Case 5 : Merge Overlapping Intervals.
        // Starting time of new merged interval is
        // minimum of starting time of both
        // overlapping intervals.
        Interval temp;
        temp.start = std::min(newInterval.start, Intervals[i].start);
        // temp.timestamp = Intervals[i].timestamp;
 
        // Traverse the set until intervals are
        // overlapping
        while (i < n && overlap)
        {
 
            // Ending time of new merged interval
            // is maximum of ending time both
            // overlapping intervals.
            temp.end = std::max(newInterval.end, Intervals[i].end);
            if (i == n - 1)
                overlap = false;
            else
                overlap = doesOverlap(Intervals[i + 1], newInterval);
            i++;
        }
 
        i--;
        if(temp.start < temp.end)
            ans.push_back(temp);
        else
            printf("insertNewInterval: temp start > end\n");
    }
    Intervals = ans;
    return;
}

// Function to insert new interval and
// merge overlapping intervals
void IntervalList::removeInterval(unsigned int start, unsigned int end)
{
    std::vector<Interval> ans;
    int n = Intervals.size();
 
    if(start >= end)
        return;

    // If set is empty then simply return.
    if (n == 0)
        return;
 
    // Case 1 and Case 2 (new interval to be at corners), return
    if (end < Intervals[0].start || start > Intervals[n - 1].end)
        return;
 
    // Case 3 (New interval covers all existing), empty the list
    if (start <= Intervals[0].start && end >= Intervals[n - 1].end)
    {   
        Intervals.clear();
        return;
    }
 
    // Case 4 and Case 5
    // These two cases need to check whether
    // intervals overlap or not. For this we
    // can use a subroutine that will perform
    // this function.
    for (int i = 0; i < n; i++)
    {
        if(doesOverlap(Intervals[i], Interval(start, end))){
            if(Intervals[i].start < start){
                Interval left(Intervals[i].start, start);
                ans.push_back(left);
            }
            if(end < Intervals[i].end){
                Interval right(end, Intervals[i].end);
                ans.push_back(right);
            }
        }
        else
        {
            ans.push_back(Intervals[i]);
        }
        
    }
    Intervals = ans;
    return;
}

void IntervalList::substract(IntervalList* other){
    std::vector<Interval> other_intervals = other->getIntervalList();
    for(auto& intvl: other_intervals){
        removeInterval(intvl.start, intvl.end);
        if(Intervals.empty())
            return;
    }
}



void IntervalList::printIntervals(){
    for (size_t i = 0; i < Intervals.size(); i++)
        printf("[%u, %u], ", Intervals[i].start, Intervals[i].end);
    printf("\n");
}

std::string IntervalList::Intervals2str(){
    std::string result = "";
    for (size_t i = 0; i < Intervals.size(); i++)
        result += "[" + std::to_string(Intervals[i].start) + ", " + std::to_string(Intervals[i].end) + "], ";
    return result;
}