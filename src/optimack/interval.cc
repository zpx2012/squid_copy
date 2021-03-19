#include "interval.h"
#include <stdio.h>

// A subroutine to check if intervals overlap or not.
bool doesOverlap(Interval a, Interval b)
{
    return (std::min(a.end, b.end) >= std::max(a.start, b.start));
}

 
// Function to insert new interval and
// merge overlapping intervals
std::vector<Interval> insertNewInterval(std::vector<Interval>& Intervals, Interval newInterval)
{
    std::vector<Interval> ans;
    int n = Intervals.size();

    if(newInterval.start >= newInterval.end)
        return Intervals;
 
    // If set is empty then simply insert
    // newInterval and return.
    if (n == 0)
    {
        Intervals.push_back(newInterval);
        return Intervals;
    }
 
 
    // Case 1 and Case 2 (new interval to be
    // inserted at corners)
    if (newInterval.end < Intervals[0].start ||
            newInterval.start > Intervals[n - 1].end)
    {
        if (newInterval.end < Intervals[0].start)
            Intervals.insert(Intervals.begin(), newInterval);
 
        if (newInterval.start > Intervals[n - 1].end)
            Intervals.insert(Intervals.end(), newInterval);
 
        return Intervals;
    }
 
    // Case 3 (New interval covers all existing)
    if (newInterval.start <= Intervals[0].start &&
        newInterval.end >= Intervals[n - 1].end)
    {
        ans.push_back(newInterval);
        return ans;
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
        temp.start = std::min(newInterval.start,
                         Intervals[i].start);
        temp.timestamp = Intervals[i].timestamp;
 
        // Traverse the set until intervals are
        // overlapping
        while (i < n && overlap)
        {
 
            // Ending time of new merged interval
            // is maximum of ending time both
            // overlapping intervals.
            temp.end = std::max(newInterval.end,
                           Intervals[i].end);
            if (i == n - 1)
                overlap = false;
            else
                overlap = doesOverlap(Intervals[i + 1],
                                          newInterval);
            i++;
        }
 
        i--;
        if(temp.start < temp.end)
            ans.push_back(temp);
        else
            printf("insertNewInterval: temp start > end\n");
    }
 
    return ans;
}

// Function to insert new interval and
// merge overlapping intervals
std::vector<Interval> removeInterval(std::vector<Interval>& Intervals, Interval newInterval)
{
    std::vector<Interval> ans;
    int n = Intervals.size();
 
    if(newInterval.start >= newInterval.end)
        return Intervals;

    // If set is empty then simply return.
    if (n == 0)
        return Intervals;
 
    // Case 1 and Case 2 (new interval to be at corners), return
    if (newInterval.end < Intervals[0].start ||
            newInterval.start > Intervals[n - 1].end)
        return Intervals;
 
    // Case 3 (New interval covers all existing), empty the list
    if (newInterval.start <= Intervals[0].start &&
        newInterval.end >= Intervals[n - 1].end)
    {   
        return ans;
    }
 
    // Case 4 and Case 5
    // These two cases need to check whether
    // intervals overlap or not. For this we
    // can use a subroutine that will perform
    // this function.
    for (int i = 0; i < n; i++)
    {
        if(doesOverlap(Intervals[i], newInterval)){
            if(Intervals[i].start < newInterval.start){
                Interval left(Intervals[i].start, newInterval.start, Intervals[i].timestamp);
                ans.push_back(left);
            }
            if(newInterval.end < Intervals[i].end){
                Interval right(newInterval.end, Intervals[i].end, Intervals[i].timestamp);
                ans.push_back(right);
            }
        }
        else
        {
            ans.push_back(Intervals[i]);
        }
        
    }
    return ans;
}


void printIntervals(std::vector<Interval>& Intervals){
    for (int i = 0; i < Intervals.size(); i++)
        printf("[%u, %u], ", Intervals[i].start, Intervals[i].end);
    printf("\n");
}

std::string Intervals2str(std::vector<Interval>& Intervals){
    std::string result = "";
    for (int i = 0; i < Intervals.size(); i++)
        result += "[" + std::to_string(Intervals[i].start) + ", " + std::to_string(Intervals[i].end) + "], ";
    return result;
}