#ifndef INTERVAL_H
#define INTERVAL_H

#include <vector>
#include <string>

// Define the structure of interval
struct Interval
{
    unsigned int start;
    unsigned int end;
    std::string timestamp;
    Interval()
        : start(0), end(0)
    {
    }
    Interval(unsigned int s, unsigned int e, char* ts)
        : start(s), end(e), timestamp(ts)
    {
    }
    Interval(unsigned int s, unsigned int e, std::string ts)
        : start(s), end(e), timestamp(ts)
    {
    }
};

// A subroutine to check if intervals overlap or not.
bool doesOverlap(Interval a, Interval b);

// Function to insert new interval and
// merge overlapping intervals
std::vector<Interval> insertNewInterval(std::vector<Interval>& Intervals, Interval newInterval);

// Function to insert new interval and
// merge overlapping intervals
std::vector<Interval> removeInterval(std::vector<Interval>& Intervals, Interval newInterval);

void printIntervals(std::vector<Interval>& Intervals);
std::string Intervals2str(std::vector<Interval>& Intervals);
#endif