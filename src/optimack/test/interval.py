def does_overlap(a,b):
	return min(a[1], b[1]) >= max(a[0], b[0])

def insert_new_interval(intervals, newInterval):
	ans, n = [], len(intervals)

	if newInterval[0] >= newInterval[1]:
		return intervals

	if n == 0:
		intervals.append(newInterval)
		return intervals

	if newInterval[1] < intervals[0][0]:
		intervals.insert(0, newInterval)
		return intervals

	if newInterval[0] > intervals[n-1][1]:
		intervals.insert(n, newInterval)
		return intervals

	if newInterval[0] <= intervals[0][0] and newInterval[1] >= intervals[n-1][1]:
		ans.append(newInterval)
		return ans

	overlap = True
	i = 0
	while i < n:
		overlap = does_overlap(intervals[i], newInterval)
		if not overlap:
			ans.append(intervals[i])
			if i < n and newInterval[0] > intervals[i][1] and newInterval[1] < intervals[i+1][0]:
				ans.append(newInterval)
			continue

		temp = (-1,-1)
		temp[0] = min(newInterval[0], intervals[i][0])
		while i < n and overlap:
			temp[1] = max(newInterval[1], intervals[i][1])
			if i == n - 1:
				overlap = True
			else:
				overlap = does_overlap(intervals[i+1], newInterval)
			i += 1
		i -= 1
		if temp[0] < temp[1]:
			ans.append(temp)
		else:
			print("insertNewInterval: temp start > end")
		i += 1

	return ans


def remove_interval(intervals, newInterval):
	ans, n = [], len(intervals)

	if newInterval[0] >= newInterval[1]:
		return 

	if n == 0:
		return 

	if newInterval[1] < intervals[0][0] or newInterval[0] > intervals[n-1][1]:
		return 

	if newInterval[0] <= intervals[0][0] and newInterval[1] >= intervals[n-1][1]:
		intervals[:] = ans
		return

	for i in range(n):
		if does_overlap(intervals[i], newInterval):
			if intervals[i][0] < newInterval[0]:
				ans.append((intervals[i][0], newInterval[0]))
			if newInterval[1] < intervals[i][1]:
				ans.append((newInterval[1], intervals[i][1]))
		else:
			ans.append(intervals[i])
	intervals[:] = ans
	return

def print_interval(intervals):
	for interval in intervals:
		print("[%d, %d], " % (interval[0], interval[1]))


# Function to print intersecting 
# intervals
def intersect_intervals(arr1, arr2):
	ranges = []
	i = j = 0
	n, m = len(arr1), len(arr2)

	# Loop through all intervals unless one of the interval gets exhausted
	while i < n and j < m:
		l = max(arr1[i][0], arr2[j][0]) # Left bound for intersecting segment
		r = min(arr1[i][1], arr2[j][1]) # Right bound for intersecting segment

		# If segment is valid print it
		if l < r: 
			ranges.append([l, r])
			# print('{', l, ',', r, '}')

		# If i-th interval's right bound is smaller increment i else increment j
		if arr1[i][1] < arr2[j][1]:
			i += 1
		else:
			j += 1
	
	return ranges

def total_bytes(intervals):
	sum = 0
	for gap in intervals:
		if gap[1] < gap[0]:
			print("Error: gap[1] < gap[0]")
		sum += gap[1] - gap[0]
	return sum